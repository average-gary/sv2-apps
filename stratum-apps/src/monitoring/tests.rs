//! Tests for the monitoring snapshot cache
//!
//! Verifies that the snapshot cache eliminates lock contention between
//! monitoring API requests and business logic operations.

#[cfg(test)]
mod snapshot_cache_tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::monitoring::client::{ClientInfo, ClientsMonitoring};
    use crate::monitoring::server::{ServerInfo, ServerMonitoring};
    use crate::monitoring::snapshot_cache::{CachedMonitoring, SnapshotCache};

    /// Mock monitoring that simulates lock contention with business logic.
    struct ContendedMonitoring {
        lock_hold_duration: Duration,
        monitoring_lock_acquisitions: AtomicU64,
        total_wait_time_ns: AtomicU64,
        business_lock: std::sync::Mutex<()>,
    }

    impl ContendedMonitoring {
        fn new(lock_hold_duration: Duration) -> Self {
            Self {
                lock_hold_duration,
                monitoring_lock_acquisitions: AtomicU64::new(0),
                total_wait_time_ns: AtomicU64::new(0),
                business_lock: std::sync::Mutex::new(()),
            }
        }

        fn simulate_business_logic(&self) {
            let _guard = self.business_lock.lock().unwrap();
            std::thread::sleep(self.lock_hold_duration);
        }

        fn get_monitoring_acquisitions(&self) -> u64 {
            self.monitoring_lock_acquisitions.load(Ordering::SeqCst)
        }
    }

    impl ClientsMonitoring for ContendedMonitoring {
        fn get_clients(&self) -> Vec<ClientInfo> {
            let start = Instant::now();
            let _guard = self.business_lock.lock().unwrap();

            let wait_time = start.elapsed();
            self.total_wait_time_ns
                .fetch_add(wait_time.as_nanos() as u64, Ordering::SeqCst);
            self.monitoring_lock_acquisitions
                .fetch_add(1, Ordering::SeqCst);

            std::thread::sleep(Duration::from_micros(100));
            vec![]
        }
    }

    impl ServerMonitoring for ContendedMonitoring {
        fn get_server(&self) -> ServerInfo {
            let start = Instant::now();
            let _guard = self.business_lock.lock().unwrap();

            let wait_time = start.elapsed();
            self.total_wait_time_ns
                .fetch_add(wait_time.as_nanos() as u64, Ordering::SeqCst);
            self.monitoring_lock_acquisitions
                .fetch_add(1, Ordering::SeqCst);

            std::thread::sleep(Duration::from_micros(100));
            ServerInfo {
                extended_channels: vec![],
                standard_channels: vec![],
            }
        }
    }

    /// Verifies that the snapshot cache eliminates lock contention.
    ///
    /// Without the cache, monitoring API requests would acquire the same lock
    /// used by business logic (share validation, job distribution), causing
    /// performance degradation. The cache decouples these operations by
    /// periodically refreshing a snapshot that API requests read from.
    #[test]
    fn test_snapshot_cache_eliminates_lock_contention() {
        let real_monitoring = Arc::new(ContendedMonitoring::new(Duration::from_millis(1)));

        let cache = Arc::new(SnapshotCache::new(
            Duration::from_secs(5),
            None,
            Some(real_monitoring.clone() as Arc<dyn ClientsMonitoring + Send + Sync>),
        ));

        cache.refresh();

        let cached_monitoring = Arc::new(CachedMonitoring::new(cache.clone()));

        // Simulate business logic running concurrently
        let business_mon = Arc::clone(&real_monitoring);
        let business_handle = std::thread::spawn(move || {
            let start = Instant::now();
            let mut ops = 0u64;
            while start.elapsed() < Duration::from_millis(100) {
                business_mon.simulate_business_logic();
                ops += 1;
            }
            ops
        });

        // Simulate rapid API requests via cache (4 threads)
        let mut monitoring_handles = vec![];
        for _ in 0..4 {
            let cached = Arc::clone(&cached_monitoring);
            monitoring_handles.push(std::thread::spawn(move || {
                let start = Instant::now();
                let mut requests = 0u64;
                while start.elapsed() < Duration::from_millis(100) {
                    let _ = cached.get_clients();
                    requests += 1;
                }
                requests
            }));
        }

        let business_ops = business_handle.join().unwrap();
        let total_cache_requests: u64 = monitoring_handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .sum();

        let real_lock_acquisitions = real_monitoring.get_monitoring_acquisitions();

        // Cache should only acquire lock during refresh (1-2 times), not per request
        assert!(
            real_lock_acquisitions <= 2,
            "Cache acquired lock {} times, expected ≤2 (refresh only)",
            real_lock_acquisitions
        );

        // Cache should enable high throughput (>1000 requests in 100ms)
        assert!(
            total_cache_requests > 1000,
            "Cache processed only {} requests in 100ms, expected >1000",
            total_cache_requests
        );

        println!(
            "✓ Cache processed {} requests with only {} lock acquisitions ({} business ops)",
            total_cache_requests, real_lock_acquisitions, business_ops
        );
    }
}
