//! Event-driven metrics for real-time Prometheus counter increments.
//!
//! This module provides metrics that are incremented at the point where events occur
//! (e.g., share acceptance, share rejection, block discovery) rather than being
//! sampled periodically from snapshots.
//!
//! ## Architecture
//!
//! - **EventMetrics** is passed to business logic components (e.g., ChannelManager)
//! - Events trigger immediate counter increments (e.g., `shares_accepted_total.inc()`)
//! - Prometheus scrapes these counters directly from the registry
//! - No snapshot cache needed for event metrics
//!
//! ## Metric Types
//!
//! - **Counters**: Monotonically increasing values (shares accepted, blocks found)
//! - **Histograms**: Distribution tracking (share validation latency) - future
//! - **Gauges**: Use snapshot-based collection in `SnapshotMetrics` (channel counts, hashrate)
//!
//! ## Cardinality
//!
//! All counters use either no labels or bounded enum labels to prevent cardinality explosion.
//! Per-channel share data is available via the REST API (`/api/v1/server/channels`,
//! `/api/v1/client/channels`) for detailed debugging without Prometheus cardinality risk.

use prometheus::{Counter, IntCounterVec, Opts, Registry};

/// Reasons why a share may be rejected.
///
/// This enum is used as a label value for `sv2_shares_rejected_total`.
/// The variants are bounded to prevent cardinality explosion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareRejectionReason {
    /// Share nonce is invalid
    InvalidNonce,
    /// Share does not meet difficulty target
    InvalidDifficulty,
    /// Share references an old job that is no longer valid
    StaleShare,
    /// Share has already been submitted
    DuplicateShare,
    /// Share has invalid merkle root
    InvalidMerkleRoot,
    /// Job ID not found
    JobNotFound,
    /// Other/unknown reason
    Other,
}

impl ShareRejectionReason {
    /// Convert to string for use as Prometheus label value
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareRejectionReason::InvalidNonce => "invalid_nonce",
            ShareRejectionReason::InvalidDifficulty => "invalid_difficulty",
            ShareRejectionReason::StaleShare => "stale_share",
            ShareRejectionReason::DuplicateShare => "duplicate_share",
            ShareRejectionReason::InvalidMerkleRoot => "invalid_merkle_root",
            ShareRejectionReason::JobNotFound => "job_not_found",
            ShareRejectionReason::Other => "other",
        }
    }
}

/// Event-driven metrics that are incremented at the point where events occur.
///
/// These metrics are passed to business logic components and incremented
/// immediately when events happen, providing real-time data to Prometheus.
///
/// All counters use either no labels or bounded enum labels to ensure safe cardinality.
/// Per-channel share data is available via the REST API for detailed debugging.
#[derive(Clone)]
pub struct EventMetrics {
    /// Total shares accepted across all channels (aggregate, no labels)
    pub sv2_shares_accepted_total: Counter,

    /// Total shares rejected by reason (bounded enum labels, max 7 values)
    pub sv2_shares_rejected_total: IntCounterVec,
}

impl EventMetrics {
    /// Create new EventMetrics and register them with the provided Prometheus registry.
    ///
    /// # Arguments
    ///
    /// * `registry` - Prometheus registry to register metrics with
    /// * `_enable_server_metrics` - Unused, kept for API compatibility
    /// * `_enable_clients_metrics` - Unused, kept for API compatibility
    ///
    /// Note: The enable flags are kept for backward compatibility but are no longer used.
    /// All event metrics are now aggregate counters without per-entity labels.
    pub fn new(
        registry: &Registry,
        _enable_server_metrics: bool,
        _enable_clients_metrics: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sv2_shares_accepted_total = Counter::new(
            "sv2_shares_accepted_total",
            "Total shares accepted across all channels (aggregate)",
        )?;
        registry.register(Box::new(sv2_shares_accepted_total.clone()))?;

        let sv2_shares_rejected_total = IntCounterVec::new(
            Opts::new(
                "sv2_shares_rejected_total",
                "Total shares rejected by reason",
            ),
            &["reason"],
        )?;
        registry.register(Box::new(sv2_shares_rejected_total.clone()))?;

        Ok(Self {
            sv2_shares_accepted_total,
            sv2_shares_rejected_total,
        })
    }

    /// Increment the aggregate shares accepted counter.
    ///
    /// This should be called for every accepted share, regardless of channel.
    /// Provides simple operational visibility without cardinality concerns.
    #[inline]
    pub fn inc_shares_accepted(&self) {
        self.sv2_shares_accepted_total.inc();
    }

    /// Increment the shares rejected counter for a specific reason.
    ///
    /// Uses bounded enum labels to prevent cardinality explosion.
    #[inline]
    pub fn inc_shares_rejected(&self, reason: ShareRejectionReason) {
        self.sv2_shares_rejected_total
            .with_label_values(&[reason.as_str()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_counter_increment() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        metrics.inc_shares_accepted();
        metrics.inc_shares_accepted();

        assert_eq!(metrics.sv2_shares_accepted_total.get(), 2.0);
    }

    #[test]
    fn test_rejection_counter_by_reason() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        metrics.inc_shares_rejected(ShareRejectionReason::StaleShare);
        metrics.inc_shares_rejected(ShareRejectionReason::StaleShare);
        metrics.inc_shares_rejected(ShareRejectionReason::InvalidNonce);

        let stale = metrics
            .sv2_shares_rejected_total
            .with_label_values(&["stale_share"])
            .get();
        let invalid = metrics
            .sv2_shares_rejected_total
            .with_label_values(&["invalid_nonce"])
            .get();

        assert_eq!(stale, 2);
        assert_eq!(invalid, 1);
    }

    #[test]
    fn test_rejection_reason_cardinality_bounded() {
        // Verify all enum variants produce valid label values
        let reasons = [
            ShareRejectionReason::InvalidNonce,
            ShareRejectionReason::InvalidDifficulty,
            ShareRejectionReason::StaleShare,
            ShareRejectionReason::DuplicateShare,
            ShareRejectionReason::InvalidMerkleRoot,
            ShareRejectionReason::JobNotFound,
            ShareRejectionReason::Other,
        ];

        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        for reason in reasons {
            metrics.inc_shares_rejected(reason);
        }

        // Should have exactly 7 label combinations (one per enum variant)
        let metric_families = registry.gather();
        let rejected_family = metric_families
            .iter()
            .find(|f| f.get_name() == "sv2_shares_rejected_total")
            .unwrap();

        assert_eq!(rejected_family.get_metric().len(), 7);
    }

    #[test]
    fn test_counters_are_monotonic() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        let mut prev = 0.0;
        for _ in 0..100 {
            metrics.inc_shares_accepted();
            let current = metrics.sv2_shares_accepted_total.get();
            assert!(current > prev, "Counter must be monotonically increasing");
            prev = current;
        }
    }

    #[test]
    fn test_enable_flags_are_ignored() {
        // The enable flags are kept for API compatibility but no longer used
        // All metrics are now aggregate counters
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, false, false).unwrap();

        // Aggregate counters should still work regardless of flags
        metrics.inc_shares_accepted();
        assert_eq!(metrics.sv2_shares_accepted_total.get(), 1.0);

        metrics.inc_shares_rejected(ShareRejectionReason::StaleShare);
        assert_eq!(
            metrics
                .sv2_shares_rejected_total
                .with_label_values(&["stale_share"])
                .get(),
            1
        );
    }
}
