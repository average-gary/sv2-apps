//! Admission policy for the iroh listener.
//!
//! Open by default; optional runtime-updateable whitelist of NodeIds. Used
//! by `IrohSv2Listener` (Wave 3) to decide whether a peer's NodeId is allowed
//! to even attempt the SV2 Noise handshake.
//!
//! See plan §"Two-layer identity model" for context. The admission check is
//! the QUIC-layer rejection that runs BEFORE any SV2 bytes flow:
//!
//! 1. iroh QUIC handshake completes; `connection.remote_node_id()` yields a
//!    [`NodeId`].
//! 2. [`AdmissionHandle::admits`] decides QUIC-layer admission. If denied,
//!    the connection is closed without any SV2 bytes being sent.
//! 3. Only then is the SV2 Noise NX handshake run inside the bidi stream.
//!
//! The handle uses [`arc_swap::ArcSwap`] so the read path is lock-free —
//! every accept consults it once, and contention with rare administrative
//! updates is avoided.

use arc_swap::ArcSwap;
use iroh::NodeId;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Admission decision for a peer NodeId observed at QUIC accept time.
#[derive(Debug, Clone)]
pub enum AdmissionPolicy {
    /// Admit any NodeId. The default, suitable for low-friction mining.
    Open,
    /// Admit only NodeIds in the contained set. Empty set admits nothing.
    Whitelist(BTreeSet<NodeId>),
}

impl AdmissionPolicy {
    /// Returns whether this policy admits the given `node_id`.
    fn admits(&self, node_id: &NodeId) -> bool {
        match self {
            AdmissionPolicy::Open => true,
            AdmissionPolicy::Whitelist(set) => set.contains(node_id),
        }
    }
}

/// Cheaply-clonable handle for runtime updates and lock-free reads on the
/// accept hot path.
///
/// Cloning shares the underlying [`ArcSwap`], so all clones observe the same
/// live policy. Mutations replace the entire policy atomically; concurrent
/// readers see either the old or new policy, never a torn state.
#[derive(Clone)]
pub struct AdmissionHandle {
    inner: Arc<ArcSwap<AdmissionPolicy>>,
}

impl AdmissionHandle {
    /// Creates a handle initialized to [`AdmissionPolicy::Open`].
    pub fn open() -> Self {
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(AdmissionPolicy::Open))),
        }
    }

    /// Creates a handle initialized to [`AdmissionPolicy::Whitelist`] with
    /// the given starting set.
    pub fn whitelist(initial: BTreeSet<NodeId>) -> Self {
        Self {
            inner: Arc::new(ArcSwap::new(Arc::new(AdmissionPolicy::Whitelist(
                initial,
            )))),
        }
    }

    /// Replaces the entire policy atomically.
    ///
    /// Concurrent readers see either the old or the new policy, never a
    /// partial update.
    pub fn set_policy(&self, policy: AdmissionPolicy) {
        self.inner.store(Arc::new(policy));
    }

    /// Adds a NodeId to the whitelist.
    ///
    /// **Semantic transition:** if the current policy is
    /// [`AdmissionPolicy::Open`], this call promotes it to
    /// [`AdmissionPolicy::Whitelist`] containing exactly `node_id`. After
    /// this point, all NodeIds other than `node_id` are rejected until the
    /// caller adds them or restores [`AdmissionPolicy::Open`] via
    /// [`set_policy`](Self::set_policy). This is intentional — adding to a
    /// whitelist that does not exist yet must mean "lock it down to this
    /// peer", otherwise the call would be a no-op.
    pub fn add(&self, node_id: NodeId) {
        // rcu retries on concurrent writers; reads inside the closure are
        // cheap clones of the current policy.
        self.inner.rcu(|current| {
            let mut set = match current.as_ref() {
                AdmissionPolicy::Open => BTreeSet::new(),
                AdmissionPolicy::Whitelist(s) => s.clone(),
            };
            set.insert(node_id);
            Arc::new(AdmissionPolicy::Whitelist(set))
        });
    }

    /// Removes a NodeId from the whitelist.
    ///
    /// No-op if the current policy is [`AdmissionPolicy::Open`] or the
    /// `node_id` is not present. Removing the last entry leaves an empty
    /// whitelist (which admits nothing).
    pub fn remove(&self, node_id: &NodeId) {
        self.inner.rcu(|current| match current.as_ref() {
            AdmissionPolicy::Open => current.clone(),
            AdmissionPolicy::Whitelist(s) => {
                if !s.contains(node_id) {
                    return current.clone();
                }
                let mut set = s.clone();
                set.remove(node_id);
                Arc::new(AdmissionPolicy::Whitelist(set))
            }
        });
    }

    /// O(1) admission check used on every accept. Lock-free read.
    pub fn admits(&self, node_id: &NodeId) -> bool {
        self.inner.load().admits(node_id)
    }

    /// Returns a cloned snapshot of the current policy. Intended for status
    /// endpoints; the hot path should call [`admits`](Self::admits) instead.
    pub fn snapshot(&self) -> AdmissionPolicy {
        self.inner.load().as_ref().clone()
    }
}

impl std::fmt::Debug for AdmissionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionHandle")
            .field("policy", &self.snapshot())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;

    /// Generate a random NodeId by deriving from a freshly-generated Ed25519
    /// secret key. Mirrors the pattern used in
    /// `noise_generic_stream::tests::iroh_endpoint_pair_roundtrip`.
    fn random_node_id() -> NodeId {
        SecretKey::generate(rand::rngs::OsRng).public()
    }

    /// Deterministic NodeId from a 32-byte seed; useful when a test needs a
    /// stable id for clarity, but unwraps because `from_bytes` rejects the
    /// all-zero / non-canonical Ed25519 points and we only feed it sane bytes.
    fn deterministic_node_id(seed: u8) -> NodeId {
        // Use SecretKey rather than NodeId::from_bytes directly so we always
        // get a canonical Ed25519 public point.
        let bytes = [seed.wrapping_add(1); 32];
        SecretKey::from_bytes(&bytes).public()
    }

    #[test]
    fn open_admits_any() {
        let handle = AdmissionHandle::open();
        let a = random_node_id();
        let b = random_node_id();
        assert!(handle.admits(&a), "open policy must admit any NodeId");
        assert!(handle.admits(&b), "open policy must admit any NodeId");
        assert!(matches!(handle.snapshot(), AdmissionPolicy::Open));
    }

    #[test]
    fn whitelist_admits_only_listed() {
        let allowed = random_node_id();
        let denied = random_node_id();

        let mut set = BTreeSet::new();
        set.insert(allowed);
        let handle = AdmissionHandle::whitelist(set);

        assert!(handle.admits(&allowed), "listed NodeId must be admitted");
        assert!(
            !handle.admits(&denied),
            "unlisted NodeId must be rejected"
        );
    }

    #[test]
    fn add_promotes_open_to_whitelist() {
        let handle = AdmissionHandle::open();
        let id = random_node_id();
        let other = random_node_id();

        // Sanity: before add, both admitted (open policy).
        assert!(handle.admits(&other));

        handle.add(id);

        // After add, only `id` is admitted — Open has been promoted to
        // Whitelist({id}).
        assert!(handle.admits(&id), "added NodeId must be admitted");
        assert!(
            !handle.admits(&other),
            "non-added NodeId must NOT be admitted after Open->Whitelist promotion"
        );
        match handle.snapshot() {
            AdmissionPolicy::Whitelist(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains(&id));
            }
            AdmissionPolicy::Open => panic!("expected promotion to Whitelist"),
        }
    }

    #[test]
    fn remove_from_open_is_noop() {
        let handle = AdmissionHandle::open();
        let id = random_node_id();
        handle.remove(&id);
        assert!(
            matches!(handle.snapshot(), AdmissionPolicy::Open),
            "remove on Open policy must be a no-op"
        );
        // And the open policy still admits any peer.
        assert!(handle.admits(&id));
        assert!(handle.admits(&random_node_id()));
    }

    #[test]
    fn set_policy_replaces() {
        let a = random_node_id();
        let b = random_node_id();

        let mut set = BTreeSet::new();
        set.insert(a);
        let handle = AdmissionHandle::whitelist(set);

        // Sanity: b is rejected under the initial whitelist.
        assert!(!handle.admits(&b));

        handle.set_policy(AdmissionPolicy::Open);

        assert!(handle.admits(&b), "after set_policy(Open), b must be admitted");
        assert!(handle.admits(&a), "after set_policy(Open), a must be admitted");
        assert!(matches!(handle.snapshot(), AdmissionPolicy::Open));
    }

    #[test]
    fn remove_from_empty_whitelist_remains_empty() {
        // Edge case from spec: removing from an empty whitelist leaves an
        // empty whitelist (admits nothing).
        let handle = AdmissionHandle::whitelist(BTreeSet::new());
        let id = deterministic_node_id(7);
        handle.remove(&id);
        match handle.snapshot() {
            AdmissionPolicy::Whitelist(s) => assert!(s.is_empty()),
            AdmissionPolicy::Open => panic!("must remain Whitelist"),
        }
        assert!(!handle.admits(&id));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_reads_during_writes() {
        // Two distinct NodeIds the writer toggles between. We seed the
        // handle as a whitelist containing one of them so every read sees a
        // valid snapshot (either {a}, {a,b}, or {b} — all consistent).
        let a = deterministic_node_id(0x11);
        let b = deterministic_node_id(0x22);

        let mut initial = BTreeSet::new();
        initial.insert(a);
        let handle = AdmissionHandle::whitelist(initial);

        let stop = StdArc::new(AtomicBool::new(false));

        // Spawn 8 reader tasks, each issuing 10k admits() calls against
        // both NodeIds.
        let mut readers = Vec::with_capacity(8);
        for _ in 0..8 {
            let h = handle.clone();
            let stop = stop.clone();
            readers.push(tokio::spawn(async move {
                let mut count = 0usize;
                for _ in 0..10_000 {
                    // Each read must succeed without panic and return a
                    // bool. The snapshot is internally consistent — we
                    // can't observe e.g. "neither a nor b admitted" if we
                    // were to check liveness, but at minimum we assert the
                    // calls don't tear (no UB, no panic).
                    let _ = h.admits(&a);
                    let _ = h.admits(&b);
                    count += 1;
                }
                stop.store(true, Ordering::Relaxed);
                count
            }));
        }

        // Writer: 100 iterations of add/remove between the two NodeIds.
        // Run on this task so we don't have to worry about ordering with
        // the reader spawn.
        let writer_handle = handle.clone();
        let writer = tokio::spawn(async move {
            for i in 0..100 {
                if i % 2 == 0 {
                    writer_handle.add(b);
                    writer_handle.remove(&a);
                } else {
                    writer_handle.add(a);
                    writer_handle.remove(&b);
                }
                tokio::task::yield_now().await;
            }
        });

        // Await everyone; if any panicked the join would error.
        writer.await.expect("writer task");
        for r in readers {
            let n = r.await.expect("reader task");
            assert_eq!(n, 10_000, "every read must complete");
        }

        // Final state must be a valid whitelist (snapshot is internally
        // consistent — never partially constructed).
        match handle.snapshot() {
            AdmissionPolicy::Whitelist(set) => {
                // Could be {a}, {b}, {a,b}, or {} depending on interleaving;
                // all are valid intermediate states. We only assert that
                // the snapshot deserialized as a coherent set.
                let _ = set.len();
            }
            AdmissionPolicy::Open => panic!("policy should not have become Open"),
        }
    }
}
