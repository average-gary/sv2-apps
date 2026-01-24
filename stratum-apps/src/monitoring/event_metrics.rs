//! Event-driven metrics for real-time Prometheus counter increments.
//!
//! This module provides metrics that are incremented at the point where events occur
//! (e.g., share acceptance, share rejection, block discovery) rather than being
//! sampled periodically from snapshots.
//!
//! ## Architecture
//!
//! - **EventMetrics** is passed to business logic components (e.g., ChannelManager)
//! - Events trigger immediate counter increments (e.g., `shares_accepted.inc()`)
//! - Prometheus scrapes these counters directly from the registry
//! - No snapshot cache needed for event metrics
//!
//! ## Consolidated Metrics Design
//!
//! Counters use bounded labels to enable dashboard filtering and API linkage:
//! - `sv2_shares_accepted{direction}` - Shares by direction (2 combinations)
//! - `sv2_shares_rejected{reason}` - Rejections by reason (7 combinations)
//!
//! The `direction` label (server/client) maps to API endpoints:
//! - `direction="server"` → `/api/v1/server/channels`
//! - `direction="client"` → `/api/v1/client/channels`
//!
//! Per-channel share data is available via the REST API for detailed debugging.

use prometheus::{IntCounterVec, Opts, Registry};

// Re-export direction constants for consistency
pub use super::snapshot_metrics::direction;

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
/// Uses consolidated metrics with bounded labels:
/// - `direction`: "server" (upstream) or "client" (downstream)
/// - `reason`: bounded enum for rejection reasons
///
/// This enables dashboard filtering by direction and API linkage.
#[derive(Clone)]
pub struct EventMetrics {
    /// Shares accepted by direction
    /// Labels: direction (server|client)
    /// Cardinality: 2
    pub sv2_shares_accepted: IntCounterVec,

    /// Shares rejected by reason
    /// Labels: reason (bounded enum, 7 values)
    /// Cardinality: 7
    pub sv2_shares_rejected: IntCounterVec,
}

impl EventMetrics {
    /// Create new EventMetrics and register them with the provided Prometheus registry.
    ///
    /// # Arguments
    ///
    /// * `registry` - Prometheus registry to register metrics with
    /// * `_enable_server_metrics` - Unused, kept for API compatibility
    /// * `_enable_clients_metrics` - Unused, kept for API compatibility
    pub fn new(
        registry: &Registry,
        _enable_server_metrics: bool,
        _enable_clients_metrics: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let sv2_shares_accepted = IntCounterVec::new(
            Opts::new("sv2_shares_accepted", "Shares accepted by direction"),
            &["direction"],
        )?;
        registry.register(Box::new(sv2_shares_accepted.clone()))?;

        let sv2_shares_rejected = IntCounterVec::new(
            Opts::new("sv2_shares_rejected", "Shares rejected by reason"),
            &["reason"],
        )?;
        registry.register(Box::new(sv2_shares_rejected.clone()))?;

        Ok(Self {
            sv2_shares_accepted,
            sv2_shares_rejected,
        })
    }

    /// Increment shares accepted counter for a specific direction.
    ///
    /// # Arguments
    /// * `direction` - Use `direction::SERVER` or `direction::CLIENT`
    #[inline]
    pub fn inc_shares_accepted(&self, direction: &str) {
        self.sv2_shares_accepted
            .with_label_values(&[direction])
            .inc();
    }

    /// Increment shares rejected counter for a specific reason.
    ///
    /// Uses bounded enum labels to prevent cardinality explosion.
    #[inline]
    pub fn inc_shares_rejected(&self, reason: ShareRejectionReason) {
        self.sv2_shares_rejected
            .with_label_values(&[reason.as_str()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shares_accepted_by_direction() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        metrics.inc_shares_accepted(direction::SERVER);
        metrics.inc_shares_accepted(direction::SERVER);
        metrics.inc_shares_accepted(direction::CLIENT);

        let server = metrics
            .sv2_shares_accepted
            .with_label_values(&[direction::SERVER])
            .get();
        let client = metrics
            .sv2_shares_accepted
            .with_label_values(&[direction::CLIENT])
            .get();

        assert_eq!(server, 2);
        assert_eq!(client, 1);
    }

    #[test]
    fn test_shares_accepted_cardinality_bounded() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        metrics.inc_shares_accepted(direction::SERVER);
        metrics.inc_shares_accepted(direction::CLIENT);

        // Should have exactly 2 label combinations
        let metric_families = registry.gather();
        let accepted_family = metric_families
            .iter()
            .find(|f| f.get_name() == "sv2_shares_accepted")
            .unwrap();

        assert_eq!(accepted_family.get_metric().len(), 2);
    }

    #[test]
    fn test_rejection_counter_by_reason() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        metrics.inc_shares_rejected(ShareRejectionReason::StaleShare);
        metrics.inc_shares_rejected(ShareRejectionReason::StaleShare);
        metrics.inc_shares_rejected(ShareRejectionReason::InvalidNonce);

        let stale = metrics
            .sv2_shares_rejected
            .with_label_values(&["stale_share"])
            .get();
        let invalid = metrics
            .sv2_shares_rejected
            .with_label_values(&["invalid_nonce"])
            .get();

        assert_eq!(stale, 2);
        assert_eq!(invalid, 1);
    }

    #[test]
    fn test_rejection_reason_cardinality_bounded() {
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

        // Should have exactly 7 label combinations
        let metric_families = registry.gather();
        let rejected_family = metric_families
            .iter()
            .find(|f| f.get_name() == "sv2_shares_rejected")
            .unwrap();

        assert_eq!(rejected_family.get_metric().len(), 7);
    }

    #[test]
    fn test_counters_are_monotonic() {
        let registry = Registry::new();
        let metrics = EventMetrics::new(&registry, true, true).unwrap();

        let mut prev = 0;
        for _ in 0..100 {
            metrics.inc_shares_accepted(direction::SERVER);
            let current = metrics
                .sv2_shares_accepted
                .with_label_values(&[direction::SERVER])
                .get();
            assert!(current > prev, "Counter must be monotonically increasing");
            prev = current;
        }
    }
}
