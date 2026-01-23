//! Helper functions for cleaning up stale Prometheus gauge metrics
//!
//! Note: Counter metrics (event-driven) should NEVER be cleaned up or reset.
//! Counters are monotonically increasing and Prometheus handles rate calculations.

use super::super::snapshot_metrics::SnapshotMetrics;
use std::collections::HashSet;

/// Clean up stale server channel gauge metrics.
///
/// This removes gauge metric label combinations that are no longer active,
/// preventing memory leaks when miners reconnect on different channels.
///
/// **Important:** This only cleans up gauges (snapshot-based metrics).
/// Counters in EventMetrics are never cleaned up as they must be monotonically increasing.
pub(super) fn cleanup_stale_server_gauges(
    old_labels: &HashSet<(String, String)>,
    new_labels: &HashSet<(String, String)>,
    metrics: &SnapshotMetrics,
) {
    let stale: Vec<_> = old_labels.difference(new_labels).cloned().collect();
    for (channel_id, user) in &stale {
        if let Some(metric) = &metrics.sv2_server_channel_hashrate {
            let _ = metric.remove_label_values(&[channel_id.as_str(), user.as_str()]);
        }
    }
}

/// Clean up stale client channel gauge metrics.
///
/// This removes gauge metric label combinations that are no longer active,
/// preventing memory leaks when miners reconnect on different channels.
///
/// **Important:** This only cleans up gauges (snapshot-based metrics).
/// Counters in EventMetrics are never cleaned up as they must be monotonically increasing.
pub(super) fn cleanup_stale_client_gauges(
    old_labels: &HashSet<(String, String, String)>,
    new_labels: &HashSet<(String, String, String)>,
    metrics: &SnapshotMetrics,
) {
    let stale: Vec<_> = old_labels.difference(new_labels).cloned().collect();
    for (client_id, channel_id, user) in &stale {
        if let Some(metric) = &metrics.sv2_client_channel_hashrate {
            let _ = metric.remove_label_values(&[
                client_id.as_str(),
                channel_id.as_str(),
                user.as_str(),
            ]);
        }
        if let Some(metric) = &metrics.sv2_client_channel_shares_per_minute {
            let _ = metric.remove_label_values(&[
                client_id.as_str(),
                channel_id.as_str(),
                user.as_str(),
            ]);
        }
    }
}
