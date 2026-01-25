//! Snapshot-based Prometheus metrics for Stratum monitoring.
//!
//! These metrics are populated from the snapshot cache during periodic refreshes
//! and Prometheus scrapes. They represent point-in-time state (gauges) rather than
//! real-time event counts (counters/histograms in EventMetrics).
//!
//! ## Consolidated Metrics Design
//!
//! Metrics use bounded labels to reduce metric count while preserving topology:
//! - `stratum_channels{direction,type}` - Channel counts (6 combinations: 3 directions × 2 types)
//! - `stratum_hashrate{direction}` or `stratum_hashrate{direction,user_identity}` - Hashrate
//! - `stratum_connections{direction}` - Connection counts (3 combinations)
//! - `stratum_shares{direction,type}` - Share counts (6 combinations: 3 directions × 2 types)
//!
//! Direction values: "server", "client", "sv1_client"
//!
//! This design enables:
//! - Prometheus recording rules for aggregates
//! - Dashboard filtering by direction
//! - API linkage via direction label
//! - Optional user_identity breakdown (config-controlled)

use prometheus::{GaugeVec, Opts, Registry};

/// Direction label values for metrics
pub mod direction {
    pub const SERVER: &str = "server";
    pub const CLIENT: &str = "client";
    pub const SV1_CLIENT: &str = "sv1_client";
}

/// Channel type label values for metrics
pub mod channel_type {
    pub const EXTENDED: &str = "extended";
    pub const STANDARD: &str = "standard";
}

/// Snapshot-based metrics populated from cached monitoring state.
///
/// Uses consolidated metrics with bounded labels:
/// - `direction`: "server", "client", or "sv1_client"
/// - `type`: "extended" or "standard" (for channel counts)
/// - `user_identity`: optional, enabled via config (for hashrate breakdown)
///
/// This reduces metric count while preserving topology for dashboards and API linkage.
#[derive(Clone)]
pub struct SnapshotMetrics {
    pub registry: Registry,

    /// Whether user_identity labels are enabled (high cardinality)
    pub enable_user_identity_labels: bool,

    // === Consolidated Metrics with Labels ===
    /// Channel counts by direction and type
    /// Labels: direction (server|client|sv1_client), type (extended|standard)
    /// Cardinality: 6 (3 directions × 2 types)
    pub stratum_channels: Option<GaugeVec>,

    /// Hashrate by direction (and optionally user_identity)
    /// Labels: direction (server|client|sv1_client), [user_identity]
    /// Cardinality: 3 without user_identity, unbounded with user_identity
    pub stratum_hashrate: Option<GaugeVec>,

    /// Connection counts by direction
    /// Labels: direction (server|client|sv1_client)
    /// Cardinality: 3
    pub stratum_connections: Option<GaugeVec>,

    /// Share counts by direction and type
    /// Labels: direction (server|client|sv1_client), type (extended|standard)
    /// Cardinality: 6 (3 directions × 2 types)
    pub stratum_shares: Option<GaugeVec>,
}

impl SnapshotMetrics {
    /// Create new snapshot metrics.
    ///
    /// # Arguments
    /// * `enable_server_metrics` - Enable server (upstream) metrics
    /// * `enable_clients_metrics` - Enable client (downstream) metrics
    /// * `enable_sv1_metrics` - Enable SV1 client metrics
    /// * `enable_user_identity_labels` - Enable user_identity label on hashrate (high cardinality)
    pub fn new(
        enable_server_metrics: bool,
        enable_clients_metrics: bool,
        enable_sv1_metrics: bool,
        enable_user_identity_labels: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let registry = Registry::new();

        // Consolidated metrics (registered if any metrics enabled)
        let enable_consolidated =
            enable_server_metrics || enable_clients_metrics || enable_sv1_metrics;

        let stratum_channels = if enable_consolidated {
            let metric = GaugeVec::new(
                Opts::new("stratum_channels", "Channel counts by direction and type"),
                &["direction", "type"],
            )?;
            registry.register(Box::new(metric.clone()))?;
            Some(metric)
        } else {
            None
        };

        // Hashrate metric: labels depend on whether user_identity is enabled
        let stratum_hashrate = if enable_consolidated {
            let labels: &[&str] = if enable_user_identity_labels {
                &["direction", "user_identity"]
            } else {
                &["direction"]
            };
            let metric = GaugeVec::new(
                Opts::new("stratum_hashrate", "Hashrate by direction"),
                labels,
            )?;
            registry.register(Box::new(metric.clone()))?;
            Some(metric)
        } else {
            None
        };

        let stratum_connections = if enable_consolidated {
            let metric = GaugeVec::new(
                Opts::new("stratum_connections", "Connection counts by direction"),
                &["direction"],
            )?;
            registry.register(Box::new(metric.clone()))?;
            Some(metric)
        } else {
            None
        };

        let stratum_shares = if enable_consolidated {
            let metric = GaugeVec::new(
                Opts::new("stratum_shares", "Share counts by direction and type"),
                &["direction", "type"],
            )?;
            registry.register(Box::new(metric.clone()))?;
            Some(metric)
        } else {
            None
        };

        Ok(Self {
            registry,
            enable_user_identity_labels,
            stratum_channels,
            stratum_hashrate,
            stratum_connections,
            stratum_shares,
        })
    }

    // === Helper methods for setting consolidated metrics ===

    /// Set channel count for a specific direction and type
    pub fn set_channels(&self, direction: &str, channel_type: &str, count: f64) {
        if let Some(ref metric) = self.stratum_channels {
            metric
                .with_label_values(&[direction, channel_type])
                .set(count);
        }
    }

    /// Set hashrate for a specific direction.
    /// If user_identity labels are enabled, use `set_hashrate_with_user` instead.
    pub fn set_hashrate(&self, direction: &str, hashrate: f64) {
        if let Some(ref metric) = self.stratum_hashrate {
            if self.enable_user_identity_labels {
                // When user_identity is enabled, we need to provide it
                // Use empty string for aggregate hashrate
                metric.with_label_values(&[direction, ""]).set(hashrate);
            } else {
                metric.with_label_values(&[direction]).set(hashrate);
            }
        }
    }

    /// Set hashrate for a specific direction and user_identity.
    /// Only works when user_identity labels are enabled.
    pub fn set_hashrate_with_user(&self, direction: &str, user_identity: &str, hashrate: f64) {
        if let Some(ref metric) = self.stratum_hashrate {
            if self.enable_user_identity_labels {
                metric
                    .with_label_values(&[direction, user_identity])
                    .set(hashrate);
            }
        }
    }

    /// Set connection count for a specific direction
    pub fn set_connections(&self, direction: &str, count: f64) {
        if let Some(ref metric) = self.stratum_connections {
            metric.with_label_values(&[direction]).set(count);
        }
    }

    /// Set share count for a specific direction and type
    pub fn set_shares(&self, direction: &str, channel_type: &str, count: f64) {
        if let Some(ref metric) = self.stratum_shares {
            metric
                .with_label_values(&[direction, channel_type])
                .set(count);
        }
    }
}
