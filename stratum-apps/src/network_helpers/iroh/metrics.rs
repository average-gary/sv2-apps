//! Prometheus metrics for the iroh transport.
//!
//! Per plan §"Mandatory operational primitives" #6 — observability ships at
//! v1. Only compiled when feature `iroh-transport-monitoring` is enabled.
//!
//! All metrics are lazy-initialised singletons (`std::sync::OnceLock`). On
//! first access they self-register with the `prometheus` crate's process-wide
//! [`prometheus::default_registry`]. Naming follows the `sv2_*` convention
//! from [`crate::monitoring::prometheus_metrics`].
//!
//! ## Integrating with a custom [`prometheus::Registry`]
//!
//! The existing monitoring server in `crate::monitoring` owns its own
//! [`prometheus::Registry`] rather than using the global default. To make
//! these iroh metrics show up there as well, callers should invoke
//! [`register`] passing that registry once at startup. Each underlying
//! collector is reference-counted (`Clone` over `Arc`), so registering with
//! multiple registries is safe — both will report the same numbers.
//!
//! ## Public surface
//!
//! Implementation detail (the `Lazy<...>` singletons, the `*Vec` collectors,
//! the registration helper) is private. Callers only ever touch:
//!
//! - The label enums (`Role`, `Transport`, ...).
//! - The `record_*` / `observe_*` / `inc_*` / `dec_*` recording functions.
//! - [`register`] for explicit registration with an external [`Registry`].

use std::{
    sync::OnceLock,
    time::Duration,
};

use prometheus::{
    HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts, Registry,
};

// ---------------------------------------------------------------------------
// Label enums.
// ---------------------------------------------------------------------------

/// SV2 role producing the metric.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Role {
    /// Mining pool (pool-apps/pool).
    Pool,
    /// Job Declarator Server.
    Jds,
    /// Job Declarator Client.
    Jdc,
    /// SV1↔SV2 translator proxy.
    Tproxy,
}

impl Role {
    /// Prom-safe (lowercase, ASCII alphanumeric or hyphen) string label.
    pub fn as_label(&self) -> &'static str {
        match self {
            Role::Pool => "pool",
            Role::Jds => "jds",
            Role::Jdc => "jdc",
            Role::Tproxy => "tproxy",
        }
    }
}

/// Iroh transport flavour: direct hole-punched UDP vs. relayed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Transport {
    IrohDirect,
    IrohRelay,
}

impl Transport {
    pub fn as_label(&self) -> &'static str {
        match self {
            Transport::IrohDirect => "iroh-direct",
            Transport::IrohRelay => "iroh-relay",
        }
    }
}

/// Connection direction (relative to the local node).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Direction {
    Inbound,
    Outbound,
}

impl Direction {
    pub fn as_label(&self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
        }
    }
}

/// Outcome of a handshake observation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    Established,
    Rejected,
    NoiseFailed,
    QuicFailed,
}

impl Outcome {
    pub fn as_label(&self) -> &'static str {
        match self {
            Outcome::Established => "established",
            Outcome::Rejected => "rejected",
            Outcome::NoiseFailed => "noise-failed",
            Outcome::QuicFailed => "quic-failed",
        }
    }
}

/// Why an inbound connection was rejected before establishing SV2.
///
/// Mapped onto the `outcome` label of `sv2_iroh_connections_total`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RejectReason {
    Admission,
    AlpnMismatch,
    NoiseFailed,
    QuicFailed,
}

impl RejectReason {
    /// The `outcome` label written to `sv2_iroh_connections_total`.
    pub fn as_label(&self) -> &'static str {
        match self {
            RejectReason::Admission => "rejected-admission",
            RejectReason::AlpnMismatch => "alpn-mismatch",
            RejectReason::NoiseFailed => "noise-failed",
            RejectReason::QuicFailed => "quic-failed",
        }
    }
}

/// Why admission denied a NodeId.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AdmissionDenyReason {
    NotInWhitelist,
    PolicyLoadFailed,
}

impl AdmissionDenyReason {
    pub fn as_label(&self) -> &'static str {
        match self {
            AdmissionDenyReason::NotInWhitelist => "not-in-whitelist",
            AdmissionDenyReason::PolicyLoadFailed => "policy-load-failed",
        }
    }
}

/// Why an outbound dial fell back from iroh to TCP.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FallbackReason {
    IrohConnectError,
    IrohHandshakeTimeout,
    IrohNoiseFailed,
}

impl FallbackReason {
    pub fn as_label(&self) -> &'static str {
        match self {
            FallbackReason::IrohConnectError => "iroh-connect-error",
            FallbackReason::IrohHandshakeTimeout => "iroh-handshake-timeout",
            FallbackReason::IrohNoiseFailed => "iroh-noise-failed",
        }
    }
}

// ---------------------------------------------------------------------------
// Collector singletons.
//
// Each is built once on first access and registered with
// `prometheus::default_registry()` so callers that don't plumb a custom
// registry still get metrics out of the box. `register(&Registry)` adds the
// same collectors to a caller-supplied registry — collectors are reference-
// counted (Clone over Arc internally) so multi-registration is safe.
// ---------------------------------------------------------------------------

/// Histogram bucket boundaries (seconds) tuned to share-submission timing.
/// Plan §"Required metrics" specifies these literal values; do not tweak
/// without updating the plan and any dashboards built off them.
const HANDSHAKE_BUCKETS_SECS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0,
];

struct Collectors {
    connections_total: IntCounterVec,
    request_timeouts_total: IntCounterVec,
    admission_denied_total: IntCounterVec,
    fallback_total: IntCounterVec,
    active_connections: IntGaugeVec,
    handshake_duration: HistogramVec,
    noise_handshake_duration: HistogramVec,
}

impl Collectors {
    fn build() -> Self {
        let connections_total = IntCounterVec::new(
            Opts::new(
                "sv2_iroh_connections_total",
                "iroh transport connection attempts by outcome",
            ),
            &["role", "transport", "direction", "outcome"],
        )
        .expect("metric construction never fails for a valid name + label set");

        let request_timeouts_total = IntCounterVec::new(
            Opts::new(
                "sv2_iroh_request_timeouts_total",
                "iroh per-request timeouts (Fedimint PR #8571 lesson)",
            ),
            &["role"],
        )
        .expect("valid metric");

        let admission_denied_total = IntCounterVec::new(
            Opts::new(
                "sv2_iroh_admission_denied_total",
                "iroh admission policy denials",
            ),
            &["role", "reason"],
        )
        .expect("valid metric");

        let fallback_total = IntCounterVec::new(
            Opts::new(
                "sv2_iroh_fallback_total",
                "Outbound dial fell back from iroh to TCP",
            ),
            &["role", "reason"],
        )
        .expect("valid metric");

        let active_connections = IntGaugeVec::new(
            Opts::new(
                "sv2_iroh_active_connections",
                "Live iroh connections by transport flavour",
            ),
            &["role", "transport"],
        )
        .expect("valid metric");

        let handshake_duration = HistogramVec::new(
            HistogramOpts::new(
                "sv2_iroh_handshake_duration_seconds",
                "iroh QUIC handshake time (excludes inner SV2 Noise handshake)",
            )
            .buckets(HANDSHAKE_BUCKETS_SECS.to_vec()),
            &["role", "direction", "outcome"],
        )
        .expect("valid metric");

        let noise_handshake_duration = HistogramVec::new(
            HistogramOpts::new(
                "sv2_iroh_noise_handshake_duration_seconds",
                "SV2 Noise NX handshake time when run inside an iroh bidi stream",
            )
            .buckets(HANDSHAKE_BUCKETS_SECS.to_vec()),
            &["role", "direction", "outcome"],
        )
        .expect("valid metric");

        Self {
            connections_total,
            request_timeouts_total,
            admission_denied_total,
            fallback_total,
            active_connections,
            handshake_duration,
            noise_handshake_duration,
        }
    }

    /// Register all collectors with the supplied registry. Returns `Ok(())`
    /// on success; an error means a collector with one of these names was
    /// already registered with `reg` (e.g. [`register`] called twice on the
    /// same registry).
    fn register_with(&self, reg: &Registry) -> Result<(), prometheus::Error> {
        reg.register(Box::new(self.connections_total.clone()))?;
        reg.register(Box::new(self.request_timeouts_total.clone()))?;
        reg.register(Box::new(self.admission_denied_total.clone()))?;
        reg.register(Box::new(self.fallback_total.clone()))?;
        reg.register(Box::new(self.active_connections.clone()))?;
        reg.register(Box::new(self.handshake_duration.clone()))?;
        reg.register(Box::new(self.noise_handshake_duration.clone()))?;
        Ok(())
    }
}

static COLLECTORS: OnceLock<Collectors> = OnceLock::new();

fn collectors() -> &'static Collectors {
    COLLECTORS.get_or_init(|| {
        let c = Collectors::build();
        // Best-effort registration with the process-wide default registry.
        // We swallow `AlreadyReg` so a `register(&default_registry())`-then-
        // singleton-init ordering doesn't panic; any other error is
        // unreachable for fresh, valid collectors.
        if let Err(e) = c.register_with(prometheus::default_registry()) {
            if !matches!(e, prometheus::Error::AlreadyReg) {
                // Surface unexpected errors via tracing rather than panicking
                // — metrics must never take down the transport.
                tracing::warn!(
                    "iroh metrics: failed to register with default registry: {}",
                    e
                );
            }
        }
        c
    })
}

/// Register the iroh transport metrics with `reg`.
///
/// Call this once at startup, passing the [`prometheus::Registry`] owned by
/// your monitoring server (e.g. `crate::monitoring::PrometheusMetrics`'s
/// `registry` field). The same collectors are also registered with
/// [`prometheus::default_registry`] on first access.
///
/// Returns an error if any of the collectors are already registered with
/// `reg`.
pub fn register(reg: &Registry) -> Result<(), prometheus::Error> {
    collectors().register_with(reg)
}

// ---------------------------------------------------------------------------
// Recording API.
//
// All `record_*` functions are infallible and cheap (atomic increments). They
// are safe to call from any task or thread.
// ---------------------------------------------------------------------------

/// Increment `sv2_iroh_connections_total` with `outcome="established"`.
pub fn record_connection_established(role: Role, transport: Transport, direction: Direction) {
    collectors()
        .connections_total
        .with_label_values(&[
            role.as_label(),
            transport.as_label(),
            direction.as_label(),
            "established",
        ])
        .inc();
}

/// Increment `sv2_iroh_connections_total` with the rejection-specific
/// `outcome` label. The `transport` label is set to `"iroh-direct"` —
/// rejections happen before the relay vs. direct distinction matters for the
/// established connection, and we still want a single concrete value for the
/// label set.
pub fn record_connection_rejected(role: Role, direction: Direction, reason: RejectReason) {
    collectors()
        .connections_total
        .with_label_values(&[
            role.as_label(),
            // Rejections fire before the connection materialises, so we
            // report `iroh-direct` as a conventional placeholder. Operators
            // distinguish rejections from established by the `outcome`
            // dimension, not by `transport`.
            Transport::IrohDirect.as_label(),
            direction.as_label(),
            reason.as_label(),
        ])
        .inc();
}

/// Increment `sv2_iroh_request_timeouts_total{role}` (Fedimint PR #8571).
pub fn record_request_timeout(role: Role) {
    collectors()
        .request_timeouts_total
        .with_label_values(&[role.as_label()])
        .inc();
}

/// Increment `sv2_iroh_admission_denied_total{role, reason}`.
pub fn record_admission_denied(role: Role, reason: AdmissionDenyReason) {
    collectors()
        .admission_denied_total
        .with_label_values(&[role.as_label(), reason.as_label()])
        .inc();
}

/// Increment `sv2_iroh_fallback_total{role, reason}`.
pub fn record_fallback(role: Role, reason: FallbackReason) {
    collectors()
        .fallback_total
        .with_label_values(&[role.as_label(), reason.as_label()])
        .inc();
}

/// Observe a sample on `sv2_iroh_handshake_duration_seconds`.
///
/// `duration` is the QUIC handshake elapsed time, **not** including the inner
/// SV2 Noise handshake — that's [`observe_noise_handshake`].
pub fn observe_handshake(
    role: Role,
    direction: Direction,
    outcome: Outcome,
    duration: Duration,
) {
    collectors()
        .handshake_duration
        .with_label_values(&[role.as_label(), direction.as_label(), outcome.as_label()])
        .observe(duration.as_secs_f64());
}

/// Observe a sample on `sv2_iroh_noise_handshake_duration_seconds`.
pub fn observe_noise_handshake(
    role: Role,
    direction: Direction,
    outcome: Outcome,
    duration: Duration,
) {
    collectors()
        .noise_handshake_duration
        .with_label_values(&[role.as_label(), direction.as_label(), outcome.as_label()])
        .observe(duration.as_secs_f64());
}

/// Increment `sv2_iroh_active_connections{role, transport}`.
pub fn inc_active_connections(role: Role, transport: Transport) {
    collectors()
        .active_connections
        .with_label_values(&[role.as_label(), transport.as_label()])
        .inc();
}

/// Decrement `sv2_iroh_active_connections{role, transport}`.
pub fn dec_active_connections(role: Role, transport: Transport) {
    collectors()
        .active_connections
        .with_label_values(&[role.as_label(), transport.as_label()])
        .dec();
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, Registry, TextEncoder};

    /// Returns true iff `s` is composed only of ASCII lowercase letters,
    /// ASCII digits, or hyphens — Prometheus-safe label values per the
    /// project convention.
    fn is_prom_safe(s: &str) -> bool {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    }

    #[test]
    fn role_labels_are_prom_safe() {
        for r in [Role::Pool, Role::Jds, Role::Jdc, Role::Tproxy] {
            assert!(is_prom_safe(r.as_label()), "role label {:?}", r);
        }
    }

    #[test]
    fn transport_labels_are_prom_safe() {
        for t in [Transport::IrohDirect, Transport::IrohRelay] {
            assert!(is_prom_safe(t.as_label()), "transport label {:?}", t);
        }
    }

    #[test]
    fn direction_labels_are_prom_safe() {
        for d in [Direction::Inbound, Direction::Outbound] {
            assert!(is_prom_safe(d.as_label()), "direction label {:?}", d);
        }
    }

    #[test]
    fn outcome_labels_are_prom_safe() {
        for o in [
            Outcome::Established,
            Outcome::Rejected,
            Outcome::NoiseFailed,
            Outcome::QuicFailed,
        ] {
            assert!(is_prom_safe(o.as_label()), "outcome label {:?}", o);
        }
    }

    #[test]
    fn reject_reason_labels_are_prom_safe() {
        for r in [
            RejectReason::Admission,
            RejectReason::AlpnMismatch,
            RejectReason::NoiseFailed,
            RejectReason::QuicFailed,
        ] {
            assert!(is_prom_safe(r.as_label()), "reject label {:?}", r);
        }
    }

    #[test]
    fn admission_deny_reason_labels_are_prom_safe() {
        for r in [
            AdmissionDenyReason::NotInWhitelist,
            AdmissionDenyReason::PolicyLoadFailed,
        ] {
            assert!(is_prom_safe(r.as_label()), "admission deny label {:?}", r);
        }
    }

    #[test]
    fn fallback_reason_labels_are_prom_safe() {
        for r in [
            FallbackReason::IrohConnectError,
            FallbackReason::IrohHandshakeTimeout,
            FallbackReason::IrohNoiseFailed,
        ] {
            assert!(is_prom_safe(r.as_label()), "fallback label {:?}", r);
        }
    }

    #[test]
    fn recording_each_metric_does_not_panic() {
        // Touches every public recording entry point. Asserts only that no
        // call panics — the roundtrip test below covers value propagation.
        record_connection_established(Role::Pool, Transport::IrohDirect, Direction::Inbound);
        record_connection_rejected(Role::Jds, Direction::Inbound, RejectReason::Admission);
        record_request_timeout(Role::Jdc);
        record_admission_denied(Role::Pool, AdmissionDenyReason::NotInWhitelist);
        record_fallback(Role::Tproxy, FallbackReason::IrohConnectError);
        observe_handshake(
            Role::Pool,
            Direction::Outbound,
            Outcome::Established,
            Duration::from_millis(7),
        );
        observe_noise_handshake(
            Role::Pool,
            Direction::Outbound,
            Outcome::Established,
            Duration::from_millis(3),
        );
        inc_active_connections(Role::Pool, Transport::IrohDirect);
        dec_active_connections(Role::Pool, Transport::IrohDirect);
    }

    /// Roundtrip: register the iroh collectors with a fresh registry, fire
    /// each public recorder once, gather, and assert the expected metric
    /// names are present in the text-format output.
    #[test]
    fn roundtrip_registers_and_emits_all_metric_families() {
        let reg = Registry::new();
        register(&reg).expect("first registration with a fresh registry must succeed");

        // Hit every metric family at least once.
        record_connection_established(Role::Pool, Transport::IrohDirect, Direction::Inbound);
        record_connection_rejected(Role::Pool, Direction::Inbound, RejectReason::AlpnMismatch);
        record_request_timeout(Role::Pool);
        record_admission_denied(Role::Pool, AdmissionDenyReason::NotInWhitelist);
        record_fallback(Role::Pool, FallbackReason::IrohConnectError);
        observe_handshake(
            Role::Pool,
            Direction::Inbound,
            Outcome::Established,
            Duration::from_millis(12),
        );
        observe_noise_handshake(
            Role::Pool,
            Direction::Inbound,
            Outcome::Established,
            Duration::from_millis(4),
        );
        inc_active_connections(Role::Pool, Transport::IrohDirect);

        let families = reg.gather();
        let names: Vec<&str> = families.iter().map(|f| f.get_name()).collect();

        for expected in [
            "sv2_iroh_connections_total",
            "sv2_iroh_request_timeouts_total",
            "sv2_iroh_admission_denied_total",
            "sv2_iroh_fallback_total",
            "sv2_iroh_active_connections",
            "sv2_iroh_handshake_duration_seconds",
            "sv2_iroh_noise_handshake_duration_seconds",
        ] {
            assert!(
                names.contains(&expected),
                "expected metric family {} in {:?}",
                expected,
                names
            );
        }

        // Sanity-check that the text encoding works (catches malformed
        // label sets that compile but explode at scrape time).
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&families, &mut buf)
            .expect("text encoding must succeed");
        let text = String::from_utf8(buf).expect("prom text format is utf-8");
        assert!(text.contains("sv2_iroh_connections_total"));
        assert!(text.contains("role=\"pool\""));
        assert!(text.contains("transport=\"iroh-direct\""));
    }

    #[test]
    fn second_registration_with_same_registry_returns_error() {
        let reg = Registry::new();
        register(&reg).expect("first registration succeeds");
        // Registering twice on the same registry must error rather than
        // silently no-op or panic.
        let err = register(&reg).expect_err("second registration must fail");
        assert!(matches!(err, prometheus::Error::AlreadyReg));
    }
}
