//! Per-role iroh transport configuration.
//!
//! Each Stratum v2 role's main `Config` struct embeds
//! `iroh: Option<IrohRoleConfig>`. When present, the role spins up an iroh
//! [`Endpoint`](iroh::Endpoint) alongside (or instead of) its TCP listener.
//!
//! See `/Users/garykrause/.claude/plans/how-might-we-implement-snoopy-lollipop.md`
//! § "Per-role `[iroh]` section (TOML)" for the canonical schema and §
//! "Two-layer identity model" for how `admission` interacts with the SV2
//! Noise NX handshake.
//!
//! # Example TOML
//!
//! ```toml
//! [iroh]
//! listen_address     = "0.0.0.0:34256"
//! secret_key_path    = "~/.config/sv2/pool/iroh-secret.ed25519"
//! relay_url          = ""
//! max_idle_timeout_secs    = 60
//! keep_alive_interval_secs = 30
//! per_request_timeout_secs = 30
//!
//! discovery_relay_enable     = true
//! discovery_pkarr_pub_enable = true
//! discovery_pkarr_res_enable = true
//! discovery_dht_enable       = false
//! discovery_n0_enable        = true
//!
//! [iroh.connection_overrides]
//! # "k51..." = "1.2.3.4:34256"
//!
//! [iroh.admission]
//! mode = "open"
//! allowed_node_ids = []
//! ```
//!
//! # Resolve pipeline
//!
//! [`IrohRoleConfig::resolve`] turns the raw TOML form into the runtime types
//! consumed by `endpoint.rs` and `listener.rs`:
//!
//! 1. Run [`DiscoveryConfig::resolve`] (env vars override TOML, per Fedimint
//!    pattern).
//! 2. Build [`EndpointBuildConfig`] with the resolved discovery, listener
//!    address, secret-key path, and the QUIC keepalive primitives. **The
//!    `alpns` field is left empty** — call sites must fill in the right ALPN
//!    from [`crate::network_helpers::iroh::alpn`] before invoking
//!    [`build_endpoint`](crate::network_helpers::iroh::endpoint::build_endpoint).
//! 3. Build the [`AdmissionHandle`] from `admission`.
//! 4. Lift each `connection_overrides` entry from `(EndpointId, SocketAddr)` into
//!    `(EndpointId, EndpointAddr)` so the connector can dial it directly.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use iroh::{EndpointAddr, EndpointId};
use serde::Deserialize;

use crate::network_helpers::iroh::admission::AdmissionHandle;
use crate::network_helpers::iroh::discovery::{
    DiscoveryConfig, DiscoveryConfigError, DiscoveryConfigToml,
};
use crate::network_helpers::iroh::endpoint::EndpointBuildConfig;

/// Default for `max_idle_timeout_secs`. Matches plan §"Mandatory operational
/// primitives" #1 (Fedimint PR #8422 lesson).
fn default_max_idle_timeout_secs() -> u64 {
    60
}

/// Default for `keep_alive_interval_secs`. Matches plan §"Mandatory
/// operational primitives" #1 (Fedimint PR #8422 lesson).
fn default_keep_alive_interval_secs() -> u64 {
    30
}

/// Default for `per_request_timeout_secs`. Matches plan §"Mandatory
/// operational primitives" #2 (Fedimint PR #8571 lesson).
fn default_per_request_timeout_secs() -> u64 {
    30
}

fn default_admission_mode() -> AdmissionMode {
    AdmissionMode::Open
}

/// Per-role iroh configuration block, deserialized from the `[iroh]` section
/// of each role's TOML config file.
///
/// Embedded as `iroh: Option<IrohRoleConfig>` in each role's main Config
/// struct. See the module-level docs for the full schema.
///
/// `#[serde(deny_unknown_fields)]` is on the surface struct so typos like
/// `listen_addresss = ...` are surfaced rather than silently ignored. Note
/// that this attribute does not propagate through the flattened
/// [`DiscoveryConfigToml`] sub-struct — discovery fields use `#[serde(default)]`
/// and tolerate unknown keys at that level by design (Fedimint env-var
/// pattern allows future-compatible additions).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrohRoleConfig {
    /// UDP socket the iroh endpoint binds on. Use `0.0.0.0:34256` for v4 or
    /// `[::]:34256` for v6 dual-stack.
    pub listen_address: std::net::SocketAddr,

    /// Path to a 32-byte raw Ed25519 secret key file. Auto-generated (mode
    /// 0600) if missing. The path is read by
    /// [`identity::load_or_generate`](crate::network_helpers::iroh::identity::load_or_generate)
    /// inside
    /// [`build_endpoint`](crate::network_helpers::iroh::endpoint::build_endpoint),
    /// not by [`IrohRoleConfig::resolve`].
    ///
    /// `~`, `$VAR`, and `${VAR}` are expanded by `shellexpand::full` at load
    /// time.
    pub secret_key_path: PathBuf,

    /// Per-mechanism discovery toggles, the optional `relay_url`, and the
    /// `connection_overrides` map. Flattened into the surface so the TOML
    /// surface is a flat key list under `[iroh]` (matches the plan's
    /// canonical schema and Fedimint's `FM_IROH_*` env-var naming).
    #[serde(flatten)]
    pub discovery: DiscoveryConfigToml,

    /// QUIC `max_idle_timeout`. Plan default: 60s. Fedimint PR #8422 lesson:
    /// not setting this caused production-scale federation drops; we make it
    /// non-optional with a documented default.
    #[serde(default = "default_max_idle_timeout_secs")]
    pub max_idle_timeout_secs: u64,

    /// QUIC `keep_alive_interval`. Plan default: 30s. See `max_idle_timeout`.
    #[serde(default = "default_keep_alive_interval_secs")]
    pub keep_alive_interval_secs: u64,

    /// Per-bi-stream-op timeout. Plan default: 30s. Fedimint PR #8571 lesson:
    /// every `open_bi`/`accept_bi`/`write_all`/`read_to_end` is wrapped in
    /// `tokio::time::timeout(per_request_timeout, ...)` so a slowloris-style
    /// peer can't pin a worker.
    #[serde(default = "default_per_request_timeout_secs")]
    pub per_request_timeout_secs: u64,

    /// Admission policy for the listener. Defaults to
    /// [`AdmissionMode::Open`] with no allowlist. See
    /// [`AdmissionConfig`].
    #[serde(default)]
    pub admission: AdmissionConfig,
}

/// Initial admission policy for the iroh listener. Mutable at runtime via
/// [`AdmissionHandle`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionConfig {
    /// `"open"` or `"whitelist"`. See [`AdmissionMode`].
    #[serde(default = "default_admission_mode")]
    pub mode: AdmissionMode,
    /// Initial allowlist when `mode = "whitelist"`. Updateable at runtime.
    /// Each entry is a base32-lowercase `EndpointId`, parsed by
    /// [`EndpointId::from_str`].
    #[serde(default)]
    pub allowed_node_ids: Vec<String>,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            mode: AdmissionMode::Open,
            allowed_node_ids: Vec::new(),
        }
    }
}

/// Admission policy mode for the iroh listener.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMode {
    /// Admit any EndpointId. Default. Suitable for low-friction mining where
    /// peer-level filtering happens elsewhere (Noise authority verification).
    Open,
    /// Admit only EndpointIds in `allowed_node_ids`. The two-layer identity
    /// model rejects non-listed EndpointIds at the QUIC layer, before any SV2
    /// bytes flow.
    Whitelist,
}

/// Resolved runtime form of [`IrohRoleConfig`].
///
/// **Important:** [`ResolvedIrohRoleConfig::endpoint_config`] has an empty
/// `alpns` field. The role-specific call site MUST fill in the right ALPN
/// from [`crate::network_helpers::iroh::alpn`] (one of `SV2_POOL_ALPN`,
/// `SV2_JDS_ALPN`, `SV2_JDC_ALPN`, or `SV2_TPROXY_ALPN`) before passing
/// `endpoint_config` to
/// [`build_endpoint`](crate::network_helpers::iroh::endpoint::build_endpoint).
#[derive(Debug, Clone)]
pub struct ResolvedIrohRoleConfig {
    /// Endpoint-builder inputs (listen address, secret-key path, discovery,
    /// keepalive). The `alpns` field is empty — see struct-level note.
    pub endpoint_config: EndpointBuildConfig,
    /// Initial admission handle, ready to hand to
    /// [`IrohSv2Listener::new`](crate::network_helpers::iroh::listener::IrohSv2Listener::new).
    pub admission: AdmissionHandle,
    /// Per-bi-stream-op timeout, used by both connector and listener
    /// pipelines.
    pub per_request_timeout: Duration,
    /// Operator-supplied dial overrides, lifted from the discovery resolve
    /// output (`SocketAddr` per EndpointId) into the [`EndpointAddr`] form the
    /// [`IrohSv2Connector`](crate::network_helpers::iroh::connector::IrohSv2Connector)
    /// consumes.
    pub connection_overrides: BTreeMap<EndpointId, EndpointAddr>,
}

/// Errors produced while resolving an [`IrohRoleConfig`] into its runtime
/// form.
#[derive(Debug)]
pub enum IrohConfigError {
    /// Discovery resolution (TOML + env var) failed. See
    /// [`DiscoveryConfigError`].
    Discovery(DiscoveryConfigError),
    /// An entry in `admission.allowed_node_ids` failed to parse as a
    /// [`EndpointId`].
    InvalidEndpointId {
        /// The base32 string that failed to parse.
        value: String,
        /// Stringified underlying error.
        source: String,
    },
    /// Reserved for future "admission section structurally required" errors
    /// (e.g. whitelist mode but the section was absent). Currently unused —
    /// the spec accepts an empty allowlist as a deliberate "admit nothing"
    /// state — but kept as part of the public API so adding such validation
    /// later isn't a breaking change.
    AdmissionRequired(&'static str),
}

impl From<DiscoveryConfigError> for IrohConfigError {
    fn from(value: DiscoveryConfigError) -> Self {
        IrohConfigError::Discovery(value)
    }
}

impl std::fmt::Display for IrohConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IrohConfigError::Discovery(e) => write!(f, "discovery config error: {e}"),
            IrohConfigError::InvalidEndpointId { value, source } => {
                write!(f, "invalid EndpointId {value}: {source}")
            }
            IrohConfigError::AdmissionRequired(reason) => {
                write!(f, "admission section required: {reason}")
            }
        }
    }
}

impl std::error::Error for IrohConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IrohConfigError::Discovery(e) => Some(e),
            _ => None,
        }
    }
}

impl IrohRoleConfig {
    /// Resolve the TOML form into the runtime types used by `endpoint.rs`,
    /// `listener.rs`, and `connector.rs`.
    ///
    /// Pipeline:
    ///
    /// 1. [`DiscoveryConfig::resolve`] — applies env-var overrides on top of
    ///    the TOML-supplied defaults.
    /// 2. Build [`EndpointBuildConfig`] from the resolved discovery, the
    ///    listen address, the secret-key path, and the keepalive primitives.
    ///    `alpns` is left empty for the call site to fill.
    /// 3. Build the [`AdmissionHandle`] per `admission.mode`. Whitelist mode
    ///    parses each `allowed_node_ids` entry; failures surface as
    ///    [`IrohConfigError::InvalidEndpointId`].
    /// 4. Lift each `connection_overrides` entry from
    ///    `(EndpointId, SocketAddr)` into `(EndpointId, EndpointAddr)` via
    ///    [`EndpointAddr::from_parts`].
    ///
    /// Two warnings are emitted via `tracing` (not errors):
    ///
    /// - `mode = "open"` with a non-empty `allowed_node_ids` (likely a
    ///   misconfiguration — the list is silently ignored).
    /// - `mode = "whitelist"` with an empty `allowed_node_ids` (admits
    ///   nothing; almost certainly a mistake).
    pub fn resolve(&self) -> Result<ResolvedIrohRoleConfig, IrohConfigError> {
        // --- Step 1: resolve discovery (TOML + env vars). ---
        let discovery = DiscoveryConfig::resolve(self.discovery.clone())?;

        // --- Step 2: build EndpointBuildConfig.
        // alpns is intentionally empty — the role-specific call site fills it.
        let endpoint_config = EndpointBuildConfig {
            listen_address: self.listen_address,
            secret_key_path: self.secret_key_path.clone(),
            alpns: Vec::new(),
            discovery: discovery.clone(),
            max_idle_timeout: Duration::from_secs(self.max_idle_timeout_secs),
            keep_alive_interval: Duration::from_secs(self.keep_alive_interval_secs),
        };

        // --- Step 3: build the AdmissionHandle. ---
        let admission = match self.admission.mode {
            AdmissionMode::Open => {
                if !self.admission.allowed_node_ids.is_empty() {
                    tracing::warn!(
                        count = self.admission.allowed_node_ids.len(),
                        "iroh.admission.mode = \"open\" but allowed_node_ids is non-empty; \
                         the list will be ignored. Did you mean mode = \"whitelist\"?"
                    );
                }
                AdmissionHandle::open()
            }
            AdmissionMode::Whitelist => {
                let mut set = BTreeSet::new();
                for raw in &self.admission.allowed_node_ids {
                    let node_id = EndpointId::from_str(raw).map_err(|e| {
                        IrohConfigError::InvalidEndpointId {
                            value: raw.clone(),
                            source: e.to_string(),
                        }
                    })?;
                    set.insert(node_id);
                }
                if set.is_empty() {
                    tracing::warn!(
                        "iroh.admission.mode = \"whitelist\" with an empty allowed_node_ids; \
                         the listener will admit no peers. Add at least one EndpointId or set \
                         mode = \"open\"."
                    );
                }
                AdmissionHandle::whitelist(set)
            }
        };

        // --- Step 4: lift SocketAddr overrides into EndpointAddr overrides. ---
        let mut connection_overrides = BTreeMap::new();
        for (node_id, socket_addr) in &discovery.connection_overrides {
            // iroh 1.0-rc EndpointAddr is built from an EndpointId + a set of
            // TransportAddr values; operator overrides are explicit direct IP
            // dials, so we add a single Ip transport address.
            let node_addr = EndpointAddr::new(*node_id).with_ip_addr(*socket_addr);
            connection_overrides.insert(*node_id, node_addr);
        }

        Ok(ResolvedIrohRoleConfig {
            endpoint_config,
            admission,
            per_request_timeout: Duration::from_secs(self.per_request_timeout_secs),
            connection_overrides,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_helpers::iroh::admission::AdmissionPolicy;
    use iroh::SecretKey;

    /// Derive a deterministic [`EndpointId`] (and its base32 string form) from a
    /// 32-byte seed. Mirrors the helper used in `discovery::tests`.
    fn node_id_from_seed(seed: [u8; 32]) -> (EndpointId, String) {
        let secret = SecretKey::from_bytes(&seed);
        let pk = secret.public();
        let s = pk.to_string();
        (pk, s)
    }

    /// Test 1: parse a minimal `[iroh]` block — only the required fields are
    /// set; every default applies; `resolve()` succeeds; admission defaults
    /// to Open.
    #[test]
    fn parse_minimal_toml() {
        let raw = r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/test-key"
"#;
        let cfg: IrohRoleConfig = toml::from_str(raw).expect("minimal toml parse");
        assert_eq!(cfg.listen_address.to_string(), "127.0.0.1:0");
        assert_eq!(cfg.secret_key_path, PathBuf::from("/tmp/test-key"));
        assert_eq!(cfg.max_idle_timeout_secs, 60);
        assert_eq!(cfg.keep_alive_interval_secs, 30);
        assert_eq!(cfg.per_request_timeout_secs, 30);
        assert_eq!(cfg.admission.mode, AdmissionMode::Open);
        assert!(cfg.admission.allowed_node_ids.is_empty());

        let resolved = cfg.resolve().expect("minimal resolve");
        assert!(matches!(resolved.admission.snapshot(), AdmissionPolicy::Open));
        assert_eq!(resolved.per_request_timeout, Duration::from_secs(30));
        assert!(
            resolved.endpoint_config.alpns.is_empty(),
            "ResolvedIrohRoleConfig::endpoint_config.alpns must be empty; \
             callers fill it from network_helpers::iroh::alpn"
        );
        assert_eq!(
            resolved.endpoint_config.max_idle_timeout,
            Duration::from_secs(60)
        );
        assert_eq!(
            resolved.endpoint_config.keep_alive_interval,
            Duration::from_secs(30)
        );
        assert!(resolved.connection_overrides.is_empty());
    }

    /// Test 2: parse a fully-populated `[iroh]` block; `resolve()` succeeds
    /// and the values reflect the TOML.
    #[test]
    fn parse_full_toml() {
        let (id_a, s_a) = node_id_from_seed([1u8; 32]);

        let raw = format!(
            r#"
listen_address = "0.0.0.0:34256"
secret_key_path = "/var/sv2/iroh-secret.ed25519"
relay_url = "https://relay.example.com"

max_idle_timeout_secs = 120
keep_alive_interval_secs = 45
per_request_timeout_secs = 25

discovery_relay_enable = true
discovery_pkarr_pub_enable = false
discovery_pkarr_res_enable = true
discovery_dht_enable = true
discovery_n0_enable = false

[connection_overrides]
"{s_a}" = "192.0.2.5:34256"

[admission]
mode = "whitelist"
allowed_node_ids = ["{s_a}"]
"#
        );

        let cfg: IrohRoleConfig = toml::from_str(&raw).expect("full toml parse");
        assert_eq!(cfg.listen_address.to_string(), "0.0.0.0:34256");
        assert_eq!(cfg.max_idle_timeout_secs, 120);
        assert_eq!(cfg.keep_alive_interval_secs, 45);
        assert_eq!(cfg.per_request_timeout_secs, 25);
        assert_eq!(cfg.admission.mode, AdmissionMode::Whitelist);
        assert_eq!(cfg.admission.allowed_node_ids, vec![s_a.clone()]);

        let resolved = cfg.resolve().expect("full resolve");
        assert_eq!(
            resolved.endpoint_config.max_idle_timeout,
            Duration::from_secs(120)
        );
        assert_eq!(
            resolved.endpoint_config.keep_alive_interval,
            Duration::from_secs(45)
        );
        assert_eq!(resolved.per_request_timeout, Duration::from_secs(25));
        // Discovery values flowed through.
        assert!(resolved.endpoint_config.discovery.relay_enable);
        assert!(!resolved.endpoint_config.discovery.pkarr_publisher_enable);
        assert!(resolved.endpoint_config.discovery.pkarr_resolver_enable);
        assert!(resolved.endpoint_config.discovery.dht_enable);
        assert!(!resolved.endpoint_config.discovery.n0_discovery_enable);
        assert_eq!(
            resolved.endpoint_config.discovery.relay_url.as_deref(),
            Some("https://relay.example.com")
        );
        // Whitelist resolved with the one configured EndpointId.
        match resolved.admission.snapshot() {
            AdmissionPolicy::Whitelist(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains(&id_a));
            }
            AdmissionPolicy::Open => panic!("expected Whitelist, got Open"),
        }
        // Override lifted from SocketAddr -> EndpointAddr.
        assert_eq!(resolved.connection_overrides.len(), 1);
        let na = resolved
            .connection_overrides
            .get(&id_a)
            .expect("override for id_a");
        assert_eq!(na.id, id_a);
        let directs: Vec<_> = na.ip_addrs().copied().collect();
        assert_eq!(directs.len(), 1);
        assert_eq!(directs[0].to_string(), "192.0.2.5:34256");
    }

    /// Test 3: `mode = "whitelist"` with two valid EndpointIds yields a
    /// [`AdmissionPolicy::Whitelist`] snapshot containing both.
    #[test]
    fn admission_whitelist_with_valid_node_ids() {
        let (id_a, s_a) = node_id_from_seed([1u8; 32]);
        let (id_b, s_b) = node_id_from_seed([2u8; 32]);

        let raw = format!(
            r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/key"

[admission]
mode = "whitelist"
allowed_node_ids = ["{s_a}", "{s_b}"]
"#
        );

        let cfg: IrohRoleConfig = toml::from_str(&raw).expect("parse");
        let resolved = cfg.resolve().expect("resolve");
        match resolved.admission.snapshot() {
            AdmissionPolicy::Whitelist(set) => {
                assert_eq!(set.len(), 2);
                assert!(set.contains(&id_a));
                assert!(set.contains(&id_b));
            }
            AdmissionPolicy::Open => panic!("expected Whitelist"),
        }
    }

    /// Test 4: a malformed base32 string in `allowed_node_ids` surfaces
    /// [`IrohConfigError::InvalidEndpointId`] from `resolve()`.
    #[test]
    fn admission_whitelist_with_invalid_node_id() {
        let raw = r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/key"

[admission]
mode = "whitelist"
allowed_node_ids = ["not-a-real-node-id"]
"#;

        let cfg: IrohRoleConfig = toml::from_str(raw).expect("parse");
        let err = cfg.resolve().expect_err("invalid EndpointId must error");
        match err {
            IrohConfigError::InvalidEndpointId { value, .. } => {
                assert_eq!(value, "not-a-real-node-id");
            }
            other => panic!("expected InvalidEndpointId, got {other:?}"),
        }
    }

    /// Test 5: `mode = "open"` paired with a non-empty `allowed_node_ids`
    /// resolves successfully; the resulting policy is Open. (The warning is
    /// emitted via `tracing::warn!` and intentionally not captured here —
    /// the contract is "policy is Open, list is silently ignored".)
    #[test]
    fn admission_open_warns_on_unused_allowed_node_ids() {
        let (_id, s) = node_id_from_seed([1u8; 32]);

        let raw = format!(
            r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/key"

[admission]
mode = "open"
allowed_node_ids = ["{s}"]
"#
        );

        let cfg: IrohRoleConfig = toml::from_str(&raw).expect("parse");
        let resolved = cfg.resolve().expect("resolve");
        assert!(
            matches!(resolved.admission.snapshot(), AdmissionPolicy::Open),
            "open mode must yield AdmissionPolicy::Open even with allowed_node_ids set"
        );
    }

    /// Test 6: `mode = "whitelist"` with an empty `allowed_node_ids` resolves
    /// successfully to an empty [`AdmissionPolicy::Whitelist`] (admits
    /// nothing). The warning is logged but not asserted on.
    #[test]
    fn admission_whitelist_empty_allowlist() {
        let raw = r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/key"

[admission]
mode = "whitelist"
allowed_node_ids = []
"#;
        let cfg: IrohRoleConfig = toml::from_str(raw).expect("parse");
        let resolved = cfg.resolve().expect("resolve");
        match resolved.admission.snapshot() {
            AdmissionPolicy::Whitelist(set) => assert!(set.is_empty()),
            AdmissionPolicy::Open => panic!("expected empty Whitelist, got Open"),
        }
    }

    /// Test 7: unknown fields at the top level of `[iroh]` are rejected by
    /// `#[serde(deny_unknown_fields)]`.
    ///
    /// Note: serde's `deny_unknown_fields` does not propagate through
    /// `#[serde(flatten)]` — keys that match the flattened
    /// [`DiscoveryConfigToml`] are accepted at this level even though they
    /// don't appear on `IrohRoleConfig`. The intent of this test is to
    /// confirm a typo in a top-level required field (e.g. `listen_addresss`)
    /// is surfaced loudly.
    #[test]
    fn unknown_field_rejected() {
        let raw = r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/key"
listen_addresss = "127.0.0.1:9999"
"#;
        let res: Result<IrohRoleConfig, _> = toml::from_str(raw);
        assert!(
            res.is_err(),
            "deny_unknown_fields should reject `listen_addresss` typo"
        );
    }

    /// Test 8: defaults match the plan's spec values.
    #[test]
    fn defaults_match_plan_specs() {
        let raw = r#"
listen_address = "127.0.0.1:0"
secret_key_path = "/tmp/key"
"#;
        let cfg: IrohRoleConfig = toml::from_str(raw).expect("parse");

        // Per plan §"Mandatory operational primitives":
        assert_eq!(
            cfg.max_idle_timeout_secs, 60,
            "max_idle_timeout_secs default must be 60 (Fedimint PR #8422)"
        );
        assert_eq!(
            cfg.keep_alive_interval_secs, 30,
            "keep_alive_interval_secs default must be 30 (Fedimint PR #8422)"
        );
        assert_eq!(
            cfg.per_request_timeout_secs, 30,
            "per_request_timeout_secs default must be 30 (Fedimint PR #8571)"
        );

        // Discovery defaults must match DiscoveryConfig::default().
        let resolved = cfg.resolve().expect("resolve");
        let default_discovery = DiscoveryConfig::default();
        assert_eq!(resolved.endpoint_config.discovery, default_discovery);
    }
}
