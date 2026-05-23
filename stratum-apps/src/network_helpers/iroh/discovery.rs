//! Per-mechanism iroh discovery toggles.
//!
//! TOML provides defaults; environment variables override. Consumed by
//! `iroh/endpoint.rs` (Wave 3) to wire the right discovery mechanisms into the
//! [`iroh::Endpoint`] builder.
//!
//! See `/Users/garykrause/.claude/plans/how-might-we-implement-snoopy-lollipop.md`
//! § "Environment variable overrides" for the env var contract and § "Per-role
//! `[iroh]` section (TOML)" for the TOML defaults.
//!
//! # Resolution order
//!
//! 1. Start from [`DiscoveryConfig::default`] (the documented per-role
//!    defaults).
//! 2. Apply each `Some(_)` field from [`DiscoveryConfigToml`] (TOML wins over
//!    defaults).
//! 3. Apply any environment variable that is set (env wins over TOML), per the
//!    Fedimint pattern.
//!
//! `connection_overrides` is replaced wholesale by `SV2_IROH_CONNECT_OVERRIDES`
//! when that variable is set — entries are not merged with the TOML map. This
//! mirrors the behavior of Fedimint's `FM_IROH_CONNECT_OVERRIDES_ENV`.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::str::FromStr;

use iroh::EndpointId;

/// Environment variable that toggles relay-based discovery.
pub const ENV_RELAYS_ENABLE: &str = "SV2_IROH_RELAYS_ENABLE";
/// Environment variable that toggles publishing the local node's records to
/// the pkarr DHT.
pub const ENV_PKARR_PUBLISHER_ENABLE: &str = "SV2_IROH_PKARR_PUBLISHER_ENABLE";
/// Environment variable that toggles resolving remote node records via pkarr.
pub const ENV_PKARR_RESOLVER_ENABLE: &str = "SV2_IROH_PKARR_RESOLVER_ENABLE";
/// Environment variable that toggles BitTorrent-style mainline DHT discovery.
pub const ENV_DHT_ENABLE: &str = "SV2_IROH_DHT_ENABLE";
/// Environment variable that toggles n0's hosted discovery network.
pub const ENV_N0_DISCOVERY_ENABLE: &str = "SV2_IROH_N0_DISCOVERY_ENABLE";
/// Environment variable that overrides connection addresses (`node_id=host:port`,
/// comma-separated). Replaces the TOML map wholesale when set.
pub const ENV_CONNECT_OVERRIDES: &str = "SV2_IROH_CONNECT_OVERRIDES";

/// Resolved per-mechanism discovery configuration.
///
/// All defaults match the plan's "Per-role `[iroh]` section (TOML)" defaults:
/// relay / pkarr publisher / pkarr resolver / n0 discovery on, DHT off
/// (matches Fedimint's production posture).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DiscoveryConfig {
    /// Whether to use relay-based discovery / fallback when direct dials fail.
    pub relay_enable: bool,
    /// Whether to publish this node's address records to pkarr.
    pub pkarr_publisher_enable: bool,
    /// Whether to resolve remote node addresses via pkarr.
    pub pkarr_resolver_enable: bool,
    /// Whether to participate in the BitTorrent mainline DHT for discovery.
    pub dht_enable: bool,
    /// Whether to use n0's hosted discovery network.
    pub n0_discovery_enable: bool,
    /// Optional relay URL. `None` means "no relay configured" (direct only);
    /// `Some(_)` carries the configured relay URL string. The endpoint builder
    /// will parse / validate the URL — we only round-trip the string here so
    /// this module stays free of any iroh URL parsing.
    pub relay_url: Option<String>,
    /// Operator-supplied dial overrides: forces a given [`EndpointId`] to be
    /// reached at a fixed [`SocketAddr`] regardless of discovery results.
    pub connection_overrides: BTreeMap<EndpointId, SocketAddr>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            relay_enable: true,
            pkarr_publisher_enable: true,
            pkarr_resolver_enable: true,
            dht_enable: false,
            n0_discovery_enable: true,
            relay_url: None,
            connection_overrides: BTreeMap::new(),
        }
    }
}

/// TOML-deserializable form of [`DiscoveryConfig`]. Each field is `Option`
/// so the resolver can distinguish "absent in TOML" from "explicitly set".
#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default)]
pub struct DiscoveryConfigToml {
    /// Override for `relay_enable`.
    pub discovery_relay_enable: Option<bool>,
    /// Override for `pkarr_publisher_enable`.
    pub discovery_pkarr_pub_enable: Option<bool>,
    /// Override for `pkarr_resolver_enable`.
    pub discovery_pkarr_res_enable: Option<bool>,
    /// Override for `dht_enable`.
    pub discovery_dht_enable: Option<bool>,
    /// Override for `n0_discovery_enable`.
    pub discovery_n0_enable: Option<bool>,
    /// Relay URL. The empty string is normalized to `None` to keep the TOML
    /// surface comfortable for operators who don't want to delete the key.
    pub relay_url: Option<String>,
    /// `node_id (base32) -> "host:port"` overrides. Parsed in [`DiscoveryConfig::resolve`].
    pub connection_overrides: Option<BTreeMap<String, String>>,
}

/// Errors produced while resolving discovery configuration from TOML and the
/// environment.
#[derive(Debug)]
pub enum DiscoveryConfigError {
    /// An environment variable that should have been a boolean was something
    /// else.
    InvalidBool {
        /// Name of the offending environment variable.
        var: &'static str,
        /// The raw value we tried (and failed) to parse.
        value: String,
    },
    /// A `SV2_IROH_CONNECT_OVERRIDES` entry was structurally malformed (e.g.
    /// missing `=`).
    InvalidOverride {
        /// The offending `node_id=host:port` entry.
        entry: String,
        /// Human-readable reason describing what was wrong.
        reason: String,
    },
    /// Failed to parse a [`EndpointId`] from a connection-override key.
    InvalidEndpointId {
        /// The base32 string we tried to parse.
        value: String,
        /// The underlying parse error stringified.
        source: String,
    },
    /// Failed to parse a [`SocketAddr`] from a connection-override value.
    InvalidSocketAddr {
        /// The `host:port` string we tried to parse.
        value: String,
        /// The underlying parse error stringified.
        source: String,
    },
}

impl std::fmt::Display for DiscoveryConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryConfigError::InvalidBool { var, value } => write!(
                f,
                "invalid env var {var}={value}: expected true/false/1/0/yes/no"
            ),
            DiscoveryConfigError::InvalidOverride { entry, reason } => {
                write!(f, "invalid SV2_IROH_CONNECT_OVERRIDES entry {entry}: {reason}")
            }
            DiscoveryConfigError::InvalidEndpointId { value, source } => {
                write!(f, "invalid EndpointId {value}: {source}")
            }
            DiscoveryConfigError::InvalidSocketAddr { value, source } => {
                write!(f, "invalid SocketAddr {value}: {source}")
            }
        }
    }
}

impl std::error::Error for DiscoveryConfigError {}

impl DiscoveryConfig {
    /// Resolve discovery configuration: defaults, then TOML, then env vars.
    ///
    /// Step-by-step:
    ///
    /// 1. Start with [`DiscoveryConfig::default`].
    /// 2. Apply each `Some(_)` field from `toml`.
    /// 3. For each per-mechanism env var (`SV2_IROH_*_ENABLE`), if set, parse
    ///    a boolean (`true|false|1|0|yes|no`, case-insensitive) and override.
    /// 4. If `SV2_IROH_CONNECT_OVERRIDES` is set, parse it as
    ///    `node_id=host:port` comma-separated pairs and replace the entire
    ///    overrides map (matches Fedimint env semantics — env wins for the
    ///    whole field).
    ///
    /// `relay_url`: `Some("")` from TOML or env collapses to `None`.
    pub fn resolve(toml: DiscoveryConfigToml) -> Result<Self, DiscoveryConfigError> {
        let mut cfg = Self::default();

        // --- Step 2: apply TOML on top of defaults. ---
        if let Some(v) = toml.discovery_relay_enable {
            cfg.relay_enable = v;
        }
        if let Some(v) = toml.discovery_pkarr_pub_enable {
            cfg.pkarr_publisher_enable = v;
        }
        if let Some(v) = toml.discovery_pkarr_res_enable {
            cfg.pkarr_resolver_enable = v;
        }
        if let Some(v) = toml.discovery_dht_enable {
            cfg.dht_enable = v;
        }
        if let Some(v) = toml.discovery_n0_enable {
            cfg.n0_discovery_enable = v;
        }
        if let Some(url) = toml.relay_url {
            cfg.relay_url = normalize_relay_url(url);
        }
        if let Some(map) = toml.connection_overrides {
            cfg.connection_overrides = parse_overrides_map(&map)?;
        }

        // --- Step 3: per-mechanism env var overrides. ---
        if let Some(v) = read_env_bool(ENV_RELAYS_ENABLE)? {
            cfg.relay_enable = v;
        }
        if let Some(v) = read_env_bool(ENV_PKARR_PUBLISHER_ENABLE)? {
            cfg.pkarr_publisher_enable = v;
        }
        if let Some(v) = read_env_bool(ENV_PKARR_RESOLVER_ENABLE)? {
            cfg.pkarr_resolver_enable = v;
        }
        if let Some(v) = read_env_bool(ENV_DHT_ENABLE)? {
            cfg.dht_enable = v;
        }
        if let Some(v) = read_env_bool(ENV_N0_DISCOVERY_ENABLE)? {
            cfg.n0_discovery_enable = v;
        }

        // --- Step 4: connection-overrides env replaces the whole map. ---
        if let Ok(raw) = std::env::var(ENV_CONNECT_OVERRIDES) {
            cfg.connection_overrides = parse_overrides_env(&raw)?;
        }

        Ok(cfg)
    }
}

/// Empty string (after trimming) collapses to `None`; otherwise pass the value
/// through. The endpoint builder is responsible for actually parsing the URL.
fn normalize_relay_url(url: String) -> Option<String> {
    if url.trim().is_empty() {
        None
    } else {
        Some(url)
    }
}

/// Parse `var` as a boolean if set; return `None` if unset.
///
/// Accepts (case-insensitive): `true`, `false`, `1`, `0`, `yes`, `no`. Empty
/// or whitespace-only strings are rejected as `InvalidBool` rather than
/// silently treated as unset, because the Fedimint contract is "presence
/// means override".
fn read_env_bool(var: &'static str) -> Result<Option<bool>, DiscoveryConfigError> {
    match std::env::var(var) {
        Ok(raw) => Ok(Some(parse_bool_str(var, &raw)?)),
        Err(_) => Ok(None),
    }
}

fn parse_bool_str(var: &'static str, raw: &str) -> Result<bool, DiscoveryConfigError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(DiscoveryConfigError::InvalidBool {
            var,
            value: raw.to_string(),
        }),
    }
}

/// Parse the TOML `connection_overrides` map into the typed runtime map.
fn parse_overrides_map(
    map: &BTreeMap<String, String>,
) -> Result<BTreeMap<EndpointId, SocketAddr>, DiscoveryConfigError> {
    let mut out = BTreeMap::new();
    for (k, v) in map {
        let node_id = parse_node_id(k)?;
        let addr = parse_socket_addr(v)?;
        out.insert(node_id, addr);
    }
    Ok(out)
}

/// Parse the `SV2_IROH_CONNECT_OVERRIDES` env var.
///
/// Format: comma-separated `node_id=host:port` entries. Whitespace around
/// entries (and around `=`) is tolerated. An empty string yields an empty
/// map; trailing commas are tolerated. Duplicate node IDs are tolerated and
/// last-write-wins, matching `BTreeMap::insert` behavior.
fn parse_overrides_env(raw: &str) -> Result<BTreeMap<EndpointId, SocketAddr>, DiscoveryConfigError> {
    let mut out = BTreeMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            DiscoveryConfigError::InvalidOverride {
                entry: entry.to_string(),
                reason: "expected `node_id=host:port`".to_string(),
            }
        })?;
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(DiscoveryConfigError::InvalidOverride {
                entry: entry.to_string(),
                reason: "empty node_id or address".to_string(),
            });
        }
        let node_id = parse_node_id(key)?;
        let addr = parse_socket_addr(value)?;
        out.insert(node_id, addr);
    }
    Ok(out)
}

fn parse_node_id(s: &str) -> Result<EndpointId, DiscoveryConfigError> {
    EndpointId::from_str(s).map_err(|e| DiscoveryConfigError::InvalidEndpointId {
        value: s.to_string(),
        source: e.to_string(),
    })
}

fn parse_socket_addr(s: &str) -> Result<SocketAddr, DiscoveryConfigError> {
    SocketAddr::from_str(s).map_err(|e| DiscoveryConfigError::InvalidSocketAddr {
        value: s.to_string(),
        source: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// Tests that mutate process-global env vars must not run in parallel.
    /// Each env-touching test acquires this mutex for the duration of the
    /// test (released on drop, including on panic). This is the in-tree
    /// substitute for the `serial_test` crate; see the report for rationale.
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // If a previous test panicked while holding the lock, treat the
        // poisoning as benign — the env state was restored by the EnvGuard
        // Drop impl regardless.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// RAII guard that records whatever an env var was set to at construction
    /// and restores it on drop, even if the test panics. Use this around any
    /// `std::env::set_var` in tests so other tests see a clean environment.
    struct EnvGuard {
        var: &'static str,
        prior: Option<String>,
    }

    impl EnvGuard {
        fn set(var: &'static str, value: &str) -> Self {
            let prior = std::env::var(var).ok();
            // SAFETY: env mutation is serialized via `env_lock`.
            std::env::set_var(var, value);
            Self { var, prior }
        }

        fn unset(var: &'static str) -> Self {
            let prior = std::env::var(var).ok();
            // SAFETY: env mutation is serialized via `env_lock`.
            std::env::remove_var(var);
            Self { var, prior }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.var, v),
                None => std::env::remove_var(self.var),
            }
        }
    }

    /// Clear every env var this module observes so a test starts from a known
    /// state regardless of how the surrounding shell set things up.
    fn clear_all_env() -> Vec<EnvGuard> {
        vec![
            EnvGuard::unset(ENV_RELAYS_ENABLE),
            EnvGuard::unset(ENV_PKARR_PUBLISHER_ENABLE),
            EnvGuard::unset(ENV_PKARR_RESOLVER_ENABLE),
            EnvGuard::unset(ENV_DHT_ENABLE),
            EnvGuard::unset(ENV_N0_DISCOVERY_ENABLE),
            EnvGuard::unset(ENV_CONNECT_OVERRIDES),
        ]
    }

    /// Derive a deterministic [`EndpointId`] from a 32-byte seed. Used to build
    /// test fixtures without committing a base32 string that depends on the
    /// exact iroh-base display alphabet. `seed = [1; 32]` and `[2; 32]` give
    /// us two distinct, stable EndpointIds for env-override tests.
    fn node_id_from_seed(seed: [u8; 32]) -> (EndpointId, String) {
        let secret = iroh::SecretKey::from_bytes(&seed);
        let pk = secret.public();
        let s = pk.to_string();
        // Sanity-check: round-trip through the parser we'll exercise in
        // production. If this ever fails, the fixture itself is broken
        // (not the code under test).
        let parsed = EndpointId::from_str(&s).expect("derived EndpointId must round-trip");
        assert_eq!(parsed, pk);
        (pk, s)
    }

    fn sample_node_id_a() -> (EndpointId, String) {
        node_id_from_seed([1u8; 32])
    }

    fn sample_node_id_b() -> (EndpointId, String) {
        node_id_from_seed([2u8; 32])
    }

    // 1. Defaults match the documented defaults.
    #[test]
    fn defaults_match_plan() {
        let d = DiscoveryConfig::default();
        assert!(d.relay_enable);
        assert!(d.pkarr_publisher_enable);
        assert!(d.pkarr_resolver_enable);
        assert!(!d.dht_enable);
        assert!(d.n0_discovery_enable);
        assert!(d.relay_url.is_none());
        assert!(d.connection_overrides.is_empty());
    }

    // 2. resolve with empty TOML and no env vars equals default.
    #[test]
    fn empty_toml_no_env_equals_default() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let resolved = DiscoveryConfig::resolve(DiscoveryConfigToml::default())
            .expect("empty resolve must succeed");
        assert_eq!(resolved, DiscoveryConfig::default());
    }

    // 3. TOML override of dht_enable=true.
    #[test]
    fn toml_overrides_default() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let toml = DiscoveryConfigToml {
            discovery_dht_enable: Some(true),
            ..Default::default()
        };
        let resolved = DiscoveryConfig::resolve(toml).expect("resolve");
        assert!(resolved.dht_enable);
        // Other fields untouched.
        assert!(resolved.relay_enable);
        assert!(resolved.n0_discovery_enable);
    }

    // 4. Env var overrides TOML.
    #[test]
    fn env_overrides_toml() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let _g_dht = EnvGuard::set(ENV_DHT_ENABLE, "true");
        let toml = DiscoveryConfigToml {
            discovery_dht_enable: Some(false),
            ..Default::default()
        };
        let resolved = DiscoveryConfig::resolve(toml).expect("resolve");
        assert!(resolved.dht_enable, "env true must beat toml false");
    }

    // 5. SV2_IROH_CONNECT_OVERRIDES env parses two entries.
    #[test]
    fn connect_overrides_env_two_entries() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let (id_a, s_a) = sample_node_id_a();
        let (id_b, s_b) = sample_node_id_b();
        let raw = format!("{s_a}=192.0.2.5:34256, {s_b}=198.51.100.7:9000");
        let _g_o = EnvGuard::set(ENV_CONNECT_OVERRIDES, &raw);

        let resolved =
            DiscoveryConfig::resolve(DiscoveryConfigToml::default()).expect("resolve");
        assert_eq!(resolved.connection_overrides.len(), 2);
        assert_eq!(
            resolved.connection_overrides.get(&id_a),
            Some(&"192.0.2.5:34256".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            resolved.connection_overrides.get(&id_b),
            Some(&"198.51.100.7:9000".parse::<SocketAddr>().unwrap())
        );
    }

    // 5b. Env replaces the whole map (no merging with TOML).
    #[test]
    fn connect_overrides_env_replaces_toml_map() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let (_id_a, s_a) = sample_node_id_a();
        let (_id_b, s_b) = sample_node_id_b();

        let mut toml_map = BTreeMap::new();
        toml_map.insert(s_a.clone(), "10.0.0.1:1111".to_string());
        let toml = DiscoveryConfigToml {
            connection_overrides: Some(toml_map),
            ..Default::default()
        };

        let _g_o = EnvGuard::set(
            ENV_CONNECT_OVERRIDES,
            &format!("{s_b}=198.51.100.7:9000"),
        );

        let resolved = DiscoveryConfig::resolve(toml).expect("resolve");
        // Only the env's single entry remains; the TOML map is gone.
        assert_eq!(resolved.connection_overrides.len(), 1);
        let (id_b, _) = sample_node_id_b();
        assert!(resolved.connection_overrides.contains_key(&id_b));
    }

    // 6. Invalid env bool returns InvalidBool.
    #[test]
    fn invalid_env_bool_errors() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let _g_dht = EnvGuard::set(ENV_DHT_ENABLE, "definitely-not-a-bool");
        let err = DiscoveryConfig::resolve(DiscoveryConfigToml::default())
            .expect_err("invalid bool must error");
        match err {
            DiscoveryConfigError::InvalidBool { var, value } => {
                assert_eq!(var, ENV_DHT_ENABLE);
                assert_eq!(value, "definitely-not-a-bool");
            }
            other => panic!("expected InvalidBool, got {other:?}"),
        }
    }

    // 7. relay_url empty string in TOML -> None.
    #[test]
    fn relay_url_empty_string_is_none() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let toml = DiscoveryConfigToml {
            relay_url: Some(String::new()),
            ..Default::default()
        };
        let resolved = DiscoveryConfig::resolve(toml).expect("resolve");
        assert!(resolved.relay_url.is_none());

        // Also: whitespace-only string normalizes to None, so operators who
        // hit space accidentally don't get a junk URL handed to the
        // endpoint builder.
        let toml = DiscoveryConfigToml {
            relay_url: Some("   ".to_string()),
            ..Default::default()
        };
        let resolved = DiscoveryConfig::resolve(toml).expect("resolve");
        assert!(resolved.relay_url.is_none());
    }

    // 8. relay_url "https://..." -> Some(...).
    #[test]
    fn relay_url_https_is_passed_through() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let toml = DiscoveryConfigToml {
            relay_url: Some("https://relay.example.com".to_string()),
            ..Default::default()
        };
        let resolved = DiscoveryConfig::resolve(toml).expect("resolve");
        assert_eq!(
            resolved.relay_url.as_deref(),
            Some("https://relay.example.com")
        );
    }

    // Bonus: env bool accepts the documented variants.
    #[test]
    fn env_bool_accepts_documented_variants() {
        let _g = env_lock();
        let _restore = clear_all_env();
        for (raw, expected) in [
            ("true", true),
            ("TRUE", true),
            ("True", true),
            ("1", true),
            ("yes", true),
            ("YES", true),
            ("false", false),
            ("FALSE", false),
            ("0", false),
            ("no", false),
            (" true ", true), // surrounding whitespace tolerated
        ] {
            let _g_dht = EnvGuard::set(ENV_DHT_ENABLE, raw);
            let resolved = DiscoveryConfig::resolve(DiscoveryConfigToml::default())
                .unwrap_or_else(|e| panic!("resolve({raw:?}) failed: {e}"));
            assert_eq!(resolved.dht_enable, expected, "raw = {raw:?}");
        }
    }

    // Bonus: malformed override entries surface a useful error.
    #[test]
    fn invalid_override_entry_errors() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let _g_o = EnvGuard::set(ENV_CONNECT_OVERRIDES, "no-equals-sign");
        let err = DiscoveryConfig::resolve(DiscoveryConfigToml::default()).unwrap_err();
        assert!(
            matches!(err, DiscoveryConfigError::InvalidOverride { .. }),
            "expected InvalidOverride, got {err:?}"
        );
    }

    // Bonus: bad EndpointId in env override surfaces InvalidEndpointId.
    #[test]
    fn invalid_node_id_in_env_overrides() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let _g_o = EnvGuard::set(ENV_CONNECT_OVERRIDES, "not-a-node-id=192.0.2.5:34256");
        let err = DiscoveryConfig::resolve(DiscoveryConfigToml::default()).unwrap_err();
        assert!(
            matches!(err, DiscoveryConfigError::InvalidEndpointId { .. }),
            "expected InvalidEndpointId, got {err:?}"
        );
    }

    // Bonus: bad SocketAddr in env override surfaces InvalidSocketAddr.
    #[test]
    fn invalid_socket_addr_in_env_overrides() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let (_id_a, s_a) = sample_node_id_a();
        let _g_o = EnvGuard::set(
            ENV_CONNECT_OVERRIDES,
            &format!("{s_a}=not-a-socket-addr"),
        );
        let err = DiscoveryConfig::resolve(DiscoveryConfigToml::default()).unwrap_err();
        assert!(
            matches!(err, DiscoveryConfigError::InvalidSocketAddr { .. }),
            "expected InvalidSocketAddr, got {err:?}"
        );
    }

    // Bonus: empty env string for overrides yields an empty map (no error).
    #[test]
    fn empty_overrides_env_yields_empty_map() {
        let _g = env_lock();
        let _restore = clear_all_env();
        let _g_o = EnvGuard::set(ENV_CONNECT_OVERRIDES, "");
        let resolved =
            DiscoveryConfig::resolve(DiscoveryConfigToml::default()).expect("resolve");
        assert!(resolved.connection_overrides.is_empty());
    }
}
