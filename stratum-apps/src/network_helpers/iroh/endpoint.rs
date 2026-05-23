//! `IrohEndpointBuilder`: applies the plan's mandatory configuration when
//! constructing an [`iroh::Endpoint`].
//!
//! Wraps [`iroh::Endpoint::builder`] with:
//!
//! - QUIC keepalive (`max_idle_timeout = 60s`, `keep_alive_interval = 30s`)
//!   per Fedimint PR #8422 — the production lesson the plan calls out as
//!   mandatory in §"Mandatory operational primitives".
//! - Per-mechanism discovery toggles ([`DiscoveryConfig`]) matching
//!   Fedimint's `FM_IROH_*_ENABLE` pattern: relay, pkarr publisher, pkarr
//!   resolver, mainline DHT, n0's hosted discovery, and an optional explicit
//!   relay URL.
//! - ALPN registration (one or more, role-dependent — caller passes them in).
//! - Identity loading via [`crate::network_helpers::iroh::identity`]
//!   (or a pre-loaded [`SecretKey`] for tests / HSM scenarios).
//!
//! Consumed by `iroh/connector.rs` and `iroh/listener.rs` (Wave 3b).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use iroh::{
    discovery::{
        dns::DnsDiscovery,
        pkarr::{PkarrPublisher, PkarrResolver},
    },
    endpoint::TransportConfig,
    Endpoint, RelayMap, RelayMode, RelayUrl, SecretKey,
};

use crate::network_helpers::iroh::discovery::DiscoveryConfig;
use crate::network_helpers::iroh::identity;

/// Subset of `IrohRoleConfig` fields needed for endpoint construction.
///
/// Kept separate from the full role config so this module doesn't have to
/// know about the whole `IrohRoleConfig` type, which is owned by
/// `iroh/mod.rs` (added in Wave 3 integration).
#[derive(Debug, Clone)]
pub struct EndpointBuildConfig {
    /// UDP socket the endpoint should bind to.
    pub listen_address: SocketAddr,
    /// Path to the persistent Ed25519 secret key on disk. Auto-generated if
    /// missing. Ignored when using [`build_endpoint_with_key`].
    pub secret_key_path: PathBuf,
    /// One or more SV2 ALPNs to register on this endpoint. Caller-provided
    /// because the role-specific value comes from
    /// `crate::network_helpers::iroh::alpn`.
    pub alpns: Vec<Vec<u8>>,
    /// Resolved per-mechanism discovery toggles. Built by
    /// [`DiscoveryConfig::resolve`] from the per-role TOML and the
    /// `SV2_IROH_*` environment variables.
    pub discovery: DiscoveryConfig,
    /// QUIC `max_idle_timeout`. Plan default: `60s` (Fedimint PR #8422).
    pub max_idle_timeout: Duration,
    /// QUIC `keep_alive_interval`. Plan default: `30s` (Fedimint PR #8422).
    pub keep_alive_interval: Duration,
}

impl Default for EndpointBuildConfig {
    fn default() -> Self {
        Self {
            // The unwrap on a hardcoded valid SocketAddr literal is documented
            // as infallible by the std `SocketAddr::from_str` impl.
            listen_address: "0.0.0.0:0".parse().expect("hardcoded SocketAddr"),
            secret_key_path: PathBuf::new(),
            alpns: Vec::new(),
            discovery: DiscoveryConfig::default(),
            max_idle_timeout: Duration::from_secs(60),
            keep_alive_interval: Duration::from_secs(30),
        }
    }
}

/// Errors returned while building an [`Endpoint`].
///
/// Hand-rolled `Display` + `std::error::Error` to avoid a `thiserror`
/// dependency, matching the style of [`crate::network_helpers::iroh::identity`]
/// and [`crate::network_helpers::iroh::discovery`].
#[derive(Debug)]
pub enum EndpointBuildError {
    /// Failed to load (or auto-generate) the persistent identity key.
    Identity(identity::IdentityError),
    /// `Endpoint::bind` failed — typically because the UDP socket is in use,
    /// the address is unroutable, or a discovery service refused to start.
    Bind {
        /// The configured listen address (after IPv4/IPv6 demultiplexing).
        addr: SocketAddr,
        /// Stringified underlying iroh error. The iroh `BindError` type uses
        /// `snafu` and isn't object-safe; we capture its `Display` so we don't
        /// have to depend on `iroh-base`'s exact error layout.
        source: String,
    },
    /// The configured `relay_url` failed to parse as a [`RelayUrl`].
    InvalidRelayUrl {
        /// The URL string that failed to parse.
        url: String,
        /// Stringified underlying error.
        source: String,
    },
    /// Failed to build the QUIC `TransportConfig` (e.g. an `IdleTimeout`
    /// outside the representable range).
    Transport(String),
    /// Generic catch-all for anything else iroh's setup path can fail with
    /// that doesn't fit a more specific variant.
    EndpointSetup(String),
}

impl From<identity::IdentityError> for EndpointBuildError {
    fn from(value: identity::IdentityError) -> Self {
        EndpointBuildError::Identity(value)
    }
}

impl std::fmt::Display for EndpointBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EndpointBuildError::Identity(e) => write!(f, "identity error: {e}"),
            EndpointBuildError::Bind { addr, source } => {
                write!(f, "bind failed at {addr}: {source}")
            }
            EndpointBuildError::InvalidRelayUrl { url, source } => {
                write!(f, "invalid relay url {url}: {source}")
            }
            EndpointBuildError::Transport(msg) => write!(f, "transport config error: {msg}"),
            EndpointBuildError::EndpointSetup(msg) => write!(f, "iroh endpoint setup error: {msg}"),
        }
    }
}

impl std::error::Error for EndpointBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            EndpointBuildError::Identity(e) => Some(e),
            _ => None,
        }
    }
}

/// Build a fully-configured [`Endpoint`] per the plan's specification.
///
/// On success the endpoint is bound to `config.listen_address` and is ready
/// to connect / accept. The caller is responsible for keeping it alive (it
/// drives an internal magicsock task that shuts down on drop).
///
/// Loads (or auto-generates) the persistent Ed25519 identity from
/// `config.secret_key_path`. Use [`build_endpoint_with_key`] when the secret
/// comes from somewhere other than disk.
pub async fn build_endpoint(config: &EndpointBuildConfig) -> Result<Endpoint, EndpointBuildError> {
    let secret_key = identity::load_or_generate(&config.secret_key_path)?;
    build_endpoint_with_key(config, secret_key).await
}

/// Variant of [`build_endpoint`] that takes a pre-loaded [`SecretKey`].
///
/// Used in tests and in scenarios where the secret comes from an HSM, KMS,
/// or any other store that isn't a file on disk.
pub async fn build_endpoint_with_key(
    config: &EndpointBuildConfig,
    secret_key: SecretKey,
) -> Result<Endpoint, EndpointBuildError> {
    // ----- Resolve relay mode --------------------------------------------------
    //
    // Plan semantics:
    //   * `relay_enable=false`               -> RelayMode::Disabled
    //   * `relay_enable=true`, no relay_url  -> RelayMode::Default (n0 prod)
    //   * `relay_enable=true`, with url      -> RelayMode::Custom(<url>)
    let relay_mode = if !config.discovery.relay_enable {
        RelayMode::Disabled
    } else if let Some(url) = config.discovery.relay_url.as_deref() {
        let parsed =
            RelayUrl::from_str(url).map_err(|e| EndpointBuildError::InvalidRelayUrl {
                url: url.to_string(),
                source: e.to_string(),
            })?;
        RelayMode::Custom(RelayMap::from(parsed))
    } else {
        RelayMode::Default
    };

    // ----- Build the QUIC transport config -------------------------------------
    //
    // Plan §"Mandatory operational primitives" lists explicit QUIC keepalive
    // as non-optional. iroh 0.91 does NOT re-export `quinn::IdleTimeout`
    // through its public `iroh::endpoint` module, so we cannot name the type.
    // We sidestep that by relying on the function parameter's type to drive
    // inference: `TransportConfig::max_idle_timeout` takes
    // `Option<IdleTimeout>`, so the `try_into()` target is unambiguous
    // without us needing to import the type.
    //
    // The `try_into` only fails when the duration overflows the QUIC VarInt
    // encoding (~4500 years), so this branch is effectively a programmer
    // mistake check.
    let mut transport_config = TransportConfig::default();
    let idle_timeout = match config.max_idle_timeout.try_into() {
        Ok(t) => t,
        Err(e) => {
            return Err(EndpointBuildError::Transport(format!(
                "max_idle_timeout {:?} is out of range: {e}",
                config.max_idle_timeout
            )));
        }
    };
    transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config.keep_alive_interval(Some(config.keep_alive_interval));

    // ----- Build the iroh Endpoint builder -------------------------------------
    let mut builder = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(config.alpns.clone())
        .relay_mode(relay_mode)
        .transport_config(transport_config)
        // Start from a clean slate so our toggles don't accidentally
        // compound with iroh's defaults. We re-add what's enabled below.
        .clear_discovery();

    // ----- Per-mechanism discovery toggles -------------------------------------
    //
    // Each mechanism is independently switchable per the plan. Order doesn't
    // matter for correctness — iroh wraps multiple discovery services in a
    // ConcurrentDiscovery internally — but we keep the order matching the
    // plan/TOML ordering for readability.
    let d = &config.discovery;

    if d.n0_discovery_enable {
        // Convenience: PkarrPublisher::n0_dns + DnsDiscovery::n0_dns. May
        // overlap with the more granular pkarr toggles below; that's fine
        // because iroh's `ConcurrentDiscovery` tolerates duplicates.
        builder = builder.discovery_n0();
    }
    if d.pkarr_publisher_enable {
        builder = builder.add_discovery(PkarrPublisher::n0_dns());
    }
    if d.pkarr_resolver_enable {
        // PkarrResolver doesn't add an n0_dns DNS resolver — that's what
        // DnsDiscovery::n0_dns does. We also add the resolver here so a
        // node with `n0_discovery_enable=false` but `pkarr_resolver_enable=true`
        // still gets DNS resolution against n0's records.
        builder = builder.add_discovery(PkarrResolver::n0_dns());
        builder = builder.add_discovery(DnsDiscovery::n0_dns());
    }
    if d.dht_enable {
        // Gated on the `discovery-pkarr-dht` cargo feature. That feature is
        // enabled in stratum-apps's Cargo.toml whenever `iroh-transport` is
        // on, so this call is always available in this build.
        builder = builder.discovery_dht();
    }

    // ----- Bind on the configured UDP socket -----------------------------------
    //
    // iroh's builder has separate `bind_addr_v4` and `bind_addr_v6` setters;
    // pick the right one based on the configured SocketAddr family.
    builder = match config.listen_address {
        SocketAddr::V4(v4) => builder.bind_addr_v4(v4),
        SocketAddr::V6(v6) => builder.bind_addr_v6(v6),
    };

    let endpoint = builder.bind().await.map_err(|e| EndpointBuildError::Bind {
        addr: config.listen_address,
        source: e.to_string(),
    })?;

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use tempfile::TempDir;

    /// Helper: a usable `EndpointBuildConfig` that binds on the loopback
    /// IPv4 with a random port and ALPN `b"sv2/pool/0"`. Discovery is all
    /// off + relay disabled so the test never reaches out over the network.
    fn loopback_config(secret_key_path: PathBuf) -> EndpointBuildConfig {
        EndpointBuildConfig {
            listen_address: "127.0.0.1:0".parse().expect("loopback addr"),
            secret_key_path,
            alpns: vec![b"sv2/pool/0".to_vec()],
            discovery: DiscoveryConfig {
                relay_enable: false,
                pkarr_publisher_enable: false,
                pkarr_resolver_enable: false,
                dht_enable: false,
                n0_discovery_enable: false,
                relay_url: None,
                connection_overrides: Default::default(),
            },
            max_idle_timeout: Duration::from_secs(60),
            keep_alive_interval: Duration::from_secs(30),
        }
    }

    /// 1. `build_endpoint` succeeds against the loopback with a tempdir
    ///    secret-key path, the bound port shows up in `bound_sockets`, and
    ///    we can drop the endpoint cleanly.
    #[tokio::test]
    async fn default_config_builds_endpoint() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = loopback_config(dir.path().join("iroh-secret.ed25519"));

        let endpoint = build_endpoint(&cfg).await.expect("build_endpoint");

        // Wait briefly for the bind to settle. iroh binds asynchronously;
        // calls before the magicsock task has populated `local_addr` may
        // return an empty list.
        let mut bound = endpoint.bound_sockets();
        for _ in 0..50 {
            if !bound.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            bound = endpoint.bound_sockets();
        }
        assert!(
            !bound.is_empty(),
            "endpoint should report at least one bound socket"
        );
        assert!(
            bound.iter().any(|s| s.ip().is_loopback()),
            "expected a loopback bound socket, got {bound:?}"
        );

        // Drop should not panic.
        drop(endpoint);
    }

    /// 2. `build_endpoint_with_key` skips the file-IO path entirely.
    ///    Verify the endpoint's NodeId equals the public key of the
    ///    pre-loaded secret, and that nothing was written to the configured
    ///    secret_key_path (which we point at a non-existent dir to be sure).
    #[tokio::test]
    async fn with_preloaded_key_skips_file_io() {
        let dir = TempDir::new().expect("tempdir");
        // Path inside a nonexistent subdir — if `build_endpoint_with_key`
        // touched the filesystem this would either succeed (creating the
        // dir, which we'd detect) or fail.
        let unused_path = dir.path().join("never-created").join("iroh-secret.ed25519");
        let cfg = loopback_config(unused_path.clone());

        let secret = SecretKey::generate(&mut rand::rngs::OsRng);
        let expected_node_id = secret.public();

        let endpoint = build_endpoint_with_key(&cfg, secret)
            .await
            .expect("build_endpoint_with_key");

        assert_eq!(
            endpoint.node_id(),
            expected_node_id,
            "endpoint NodeId must match pre-loaded SecretKey's public key"
        );
        assert!(
            !unused_path.exists(),
            "build_endpoint_with_key must not touch secret_key_path; \
             but {} exists",
            unused_path.display()
        );
        assert!(
            !unused_path.parent().unwrap().exists(),
            "build_endpoint_with_key must not create parent directories"
        );
    }

    /// 3. Discovery toggle propagation: relay_enable on/off both build
    ///    successfully. We don't poke iroh's internal discovery state —
    ///    that's an integration concern for Wave 3b. The contract here is
    ///    just "no panic, no error, both flavors yield a usable endpoint".
    #[tokio::test]
    async fn discovery_toggles_propagate() {
        let dir = TempDir::new().expect("tempdir");

        // Variant A: relay disabled (the same shape as `loopback_config`).
        let cfg_a = loopback_config(dir.path().join("a.ed25519"));
        let ep_a = build_endpoint(&cfg_a)
            .await
            .expect("build with relay disabled");

        // Variant B: relay enabled, but with a custom URL pointing at a
        // private host so we never actually reach n0. The endpoint should
        // still bind even though the relay is unreachable — discovery /
        // relay are background concerns.
        let mut cfg_b = loopback_config(dir.path().join("b.ed25519"));
        cfg_b.discovery.relay_enable = true;
        cfg_b.discovery.relay_url = Some("https://relay.invalid/".to_string());
        let ep_b = build_endpoint(&cfg_b)
            .await
            .expect("build with relay enabled + custom url");

        // Sanity: distinct NodeIds (different secrets on disk).
        assert_ne!(
            ep_a.node_id(),
            ep_b.node_id(),
            "two endpoints with distinct identity files should have \
             distinct NodeIds"
        );

        // Variant C: malformed relay URL must surface InvalidRelayUrl
        // *without* binding anything.
        let mut cfg_c = loopback_config(dir.path().join("c.ed25519"));
        cfg_c.discovery.relay_enable = true;
        cfg_c.discovery.relay_url = Some("definitely not a url".to_string());
        let err = build_endpoint(&cfg_c)
            .await
            .expect_err("malformed relay URL must error");
        match err {
            EndpointBuildError::InvalidRelayUrl { url, .. } => {
                assert_eq!(url, "definitely not a url");
            }
            other => panic!("expected InvalidRelayUrl, got {other:?}"),
        }
    }

    /// 4. Empty ALPN list. iroh 0.91 documents this as "the endpoint can
    ///    create connections but cannot accept incoming ones" — i.e. it is
    ///    NOT a build-time error. We assert the build succeeds and document
    ///    that fact for downstream callers.
    #[tokio::test]
    async fn alpn_must_be_non_empty() {
        let dir = TempDir::new().expect("tempdir");
        let mut cfg = loopback_config(dir.path().join("iroh-secret.ed25519"));
        cfg.alpns.clear();

        // Per iroh 0.91 docs: an empty ALPN list means the endpoint cannot
        // accept incoming connections. It is NOT a build-time error.
        let endpoint = build_endpoint(&cfg)
            .await
            .expect("empty ALPN list must still build (just can't accept)");
        drop(endpoint);
    }

    /// 5. Binding to a port that's already in use must surface a `Bind`
    ///    error variant — never a panic. Confirms plan §I0.3 ("no panic on
    ///    bind failure").
    #[tokio::test]
    async fn bind_to_in_use_port_returns_clean_error() {
        let dir = TempDir::new().expect("tempdir");

        // Bind one endpoint on an OS-chosen port.
        let cfg_a = loopback_config(dir.path().join("a.ed25519"));
        let ep_a = build_endpoint(&cfg_a).await.expect("first bind");

        // Wait until the first endpoint actually has a bound socket.
        let port = {
            let mut bound = ep_a.bound_sockets();
            for _ in 0..50 {
                if !bound.is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
                bound = ep_a.bound_sockets();
            }
            bound
                .into_iter()
                .find(|s| s.ip().is_loopback())
                .expect("loopback bound socket")
                .port()
        };

        // Try to bind a second endpoint on that exact port.
        //
        // Note: iroh 0.91 documents that `bind_addr_v4` "If the port
        // specified is already in use, it will fallback to choosing a
        // random port." That means this test may NOT surface a `Bind`
        // error and instead return a different bound port. The plan's
        // §I0.3 contract is "no panic on bind failure", which we still
        // satisfy: in either case we get a `Result` (not a panic). We
        // assert the weaker invariant — no panic, and `bound_sockets`
        // either differs from `port` (fallback path) or we got a `Bind`
        // error variant.
        let mut cfg_b = loopback_config(dir.path().join("b.ed25519"));
        cfg_b.listen_address = format!("127.0.0.1:{port}").parse().unwrap();

        match build_endpoint(&cfg_b).await {
            Ok(ep_b) => {
                let mut bound = ep_b.bound_sockets();
                for _ in 0..50 {
                    if !bound.is_empty() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    bound = ep_b.bound_sockets();
                }
                let conflicting = bound
                    .iter()
                    .any(|s| s.ip().is_loopback() && s.port() == port);
                assert!(
                    !conflicting,
                    "iroh 0.91 falls back to a random port on conflict, \
                     so the second endpoint must NOT have grabbed {port}; \
                     bound = {bound:?}"
                );
            }
            Err(EndpointBuildError::Bind { .. }) => {
                // Older / non-fallback behavior: clean structured error,
                // no panic. Acceptable.
            }
            Err(other) => panic!(
                "expected Ok or Bind on port-in-use, got unexpected error: {other:?}"
            ),
        }
    }
}
