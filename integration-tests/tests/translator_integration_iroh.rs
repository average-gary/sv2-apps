//! Integration tests for the SV2 translator with iroh transport on the
//! upstream-to-pool leg.
//!
//! These tests mirror the happy paths in `translator_integration.rs` but
//! reroute the translator's outbound dial to the pool over iroh QUIC instead
//! of plain TCP. The SV1 downstream miner side stays unchanged — that side is
//! plain TCP+JSON, not Noise (see plan §"Phase 4c — Translator dial site").
//!
//! Test 1 (`translator_dials_pool_over_iroh_with_sv1_downstream_unchanged`):
//!     Happy path. Pool listens on iroh. Translator's upstream entry points
//!     at an unbound TCP port for the TCP leg, so the translator can only
//!     reach the pool via iroh. An SV1 minerd connects to the translator,
//!     receives a job, and submits a share — proving the iroh-routed
//!     SetupConnection / OpenExtendedMiningChannel / NewExtendedMiningJob /
//!     SubmitSharesExtended flow end-to-end.
//!
//! Test 2 (`translator_iroh_with_whitelist_admission`):
//!     Pool admission policy is set to whitelist mode. First half of the
//!     test: whitelist contains the translator's EndpointId — translator
//!     connects. Second half: the pool is restarted with a whitelist that
//!     does NOT contain the translator's EndpointId — the translator's iroh
//!     dial fails (connection cannot complete, no SV1 mining.notify ever
//!     arrives at the SV1 sniffer in front of the translator).

#![cfg(feature = "iroh-transport")]

use integration_tests_sv2::{
    interceptor::MessageDirection,
    template_provider::DifficultyLevel,
    utils::{
        get_available_address, iroh_role_config_for_test, wait_for_iroh_client,
        AdmissionTestConfig,
    },
    *,
};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use pool_sv2::config::PoolConfig;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use stratum_apps::{
    config_helpers::CoinbaseRewardScript,
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::{
        iroh::{alpn::SV2_POOL_ALPN, IrohRoleConfig},
        transport::PreferTransport,
    },
};
use translator_sv2::{
    config::{DownstreamDifficultyConfig, TranslatorConfig, Upstream as TranslatorUpstream},
    TranslatorSv2,
};

// ---------------------------------------------------------------------------
// Local helpers (test-only)
// ---------------------------------------------------------------------------

const POOL_AUTHORITY_PUBKEY: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const POOL_AUTHORITY_SECKEY: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const POOL_COINBASE_REWARD_DESCRIPTOR: &str = "addr(tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8)";
const SHARES_PER_MINUTE: f32 = 120.0;

/// Counter for unique temp-file paths within a single process run. The test
/// suite intentionally does not depend on the `tempfile` crate (it is not in
/// `integration-tests`'s direct dependency list); a process-id-plus-counter
/// path under `std::env::temp_dir()` is sufficient for the test's lifetime.
static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn unique_secret_key_path(label: &str) -> PathBuf {
    let n = UNIQUE.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let mut p = std::env::temp_dir();
    p.push(format!("sv2-iroh-test-{label}-{pid}-{n}.ed25519"));
    p
}

/// Persist a freshly-generated 32-byte iroh Ed25519 secret to `path` (Unix
/// mode 0600) and return both the `SecretKey` (for deriving EndpointId) and the
/// path. Mirrors what `iroh::network_helpers::iroh::identity::load_or_generate`
/// would write at runtime, but lets the test know the EndpointId BEFORE the role
/// boots — required because the translator's `[[upstreams]]` entry must
/// carry the pool's EndpointId at config-build time.
fn generate_and_persist_secret_key(path: &Path) -> SecretKey {
    let secret = SecretKey::generate();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).expect("create parent dir for iroh secret key");
        }
    }
    std::fs::write(path, secret.to_bytes()).expect("write iroh secret key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set 0600 on iroh secret key file");
    }
    secret
}

/// Returns a local TCP socket address whose port is free at the moment but
/// is NOT actually bound by anything — calling `connect` on it is reasonably
/// expected to fail. Used to wire the translator's TCP leg of an upstream to
/// a definitely-unreachable address so iroh is the only viable transport.
///
/// Note: the OS may reassign this port to another process after the
/// `TcpListener` here is dropped. For the test's purposes this is fine: even
/// if something happens to grab the port, that "something" will not speak
/// SV2 Noise NX, so a TCP fallback would still fail the handshake.
fn unbound_tcp_address() -> SocketAddr {
    // `get_available_address` uses a HashSet-backed allocator that prevents
    // returning the same port twice in one process — so this address is
    // distinct from any pool's real TCP listener.
    get_available_address()
}

/// Build a `PoolConfig` with the iroh listener configured. The TCP listener
/// also binds; both transports are accepted by the pool. We rely on the
/// translator's upstream entry choosing iroh (via `prefer_transport = Iroh`)
/// to actually exercise the iroh path.
async fn start_pool_with_iroh(
    template_provider_config: stratum_apps::tp_type::TemplateProviderType,
    iroh_cfg: IrohRoleConfig,
) -> (pool_sv2::PoolSv2, SocketAddr) {
    let listening_address = get_available_address();
    let authority_public_key =
        Secp256k1PublicKey::try_from(POOL_AUTHORITY_PUBKEY.to_string()).unwrap();
    let authority_secret_key =
        Secp256k1SecretKey::try_from(POOL_AUTHORITY_SECKEY.to_string()).unwrap();
    let cert_validity_sec = 3600;
    let coinbase_reward_script =
        CoinbaseRewardScript::from_descriptor(POOL_COINBASE_REWARD_DESCRIPTOR).unwrap();
    let pool_signature = "Stratum V2 SRI Pool".to_string();
    let connection_config = pool_sv2::config::ConnectionConfig::new(
        listening_address,
        cert_validity_sec,
        pool_signature,
    );
    let authority_config =
        pool_sv2::config::AuthorityConfig::new(authority_public_key, authority_secret_key);

    let mut config = PoolConfig::new(
        connection_config,
        template_provider_config,
        authority_config,
        coinbase_reward_script,
        SHARES_PER_MINUTE,
        1,
        1,
        Vec::new(),
        Vec::new(),
        None,
        None,
        None,
    );
    // PoolConfig.iroh is `pub` — set it directly. No `set_iroh` accessor exists.
    config.iroh = Some(iroh_cfg);

    let pool = pool_sv2::PoolSv2::new(config);
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let _ = pool_clone.start().await;
    });
    // The pool's iroh listener readiness is verified externally by the caller
    // via `wait_for_iroh_client`; the small sleep here just lets the task
    // get scheduled.
    tokio::time::sleep(Duration::from_millis(100)).await;
    (pool, listening_address)
}

/// Build a translator with explicit iroh dial-time configuration on the
/// upstream entry. `tcp_address` is the host part of the upstream's TCP leg
/// — set to an unbound port to force the translator onto iroh.
///
/// `connection_overrides` populates the translator's iroh
/// `connection_overrides` map. Because the test fixture disables every
/// discovery mechanism (relay, pkarr, DHT, n0), the only way the translator's
/// iroh connector can find the pool's listener is via an explicit override
/// keyed by the pool's EndpointId. Populate this with `(pool_node_id, pool iroh
/// listen socket)` for the happy-path tests; leave empty when you want a dial
/// to fail (no addressing information available).
async fn start_translator_iroh(
    upstream_tcp_address: SocketAddr,
    pool_node_id: EndpointId,
    mut translator_iroh_cfg: IrohRoleConfig,
    prefer_transport: PreferTransport,
    connection_overrides: BTreeMap<EndpointId, SocketAddr>,
) -> (TranslatorSv2, SocketAddr) {
    // Stamp connection_overrides into the iroh config's discovery section.
    // Mirrors the role-config TOML's `[iroh.connection_overrides]` table
    // (see plan §"Per-role `[iroh]` section (TOML)").
    if !connection_overrides.is_empty() {
        let map: BTreeMap<String, String> = connection_overrides
            .into_iter()
            .map(|(id, addr)| (id.to_string(), addr.to_string()))
            .collect();
        translator_iroh_cfg.discovery.connection_overrides = Some(map);
    }

    let listening_address = get_available_address();
    let listening_port = listening_address.port();

    let upstream_authority_pubkey =
        Secp256k1PublicKey::try_from(POOL_AUTHORITY_PUBKEY.to_string()).unwrap();

    let mut upstream = TranslatorUpstream::new(
        upstream_tcp_address.ip().to_string(),
        upstream_tcp_address.port(),
        upstream_authority_pubkey,
        "user_identity".to_string(),
    );
    upstream.iroh_node_id = Some(pool_node_id.to_string());
    upstream.iroh_relay_url = None;
    upstream.prefer_transport = prefer_transport;

    // Measure miner hashrate so the translator's vardiff math has a sane
    // starting point. Mirrors `start_sv2_translator_with_user_identity`.
    let minerd =
        sv1_minerd::MinerdProcess::new(SocketAddr::from(([127, 0, 0, 1], 0)), false)
            .await
            .expect("spawn hashrate-measurement minerd");
    let min_individual_miner_hashrate = minerd.measure_hashrate().await.unwrap() as f32;

    let downstream_difficulty_config =
        DownstreamDifficultyConfig::new(min_individual_miner_hashrate, SHARES_PER_MINUTE, true, 60);

    let mut config = TranslatorConfig::new(
        vec![upstream],
        listening_address.ip().to_string(),
        listening_port,
        downstream_difficulty_config,
        2,
        2,
        4,
        false,
        false, // aggregate_channels
        Vec::new(),
        Vec::new(),
        None,
        None,
    );
    config.iroh = Some(translator_iroh_cfg);

    let translator = TranslatorSv2::new(config);
    let clone = translator.clone();
    tokio::spawn(async move {
        clone.start().await;
    });
    (translator, listening_address)
}

/// Probe the pool's iroh listener until a client can dial it. Builds a
/// throwaway `iroh::Endpoint` for the probe and tears it down before
/// returning.
async fn wait_for_pool_iroh(pool_node_id: EndpointId, pool_iroh_addr: SocketAddr) {
    let (probe_endpoint, _probe_addr) = utils::create_iroh_endpoint(SV2_POOL_ALPN).await;
    let pool_node_addr = EndpointAddr::new(pool_node_id)
        .with_ip_addr(SocketAddr::from(([127, 0, 0, 1], pool_iroh_addr.port())));
    wait_for_iroh_client(
        &probe_endpoint,
        pool_node_addr,
        SV2_POOL_ALPN,
        Duration::from_secs(15),
    )
    .await
    .expect("pool iroh listener never became reachable");
    // Drop the probe endpoint so it's not racing with the real translator.
    drop(probe_endpoint);
}

// ---------------------------------------------------------------------------
// Test 1 — Happy path: translator dials pool over iroh, SV1 leg unchanged.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn translator_dials_pool_over_iroh_with_sv1_downstream_unchanged() {
    start_tracing();

    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);

    // ---- Pool iroh secret key + EndpointId (pre-known so translator can dial it).
    let pool_secret_path = unique_secret_key_path("pool-happy");
    let pool_secret = generate_and_persist_secret_key(&pool_secret_path);
    let pool_node_id = pool_secret.public();

    // ---- Pool [iroh] block: bind on a known free UDP port; admission Open.
    let pool_iroh_listen = get_available_address();
    let pool_iroh_cfg = iroh_role_config_for_test(
        pool_iroh_listen.port(),
        &pool_secret_path,
        AdmissionTestConfig::Open,
    );
    let (pool, pool_tcp_addr) =
        start_pool_with_iroh(sv2_tp_config(tp_addr), pool_iroh_cfg).await;

    // Wait until the pool's iroh listener accepts connections.
    wait_for_pool_iroh(pool_node_id, pool_iroh_listen).await;

    // ---- Translator [iroh] block: bind on a free UDP port; admission Open.
    let translator_secret_path = unique_secret_key_path("translator-happy");
    let _ = generate_and_persist_secret_key(&translator_secret_path);
    let translator_iroh_cfg = iroh_role_config_for_test(
        get_available_address().port(),
        &translator_secret_path,
        AdmissionTestConfig::Open,
    );

    // The TCP leg of the upstream entry points at an unbound port. With
    // `prefer_transport = Iroh`, the translator goes directly over iroh and
    // never tries TCP. (We also assert separately via `prefer_transport=Iroh`
    // — there is no implicit fallback to TCP here.)
    let unbound = unbound_tcp_address();

    // Seed the translator's iroh connector with the pool's EndpointId → loopback
    // socket. With every discovery mechanism off, this override is the only
    // way the connector can resolve the pool's EndpointId to a dialable address.
    let mut overrides = BTreeMap::new();
    overrides.insert(pool_node_id, pool_iroh_listen);

    let (translator, tproxy_addr) = start_translator_iroh(
        unbound,
        pool_node_id,
        translator_iroh_cfg,
        PreferTransport::Iroh,
        overrides,
    )
    .await;

    // Put an SV1 sniffer between the SV1 minerd and the translator so we can
    // confirm the SV1 leg works end-to-end (mining.notify down, mining.submit
    // up).
    let (sv1_sniffer, sv1_sniffer_addr) = start_sv1_sniffer(tproxy_addr);
    let (_minerd_process, _minerd_addr) =
        start_minerd(sv1_sniffer_addr, None, None, false).await;

    // mining.notify proves: the translator handshook with the pool over iroh,
    // got a SetupConnectionSuccess, opened an extended channel, received a
    // NewExtendedMiningJob, and translated it into SV1 for the miner.
    sv1_sniffer
        .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
        .await;

    // mining.submit proves the miner is actually mining off the iroh-routed
    // job — and by extension, the share is being forwarded back to the pool
    // over iroh as a SubmitSharesExtended.
    sv1_sniffer
        .wait_for_message(&["mining.submit"], MessageDirection::ToUpstream)
        .await;

    // The SV1 OkResponse from the pool's SubmitSharesSuccess proves the share
    // was accepted by the pool — round-tripped through iroh.
    sv1_sniffer
        .wait_for_message(&["result"], MessageDirection::ToDownstream)
        .await;

    let _ = pool_tcp_addr; // keep clippy happy — kept for symmetry with start_pool.
    shutdown_all!(translator, pool);
    let _ = std::fs::remove_file(&pool_secret_path);
    let _ = std::fs::remove_file(&translator_secret_path);
}

// ---------------------------------------------------------------------------
// Test 2 — Whitelist admission: allow / deny by EndpointId.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn translator_iroh_with_whitelist_admission() {
    start_tracing();

    // ---- Sub-test A: pool whitelist contains translator EndpointId — connect succeeds.
    {
        let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);

        let pool_secret_path = unique_secret_key_path("pool-wl-allow");
        let pool_secret = generate_and_persist_secret_key(&pool_secret_path);
        let pool_node_id = pool_secret.public();

        let translator_secret_path = unique_secret_key_path("translator-wl-allow");
        let translator_secret = generate_and_persist_secret_key(&translator_secret_path);
        let translator_node_id = translator_secret.public();

        let pool_iroh_listen = get_available_address();
        let pool_iroh_cfg = iroh_role_config_for_test(
            pool_iroh_listen.port(),
            &pool_secret_path,
            AdmissionTestConfig::Whitelist(vec![translator_node_id]),
        );
        let (pool, _pool_tcp_addr) =
            start_pool_with_iroh(sv2_tp_config(tp_addr), pool_iroh_cfg).await;
        wait_for_pool_iroh(pool_node_id, pool_iroh_listen).await;

        let translator_iroh_cfg = iroh_role_config_for_test(
            get_available_address().port(),
            &translator_secret_path,
            AdmissionTestConfig::Open,
        );
        let unbound = unbound_tcp_address();
        let mut overrides = BTreeMap::new();
        overrides.insert(pool_node_id, pool_iroh_listen);
        let (translator, tproxy_addr) = start_translator_iroh(
            unbound,
            pool_node_id,
            translator_iroh_cfg,
            PreferTransport::Iroh,
            overrides,
        )
        .await;

        let (sv1_sniffer, sv1_sniffer_addr) = start_sv1_sniffer(tproxy_addr);
        let (_minerd_process, _minerd_addr) =
            start_minerd(sv1_sniffer_addr, None, None, false).await;

        // Whitelist allows this translator — happy-path message must arrive.
        sv1_sniffer
            .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
            .await;

        shutdown_all!(translator, pool);
        let _ = std::fs::remove_file(&pool_secret_path);
        let _ = std::fs::remove_file(&translator_secret_path);
    }

    // ---- Sub-test B: pool whitelist does NOT contain translator EndpointId —
    // connect fails. Assert no SV1 mining.notify arrives within a generous
    // timeout (short enough to keep the whole test under 60s).
    {
        let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);

        let pool_secret_path = unique_secret_key_path("pool-wl-deny");
        let pool_secret = generate_and_persist_secret_key(&pool_secret_path);
        let pool_node_id = pool_secret.public();

        let translator_secret_path = unique_secret_key_path("translator-wl-deny");
        let _ = generate_and_persist_secret_key(&translator_secret_path);
        // Whitelist a stranger EndpointId that is NOT the translator's.
        let stranger = SecretKey::generate().public();

        let pool_iroh_listen = get_available_address();
        let pool_iroh_cfg = iroh_role_config_for_test(
            pool_iroh_listen.port(),
            &pool_secret_path,
            AdmissionTestConfig::Whitelist(vec![stranger]),
        );
        let (pool, _pool_tcp_addr) =
            start_pool_with_iroh(sv2_tp_config(tp_addr), pool_iroh_cfg).await;
        wait_for_pool_iroh(pool_node_id, pool_iroh_listen).await;

        let translator_iroh_cfg = iroh_role_config_for_test(
            get_available_address().port(),
            &translator_secret_path,
            AdmissionTestConfig::Open,
        );
        let unbound = unbound_tcp_address();
        // Provide the override so the translator CAN reach the pool's
        // listener at the QUIC layer — this is the only way the whitelist's
        // admission denial is what stops the connection (and not a missing
        // address). Without the override, this sub-test would trivially
        // pass because the dial would never start.
        let mut overrides = BTreeMap::new();
        overrides.insert(pool_node_id, pool_iroh_listen);
        let (translator, tproxy_addr) = start_translator_iroh(
            unbound,
            pool_node_id,
            translator_iroh_cfg,
            PreferTransport::Iroh,
            overrides,
        )
        .await;

        let (sv1_sniffer, sv1_sniffer_addr) = start_sv1_sniffer(tproxy_addr);
        let (_minerd_process, _minerd_addr) =
            start_minerd(sv1_sniffer_addr, None, None, false).await;

        // Wait briefly to give the translator's iroh dial time to fail
        // and (because TCP is the unbound address) for the upstream init
        // attempt to give up. With the whitelist denying admission, no SV1
        // job ever reaches the miner.
        let timeout = Duration::from_secs(8);
        let probe = async {
            sv1_sniffer
                .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
                .await;
        };
        let res = tokio::time::timeout(timeout, probe).await;
        assert!(
            res.is_err(),
            "translator should not have received mining.notify when pool whitelist denies its EndpointId"
        );

        shutdown_all!(translator, pool);
        let _ = std::fs::remove_file(&pool_secret_path);
        let _ = std::fs::remove_file(&translator_secret_path);
    }
}
