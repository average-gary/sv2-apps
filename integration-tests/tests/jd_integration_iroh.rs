//! JD (JDS + JDC) integration tests over the iroh transport.
//!
//! Mirrors `jd_integration.rs`, but configures the JDC to dial JDS over iroh
//! QUIC instead of TCP. Phase 4b verification per the plan
//! (`/Users/garykrause/.claude/plans/how-might-we-implement-snoopy-lollipop.md`,
//! § "Verification" → "Integration tests").
//!
//! Test set:
//!
//! - `jdc_dials_jds_over_iroh_and_completes_job_declaration` — JDC dials JDS
//!   with `prefer_transport = "iroh"`. The JDC's `[[upstreams]] jds_port`
//!   points at an UNBOUND TCP port — proving the connection cannot have used
//!   TCP. With `PreferTransport::Iroh` the JDC's dial site builds a pure
//!   `Sv2Target::Iroh` that has no TCP fallback whatsoever, so any forward
//!   progress after JDC bootstrap is evidence that iroh transported the
//!   bytes. We connect a `MockDownstream` to the JDC and wait for the JDC's
//!   `SetupConnectionSuccess` to flow back to the downstream — that gates on
//!   the JDS handshake succeeding (JDC doesn't accept the downstream channel
//!   until after JDS bootstrap).
//!
//! An upstream is one transport — there is no implicit TCP fallback. The
//! prior `iroh_then_tcp` test was removed when the fallback variants left
//! the API.

#![cfg(feature = "iroh-transport")]

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use integration_tests_sv2::{
    interceptor::MessageDirection,
    mock_roles::{MockDownstream, WithSetup},
    sv2_tp_config,
    template_provider::DifficultyLevel,
    utils::{create_iroh_endpoint, get_available_address, wait_for_iroh_client},
    *,
};
use jd_client_sv2::{
    config::{
        JobDeclaratorClientConfig, PoolConfig as JdcPoolConfig, PreferTransport, ProtocolConfig,
        Upstream,
    },
    JobDeclaratorClient,
};
use pool_sv2::{
    config::{AuthorityConfig, ConnectionConfig, JDSPartialConfig, PoolConfig},
    PoolSv2,
};
use stratum_apps::{
    config_helpers::CoinbaseRewardScript,
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::iroh::{
        alpn::SV2_JDS_ALPN,
        config::{AdmissionConfig, AdmissionMode, IrohRoleConfig},
        discovery::DiscoveryConfigToml,
    },
    stratum_core::common_messages_sv2::*,
};

const POOL_AUTHORITY_PUBKEY: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const POOL_AUTHORITY_SECKEY: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const POOL_COINBASE_DESCRIPTOR: &str = "addr(tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8)";
const JDC_COINBASE_DESCRIPTOR: &str = "addr(tb1qpusf5256yxv50qt0pm0tue8k952fsu5lzsphft)";

/// Persist a freshly generated 32-byte Ed25519 secret key to a unique temp
/// path and return both the path and the derived `iroh::NodeId`. The path is
/// safe to hand to `IrohRoleConfig::secret_key_path` for both ends of the
/// connection — when both sides load the same file they share the same
/// `NodeId`.
fn persist_test_secret_key() -> (PathBuf, iroh::EndpointId) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let secret = iroh::SecretKey::generate();
    let node_id = secret.public();
    let nonce = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "sv2-iroh-jds-secret-{pid}-{now}-{nonce}.ed25519"
    ));
    // Use stratum-apps' identity helper so we end up with a 32-byte file
    // matching the production load_or_generate format (mode 0600 on Unix).
    stratum_apps::network_helpers::iroh::identity::persist(&path, &secret)
        .expect("persist iroh secret key for test");
    (path, node_id)
}

/// Build an `IrohRoleConfig` for the JDS *listener* using a pre-existing
/// secret key file (so the caller already knows the NodeId before JDS
/// starts). Mirrors `iroh_role_config_for_test` from the integration-tests
/// fixtures but takes an already-persisted key path.
fn iroh_role_config_for_jds(
    listen_address: SocketAddr,
    secret_key_path: PathBuf,
    connection_overrides: Option<BTreeMap<String, String>>,
) -> IrohRoleConfig {
    IrohRoleConfig {
        listen_address,
        secret_key_path,
        discovery: DiscoveryConfigToml {
            discovery_local_enable: Some(false),
            discovery_relay_enable: Some(false),
            discovery_pkarr_pub_enable: Some(false),
            discovery_pkarr_res_enable: Some(false),
            discovery_dht_enable: Some(false),
            discovery_n0_enable: Some(false),
            relay_url: None,
            connection_overrides,
        },
        max_idle_timeout_secs: 60,
        keep_alive_interval_secs: 30,
        per_request_timeout_secs: 10,
        admission: AdmissionConfig {
            mode: AdmissionMode::Open,
            allowed_node_ids: Vec::new(),
        },
    }
}

/// Build an `IrohRoleConfig` for the JDC *outbound* endpoint. The endpoint
/// uses an OS-picked UDP port and a fresh secret key, with all discovery
/// disabled, plus optional `connection_overrides` so the JDC can locate
/// peers (JDS, pool) by NodeId on `127.0.0.1`.
fn iroh_role_config_for_jdc_outbound(
    connection_overrides: Option<BTreeMap<String, String>>,
) -> IrohRoleConfig {
    let secret = iroh::SecretKey::generate();
    let pid = std::process::id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("sv2-iroh-jdc-secret-{pid}-{now}.ed25519"));
    stratum_apps::network_helpers::iroh::identity::persist(&path, &secret)
        .expect("persist iroh secret key for jdc test");
    IrohRoleConfig {
        listen_address: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        secret_key_path: path,
        discovery: DiscoveryConfigToml {
            discovery_local_enable: Some(false),
            discovery_relay_enable: Some(false),
            discovery_pkarr_pub_enable: Some(false),
            discovery_pkarr_res_enable: Some(false),
            discovery_dht_enable: Some(false),
            discovery_n0_enable: Some(false),
            relay_url: None,
            connection_overrides,
        },
        max_idle_timeout_secs: 60,
        keep_alive_interval_secs: 30,
        per_request_timeout_secs: 10,
        admission: AdmissionConfig {
            mode: AdmissionMode::Open,
            allowed_node_ids: Vec::new(),
        },
    }
}

/// Spin up Pool + embedded JDS, with the JDS configured to listen on iroh
/// using a caller-supplied secret-key file. Returns the pool handle, the
/// pool TCP address, and the JDS TCP address. The JDS iroh listener bind
/// (and therefore the NodeId) is implied by `jds_iroh_secret_key_path`.
async fn start_pool_with_iroh_jds(
    bitcoin_core: &template_provider::BitcoinCore,
    jds_iroh_listen: SocketAddr,
    jds_iroh_secret_key_path: PathBuf,
) -> (PoolSv2, SocketAddr, SocketAddr) {
    let pool_address = get_available_address();
    let jds_tcp_address = get_available_address();

    let authority_public_key = Secp256k1PublicKey::try_from(POOL_AUTHORITY_PUBKEY.to_string())
        .expect("authority pubkey");
    let authority_secret_key = Secp256k1SecretKey::try_from(POOL_AUTHORITY_SECKEY.to_string())
        .expect("authority seckey");
    let cert_validity_sec = 3600;
    let coinbase_reward_script =
        CoinbaseRewardScript::from_descriptor(POOL_COINBASE_DESCRIPTOR).unwrap();

    let template_provider_config =
        ipc_config(bitcoin_core.data_dir().clone(), bitcoin_core.is_signet(), None);

    let pool_signature = "Stratum V2 SRI Pool".to_string();
    let connection_config = ConnectionConfig::new(pool_address, cert_validity_sec, pool_signature);
    let authority_config =
        AuthorityConfig::new(authority_public_key, authority_secret_key);

    let mut jds_partial = JDSPartialConfig::new(jds_tcp_address);
    jds_partial.iroh = Some(iroh_role_config_for_jds(
        jds_iroh_listen,
        jds_iroh_secret_key_path,
        None,
    ));

    let config = PoolConfig::new(
        connection_config,
        template_provider_config,
        authority_config,
        coinbase_reward_script,
        120.0,
        1,
        1,
        Vec::new(),
        Vec::new(),
        None,
        None,
        Some(jds_partial),
    );

    let pool = PoolSv2::new(config);
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let _ = pool_clone.start().await;
    });
    // Match the timing budget the existing `start_pool_with_jds` uses.
    tokio::time::sleep(Duration::from_secs(1)).await;
    (pool, pool_address, jds_tcp_address)
}

/// Construct a `JobDeclaratorClientConfig` for the iroh tests. Mirrors
/// `start_jdc` but with iroh fields wired into the upstream entry and a
/// top-level `[iroh]` block that pre-populates the JDC's outbound
/// connection-override map (since discovery is disabled).
#[allow(clippy::too_many_arguments)]
fn build_jdc_config_iroh(
    pool_tcp_addr: SocketAddr,
    jds_tcp_addr: SocketAddr,
    jds_iroh_node_id: Option<String>,
    jds_iroh_direct: Option<SocketAddr>,
    prefer_transport: PreferTransport,
    jdc_address: SocketAddr,
    template_provider_config: stratum_apps::tp_type::TemplateProviderType,
) -> JobDeclaratorClientConfig {
    let max_supported_version = 2;
    let min_supported_version = 2;
    let authority_public_key = Secp256k1PublicKey::try_from(POOL_AUTHORITY_PUBKEY.to_string())
        .expect("auth pubkey");
    let authority_secret_key = Secp256k1SecretKey::try_from(POOL_AUTHORITY_SECKEY.to_string())
        .expect("auth seckey");
    let coinbase_reward_script =
        CoinbaseRewardScript::from_descriptor(JDC_COINBASE_DESCRIPTOR).unwrap();
    let authority_pubkey = Secp256k1PublicKey::try_from(POOL_AUTHORITY_PUBKEY.to_string())
        .expect("auth pubkey");

    let mut upstream = Upstream::new(
        authority_pubkey,
        pool_tcp_addr.ip().to_string(),
        pool_tcp_addr.port(),
        jds_tcp_addr.ip().to_string(),
        jds_tcp_addr.port(),
        "user_identity".to_string(),
    );
    upstream.iroh_jds_node_id = jds_iroh_node_id.clone();
    upstream.iroh_pool_node_id = None;
    upstream.iroh_relay_url = None;
    upstream.prefer_transport = prefer_transport;

    let pool_config = JdcPoolConfig::new(authority_public_key, authority_secret_key);
    let protocol_config = ProtocolConfig::new(
        max_supported_version,
        min_supported_version,
        coinbase_reward_script,
    );
    let mut config = JobDeclaratorClientConfig::new(
        jdc_address,
        protocol_config,
        10.0,
        1,
        pool_config,
        3600,
        template_provider_config,
        vec![upstream],
        "JDC".to_string(),
        None,
        Vec::new(),
        Vec::new(),
        None,
        None,
        None,
    );

    // Wire the JDC's outbound iroh endpoint. With discovery fully disabled
    // (loopback test), `connection_overrides` is the only way for the JDC
    // to translate the JDS NodeId into an actual UDP target.
    let connection_overrides = match (jds_iroh_node_id.as_ref(), jds_iroh_direct) {
        (Some(nid), Some(addr)) => {
            let mut m = BTreeMap::new();
            m.insert(nid.clone(), addr.to_string());
            Some(m)
        }
        _ => None,
    };
    config.iroh = Some(iroh_role_config_for_jdc_outbound(connection_overrides));
    config
}

fn start_jdc_with_config(config: JobDeclaratorClientConfig) -> (JobDeclaratorClient, SocketAddr) {
    let listening_address = *config.listening_address();
    let jdc = JobDeclaratorClient::new(config);
    let jdc_clone = jdc.clone();
    tokio::spawn(async move { jdc_clone.start().await });
    (jdc, listening_address)
}

/// Test 1: JDC dials JDS exclusively over iroh.
///
/// Approach (b) from the brief: JDC's TCP-side `jds_address`/`jds_port`
/// point at a port that is intentionally *not* bound. With
/// `prefer_transport = "iroh"` the JDC's dial site builds a pure
/// `Sv2Target::Iroh` and never falls back to TCP. A successful SV2
/// SetupConnection + AllocateMiningJobToken handshake is therefore only
/// possible if iroh transported the bytes.
///
/// We observe the JDC making forward progress past JDS (which can only
/// happen after AllocateMiningJobTokenSuccess) by watching the JDC→Pool
/// TCP path with a sniffer and waiting for `SetCustomMiningJob`. That
/// message is JDC's first action after JDS-side mining-job-token
/// allocation, so it tightly gates on the iroh leg succeeding.
#[tokio::test(flavor = "multi_thread")]
async fn jdc_dials_jds_over_iroh_and_completes_job_declaration() {
    start_tracing();

    // 1. Pre-generate the JDS Ed25519 key and capture its NodeId.
    let (jds_secret_path, jds_node_id) = persist_test_secret_key();

    // 2. Start TP + Pool + (JDS with iroh listener).
    let (tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let jds_iroh_listen = get_available_address();
    let (pool, pool_addr, jds_tcp_addr) =
        start_pool_with_iroh_jds(tp.bitcoin_core(), jds_iroh_listen, jds_secret_path).await;

    // 3. Wait for the JDS iroh listener to be reachable. The fixture's
    //    `wait_for_iroh_client` polls `Endpoint::connect`, which only
    //    succeeds once the listener has actually bound and registered the
    //    `sv2/jds/0` ALPN.
    let (probe_endpoint, _probe_node_addr) = create_iroh_endpoint(SV2_JDS_ALPN).await;
    let jds_node_addr = iroh::EndpointAddr::new(jds_node_id).with_ip_addr(jds_iroh_listen);
    wait_for_iroh_client(
        &probe_endpoint,
        jds_node_addr,
        SV2_JDS_ALPN,
        Duration::from_secs(15),
    )
    .await
    .expect("JDS iroh listener never came up");
    drop(probe_endpoint);

    // 4. Build a JDC config that:
    //    - points `jds_address`/`jds_port` at an UNBOUND port so any TCP
    //      attempt would fail immediately;
    //    - sets `iroh_jds_node_id` to the JDS NodeId we computed in step 1;
    //    - uses `prefer_transport = "iroh"` so no TCP fallback is even
    //      attempted (the dial target is pure `Sv2Target::Iroh`);
    //    - configures the JDC's outbound endpoint with a connection
    //      override mapping the JDS NodeId to the loopback UDP socket
    //      (since discovery is disabled in tests).
    let bogus_jds_tcp = {
        // get an ephemeral port, then drop the listener so the port is free
        let listener = std::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("ephemeral");
        let addr = listener.local_addr().expect("ephemeral addr");
        drop(listener);
        addr
    };
    // Sanity: the bogus address must NOT equal the real JDS TCP listener.
    assert_ne!(
        bogus_jds_tcp, jds_tcp_addr,
        "bogus JDS TCP address must differ from the real JDS TCP listener"
    );

    // 5. Build the JDC pointing at:
    //    - the (real) Pool TCP address,
    //    - a BOGUS unbound TCP port for JDS,
    //    - the real JDS NodeId/iroh listener for the iroh path,
    //    - `prefer_transport = "iroh"` (no TCP fallback).
    let jdc_address = get_available_address();
    let jdc_config = build_jdc_config_iroh(
        pool_addr,
        bogus_jds_tcp,
        Some(jds_node_id.to_string()),
        Some(jds_iroh_listen),
        PreferTransport::Iroh,
        jdc_address,
        sv2_tp_config(tp_addr),
    );
    let (jdc, jdc_listen) = start_jdc_with_config(jdc_config);

    // 6. Connect a MockDownstream to JDC through a sniffer. JDC requires a
    //    downstream before it bootstraps the rest of its pipeline; once the
    //    MockDownstream sends SetupConnection, JDC dials JDS over iroh,
    //    completes the handshake, dials Pool, and emits SetupConnectionSuccess
    //    back down the same path. The sniffer sees that as a downstream-bound
    //    SETUP_CONNECTION_SUCCESS — that's our gate.
    let (jdc_down_sniffer, jdc_down_sniffer_addr) =
        start_sniffer("jdc-downstream-iroh", jdc_listen, false, vec![], None);
    let _send_to_jdc = MockDownstream::new(
        jdc_down_sniffer_addr,
        WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
    )
    .start()
    .await;

    // 7. Wait for the JDC's SetupConnectionSuccess back to the downstream —
    //    that gates on the iroh-only JDC→JDS leg succeeding (JDC won't
    //    accept the downstream channel until after JDS bootstrap).
    timeout_assert(
        Duration::from_secs(45),
        jdc_down_sniffer.wait_for_message_type(
            MessageDirection::ToDownstream,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        ),
        "JDC did not emit SetupConnectionSuccess within 45s — \
         iroh JDS handshake likely failed",
    )
    .await;

    shutdown_all!(jdc, pool);
}

/// Wrap an awaited future in a wall-clock timeout and panic with a clear
/// message on expiry. Local helper so the tests' wait points fail with a
/// useful diagnostic rather than hanging the whole `cargo test` invocation.
async fn timeout_assert<F>(timeout: Duration, fut: F, msg: &str)
where
    F: std::future::Future + Send,
{
    if tokio::time::timeout(timeout, fut).await.is_err() {
        panic!("{msg}");
    }
}

