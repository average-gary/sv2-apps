// Iroh-transport integration tests for `PoolSv2`.
//
// Mirrors `pool_integration.rs` but routes the pool's downstream listener
// over iroh (in addition to the always-on TCP listener). Each test:
//
//   1. Pre-generates a 32-byte Ed25519 secret key file so the test knows the
//      pool's iroh `NodeId` ahead of time (the pool reads the same file at
//      startup; matching keys ⇒ matching NodeId). This avoids parsing pool
//      logs for the NodeId.
//   2. Picks a fixed UDP port via `get_available_address()` (same helper the
//      TCP listener uses) so the pool's iroh listener binds somewhere known
//      and the test can construct a `NodeAddr { node_id, direct_addrs:
//      [127.0.0.1:<port>] }` to dial.
//   3. Builds a `PoolConfig` with `iroh = Some(iroh_role_config_for_test(...))`
//      and starts the pool the same way `start_pool` does in `lib/mod.rs`.
//   4. Probes readiness with `wait_for_iroh_client` before any peer connects
//      (the pool's iroh listener binds asynchronously; we don't want to race
//      the dial against the `Endpoint::bind` future).
//   5. Drives the SV2 protocol over iroh and asserts on the post-handshake
//      flow.
//
// The whole file is gated on `--features iroh-transport` so the iroh symbols
// it imports compile only when the feature is on.

#![cfg(feature = "iroh-transport")]

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use integration_tests_sv2::{
    mining_device,
    prometheus_metrics_assertions::{poll_until_metric_gte, Metric},
    start_tracing,
    template_provider::DifficultyLevel,
    utils::{
        create_iroh_endpoint, get_available_address, iroh_role_config_for_test,
        wait_for_iroh_client, AdmissionTestConfig,
    },
};
use iroh::{NodeAddr, SecretKey};
use pool_sv2::{
    config::{AuthorityConfig, ConnectionConfig, PoolConfig},
    PoolSv2,
};
use rand::rngs::OsRng;
use stratum_apps::{
    config_helpers::CoinbaseRewardScript,
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::{
        iroh::{alpn::SV2_POOL_ALPN, connector::IrohSv2Connector},
        transport::{Sv2Connector, Sv2Target},
    },
    stratum_core::parsers_sv2::{AnyMessage, IsSv2Message as _},
    tp_type::TemplateProviderType,
};

// ---------------------------------------------------------------------------
// Pool authority keypair / coinbase descriptor copied from `lib/mod.rs`.
// Inlined here because the helpers in `lib/mod.rs` build their own
// `PoolConfig` and don't expose a way to inject the `iroh` block.
// ---------------------------------------------------------------------------
const POOL_AUTH_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
const POOL_AUTH_PRIV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";
const POOL_COINBASE_DESCRIPTOR: &str = "addr(tb1qa0sm0hxzj0x25rh8gw5xlzwlsfvvyz8u96w3p8)";
const SHARES_PER_MINUTE: f32 = 120.0;

// Generous CPU-mining timeout. `mining_device::connect_via_iroh` runs the
// real fast-hasher loop; with handicap=1 + low-difficulty regtest the first
// share usually arrives within a couple seconds, but slow CI hosts need
// headroom. Stays well under the 30s budget the task brief calls out.
const SHARE_POLL_TIMEOUT: Duration = Duration::from_secs(20);

// How long to wait for the pool's iroh listener to be reachable. The
// `bind_endpoint` call inside the pool is async and the listener is spawned
// as a tokio task, so even after `tokio::spawn(pool.start())` returns the
// listener may still be booting.
const LISTENER_READY_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Ensure each test gets a unique secret-key file even if `tempfile` isn't a
// direct dep here. We stash files under `std::env::temp_dir()` keyed by a
// process-unique counter so concurrent test runs don't collide.
// ---------------------------------------------------------------------------
static SECRET_KEY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Pre-generate a fresh Ed25519 iroh secret key, write it to a uniquely-named
/// file under the OS temp dir, and return `(NodeAddr { node_id, [bound_addr] },
/// secret_key_path)`. The pool will load the same file at startup (because we
/// pass `secret_key_path` into its `[iroh]` config), so the resulting
/// `NodeId` is identical and the test can dial it deterministically.
///
/// The file is written with mode `0600` on Unix (so Fedimint-flavored
/// secret-key handling stays consistent with what `identity::persist_inner`
/// does in production).
fn pregenerate_pool_iroh_identity(bound_addr: SocketAddr) -> (NodeAddr, PathBuf) {
    let secret = SecretKey::generate(OsRng);
    let node_id = secret.public();

    // Unique-per-test file path. PID + atomic counter + nanos → no overlap
    // even across parallel cargo-test invocations.
    let unique = format!(
        "sv2-pool-iroh-it-{}-{}-{}.ed25519",
        std::process::id(),
        SECRET_KEY_COUNTER.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let path = std::env::temp_dir().join(unique);
    std::fs::write(&path, secret.to_bytes()).expect("write iroh secret key file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 iroh secret key file");
    }

    let node_addr = NodeAddr::from_parts(node_id, None, std::iter::once(bound_addr));
    (node_addr, path)
}

/// Internal helper: build a [`PoolConfig`] mirroring `lib/mod.rs::start_pool`,
/// then splice an `iroh = Some(...)` block onto it.
///
/// `enable_monitoring=true` so tests can poll `sv2_client_shares_accepted_total`
/// for proof a share crossed the iroh transport.
async fn start_pool_with_iroh(
    template_provider_config: TemplateProviderType,
    iroh_listen_address: SocketAddr,
    iroh_secret_key_path: PathBuf,
    admission: AdmissionTestConfig,
    enable_monitoring: bool,
) -> (PoolSv2, SocketAddr, Option<SocketAddr>) {
    let tcp_listening_address = get_available_address();
    let authority_public_key: Secp256k1PublicKey = POOL_AUTH_PUB.parse().expect("auth pub");
    let authority_secret_key: Secp256k1SecretKey = POOL_AUTH_PRIV.parse().expect("auth priv");
    let cert_validity_sec = 3600;
    let coinbase_reward_script =
        CoinbaseRewardScript::from_descriptor(POOL_COINBASE_DESCRIPTOR).expect("coinbase descriptor");
    let pool_signature = "Stratum V2 SRI Pool".to_string();
    let connection_config =
        ConnectionConfig::new(tcp_listening_address, cert_validity_sec, pool_signature);
    let authority_config = AuthorityConfig::new(authority_public_key, authority_secret_key);
    let monitoring_address = if enable_monitoring {
        Some(get_available_address())
    } else {
        None
    };
    let monitoring_cache_refresh_secs = if enable_monitoring { Some(1) } else { None };

    let mut config = PoolConfig::new(
        connection_config,
        template_provider_config,
        authority_config,
        coinbase_reward_script,
        SHARES_PER_MINUTE,
        1, // share_batch_size
        1, // server_id
        Vec::new(),
        Vec::new(),
        monitoring_address,
        monitoring_cache_refresh_secs,
        None, // no JDS
    );

    // Splice the iroh block in. `iroh` is a `pub` field on `PoolConfig` —
    // see `pool-apps/pool/src/lib/config.rs`. The `iroh-transport` cargo
    // feature is enabled at the top of this file, so the field is visible.
    let iroh_cfg = iroh_role_config_for_test(
        iroh_listen_address.port(),
        &iroh_secret_key_path,
        admission,
    );
    config.iroh = Some(iroh_cfg);

    let pool = PoolSv2::new(config);
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        let _ = pool_clone.start().await;
    });
    // Mirrors `lib/mod.rs::start_pool`: a small fixed delay so subsequent
    // `wait_for_iroh_client` doesn't immediately race the spawn.
    tokio::time::sleep(Duration::from_secs(1)).await;

    (pool, tcp_listening_address, monitoring_address)
}

// =========================================================================
// Test 1: pool_listens_on_iroh_and_accepts_mining_device
// Happy path: pool with `[iroh]` block accepts an iroh-dialing mining device,
// the device opens a standard channel, mines, and at least one share is
// accepted server-side.
// =========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn pool_listens_on_iroh_and_accepts_mining_device() {
    use integration_tests_sv2::start_template_provider;

    start_tracing();
    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);

    // Pick the iroh listener's UDP port up front so we can build a NodeAddr
    // without scraping pool logs. `get_available_address` returns a
    // 127.0.0.1 SocketAddr; the pool will bind iroh on the same.
    let iroh_listen_addr = get_available_address();
    let (pool_node_addr, secret_key_path) = pregenerate_pool_iroh_identity(iroh_listen_addr);

    let (pool, _tcp_addr, monitoring_addr) = start_pool_with_iroh(
        integration_tests_sv2::sv2_tp_config(tp_addr),
        iroh_listen_addr,
        secret_key_path.clone(),
        AdmissionTestConfig::Open,
        true, // enable monitoring so we can poll for share acceptance
    )
    .await;
    let monitoring_addr = monitoring_addr.expect("monitoring should be enabled");

    // Build a probe endpoint and wait until the pool's iroh listener is
    // reachable at the QUIC layer. This is critical: the dial-task spawned
    // by `connect_via_iroh` would otherwise race the listener bind.
    let (probe_endpoint, _probe_addr) = create_iroh_endpoint(SV2_POOL_ALPN).await;
    wait_for_iroh_client(
        &probe_endpoint,
        pool_node_addr.clone(),
        SV2_POOL_ALPN,
        LISTENER_READY_TIMEOUT,
    )
    .await
    .expect("pool's iroh listener should become reachable");
    drop(probe_endpoint);

    // Spin up the mining device on a fresh client iroh endpoint. Use the
    // pool's SV2 authority pubkey so the Noise initiator verifies the pool.
    let (client_endpoint, _client_addr) = create_iroh_endpoint(SV2_POOL_ALPN).await;
    let auth_pub: Secp256k1PublicKey = POOL_AUTH_PUB.parse().expect("auth pub");
    let pool_node_addr_clone = pool_node_addr.clone();
    tokio::spawn(async move {
        mining_device::connect_via_iroh(
            client_endpoint,
            pool_node_addr_clone,
            Some(auth_pub),
            None,
            Some("test-iroh-miner".to_string()),
            1,    // handicap
            None, // nominal hashrate multiplier
            true, // single_submit
        )
        .await;
    });

    // Assert at least one share was accepted by the pool. The metric label
    // shape mirrors the `pool_monitoring_with_sv2_mining_device` test in
    // `monitoring_integration.rs`: client_id=1 (first downstream),
    // channel_id=2 (group_channel_id=1 is reserved internally), user_identity
    // matches the value we passed to `connect_via_iroh`.
    let _metrics = poll_until_metric_gte(
        monitoring_addr,
        Metric::with_labels(
            "sv2_client_shares_accepted_total",
            &[
                ("client_id", "1"),
                ("channel_id", "2"),
                ("user_identity", "test-iroh-miner"),
            ],
        ),
        1.0,
        SHARE_POLL_TIMEOUT,
    )
    .await;

    pool.shutdown().await;
    let _ = std::fs::remove_file(&secret_key_path);
}

// =========================================================================
// Test 2: pool_iroh_whitelist_rejects_unknown_node_id
// Pool admission whitelists ONE NodeId; a mining device with a DIFFERENT
// NodeId tries to dial. The connect must fail.
// =========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn pool_iroh_whitelist_rejects_unknown_node_id() {
    use integration_tests_sv2::start_template_provider;

    start_tracing();
    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);

    let iroh_listen_addr = get_available_address();
    let (pool_node_addr, secret_key_path) = pregenerate_pool_iroh_identity(iroh_listen_addr);

    // The "allowed" NodeId is one we generate but never use as a dialer —
    // the actual dialer's NodeId (built by `create_iroh_endpoint`) will not
    // be in the whitelist.
    let allowed_node_id = SecretKey::generate(OsRng).public();

    let (pool, _tcp_addr, _) = start_pool_with_iroh(
        integration_tests_sv2::sv2_tp_config(tp_addr),
        iroh_listen_addr,
        secret_key_path.clone(),
        AdmissionTestConfig::Whitelist(vec![allowed_node_id]),
        false,
    )
    .await;

    // Build a fresh client endpoint — its NodeId is NOT in the pool's
    // whitelist. Use `IrohSv2Connector` directly (rather than
    // `mining_device::connect_via_iroh`) so a denied dial surfaces as `Err`
    // instead of panicking inside the device's `.expect(...)`.
    let (client_endpoint, _client_addr) = create_iroh_endpoint(SV2_POOL_ALPN).await;

    // Wait briefly for the pool's iroh listener to come up. We don't
    // require this to succeed — even if the listener isn't ready yet, the
    // dial below is expected to fail. But probing first avoids a misleading
    // "connection refused" before the listener exists.
    let probe_endpoint = {
        let (ep, _) = create_iroh_endpoint(SV2_POOL_ALPN).await;
        ep
    };
    // Probe with a second endpoint — admission applies to that endpoint's
    // NodeId too, but since we used Whitelist mode the probe will also
    // fail. So we use a short timeout and ignore the result; the goal is
    // just to give the listener time to bind.
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        wait_for_iroh_client(
            &probe_endpoint,
            pool_node_addr.clone(),
            SV2_POOL_ALPN,
            Duration::from_millis(500),
        ),
    )
    .await;
    drop(probe_endpoint);

    let auth_pub: Secp256k1PublicKey = POOL_AUTH_PUB.parse().expect("auth pub");
    let connector = IrohSv2Connector::new(
        client_endpoint,
        std::collections::BTreeMap::new(),
        SV2_POOL_ALPN,
        Duration::from_secs(5),
    );
    let target = Sv2Target::Iroh {
        node_addr: pool_node_addr,
        authority_pubkey: Some(auth_pub),
    };

    let result = <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
        &connector, &target,
    )
    .await;
    assert!(
        result.is_err(),
        "Pool with iroh whitelist should reject a non-whitelisted NodeId; got Ok"
    );

    pool.shutdown().await;
    let _ = std::fs::remove_file(&secret_key_path);
}

// =========================================================================
// Test 3: pool_dual_transport_accepts_both
// `[iroh]` block AND TCP listener both serve. One mining device connects via
// TCP, another via iroh. Both submit shares; both succeed.
// =========================================================================
#[tokio::test(flavor = "multi_thread")]
async fn pool_dual_transport_accepts_both() {
    use integration_tests_sv2::{start_mining_device_sv2, start_template_provider};

    start_tracing();
    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);

    let iroh_listen_addr = get_available_address();
    let (pool_node_addr, secret_key_path) = pregenerate_pool_iroh_identity(iroh_listen_addr);

    let (pool, tcp_addr, monitoring_addr) = start_pool_with_iroh(
        integration_tests_sv2::sv2_tp_config(tp_addr),
        iroh_listen_addr,
        secret_key_path.clone(),
        AdmissionTestConfig::Open,
        true,
    )
    .await;
    let monitoring_addr = monitoring_addr.expect("monitoring should be enabled");

    // Make sure the iroh listener is reachable before either dialer fires
    // off — otherwise the iroh-side mining device may race the bind.
    let (probe_endpoint, _) = create_iroh_endpoint(SV2_POOL_ALPN).await;
    wait_for_iroh_client(
        &probe_endpoint,
        pool_node_addr.clone(),
        SV2_POOL_ALPN,
        LISTENER_READY_TIMEOUT,
    )
    .await
    .expect("pool's iroh listener should become reachable");
    drop(probe_endpoint);

    // -- TCP dialer --
    // Tagged with `tcp-miner` user_identity so we can distinguish its share
    // metric from the iroh dialer's.
    start_mining_device_sv2(
        SocketAddr::from((Ipv4Addr::LOCALHOST, tcp_addr.port())),
        None,
        None,
        Some("tcp-miner".to_string()),
        1,
        None,
        true,
    );

    // -- iroh dialer --
    let (client_endpoint, _) = create_iroh_endpoint(SV2_POOL_ALPN).await;
    let auth_pub: Secp256k1PublicKey = POOL_AUTH_PUB.parse().expect("auth pub");
    let pool_node_addr_clone = pool_node_addr.clone();
    tokio::spawn(async move {
        mining_device::connect_via_iroh(
            client_endpoint,
            pool_node_addr_clone,
            Some(auth_pub),
            None,
            Some("iroh-miner".to_string()),
            1,
            None,
            true,
        )
        .await;
    });

    // Assert BOTH dialers landed shares. Channel IDs differ between the two
    // downstreams; we don't assert on them — only on the user_identity
    // labels that we control. The pool's metric labels include
    // `user_identity`, so a >=1 hit on EACH user_identity proves both
    // transports actually reached the pool's accept loop.
    //
    // Run the polls concurrently so a slow miner on one transport doesn't
    // make the test wait sequentially.
    let tcp_share_metric = Metric::with_labels(
        "sv2_client_shares_accepted_total",
        &[("user_identity", "tcp-miner")],
    );
    let iroh_share_metric = Metric::with_labels(
        "sv2_client_shares_accepted_total",
        &[("user_identity", "iroh-miner")],
    );

    let (_tcp_metrics, _iroh_metrics) = tokio::join!(
        poll_until_metric_gte(monitoring_addr, tcp_share_metric, 1.0, SHARE_POLL_TIMEOUT),
        poll_until_metric_gte(monitoring_addr, iroh_share_metric, 1.0, SHARE_POLL_TIMEOUT),
    );

    pool.shutdown().await;
    let _ = std::fs::remove_file(&secret_key_path);
}

// Compile-time sanity: keep `AnyMessage` import live even if a future
// refactor removes the only use site (the whitelist test's
// `Sv2Connector::<AnyMessage<'static>>` type annotation).
#[allow(dead_code)]
fn _any_message_type_check(m: AnyMessage<'static>) -> u8 {
    m.message_type()
}
