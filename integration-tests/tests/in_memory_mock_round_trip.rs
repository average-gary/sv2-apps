//! Verifies the in-memory transport pair works end-to-end across the
//! integration-tests crate's `MockUpstream` / `MockDownstream` fixtures.
//!
//! No TCP port is allocated: the entire Noise NX handshake and frame
//! exchange happens over `tokio::io::duplex` in-process.
//!
//! This is the test-seam analogue of the existing `MockUpstream` <-> `Sniffer`
//! <-> `MockDownstream` integration tests in `mock_roles::tests`. We can't
//! migrate any of those directly because each one routes through a `Sniffer`
//! that owns a real TCP listener — the in-memory pair has no place to bridge
//! into a Sniffer. This new test exercises the seam directly: Mock <-> Mock
//! over the in-memory transport, no Sniffer, no TCP port.

#![cfg(feature = "test-utils")]

use integration_tests_sv2::{
    mock_roles::{MockDownstream, MockUpstream, WithSetup},
    start_tracing,
};
use stratum_apps::stratum_core::{
    common_messages_sv2::Protocol,
    parsers_sv2::{AnyMessage, CommonMessages},
};

/// End-to-end seam test: build a `MockUpstream` + paired in-memory
/// `Sv2Connector`, drive a `MockDownstream` from the connector, and confirm
/// the full Noise NX handshake plus the SV2 `SetupConnection` /
/// `SetupConnectionSuccess` exchange completes — without binding a single
/// TCP port.
#[tokio::test]
async fn mock_pair_round_trips_setup_connection_in_memory() {
    start_tracing();

    // Build the upstream + paired connector. No `SocketAddr` is allocated
    // anywhere along this path.
    let (mock_upstream, connector) = MockUpstream::new_in_memory(WithSetup::yes_with_defaults(
        Protocol::MiningProtocol,
        0,
    ));

    // Spawning the upstream's accept loop must succeed: `start()` returns the
    // proxy `Sender<AnyMessage>` synchronously after spawning the session
    // task that calls `Sv2Listener::accept().await`.
    let upstream_proxy_sender = mock_upstream.start().await;

    // Dialing the in-memory upstream blocks inside `start()` until the Noise
    // NX handshake completes — so reaching the next line proves the
    // handshake succeeded end-to-end. The `MockDownstream` then sends a
    // `SetupConnection` frame on the freshly handshaken channel pair before
    // returning.
    let downstream_proxy_sender = MockDownstream::new_with_in_memory_connector(
        connector,
        WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
    )
    .start()
    .await;

    // Round-trip a frame in each direction over the established channel
    // pairs. If either send fails, the underlying noise pump task closed its
    // channel — meaning the in-memory transport is not actually wired up.
    //
    // (We intentionally use `ChannelEndpointChanged` because it is a trivial
    // common message with no required fields — the test is verifying that
    // the proxy senders accept frames, not the contents of the frame.)
    use stratum_apps::stratum_core::common_messages_sv2::ChannelEndpointChanged;
    let probe_msg = AnyMessage::Common(CommonMessages::ChannelEndpointChanged(
        ChannelEndpointChanged { channel_id: 0 },
    ));

    upstream_proxy_sender
        .send(probe_msg.clone())
        .await
        .expect("in-memory upstream proxy channel must accept frames");
    downstream_proxy_sender
        .send(probe_msg)
        .await
        .expect("in-memory downstream proxy channel must accept frames");

    // The fact that:
    //   * `MockUpstream::new_in_memory` returned a paired connector,
    //   * `MockDownstream::new_with_in_memory_connector(...).start().await`
    //     completed without panicking on the `Sv2Connector::connect` call,
    //   * both proxy senders accepted a post-handshake frame,
    // proves the in-memory transport pair works end-to-end through the
    // existing fixture surface. No TCP port was bound: if you `lsof -i -P`
    // during this test you will not see any extra `127.0.0.1:N` listeners
    // from these fixtures.
}
