use crate::utils::{create_downstream, create_upstream, message_from_frame, wait_for_client};
use async_channel::{Receiver, Sender};
use std::{convert::TryInto, net::SocketAddr, time::Duration};
#[cfg(feature = "test-utils")]
use stratum_apps::network_helpers::{
    transport::{Sv2Connector, Sv2Listener, Sv2Target},
    transport_test_utils::{in_memory_sv2_pair, InMemorySv2Connector, InMemorySv2Listener},
};
use stratum_apps::{
    stratum_core::{
        codec_sv2::StandardEitherFrame,
        common_messages_sv2::{
            Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
            ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL, MESSAGE_TYPE_SETUP_CONNECTION,
        },
        parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message},
    },
    utils::types::Sv2Frame,
};
#[cfg(feature = "test-utils")]
use stratum_apps::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
use tokio::net::TcpStream;
use tracing::info;

use crate::types::MessageFrame;

pub enum WithSetup {
    Yes(SetupConnection<'static>),
    No,
}

impl WithSetup {
    pub fn yes_with_defaults(protocol: Protocol, flags: u32) -> Self {
        WithSetup::Yes(SetupConnection {
            protocol,
            min_version: 2,
            max_version: 2,
            flags,
            endpoint_host: b"0.0.0.0".to_vec().try_into().unwrap(),
            endpoint_port: 0,
            vendor: b"integration-test".to_vec().try_into().unwrap(),
            hardware_version: b"".to_vec().try_into().unwrap(),
            firmware: b"".to_vec().try_into().unwrap(),
            device_id: b"".to_vec().try_into().unwrap(),
        })
    }

    pub fn yes(setup_connection: SetupConnection<'static>) -> Self {
        WithSetup::Yes(setup_connection)
    }

    pub fn no() -> Self {
        WithSetup::No
    }
}

/// Authority pubkey used by the in-memory transport variants to match the
/// fixture defaults in `integration-tests/lib/utils.rs`.
#[cfg(feature = "test-utils")]
const TEST_AUTH_PUB: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
/// Authority secret key paired with [`TEST_AUTH_PUB`].
#[cfg(feature = "test-utils")]
const TEST_AUTH_PRIV: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

/// Internal: how a [`MockDownstream`] reaches its upstream.
enum MockDownstreamTransport {
    /// Connect over TCP to `upstream_address`. This is the historic path
    /// used by every existing fixture.
    Tcp { upstream_address: SocketAddr },
    /// Connect over an in-memory pair produced by
    /// [`MockUpstream::new_in_memory`]. No TCP port is bound.
    #[cfg(feature = "test-utils")]
    InMemory {
        connector: InMemorySv2Connector<AnyMessage<'static>>,
    },
}

/// Internal: how a [`MockUpstream`] receives connections.
enum MockUpstreamTransport {
    /// Bind a TCP listener on `listening_address`, accept exactly one
    /// connection, run the Noise NX handshake as responder.
    Tcp { listening_address: SocketAddr },
    /// Accept exactly one connection over an in-memory pair produced by
    /// [`MockUpstream::new_in_memory`]. No TCP port is bound.
    #[cfg(feature = "test-utils")]
    InMemory {
        listener: InMemorySv2Listener<AnyMessage<'static>>,
    },
}

pub struct MockDownstream {
    transport: MockDownstreamTransport,
    setup: WithSetup,
}

impl MockDownstream {
    pub fn new(upstream_address: SocketAddr, setup: WithSetup) -> Self {
        Self {
            transport: MockDownstreamTransport::Tcp { upstream_address },
            setup,
        }
    }

    /// Build a `MockDownstream` driven by an [`InMemorySv2Connector`] produced
    /// by [`MockUpstream::new_in_memory`]. No TCP port is allocated; the full
    /// Noise NX handshake runs in-process over `tokio::io::duplex`.
    #[cfg(feature = "test-utils")]
    pub fn new_with_in_memory_connector(
        connector: InMemorySv2Connector<AnyMessage<'static>>,
        setup: WithSetup,
    ) -> Self {
        Self {
            transport: MockDownstreamTransport::InMemory { connector },
            setup,
        }
    }

    pub async fn start(self) -> Sender<AnyMessage<'static>> {
        let (proxy_sender, proxy_receiver) = async_channel::unbounded::<AnyMessage<'static>>();

        let (upstream_receiver, upstream_sender) = match self.transport {
            MockDownstreamTransport::Tcp { upstream_address } => create_upstream(loop {
                match TcpStream::connect(upstream_address).await {
                    Ok(stream) => break stream,
                    Err(_) => {
                        tracing::warn!(
                            "MockDownstream: unable to connect to upstream, retrying after 1 second"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            })
            .await
            .expect("Failed to create upstream"),
            #[cfg(feature = "test-utils")]
            MockDownstreamTransport::InMemory { connector } => {
                // The in-memory connector ignores `addr` and falls back to
                // its pair-time `auth_pub` when `authority_pubkey` is `None`,
                // so a dummy target is sufficient.
                let target = Sv2Target::Tcp {
                    addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                    authority_pubkey: None,
                };
                <InMemorySv2Connector<AnyMessage<'static>> as Sv2Connector<AnyMessage<'static>>>::connect(
                    &connector, &target,
                )
                .await
                .expect("Failed to dial in-memory upstream")
            }
        };

        if let WithSetup::Yes(setup_connection) = self.setup {
            let protocol = setup_connection.protocol;
            let flags = setup_connection.flags;
            let msg = AnyMessage::Common(CommonMessages::SetupConnection(setup_connection));
            let message_type = msg.message_type();
            let frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                Sv2Frame::from_message(msg, message_type, 0, false)
                    .expect("Failed to create SetupConnection frame"),
            );
            upstream_sender
                .send(frame)
                .await
                .expect("Failed to send SetupConnection");
            info!(
                "MockDownstream: sent SetupConnection with protocol {:?} and flags {}",
                protocol, flags
            );
        }

        spawn_downstream_pump(upstream_receiver, upstream_sender, proxy_receiver);

        proxy_sender
    }
}

/// Post-handshake pump for `MockDownstream`: log everything received from the
/// upstream and forward outbound `AnyMessage`s from `proxy_receiver` to the
/// upstream as Sv2 frames. Shared by the TCP and in-memory paths.
fn spawn_downstream_pump(
    upstream_receiver: Receiver<MessageFrame>,
    upstream_sender: Sender<MessageFrame>,
    proxy_receiver: Receiver<AnyMessage<'static>>,
) {
    tokio::spawn(async move {
        while let Ok(mut frame) = upstream_receiver.recv().await {
            let (msg_type, msg) = message_from_frame(&mut frame);
            info!(
                "MockDownstream: received message from upstream: {} {}",
                msg_type, msg
            );
        }
    });

    tokio::spawn(async move {
        while let Ok(message) = proxy_receiver.recv().await {
            let message_type = message.message_type();
            let frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                Sv2Frame::from_message(message, message_type, 0, false)
                    .expect("Failed to create frame from message"),
            );
            if upstream_sender.send(frame).await.is_err() {
                break;
            }
        }
    });
}

pub struct MockUpstream {
    transport: MockUpstreamTransport,
    setup: WithSetup,
    disconnect_after_setup: Option<Duration>,
}

impl MockUpstream {
    pub fn new(listening_address: SocketAddr, setup: WithSetup) -> Self {
        Self {
            transport: MockUpstreamTransport::Tcp { listening_address },
            setup,
            disconnect_after_setup: None,
        }
    }

    /// Build a `MockUpstream` connected via an in-memory transport pair.
    /// Returns the upstream itself plus the matching [`InMemorySv2Connector`]
    /// the caller hands to [`MockDownstream::new_with_in_memory_connector`].
    ///
    /// Eliminates TCP-port allocation in tests — the full Noise NX handshake
    /// runs in-process over `tokio::io::duplex`.
    #[cfg(feature = "test-utils")]
    pub fn new_in_memory(setup: WithSetup) -> (Self, InMemorySv2Connector<AnyMessage<'static>>) {
        let auth_pub = TEST_AUTH_PUB
            .parse::<Secp256k1PublicKey>()
            .expect("hardcoded test pubkey");
        let auth_priv = TEST_AUTH_PRIV
            .parse::<Secp256k1SecretKey>()
            .expect("hardcoded test privkey");
        let (connector, listener) =
            in_memory_sv2_pair::<AnyMessage<'static>>(auth_pub, auth_priv, 10_000);
        let upstream = Self {
            transport: MockUpstreamTransport::InMemory { listener },
            setup,
            disconnect_after_setup: None,
        };
        (upstream, connector)
    }

    pub fn disconnect_after_setup_connection_success(mut self, delay: Duration) -> Self {
        self.disconnect_after_setup = Some(delay);
        self
    }

    pub async fn start(self) -> Sender<AnyMessage<'static>> {
        let (proxy_sender, proxy_receiver) = async_channel::unbounded::<AnyMessage<'static>>();

        let setup = self.setup;
        let disconnect_after_setup = self.disconnect_after_setup;

        match self.transport {
            MockUpstreamTransport::Tcp { listening_address } => {
                tokio::spawn(async move {
                    let (downstream_receiver, downstream_sender) =
                        create_downstream(wait_for_client(listening_address).await)
                            .await
                            .expect("Failed to connect to downstream");
                    run_upstream_session(
                        downstream_receiver,
                        downstream_sender,
                        proxy_receiver,
                        setup,
                        disconnect_after_setup,
                    )
                    .await;
                });
            }
            #[cfg(feature = "test-utils")]
            MockUpstreamTransport::InMemory { listener } => {
                tokio::spawn(async move {
                    let (_peer, (downstream_receiver, downstream_sender)) =
                        <InMemorySv2Listener<AnyMessage<'static>> as Sv2Listener<
                            AnyMessage<'static>,
                        >>::accept(&listener)
                        .await
                        .expect("Failed to accept in-memory downstream");
                    run_upstream_session(
                        downstream_receiver,
                        downstream_sender,
                        proxy_receiver,
                        setup,
                        disconnect_after_setup,
                    )
                    .await;
                });
            }
        }

        proxy_sender
    }
}

/// Post-handshake state machine for `MockUpstream`: optionally validate the
/// `SetupConnection` from the downstream, then pump frames in both directions.
/// Shared by the TCP and in-memory paths.
async fn run_upstream_session(
    downstream_receiver: Receiver<MessageFrame>,
    downstream_sender: Sender<MessageFrame>,
    proxy_receiver: Receiver<AnyMessage<'static>>,
    setup: WithSetup,
    disconnect_after_setup: Option<Duration>,
) {
    if let WithSetup::Yes(expected_setup) = setup {
        let expected_protocol = expected_setup.protocol;
        let flags = expected_setup.flags;

        let mut frame = downstream_receiver
            .recv()
            .await
            .expect("Failed to receive first message from downstream");
        let (msg_type, msg) = message_from_frame(&mut frame);
        info!(
            "MockUpstream: received message from downstream: {} {}",
            msg_type, msg
        );

        if msg_type == MESSAGE_TYPE_SETUP_CONNECTION {
            if let AnyMessage::Common(CommonMessages::SetupConnection(setup_msg)) = &msg {
                if setup_msg.protocol == expected_protocol {
                    let success =
                        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(
                            SetupConnectionSuccess {
                                used_version: 2,
                                flags,
                            },
                        ));
                    let success_type = success.message_type();
                    let response_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(success, success_type, 0, false)
                            .expect("Failed to create SetupConnectionSuccess frame"),
                    );
                    downstream_sender
                        .send(response_frame)
                        .await
                        .expect("Failed to send SetupConnectionSuccess");
                    info!(
                        "MockUpstream: sent SetupConnectionSuccess with flags {}",
                        flags
                    );

                    if let Some(delay) = disconnect_after_setup {
                        tokio::time::sleep(delay).await;
                        downstream_sender.close();
                        downstream_receiver.close();
                        return;
                    }
                } else {
                    let error = AnyMessage::Common(CommonMessages::SetupConnectionError(
                        SetupConnectionError {
                            flags: 0,
                            error_code: ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL
                                .to_string()
                                .into_bytes()
                                .try_into()
                                .unwrap(),
                        },
                    ));
                    let error_type = error.message_type();
                    let response_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(error, error_type, 0, false)
                            .expect("Failed to create SetupConnectionError frame"),
                    );
                    downstream_sender
                        .send(response_frame)
                        .await
                        .expect("Failed to send SetupConnectionError");
                    info!(
                        "MockUpstream: sent SetupConnectionError for wrong protocol {:?}, expected {:?}",
                        setup_msg.protocol, expected_protocol
                    );
                }
            }
        } else {
            panic!(
                "MockUpstream: first message must be SetupConnection, got {}",
                msg_type
            );
        }
    }

    tokio::spawn(async move {
        while let Ok(mut frame) = downstream_receiver.recv().await {
            let (msg_type, msg) = message_from_frame(&mut frame);
            info!(
                "MockUpstream: received message from downstream: {} {}",
                msg_type, msg
            );
        }
    });

    while let Ok(message) = proxy_receiver.recv().await {
        let message_type = message.message_type();
        let frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
            Sv2Frame::from_message(message, message_type, 0, false)
                .expect("Failed to create frame from message"),
        );
        if downstream_sender.send(frame).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{interceptor::MessageDirection, start_sniffer};
    use std::net::TcpListener;
    use stratum_apps::stratum_core::{
        common_messages_sv2::{
            MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        },
        mining_sv2::MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
    };

    #[tokio::test]
    async fn test_implicit_setup_connection() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let upstream_socket_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let _mock_upstream = MockUpstream::new(
            upstream_socket_addr,
            WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
        )
        .start()
        .await;

        let (sniffer, sniffer_addr) = start_sniffer(
            "implicit_setup_test",
            upstream_socket_addr,
            false,
            vec![],
            None,
        );

        let _send_to_upstream = MockDownstream::new(
            sniffer_addr,
            WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
        )
        .start()
        .await;

        sniffer
            .wait_for_message_type(MessageDirection::ToUpstream, MESSAGE_TYPE_SETUP_CONNECTION)
            .await;

        sniffer
            .wait_for_message_type(
                MessageDirection::ToDownstream,
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            )
            .await;
    }

    #[tokio::test]
    async fn test_assert_message_not_present() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let upstream_socket_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let _mock_upstream = MockUpstream::new(
            upstream_socket_addr,
            WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
        )
        .start()
        .await;

        let (sniffer, sniffer_addr) = start_sniffer(
            "assert_not_present_test",
            upstream_socket_addr,
            false,
            vec![],
            None,
        );

        let _send_to_upstream = MockDownstream::new(
            sniffer_addr,
            WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
        )
        .start()
        .await;

        sniffer
            .wait_for_message_type(MessageDirection::ToUpstream, MESSAGE_TYPE_SETUP_CONNECTION)
            .await;

        // SetupConnection was sent, so has_message_type should find it
        assert!(
            sniffer.has_message_type(MessageDirection::ToUpstream, MESSAGE_TYPE_SETUP_CONNECTION)
        );

        // OpenExtendedMiningChannel was never sent, so assert_message_not_present should return
        // true
        assert!(
            sniffer
                .assert_message_not_present(
                    MessageDirection::ToUpstream,
                    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL,
                    std::time::Duration::from_secs(1),
                )
                .await
        );

        // SetupConnection IS present, so assert_message_not_present should return false
        assert!(
            !sniffer
                .assert_message_not_present(
                    MessageDirection::ToUpstream,
                    MESSAGE_TYPE_SETUP_CONNECTION,
                    std::time::Duration::from_millis(200),
                )
                .await
        );
    }

    #[tokio::test]
    async fn test_setup_connection_wrong_protocol() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let upstream_socket_addr = SocketAddr::from(([127, 0, 0, 1], port));

        let _mock_upstream = MockUpstream::new(
            upstream_socket_addr,
            WithSetup::yes_with_defaults(Protocol::MiningProtocol, 0),
        )
        .start()
        .await;

        let (sniffer, sniffer_addr) = start_sniffer(
            "wrong_protocol_test",
            upstream_socket_addr,
            false,
            vec![],
            None,
        );

        let _send_to_upstream = MockDownstream::new(
            sniffer_addr,
            WithSetup::yes_with_defaults(Protocol::TemplateDistributionProtocol, 0),
        )
        .start()
        .await;

        sniffer
            .wait_for_message_type(MessageDirection::ToUpstream, MESSAGE_TYPE_SETUP_CONNECTION)
            .await;

        sniffer
            .wait_for_message_type(
                MessageDirection::ToDownstream,
                MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
            )
            .await;
    }
}
