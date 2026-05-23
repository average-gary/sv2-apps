use crate::utils::{create_downstream, create_upstream, message_from_frame, wait_for_client};
use async_channel::Sender;
use std::{convert::TryInto, net::SocketAddr, time::Duration};
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
use tokio::net::TcpStream;
use tracing::info;

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

pub struct MockDownstream {
    upstream_address: SocketAddr,
    setup: WithSetup,
}

impl MockDownstream {
    pub fn new(upstream_address: SocketAddr, setup: WithSetup) -> Self {
        Self {
            upstream_address,
            setup,
        }
    }

    pub async fn start(self) -> Sender<AnyMessage<'static>> {
        let upstream_address = self.upstream_address;

        let (proxy_sender, proxy_receiver) = async_channel::unbounded::<AnyMessage<'static>>();

        let (upstream_receiver, upstream_sender) = create_upstream(loop {
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
        .expect("Failed to create upstream");

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

        proxy_sender
    }
}

pub struct MockUpstream {
    listening_address: SocketAddr,
    setup: WithSetup,
    disconnect_after_setup: Option<Duration>,
}

impl MockUpstream {
    pub fn new(listening_address: SocketAddr, setup: WithSetup) -> Self {
        Self {
            listening_address,
            setup,
            disconnect_after_setup: None,
        }
    }

    pub fn disconnect_after_setup_connection_success(mut self, delay: Duration) -> Self {
        self.disconnect_after_setup = Some(delay);
        self
    }

    pub async fn start(self) -> Sender<AnyMessage<'static>> {
        let listening_address = self.listening_address;

        let (proxy_sender, proxy_receiver) = async_channel::unbounded::<AnyMessage<'static>>();

        tokio::spawn(async move {
            let (downstream_receiver, downstream_sender) =
                create_downstream(wait_for_client(listening_address).await)
                    .await
                    .expect("Failed to connect to downstream");

            if let WithSetup::Yes(expected_setup) = self.setup {
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
                            let success = AnyMessage::Common(
                                CommonMessages::SetupConnectionSuccess(SetupConnectionSuccess {
                                    used_version: 2,
                                    flags,
                                }),
                            );
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

                            if let Some(delay) = self.disconnect_after_setup {
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
                    panic!("MockUpstream: first message must be SetupConnection, got {msg_type}");
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
        });

        proxy_sender
    }
}

// =====================================================================
//  Iroh-transport mocks (gated on `iroh-transport` feature)
// =====================================================================
//
// These mirror `MockUpstream` / `MockDownstream` above but operate over the
// iroh transport instead of TCP. Both produce the same `Sender<AnyMessage>`
// shape so the per-role iroh integration tests can swap them in without
// touching the assertion code.

#[cfg(feature = "iroh-transport")]
pub use iroh_mocks::*;

#[cfg(feature = "iroh-transport")]
mod iroh_mocks {
    use super::*;
    use stratum_apps::{
        key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
        network_helpers::{
            iroh::{
                admission::AdmissionHandle, alpn::SV2_POOL_ALPN,
                connector::IrohSv2Connector, listener::IrohSv2Listener,
            },
            transport::{Sv2Connector, Sv2Listener, Sv2Target},
        },
    };

    /// Iroh-transport peer for a downstream role.
    ///
    /// Spins up an `IrohSv2Listener` on the supplied endpoint, accepts one
    /// inbound connection, optionally validates the first SV2 message as a
    /// `SetupConnection` (mirroring [`MockUpstream`]), and returns a
    /// `Sender<AnyMessage<'static>>` that the test uses to push messages back
    /// to the downstream.
    ///
    /// `auth_pub` / `auth_priv` / `cert_validity` flow into the SV2 Noise NX
    /// responder.
    pub struct MockIrohUpstream {
        endpoint: ::iroh::Endpoint,
        auth_pub: Secp256k1PublicKey,
        auth_priv: Secp256k1SecretKey,
        cert_validity: u64,
        setup: WithSetup,
    }

    impl MockIrohUpstream {
        /// Construct a new mock iroh upstream. The caller has already built
        /// (and is keeping alive) the iroh `Endpoint` — use
        /// [`crate::utils::create_iroh_endpoint`] to build one bound to
        /// `127.0.0.1:0` with discovery disabled.
        pub fn new(
            endpoint: ::iroh::Endpoint,
            auth_pub: Secp256k1PublicKey,
            auth_priv: Secp256k1SecretKey,
            cert_validity: u64,
            setup: WithSetup,
        ) -> Self {
            Self {
                endpoint,
                auth_pub,
                auth_priv,
                cert_validity,
                setup,
            }
        }

        /// Start the listener and return the `Sender<AnyMessage>` the test
        /// uses to push messages downstream. Mirrors
        /// [`MockUpstream::start`]'s shape so the assertion code is shared.
        pub async fn start(self) -> Sender<AnyMessage<'static>> {
            let (proxy_sender, proxy_receiver) = async_channel::unbounded::<AnyMessage<'static>>();

            let listener = IrohSv2Listener::new(
                self.endpoint,
                AdmissionHandle::open(),
                self.auth_pub,
                self.auth_priv,
                self.cert_validity,
                SV2_POOL_ALPN,
                Duration::from_secs(10),
            );

            tokio::spawn(async move {
                let (_peer, (downstream_receiver, downstream_sender)) =
                    <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(&listener)
                        .await
                        .expect("MockIrohUpstream: iroh listener accept failed");

                if let WithSetup::Yes(expected_setup) = self.setup {
                    let expected_protocol = expected_setup.protocol;
                    let flags = expected_setup.flags;

                    let mut frame = downstream_receiver
                        .recv()
                        .await
                        .expect("MockIrohUpstream: receive first message failed");
                    let (msg_type, msg) = message_from_frame(&mut frame);
                    info!(
                        "MockIrohUpstream: received message from downstream: {} {}",
                        msg_type, msg
                    );

                    if msg_type == MESSAGE_TYPE_SETUP_CONNECTION {
                        if let AnyMessage::Common(CommonMessages::SetupConnection(setup_msg)) = &msg
                        {
                            if setup_msg.protocol == expected_protocol {
                                let success = AnyMessage::Common(
                                    CommonMessages::SetupConnectionSuccess(
                                        SetupConnectionSuccess {
                                            used_version: 2,
                                            flags,
                                        },
                                    ),
                                );
                                let success_type = success.message_type();
                                let response_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                                    Sv2Frame::from_message(success, success_type, 0, false)
                                        .expect("create SetupConnectionSuccess frame"),
                                );
                                downstream_sender
                                    .send(response_frame)
                                    .await
                                    .expect("send SetupConnectionSuccess");
                                info!(
                                    "MockIrohUpstream: sent SetupConnectionSuccess (flags {})",
                                    flags
                                );
                            } else {
                                let error = AnyMessage::Common(
                                    CommonMessages::SetupConnectionError(SetupConnectionError {
                                        flags: 0,
                                        error_code:
                                            ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL
                                                .to_string()
                                                .into_bytes()
                                                .try_into()
                                                .unwrap(),
                                    }),
                                );
                                let error_type = error.message_type();
                                let response_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                                    Sv2Frame::from_message(error, error_type, 0, false)
                                        .expect("create SetupConnectionError frame"),
                                );
                                downstream_sender
                                    .send(response_frame)
                                    .await
                                    .expect("send SetupConnectionError");
                                info!(
                                    "MockIrohUpstream: sent SetupConnectionError; \
                                     wrong protocol {:?}, expected {:?}",
                                    setup_msg.protocol, expected_protocol
                                );
                            }
                        }
                    } else {
                        panic!(
                            "MockIrohUpstream: first message must be SetupConnection, got {}",
                            msg_type
                        );
                    }
                }

                tokio::spawn(async move {
                    while let Ok(mut frame) = downstream_receiver.recv().await {
                        let (msg_type, msg) = message_from_frame(&mut frame);
                        info!(
                            "MockIrohUpstream: received message from downstream: {} {}",
                            msg_type, msg
                        );
                    }
                });

                while let Ok(message) = proxy_receiver.recv().await {
                    let message_type = message.message_type();
                    let frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(message, message_type, 0, false)
                            .expect("create frame from message"),
                    );
                    if downstream_sender.send(frame).await.is_err() {
                        break;
                    }
                }
            });

            proxy_sender
        }
    }

    /// Iroh-transport mock for an upstream-facing client (the inverse of
    /// [`MockIrohUpstream`]).
    ///
    /// Dials the supplied `target_node_addr` over iroh, optionally sends a
    /// `SetupConnection` frame (mirroring [`MockDownstream`]), and returns a
    /// `Sender<AnyMessage>` the test uses to push further messages upstream.
    pub struct MockIrohDownstream {
        endpoint: ::iroh::Endpoint,
        target_node_addr: ::iroh::NodeAddr,
        authority_pubkey: Option<Secp256k1PublicKey>,
        setup: WithSetup,
    }

    impl MockIrohDownstream {
        /// Construct a new mock iroh downstream. `endpoint` is a fresh client
        /// endpoint (use [`crate::utils::create_iroh_endpoint`]).
        /// `target_node_addr` is the upstream peer's `NodeAddr` (also from
        /// `create_iroh_endpoint` on the peer side).
        pub fn new(
            endpoint: ::iroh::Endpoint,
            target_node_addr: ::iroh::NodeAddr,
            authority_pubkey: Option<Secp256k1PublicKey>,
            setup: WithSetup,
        ) -> Self {
            Self {
                endpoint,
                target_node_addr,
                authority_pubkey,
                setup,
            }
        }

        /// Dial the upstream and return the `Sender<AnyMessage>` for ongoing
        /// proxy traffic. Mirrors [`MockDownstream::start`]'s shape so test
        /// assertion code can be reused.
        pub async fn start(self) -> Sender<AnyMessage<'static>> {
            let (proxy_sender, proxy_receiver) = async_channel::unbounded::<AnyMessage<'static>>();

            let connector = IrohSv2Connector::new(
                self.endpoint,
                std::collections::BTreeMap::new(),
                SV2_POOL_ALPN,
                Duration::from_secs(10),
            );
            let target = Sv2Target::Iroh {
                node_addr: self.target_node_addr,
                authority_pubkey: self.authority_pubkey,
            };

            // Retry briefly so a test that races listener bind / dialer start
            // doesn't immediately fail. Mirrors `MockDownstream`'s loop.
            let (upstream_receiver, upstream_sender) = loop {
                match <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
                    &connector, &target,
                )
                .await
                {
                    Ok(pair) => break pair,
                    Err(e) => {
                        tracing::warn!(
                            "MockIrohDownstream: iroh dial failed ({e}); retrying in 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            };

            if let WithSetup::Yes(setup_connection) = self.setup {
                let protocol = setup_connection.protocol;
                let flags = setup_connection.flags;
                let msg = AnyMessage::Common(CommonMessages::SetupConnection(setup_connection));
                let message_type = msg.message_type();
                let frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                    Sv2Frame::from_message(msg, message_type, 0, false)
                        .expect("create SetupConnection frame"),
                );
                upstream_sender
                    .send(frame)
                    .await
                    .expect("send SetupConnection");
                info!(
                    "MockIrohDownstream: sent SetupConnection with protocol {:?}, flags {}",
                    protocol, flags
                );
            }

            tokio::spawn(async move {
                while let Ok(mut frame) = upstream_receiver.recv().await {
                    let (msg_type, msg) = message_from_frame(&mut frame);
                    info!(
                        "MockIrohDownstream: received message from upstream: {} {}",
                        msg_type, msg
                    );
                }
            });

            tokio::spawn(async move {
                while let Ok(message) = proxy_receiver.recv().await {
                    let message_type = message.message_type();
                    let frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(message, message_type, 0, false)
                            .expect("create frame from message"),
                    );
                    if upstream_sender.send(frame).await.is_err() {
                        break;
                    }
                }
            });

            proxy_sender
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
