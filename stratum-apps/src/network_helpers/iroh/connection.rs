//! `IrohConnection`: bundles an established iroh QUIC [`iroh::endpoint::Connection`]
//! with the SV2 [`NoiseIrohStream`] running inside one of its bidi streams.
//!
//! The shape mirrors [`crate::network_helpers::noise_connection::Connection`]:
//! a constructor that takes the established (post-Noise-handshake) primitives
//! and returns a `(Receiver, Sender)` channel pair which the rest of the SV2
//! app code consumes. Reader and writer tasks are spawned to pump frames in
//! both directions; each task additionally checks the underlying QUIC
//! connection's [`close_reason()`](iroh::endpoint::Connection::close_reason)
//! every iteration so that a peer-side disconnect is surfaced as a channel
//! disconnect to consumers (Fedimint PR #8571 lesson).
//!
//! Both [`IrohSv2Connector`](super::connector::IrohSv2Connector) and
//! [`IrohSv2Listener`](super::listener::IrohSv2Listener) produce an
//! `IrohConnection` and immediately call [`IrohConnection::into_channels`].

use std::sync::Arc;

use async_channel::{unbounded, Receiver, Sender};
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::StandardEitherFrame,
};
use tokio::task;
use tracing::{debug, error, warn};

use crate::network_helpers::{
    iroh::noise_iroh_stream::NoiseIrohStream,
    noise_generic_stream::{NoiseGenericReadHalf, NoiseGenericWriteHalf},
    transport::ConnPair,
};

use super::duplex::IrohDuplex;

/// An established iroh QUIC connection wrapping a single SV2 Noise NX bidi
/// stream.
///
/// `IrohConnection` is constructed by the connector / listener once the QUIC
/// handshake, the bidi stream open, and the inner SV2 Noise NX handshake have
/// all completed successfully. Calling [`into_channels`](Self::into_channels)
/// hands ownership to a pair of background tasks that pump frames between the
/// noise stream and an `async_channel` pair, returning that pair as a
/// [`ConnPair`].
///
/// The underlying [`iroh::endpoint::Connection`] is kept alive for the
/// lifetime of the channel pair: reader and writer tasks each hold a clone, so
/// the QUIC connection only drops once both halves of the noise stream have
/// terminated.
pub struct IrohConnection<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// The QUIC connection whose lifetime gates the bidi stream's reads and
    /// writes. Stored even after [`into_channels`] hands the noise halves to
    /// background tasks because dropping the [`iroh::endpoint::Connection`]
    /// closes the underlying stream — consumers expect the channel pair to
    /// remain usable until they explicitly drop it.
    connection: iroh::endpoint::Connection,
    /// The Noise NX stream we will pump frames over.
    noise_stream: NoiseIrohStream<M>,
    /// Cached remote EndpointId, exposed via [`remote_endpoint_id`](Self::remote_endpoint_id)
    /// before [`into_channels`] consumes the conn.
    endpoint_id: iroh::EndpointId,
}

struct ConnectionState<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    sender_incoming: Sender<StandardEitherFrame<M>>,
    receiver_incoming: Receiver<StandardEitherFrame<M>>,
    sender_outgoing: Sender<StandardEitherFrame<M>>,
    receiver_outgoing: Receiver<StandardEitherFrame<M>>,
    /// Held by both tasks so the QUIC connection lives at least until both
    /// directions have closed. Also queried on each loop iteration to detect
    /// peer-side disconnects (Fedimint PR #8571).
    connection: iroh::endpoint::Connection,
}

impl<M> ConnectionState<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    fn close_all(&self) {
        self.sender_incoming.close();
        self.receiver_incoming.close();
        self.sender_outgoing.close();
        self.receiver_outgoing.close();
    }
}

impl<M> IrohConnection<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Build a new `IrohConnection` from the post-handshake primitives.
    ///
    /// All three values must be from the same flow: `connection` is the QUIC
    /// connection that produced the bidi stream wrapped inside `noise_stream`,
    /// and `endpoint_id` is the verified remote EndpointId observed at QUIC
    /// handshake time.
    pub fn new(
        connection: iroh::endpoint::Connection,
        noise_stream: NoiseIrohStream<M>,
        endpoint_id: iroh::EndpointId,
    ) -> Self {
        Self {
            connection,
            noise_stream,
            endpoint_id,
        }
    }

    /// Remote EndpointId observed at QUIC handshake time. Available before
    /// [`into_channels`](Self::into_channels) consumes `self`.
    pub fn remote_endpoint_id(&self) -> iroh::EndpointId {
        self.endpoint_id
    }

    /// Spawn the reader and writer tasks and return the
    /// [`ConnPair`] channel-pair shape that the SV2 app code consumes.
    ///
    /// Mirrors the channel-pair contract of
    /// [`crate::network_helpers::noise_connection::Connection::new`] for TCP.
    pub fn into_channels(self) -> ConnPair<M> {
        let (sender_incoming, receiver_incoming) = unbounded();
        let (sender_outgoing, receiver_outgoing) = unbounded();

        let conn_state = Arc::new(ConnectionState {
            sender_incoming,
            receiver_incoming: receiver_incoming.clone(),
            sender_outgoing: sender_outgoing.clone(),
            receiver_outgoing,
            connection: self.connection,
        });

        let (read_half, write_half) = self.noise_stream.into_split();

        Self::spawn_reader(read_half, Arc::clone(&conn_state));
        Self::spawn_writer(write_half, conn_state);

        (receiver_incoming, sender_outgoing)
    }

    fn spawn_reader(
        mut read_half: NoiseGenericReadHalf<IrohDuplex, M>,
        conn_state: Arc<ConnectionState<M>>,
    ) -> task::JoinHandle<()> {
        let sender_incoming = conn_state.sender_incoming.clone();

        task::spawn(async move {
            loop {
                // Cheap pre-flight close-reason check (Fedimint PR #8571
                // lesson). If the QUIC connection has already been torn down
                // we surface the error to the channel consumers via
                // close_all() rather than blocking on a doomed read.
                if let Some(reason) = conn_state.connection.close_reason() {
                    warn!(
                        "iroh reader: QUIC connection closed before read: {reason:?}"
                    );
                    break;
                }

                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        debug!("iroh reader: received shutdown signal");
                        break;
                    }
                    res = read_half.read_frame() => match res {
                        Ok(frame) => {
                            if sender_incoming.send(frame).await.is_err() {
                                error!("iroh reader: incoming channel closed, shutting down");
                                break;
                            }
                        }
                        Err(e) => {
                            // Distinguish "connection closed by peer" from
                            // "decode failure" only by what we log; either
                            // way the read half is no longer usable.
                            if let Some(reason) = conn_state.connection.close_reason() {
                                debug!(
                                    "iroh reader: read failed and connection is closed ({reason:?}): {e:?}"
                                );
                            } else {
                                error!("iroh reader: error while reading frame: {e:?}");
                            }
                            break;
                        }
                    }
                }
            }

            conn_state.close_all();
        })
    }

    fn spawn_writer(
        mut write_half: NoiseGenericWriteHalf<IrohDuplex, M>,
        conn_state: Arc<ConnectionState<M>>,
    ) -> task::JoinHandle<()> {
        let receiver_outgoing = conn_state.receiver_outgoing.clone();

        task::spawn(async move {
            loop {
                if let Some(reason) = conn_state.connection.close_reason() {
                    warn!(
                        "iroh writer: QUIC connection closed before write: {reason:?}"
                    );
                    break;
                }

                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        debug!("iroh writer: received shutdown signal");
                        break;
                    }
                    res = receiver_outgoing.recv() => match res {
                        Ok(frame) => {
                            if let Err(e) = write_half.write_frame(frame).await {
                                if let Some(reason) = conn_state.connection.close_reason() {
                                    debug!(
                                        "iroh writer: write failed and connection is closed ({reason:?}): {e:?}"
                                    );
                                } else {
                                    error!("iroh writer: error while writing frame: {e:?}");
                                }
                                break;
                            }
                        }
                        Err(_) => {
                            debug!("iroh writer: outgoing channel closed, shutting down");
                            break;
                        }
                    }
                }
            }

            if let Err(e) = write_half.shutdown().await {
                debug!("iroh writer: error during shutdown: {e:?}");
            }

            conn_state.close_all();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
        network_helpers::{
            iroh::{alpn::SV2_POOL_ALPN, duplex::IrohDuplex},
            noise_generic_stream::NoiseGenericStream,
        },
    };
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };
    use stratum_core::{
        binary_sv2::{Str0255, B0255},
        codec_sv2::{HandshakeRole, StandardEitherFrame},
        common_messages_sv2::{Protocol, SetupConnection},
        framing_sv2::framing::Sv2Frame,
        noise_sv2::{Initiator, Responder},
        parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message},
    };

    // Authority keypair shared with the existing tests.
    const TEST_PUB_KEY: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const TEST_PRV_KEY: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    fn build_responder() -> Box<Responder> {
        let pub_key = TEST_PUB_KEY
            .parse::<Secp256k1PublicKey>()
            .unwrap()
            .into_bytes();
        let prv_key = TEST_PRV_KEY
            .parse::<Secp256k1SecretKey>()
            .unwrap()
            .into_bytes();
        Responder::from_authority_kp(&pub_key, &prv_key, Duration::from_secs(10_000)).unwrap()
    }

    fn build_initiator() -> Box<Initiator> {
        let pub_key = TEST_PUB_KEY
            .parse::<Secp256k1PublicKey>()
            .unwrap()
            .into_bytes();
        Initiator::from_raw_k(pub_key).unwrap()
    }

    fn build_setup_connection_frame() -> (StandardEitherFrame<AnyMessage<'static>>, Vec<u8>) {
        let endpoint_host: B0255 = "0.0.0.0".to_string().into_bytes().try_into().unwrap();
        let vendor: Str0255 = "test".to_string().try_into().unwrap();
        let hardware_version: Str0255 = "test".to_string().try_into().unwrap();
        let firmware: Str0255 = "test".to_string().try_into().unwrap();
        let device_id: Str0255 = "test".to_string().try_into().unwrap();

        let setup = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: 0,
            endpoint_host,
            endpoint_port: 0,
            vendor,
            hardware_version,
            firmware,
            device_id,
        };
        let expected_payload =
            stratum_core::binary_sv2::to_bytes(setup.clone()).expect("encode SetupConnection");

        let any: AnyMessage<'static> = AnyMessage::Common(CommonMessages::SetupConnection(setup));
        let message_type = any.message_type();
        let sv2_frame: Sv2Frame<AnyMessage<'static>, _> =
            Sv2Frame::from_message(any, message_type, 0, false)
                .expect("Failed to create SetupConnection frame");
        let either: StandardEitherFrame<AnyMessage<'static>> = StandardEitherFrame::Sv2(sv2_frame);
        (either, expected_payload)
    }

    fn extract_payload(frame: &mut StandardEitherFrame<AnyMessage<'static>>) -> Vec<u8> {
        match frame {
            StandardEitherFrame::Sv2(f) => f.payload().to_vec(),
            StandardEitherFrame::HandShake(_) => {
                panic!("post-handshake frame should always be Sv2, got HandShake")
            }
        }
    }

    /// Build an iroh server endpoint bound to loopback, no relay, no
    /// discovery, accepting one ALPN.
    async fn build_server_endpoint() -> (iroh::Endpoint, iroh::EndpointId, std::net::SocketAddr) {
        use ::iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};

        let secret = SecretKey::generate();
        let endpoint_id = secret.public();
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![SV2_POOL_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind addr v4")
            .bind()
            .await
            .expect("bind server endpoint");

        // Wait for the bind to settle and a real loopback socket to be
        // populated.
        let addr = loop {
            let bound = ep.bound_sockets();
            if let Some(addr) = bound.iter().find(|s| s.is_ipv4()).copied() {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };

        (ep, endpoint_id, addr)
    }

    /// Build a loopback iroh client endpoint with no relay / discovery.
    async fn build_client_endpoint() -> iroh::Endpoint {
        use ::iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};

        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .relay_mode(RelayMode::Disabled)
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind addr v4")
            .bind()
            .await
            .expect("bind client endpoint")
    }

    /// End-to-end: dial one endpoint from another over iroh, run Noise
    /// inside the bidi stream, build an [`IrohConnection`] on each side,
    /// call `into_channels`, and round-trip a SetupConnection frame.
    #[tokio::test]
    async fn into_channels_round_trips_a_frame() {
        use ::iroh::EndpointAddr;

        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (server_ep, server_endpoint_id, server_socket) = build_server_endpoint().await;
        let client_ep = build_client_endpoint().await;

        // Server: accept one connection, build IrohConnection, expose
        // channel pair, echo one frame.
        let server_task = tokio::spawn(async move {
            let incoming = server_ep.accept().await.expect("accept incoming");
            let connection = incoming.await.expect("incoming -> connection");
            let remote = connection.remote_id();
            let (send, recv) = connection.accept_bi().await.expect("accept_bi");
            let duplex = IrohDuplex { send, recv };
            let noise = NoiseGenericStream::<IrohDuplex, AnyMessage<'static>>::new(
                duplex,
                HandshakeRole::Responder(build_responder()),
                Duration::from_secs(10),
            )
            .await
            .expect("responder handshake");

            let conn = IrohConnection::<AnyMessage<'static>>::new(connection, noise, remote);
            let (rx, tx) = conn.into_channels();

            let frame = rx.recv().await.expect("recv from client");
            tx.send(frame).await.expect("echo back to client");
            // Hold the writer task alive briefly so the echo flushes.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        // Client: dial server, build IrohConnection, send a frame, read echo.
        let server_addr = EndpointAddr::new(server_endpoint_id).with_ip_addr(server_socket);
        let connection = client_ep
            .connect(server_addr, SV2_POOL_ALPN)
            .await
            .expect("client connect");
        let remote = connection.remote_id();
        let (send, recv) = connection.open_bi().await.expect("open_bi");
        let duplex = IrohDuplex { send, recv };
        let noise = NoiseGenericStream::<IrohDuplex, AnyMessage<'static>>::new(
            duplex,
            HandshakeRole::Initiator(build_initiator()),
            Duration::from_secs(10),
        )
        .await
        .expect("initiator handshake");

        let conn = IrohConnection::<AnyMessage<'static>>::new(connection, noise, remote);
        assert_eq!(conn.remote_endpoint_id(), remote);
        let (rx, tx) = conn.into_channels();

        let (frame, expected_payload) = build_setup_connection_frame();
        tx.send(frame).await.expect("send frame");

        let mut echoed = rx.recv().await.expect("recv echo");
        let echoed_payload = extract_payload(&mut echoed);
        assert_eq!(
            echoed_payload, expected_payload,
            "round-tripped SV2 frame payload must match"
        );

        server_task.await.expect("server task");
    }
}
