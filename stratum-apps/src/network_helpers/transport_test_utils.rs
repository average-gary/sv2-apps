//! In-memory transport pair for tests.
//!
//! Implements [`Sv2Connector`] and [`Sv2Listener`] over a
//! [`tokio::io::duplex`] pipe instead of TCP. The full Noise NX handshake
//! runs as usual; the bytes never reach a kernel socket.
//!
//! # Why
//!
//! Test fixtures that today bind ephemeral 127.0.0.1:0 ports and race the
//! dialer against the bind can use this pair to eliminate TCP-port
//! allocation entirely. The role under test sees the same
//! [`ConnPair<M>`] from `Sv2Listener::accept()` it always did — no behavior
//! change above the trait.
//!
//! # Constraints
//!
//! `tokio::io::duplex` returns one half-pair per call, so the API hands
//! the connector and listener back together via [`in_memory_sv2_pair`]
//! rather than independent `bind` / `connect` constructors. The listener
//! accepts exactly one connection.
//!
//! Multi-connection fakes (with an internal `mpsc<DuplexStream>` queue
//! handing fresh halves to each `connect`) are out of scope here;
//! trivially extensible later if needed.

use std::{marker::PhantomData, sync::Arc};

use async_channel::{unbounded, Receiver, Sender};
use async_trait::async_trait;
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::{HandshakeRole, StandardEitherFrame},
    noise_sv2::{Initiator, Responder},
};
use tokio::{
    io::DuplexStream,
    sync::Mutex,
    task,
};
use tracing::{debug, error};

use crate::{
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::{
        noise_generic_stream::{
            NoiseGenericReadHalf, NoiseGenericStream, NoiseGenericWriteHalf,
        },
        transport::{ConnPair, PeerIdentity, Sv2Connector, Sv2Listener, Sv2Target},
        Error, NOISE_HANDSHAKE_TIMEOUT,
    },
};

/// In-memory `Sv2Connector` backed by a [`tokio::io::DuplexStream`].
///
/// Constructed via [`in_memory_sv2_pair`]. The first call to
/// [`Sv2Connector::connect`] consumes the underlying stream; subsequent
/// calls return [`Error::SocketClosed`].
pub struct InMemorySv2Connector<M> {
    stream: Mutex<Option<DuplexStream>>,
    auth_pub: Secp256k1PublicKey,
    _marker: PhantomData<fn() -> M>,
}

/// In-memory `Sv2Listener` backed by a [`tokio::io::DuplexStream`].
///
/// Constructed via [`in_memory_sv2_pair`]. The first call to
/// [`Sv2Listener::accept`] consumes the underlying stream; subsequent
/// calls return [`Error::SocketClosed`].
pub struct InMemorySv2Listener<M> {
    stream: Mutex<Option<DuplexStream>>,
    auth_pub: Secp256k1PublicKey,
    auth_priv: Secp256k1SecretKey,
    cert_validity: u64,
    _marker: PhantomData<fn() -> M>,
}

/// Build an in-memory connector/listener pair backed by a
/// [`tokio::io::duplex`] pipe.
///
/// The returned pair shares one duplex pipe: the listener accepts exactly
/// one connection (via the half it owns), and the connector connects to
/// that same pipe. The full SV2 Noise NX handshake runs as usual using
/// `auth_pub`/`auth_priv` on the responder side and `auth_pub` on the
/// initiator side.
pub fn in_memory_sv2_pair<M>(
    auth_pub: Secp256k1PublicKey,
    auth_priv: Secp256k1SecretKey,
    cert_validity: u64,
) -> (InMemorySv2Connector<M>, InMemorySv2Listener<M>)
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);
    let connector = InMemorySv2Connector {
        stream: Mutex::new(Some(client_side)),
        auth_pub,
        _marker: PhantomData,
    };
    let listener = InMemorySv2Listener {
        stream: Mutex::new(Some(server_side)),
        auth_pub,
        auth_priv,
        cert_validity,
        _marker: PhantomData,
    };
    (connector, listener)
}

#[async_trait]
impl<M> Sv2Connector<M> for InMemorySv2Connector<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn connect(&self, target: &Sv2Target) -> Result<ConnPair<M>, Error> {
        // The in-memory pair ignores the addr field. We only consult
        // `authority_pubkey` to decide whether to validate the responder's
        // cert; if the caller did not pass one in, we fall back to the
        // pubkey baked into the connector at pair-construction time so the
        // Noise NX handshake still authenticates the responder. This keeps
        // the in-memory path semantically equivalent to the TCP path
        // without forcing test code to thread the pubkey twice.
        let authority_pubkey = match target {
            Sv2Target::Tcp {
                authority_pubkey, ..
            } => authority_pubkey.unwrap_or(self.auth_pub),
        };

        let stream = self
            .stream
            .lock()
            .await
            .take()
            .ok_or(Error::SocketClosed)?;

        let initiator =
            Initiator::from_raw_k(authority_pubkey.into_bytes()).map_err(|_| Error::InvalidKey)?;

        let noise = NoiseGenericStream::<_, M>::new(
            stream,
            HandshakeRole::Initiator(initiator),
            NOISE_HANDSHAKE_TIMEOUT,
        )
        .await?;

        Ok(spawn_pump(noise))
    }
}

#[async_trait]
impl<M> Sv2Listener<M> for InMemorySv2Listener<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn accept(&self) -> Result<(PeerIdentity, ConnPair<M>), Error> {
        let stream = self
            .stream
            .lock()
            .await
            .take()
            .ok_or(Error::SocketClosed)?;

        let responder = Responder::from_authority_kp(
            &self.auth_pub.into_bytes(),
            &self.auth_priv.into_bytes(),
            std::time::Duration::from_secs(self.cert_validity),
        )
        .map_err(|_| Error::InvalidKey)?;

        let noise = NoiseGenericStream::<_, M>::new(
            stream,
            HandshakeRole::Responder(responder),
            NOISE_HANDSHAKE_TIMEOUT,
        )
        .await?;

        // Noise NX authenticates only the responder to the initiator, so
        // the listener side does not learn the peer's authority pubkey
        // here. Match `TcpSv2Listener::accept` semantics.
        Ok((PeerIdentity::anonymous(), spawn_pump(noise)))
    }
}

// =====================================================================
//  Reader/writer pump tasks
// =====================================================================
//
// This mirrors `noise_connection::Connection::new` for the
// `NoiseGenericStream<DuplexStream, M>` case. We can't reuse
// `Connection::new` directly because it is concretely typed on
// `tokio::net::TcpStream`. The duplication is ~30 LOC and is intentional;
// extracting a shared helper would force an edit to `transport.rs` /
// `noise_connection.rs` outside this commit's scope. If a third caller
// shows up we should factor this out.

struct ConnectionState<Message> {
    sender_incoming: Sender<StandardEitherFrame<Message>>,
    receiver_incoming: Receiver<StandardEitherFrame<Message>>,
    sender_outgoing: Sender<StandardEitherFrame<Message>>,
    receiver_outgoing: Receiver<StandardEitherFrame<Message>>,
}

impl<Message> ConnectionState<Message> {
    fn close_all(&self) {
        self.sender_incoming.close();
        self.receiver_incoming.close();
        self.sender_outgoing.close();
        self.receiver_outgoing.close();
    }
}

fn spawn_pump<M>(noise: NoiseGenericStream<DuplexStream, M>) -> ConnPair<M>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let (sender_incoming, receiver_incoming) = unbounded();
    let (sender_outgoing, receiver_outgoing) = unbounded();

    let conn_state = Arc::new(ConnectionState {
        sender_incoming,
        receiver_incoming: receiver_incoming.clone(),
        sender_outgoing: sender_outgoing.clone(),
        receiver_outgoing,
    });

    let (read_half, write_half) = noise.into_split();
    spawn_reader(read_half, Arc::clone(&conn_state));
    spawn_writer(write_half, conn_state);

    (receiver_incoming, sender_outgoing)
}

fn spawn_reader<M>(
    mut read_half: NoiseGenericReadHalf<DuplexStream, M>,
    conn_state: Arc<ConnectionState<M>>,
) -> task::JoinHandle<()>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let sender_incoming = conn_state.sender_incoming.clone();

    task::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    debug!("Reader received shutdown signal.");
                    break;
                }
                res = read_half.read_frame() => match res {
                    Ok(frame) => {
                        if sender_incoming.send(frame).await.is_err() {
                            error!("Reader: channel closed, shutting down.");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Reader: error while reading frame: {e:?}");
                        break;
                    }
                }
            }
        }

        conn_state.close_all();
    })
}

fn spawn_writer<M>(
    mut write_half: NoiseGenericWriteHalf<DuplexStream, M>,
    conn_state: Arc<ConnectionState<M>>,
) -> task::JoinHandle<()>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    let receiver_outgoing = conn_state.receiver_outgoing.clone();

    task::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    debug!("Writer received shutdown signal.");
                    break;
                }
                res = receiver_outgoing.recv() => match res {
                    Ok(frame) => {
                        if let Err(e) = write_half.write_frame(frame).await {
                            error!("Writer: error while writing frame: {e:?}");
                            break;
                        }
                    }
                    Err(_) => {
                        debug!("Writer: channel closed, shutting down.");
                        break;
                    }
                }
            }
        }

        if let Err(e) = write_half.shutdown().await {
            error!("Writer: error during shutdown: {e:?}");
        }

        conn_state.close_all();
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use stratum_core::{
        binary_sv2::{Str0255, B0255},
        codec_sv2::StandardEitherFrame,
        common_messages_sv2::{Protocol, SetupConnection},
        framing_sv2::framing::Sv2Frame,
        parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message},
    };

    /// Authority keypair used by the existing integration-tests fixtures
    /// (matches `integration-tests/lib/utils.rs`).
    const TEST_PUB_KEY: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    const TEST_PRV_KEY: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    fn test_keypair() -> (Secp256k1PublicKey, Secp256k1SecretKey) {
        let pubkey = TEST_PUB_KEY.parse::<Secp256k1PublicKey>().unwrap();
        let privkey = TEST_PRV_KEY.parse::<Secp256k1SecretKey>().unwrap();
        (pubkey, privkey)
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

    /// Dummy target — the in-memory connector ignores `addr` and falls back
    /// to its pair-time `auth_pub` when `authority_pubkey` is `None`.
    fn dummy_target() -> Sv2Target {
        Sv2Target::Tcp {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            authority_pubkey: None,
        }
    }

    /// End-to-end test: the in-memory pair completes the SV2 Noise NX
    /// handshake and round-trips one [`SetupConnection`] frame.
    #[tokio::test(flavor = "multi_thread")]
    async fn in_memory_pair_round_trips_one_frame() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();
        let (connector, listener) =
            in_memory_sv2_pair::<AnyMessage<'static>>(auth_pub, auth_priv, 10_000);

        let server_task = tokio::spawn(async move {
            let (peer, (rx, tx)) = listener.accept().await.expect("accept");
            // Listener side never learns the peer's authority pubkey
            // under Noise NX; mirror `TcpSv2Listener::accept` semantics.
            assert!(
                peer.authority_pubkey.is_none(),
                "in-memory listener peer should be anonymous"
            );
            // Echo: read one frame, send it back.
            let frame = rx.recv().await.expect("recv frame from client");
            tx.send(frame).await.expect("echo frame back");
            // Hold the connection alive briefly so the client can read.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let (rx, tx) = connector.connect(&dummy_target()).await.expect("connect");

        let (frame, expected_payload) = build_setup_connection_frame();
        tx.send(frame).await.expect("send frame");
        let mut echoed = rx.recv().await.expect("recv echoed frame");
        let echoed_payload = extract_payload(&mut echoed);
        assert_eq!(
            echoed_payload, expected_payload,
            "round-tripped SV2 frame payload must match"
        );

        server_task.await.expect("server task");
    }

    /// The handshake completes (the listener actually receives a
    /// post-handshake frame). We don't verify `PeerIdentity` content
    /// because the listener side is always anonymous under Noise NX.
    #[tokio::test(flavor = "multi_thread")]
    async fn in_memory_pair_handshake_completes_with_authority_validation() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();
        let (connector, listener) =
            in_memory_sv2_pair::<AnyMessage<'static>>(auth_pub, auth_priv, 10_000);

        let server_task = tokio::spawn(async move {
            let (_peer, (rx, _tx)) = listener.accept().await.expect("accept");
            // Receiving any post-handshake frame proves the Noise
            // handshake completed end-to-end.
            let _frame = rx.recv().await.expect("recv frame from client");
        });

        // Pass an explicit authority pubkey on the target to exercise the
        // validation path (the in-memory connector still uses it to build
        // the `Initiator`).
        let target = Sv2Target::Tcp {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            authority_pubkey: Some(auth_pub),
        };
        let (_rx, tx) = connector.connect(&target).await.expect("connect");

        let (frame, _expected_payload) = build_setup_connection_frame();
        tx.send(frame).await.expect("send frame");

        server_task.await.expect("server task");
    }
}
