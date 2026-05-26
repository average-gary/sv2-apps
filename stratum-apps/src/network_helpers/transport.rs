//! Transport-agnostic abstraction for SV2 connections.
//!
//! This module defines two traits, [`Sv2Connector`] and [`Sv2Listener`], that
//! describe the connect / accept lifecycle for an SV2 connection regardless
//! of the underlying byte transport. Today's only implementation is the
//! [`TcpSv2Connector`] / [`TcpSv2Listener`] pair, which wraps the existing
//! [`connect_with_noise`](super::connect_with_noise) /
//! [`accept_noise_connection`](super::accept_noise_connection) helpers
//! unchanged.
//!
//! # Why introduce this layer now?
//!
//! Before this layer, every role in the codebase calls
//! [`tokio::net::TcpListener::bind`] and [`tokio::net::TcpStream::connect`]
//! directly, then hands the resulting `TcpStream` to the Noise helpers. That's
//! 9 listener sites and 5 dial sites across the pool, jd-server, jd-client,
//! and translator crates — each with its own copy of the timeout / cancel /
//! error-conversion plumbing. Adding any cross-cutting concern to those sites
//! (better cancellation, observability, alternate transports) means touching
//! all 14 places and risking inconsistency.
//!
//! With the abstraction in place, those 14 call sites resolve to one of two
//! lines:
//!
//! ```text
//! let conn_pair = connector.connect(&target).await?;
//! let (peer, conn_pair) = listener.accept().await?;
//! ```
//!
//! and any new behavior (timeout policy, metrics, a different transport)
//! plugs in once at the trait-implementation level.
//!
//! # Future transport implementations
//!
//! The trait shape is designed to support additional transports as additive
//! [`Sv2Connector`] and [`Sv2Listener`] implementations without changing the
//! call-site code. The motivating future case is an iroh QUIC transport
//! ([SRI Discussion #1935][1]); the matching [`Sv2Target`] variants and the
//! per-peer fallback machinery (`prefer_transport = "iroh_then_tcp"`, etc.)
//! land in the follow-up PR that introduces iroh.
//!
//! Variants of [`Sv2Target`] and fields of [`PeerIdentity`] are
//! `#[non_exhaustive]` so the iroh follow-up can add to them without breaking
//! source-compatibility for existing matchers.
//!
//! A multi-transport listener helper (something like
//! `MultiTransportListener` that fans `accept` from N inner listeners into
//! one stream) is intentionally not introduced here: with only one transport
//! in tree it would have nothing to multiplex. It lands alongside the second
//! transport implementation that needs it.
//!
//! [1]: https://github.com/stratum-mining/stratum/discussions/1935

use std::{net::SocketAddr, time::Duration};

use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::{HandshakeRole, StandardEitherFrame},
    noise_sv2::{Initiator, Responder},
};
use tokio::net::TcpStream;

use crate::{
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::{noise_connection::Connection, Error, TCP_CONNECT_TIMEOUT},
};

/// Channel pair returned by every connect/accept.
///
/// Consumers process incoming frames via the [`Receiver`] and queue outbound
/// frames via the [`Sender`]. This matches the shape of
/// [`crate::network_helpers::noise_connection::Connection::new`] so the
/// transport-agnostic API is a drop-in replacement for the existing TCP+Noise
/// pattern at every listener and dial site in the SV2 reference apps.
pub type ConnPair<M> = (
    Receiver<StandardEitherFrame<M>>,
    Sender<StandardEitherFrame<M>>,
);

/// What a remote peer presents on the wire.
///
/// On the TCP path, only the post-Noise authority pubkey is meaningful (and
/// only on the dialing side — Noise NX gives the server's authority pubkey to
/// the client, not the other way around). The struct is `#[non_exhaustive]`
/// so that future transports can attach additional peer-presented identifiers
/// (e.g. a QUIC-layer NodeId) without breaking source-compatibility for
/// existing matchers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PeerIdentity {
    /// SV2 authority pubkey of the remote peer when known.
    ///
    /// `None` means "anonymous":
    ///   * TCP listener `accept` always returns `None` here — Noise NX does not
    ///     authenticate the client to the server.
    ///   * TCP connector `connect` returns `None` when the caller passed
    ///     `authority_pubkey: None` (encrypted but unauthenticated dial).
    ///
    /// `Some(_)` means: a Noise NX certificate signed by this authority pubkey
    /// was successfully verified during the handshake (connector side only).
    pub authority_pubkey: Option<Secp256k1PublicKey>,
}

impl PeerIdentity {
    /// Constructs an "anonymous" peer identity (no authority pubkey).
    /// Used for TCP listener accepts where Noise NX does not expose
    /// the client's identity to the server.
    pub fn anonymous() -> Self {
        Self {
            authority_pubkey: None,
        }
    }

    /// Constructs a peer identity carrying the given verified SV2 authority
    /// pubkey. Used by TCP connector dials when the caller supplied an
    /// authority pubkey to verify against.
    pub fn from_authority(pubkey: Secp256k1PublicKey) -> Self {
        Self {
            authority_pubkey: Some(pubkey),
        }
    }
}

/// Description of a target to dial. Used by [`Sv2Connector::connect`].
///
/// Marked `#[non_exhaustive]` so that future transports can be added as new
/// variants without breaking source-compatibility for existing matchers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Sv2Target {
    /// TCP-only target.
    Tcp {
        /// Resolved TCP address to dial.
        addr: SocketAddr,
        /// `None` disables authority pubkey verification (encrypted but
        /// unauthenticated; used in dev/test).
        authority_pubkey: Option<Secp256k1PublicKey>,
    },
}

/// Outbound dialer abstraction.
///
/// Implementations:
///   * [`TcpSv2Connector`] (this file) — TCP+Noise.
///
/// Additional transports plug in as additive `Sv2Connector` impls.
#[async_trait]
pub trait Sv2Connector<M>: Send + Sync
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Dial the given target and return the framed channel pair on success.
    async fn connect(&self, target: &Sv2Target) -> Result<ConnPair<M>, Error>;
}

/// Inbound listener abstraction.
///
/// Implementations:
///   * [`TcpSv2Listener`] (this file) — TCP+Noise responder.
///
/// Additional transports plug in as additive `Sv2Listener` impls.
#[async_trait]
pub trait Sv2Listener<M>: Send + Sync
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    /// Accept the next inbound connection. Returns the peer's identity (as
    /// known at accept time — see [`PeerIdentity`]) and the framed channel
    /// pair.
    async fn accept(&self) -> Result<(PeerIdentity, ConnPair<M>), Error>;
}

// =====================================================================
//  TCP implementations
// =====================================================================

/// TCP+Noise connector. Wraps the existing
/// [`connect_with_noise`](super::connect_with_noise) /
/// [`Connection::new`] behavior so app code that has migrated to the
/// transport trait still gets the unmodified TCP path.
#[derive(Default, Clone, Debug)]
pub struct TcpSv2Connector;

impl TcpSv2Connector {
    /// Construct a new TCP+Noise connector.
    pub fn new() -> Self {
        Self
    }

    /// Dial `addr` over TCP, run the SV2 Noise NX initiator handshake, and
    /// return the framed channel pair. If `authority_pubkey` is `Some`, the
    /// server's Noise NX certificate is verified against it; if `None`, the
    /// dial is encrypted but unauthenticated (intended for dev/test).
    async fn dial_tcp<M>(
        &self,
        addr: SocketAddr,
        authority_pubkey: Option<Secp256k1PublicKey>,
    ) -> Result<ConnPair<M>, Error>
    where
        M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
    {
        let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::TcpConnectTimeout(addr))?
            .map_err(|e| Error::TcpConnectFailed(format!("connect {addr}: {e}")))?;

        let initiator = match authority_pubkey {
            Some(key) => Initiator::from_raw_k(key.into_bytes()).map_err(|_| Error::InvalidKey)?,
            None => Initiator::without_pk().map_err(|_| Error::InvalidKey)?,
        };
        let pair = Connection::new::<M>(stream, HandshakeRole::Initiator(initiator)).await?;
        Ok(pair)
    }
}

#[async_trait]
impl<M> Sv2Connector<M> for TcpSv2Connector
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn connect(&self, target: &Sv2Target) -> Result<ConnPair<M>, Error> {
        match target {
            Sv2Target::Tcp {
                addr,
                authority_pubkey,
            } => self.dial_tcp(*addr, *authority_pubkey).await,
        }
    }
}

/// TCP+Noise listener. Wraps `tokio::net::TcpListener::bind` + an accept loop
/// that runs the SV2 Noise NX responder handshake on each accepted socket.
pub struct TcpSv2Listener {
    listener: tokio::net::TcpListener,
    auth_pub: Secp256k1PublicKey,
    auth_priv: Secp256k1SecretKey,
    cert_validity: u64,
}

impl TcpSv2Listener {
    /// Bind a TCP listener on `addr`. The Noise NX responder uses
    /// `auth_pub` / `auth_priv` to sign its certificate, with the certificate
    /// valid for `cert_validity` seconds.
    pub async fn bind(
        addr: SocketAddr,
        auth_pub: Secp256k1PublicKey,
        auth_priv: Secp256k1SecretKey,
        cert_validity: u64,
    ) -> Result<Self, Error> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| Error::BindFailed(format!("bind {addr}: {e}")))?;
        Ok(Self {
            listener,
            auth_pub,
            auth_priv,
            cert_validity,
        })
    }

    /// Locally-bound socket address (useful for tests with port `0`).
    ///
    /// The listener is constructed via [`TcpSv2Listener::bind`], which
    /// completed a successful `tokio::net::TcpListener::bind`; the OS-level
    /// socket has a valid local address by that point, so we expose it
    /// infallibly.
    pub fn bound_addr(&self) -> SocketAddr {
        self.listener
            .local_addr()
            .expect("bound TcpListener exposes its addr")
    }
}

#[async_trait]
impl<M> Sv2Listener<M> for TcpSv2Listener
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn accept(&self) -> Result<(PeerIdentity, ConnPair<M>), Error> {
        let (stream, _peer_addr) = self
            .listener
            .accept()
            .await
            .map_err(|_| Error::SocketClosed)?;

        let responder = Responder::from_authority_kp(
            &self.auth_pub.into_bytes(),
            &self.auth_priv.into_bytes(),
            Duration::from_secs(self.cert_validity),
        )
        .map_err(|_| Error::InvalidKey)?;

        let pair = Connection::new::<M>(stream, HandshakeRole::Responder(responder)).await?;

        // Noise NX authenticates only the server (responder) to the client
        // (initiator), so the listener side does not learn the peer's
        // authority pubkey here. Surface this as an "anonymous" identity.
        Ok((PeerIdentity::anonymous(), pair))
    }
}

// =====================================================================
//  Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
    use std::net::{IpAddr, Ipv4Addr};
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

    /// End-to-end test: a [`TcpSv2Listener`] accepts a connection from a
    /// [`TcpSv2Connector`], they complete the SV2 Noise NX handshake, and
    /// they round-trip one [`SetupConnection`] frame.
    #[tokio::test]
    async fn tcp_listener_accepts_tcp_connector() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();

        let listener = TcpSv2Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            auth_pub,
            auth_priv,
            10_000,
        )
        .await
        .expect("bind TCP listener");

        let bound = listener.bound_addr();

        let server_task = tokio::spawn(async move {
            let (peer, (rx, tx)) =
                <TcpSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(&listener)
                    .await
                    .expect("accept");
            // TCP listener does not learn the peer's authority pubkey.
            assert!(
                peer.authority_pubkey.is_none(),
                "TCP listener peer should be anonymous"
            );
            // Echo: read one frame, send it back.
            let frame = rx.recv().await.expect("recv frame from client");
            tx.send(frame).await.expect("echo frame back");
            // Hold the connection alive briefly so the client can read.
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let connector = TcpSv2Connector::new();
        let target = Sv2Target::Tcp {
            addr: bound,
            authority_pubkey: Some(auth_pub),
        };
        let (rx, tx) =
            <TcpSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(&connector, &target)
                .await
                .expect("connect");

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

    /// Binding to port `0` should still expose a non-zero bound port via
    /// [`TcpSv2Listener::bound_addr`] — used by tests that don't want to
    /// hard-code a port.
    #[tokio::test]
    async fn tcp_listener_bound_addr_reflects_actual_port() {
        let (auth_pub, auth_priv) = test_keypair();

        let listener = TcpSv2Listener::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            auth_pub,
            auth_priv,
            10_000,
        )
        .await
        .expect("bind TCP listener");

        let bound = listener.bound_addr();
        assert_ne!(
            bound.port(),
            0,
            "bound_addr() must reflect the OS-assigned port, not the requested 0"
        );
    }
}
