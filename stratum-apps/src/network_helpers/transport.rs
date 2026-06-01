//! Transport-agnostic SV2 listener / connector abstraction.
//!
//! See plan §"Architectural approach" — this is the single switch point above
//! `noise_connection` (existing TCP path) and `iroh/{connector,listener}`
//! (Wave 3b). All Sv2 app code talks to these traits and never names a
//! specific transport.
//!
//! This module ships:
//!   - [`Sv2Connector`] / [`Sv2Listener`] traits
//!   - [`PeerIdentity`] / [`Sv2Target`] / [`ConnPair`] support types
//!   - [`TcpSv2Connector`] / [`TcpSv2Listener`] (the TCP+Noise impls)
//!   - [`PreferTransport`] — Phase 4 per-peer fallback-ordering enum used by
//!     every role's outbound dial site
//!
//! The iroh impls ([`IrohSv2Connector`] / [`IrohSv2Listener`]) live under
//! [`crate::network_helpers::iroh`] and are added in Wave 3b.

use std::net::SocketAddr;

use async_channel::{Receiver, Sender};
use async_trait::async_trait;
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::{HandshakeRole, StandardEitherFrame},
    noise_sv2::{Initiator, Responder},
};
use std::time::Duration;
use tokio::net::TcpStream;
#[cfg(feature = "iroh-transport")]
use tracing::{debug, warn};

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
/// pattern at the 9 listener and 12 dial sites in the SV2 reference apps.
pub type ConnPair<M> = (
    Receiver<StandardEitherFrame<M>>,
    Sender<StandardEitherFrame<M>>,
);

/// What a remote peer presents on the wire.
///
/// On the TCP path, only the post-Noise authority pubkey is meaningful (and
/// only on the dialing side — Noise NX gives the server's authority pubkey to
/// the client, not the other way around).
///
/// On the iroh path, the peer also presents an [`iroh::EndpointId`] at QUIC
/// handshake time (before any SV2 bytes flow). The `iroh_node_id` field is
/// present on both paths to keep the struct shape uniform across feature
/// combinations; it is populated only for iroh accept/connect.
#[derive(Clone, Debug)]
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

    /// The QUIC-layer NodeId observed at iroh accept/connect time, if any.
    /// Always `None` on the TCP path. Populated by iroh impls in Wave 3b.
    #[cfg(feature = "iroh-transport")]
    pub iroh_node_id: Option<iroh::EndpointId>,

    /// Placeholder so the struct shape is stable across feature combinations.
    /// Always `None` when `iroh-transport` is disabled.
    #[cfg(not(feature = "iroh-transport"))]
    pub iroh_node_id: Option<()>,
}

impl PeerIdentity {
    /// Constructs an "anonymous" peer identity (no authority pubkey, no
    /// NodeId). Used for TCP listener accepts where Noise NX does not expose
    /// the client's identity to the server.
    pub fn anonymous() -> Self {
        Self {
            authority_pubkey: None,
            iroh_node_id: None,
        }
    }

    /// Constructs a peer identity carrying the given verified SV2 authority
    /// pubkey. Used by TCP connector dials when the caller supplied an
    /// authority pubkey to verify against.
    pub fn from_authority(pubkey: Secp256k1PublicKey) -> Self {
        Self {
            authority_pubkey: Some(pubkey),
            iroh_node_id: None,
        }
    }
}

/// Description of a target to dial. Used by [`Sv2Connector::connect`].
///
/// An upstream is one transport, period. A target either dials TCP or iroh —
/// no per-peer fallback ordering. Operators who want both can configure two
/// upstream entries (one per transport) and let the role's own retry/failover
/// logic pick.
#[derive(Clone, Debug)]
pub enum Sv2Target {
    /// TCP-only target.
    Tcp {
        /// Resolved TCP address to dial.
        addr: SocketAddr,
        /// `None` disables authority pubkey verification (encrypted but
        /// unauthenticated; used in dev/test).
        authority_pubkey: Option<Secp256k1PublicKey>,
    },
    /// Iroh-only target.
    #[cfg(feature = "iroh-transport")]
    Iroh {
        /// iroh dial address (NodeId + optional direct/relay hints).
        node_addr: iroh::EndpointAddr,
        /// Optional SV2 authority pubkey to verify after Noise handshake.
        authority_pubkey: Option<Secp256k1PublicKey>,
    },
}

/// Outbound dialer abstraction.
///
/// Implementations:
///   * [`TcpSv2Connector`] (this file) — TCP+Noise.
///   * `IrohSv2Connector` (Wave 3b) — iroh QUIC + Noise inside.
///   * A future "dual" connector that owns both and applies fallback order.
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
///   * `IrohSv2Listener` (Wave 3b) — iroh QUIC + Noise responder.
///   * A future "dual" listener that fans two accept tasks into one channel.
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

/// TCP+Noise connector. Wraps the existing `connect_with_noise` /
/// `Connection::new` behavior so app code that has migrated to the
/// transport trait still gets the unmodified TCP path.
///
/// This connector has no iroh dependency and is always available (i.e.
/// independent of the `iroh-transport` cargo feature).
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
            Some(key) => {
                Initiator::from_raw_k(key.into_bytes()).map_err(|_| Error::InvalidKey)?
            }
            None => Initiator::without_pk().map_err(|_| Error::InvalidKey)?,
        };
        let pair =
            Connection::new::<M>(stream, HandshakeRole::Initiator(initiator)).await?;
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

            #[cfg(feature = "iroh-transport")]
            Sv2Target::Iroh { .. } => Err(Error::WrongTargetForTransport(
                "TcpSv2Connector cannot dial Sv2Target::Iroh; use an iroh-capable connector"
                    .to_string(),
            )),
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
    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.listener
            .local_addr()
            .map_err(|e| Error::BindFailed(format!("local_addr: {e}")))
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
//  build_target + CompositeSv2Connector (Phase 4)
// =====================================================================

/// Per-peer transport selection.
///
/// An upstream is one transport — no fallback ordering. The default is `Tcp`
/// so configs without an `[iroh]` block behave exactly as they did before
/// the iroh transport landed. Operators who want a peer reached over iroh
/// set `prefer_transport = "iroh"` and supply `iroh_node_id`. If both
/// transports are desired against the same physical peer, configure two
/// `[[upstreams]]` entries.
///
/// Defined here so all four SV2 roles share the same vocabulary.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
#[cfg_attr(feature = "iroh-transport", derive(serde::Deserialize))]
#[cfg_attr(feature = "iroh-transport", serde(rename_all = "snake_case"))]
pub enum PreferTransport {
    /// TCP only. The default.
    #[default]
    Tcp,
    /// Iroh only. Has no effect when `iroh-transport` is off (the call site
    /// errors at config-resolution time).
    Iroh,
}

/// Build a [`Sv2Target`] from the per-peer config fields.
///
/// `address` / `port` are the existing TCP fields (always present). The
/// optional iroh fields combine with `prefer` to choose the resulting
/// variant.
///
/// Compiled with `#[cfg(feature = "iroh-transport")]` aware of the
/// `iroh_node_id` and `iroh_relay_url` parameters; without the feature they
/// are not even named in the function signature, so call sites must guard
/// the iroh inputs themselves.
pub async fn build_target(
    address: &str,
    port: u16,
    authority_pubkey: Option<Secp256k1PublicKey>,
    #[cfg(feature = "iroh-transport")] iroh_node_id: Option<&str>,
    #[cfg(feature = "iroh-transport")] iroh_relay_url: Option<&str>,
    #[cfg(feature = "iroh-transport")] prefer: PreferTransport,
) -> Result<Sv2Target, Error> {
    let tcp_addr = crate::network_helpers::resolve_host(address, port)
        .await
        .map_err(Error::from)?;

    #[cfg(feature = "iroh-transport")]
    {
        let target = match prefer {
            PreferTransport::Tcp => Sv2Target::Tcp {
                addr: tcp_addr,
                authority_pubkey,
            },
            PreferTransport::Iroh => {
                let raw = iroh_node_id.ok_or_else(|| {
                    Error::WrongTargetForTransport(
                        "build_target: prefer_transport=iroh requires iroh_node_id".to_string(),
                    )
                })?;
                let node_id = raw.parse::<iroh::EndpointId>().map_err(|e| {
                    Error::WrongTargetForTransport(format!(
                        "build_target: invalid iroh_node_id `{raw}`: {e}"
                    ))
                })?;
                let mut node_addr = iroh::EndpointAddr::new(node_id);
                if let Some(url) = iroh_relay_url.filter(|s| !s.is_empty()) {
                    match iroh::RelayUrl::from_str(url) {
                        Ok(parsed) => node_addr = node_addr.with_relay_url(parsed),
                        Err(e) => {
                            warn!(
                                "build_target: invalid iroh_relay_url `{url}` ({e}); ignoring it"
                            );
                        }
                    }
                }
                Sv2Target::Iroh {
                    node_addr,
                    authority_pubkey,
                }
            }
        };
        debug!(?target, "build_target resolved");
        Ok(target)
    }

    #[cfg(not(feature = "iroh-transport"))]
    {
        Ok(Sv2Target::Tcp {
            addr: tcp_addr,
            authority_pubkey,
        })
    }
}

// `iroh::RelayUrl::from_str` requires this trait in scope.
#[cfg(feature = "iroh-transport")]
use std::str::FromStr;

// =====================================================================
//  Composite connector (Phase 4)
// =====================================================================

/// Composite outbound dialer that dispatches a [`Sv2Target`] to either a TCP
/// or iroh connector — no fallback. The variant of [`Sv2Target`] picks the
/// transport.
///
/// Usage:
///   * Build once per role at startup.
///   * Hand the per-peer [`Sv2Target`] (constructed via [`build_target`]) to
///     [`CompositeSv2Connector::connect`] on each dial.
///
/// Behaviour by [`Sv2Target`] variant:
///
/// | Variant | Behaviour                                                       |
/// |---------|-----------------------------------------------------------------|
/// | `Tcp`   | TCP only.                                                       |
/// | `Iroh`  | Iroh only. Errors with `WrongTargetForTransport` if no iroh wired. |
pub struct CompositeSv2Connector {
    tcp: TcpSv2Connector,
    #[cfg(feature = "iroh-transport")]
    iroh: Option<crate::network_helpers::iroh::connector::IrohSv2Connector>,
}

impl CompositeSv2Connector {
    /// Construct a TCP-only composite (always available).
    pub fn tcp_only() -> Self {
        Self {
            tcp: TcpSv2Connector::new(),
            #[cfg(feature = "iroh-transport")]
            iroh: None,
        }
    }

    /// Construct a TCP+iroh composite. The TCP connector is always built;
    /// the iroh connector is supplied by the caller (it carries an
    /// [`iroh::Endpoint`] which the role builds at startup).
    #[cfg(feature = "iroh-transport")]
    pub fn new(iroh: crate::network_helpers::iroh::connector::IrohSv2Connector) -> Self {
        Self {
            tcp: TcpSv2Connector::new(),
            iroh: Some(iroh),
        }
    }
}

#[async_trait]
impl<M> Sv2Connector<M> for CompositeSv2Connector
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn connect(&self, target: &Sv2Target) -> Result<ConnPair<M>, Error> {
        match target {
            Sv2Target::Tcp { .. } => self.tcp.connect(target).await,

            #[cfg(feature = "iroh-transport")]
            Sv2Target::Iroh { .. } => match &self.iroh {
                Some(iroh) => iroh.connect(target).await,
                None => Err(Error::WrongTargetForTransport(
                    "CompositeSv2Connector: Sv2Target::Iroh requested but no iroh connector \
                     was wired (iroh-transport feature disabled or iroh config absent)"
                        .to_string(),
                )),
            },
        }
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

        let bound = listener.local_addr().expect("local_addr");

        let server_task = tokio::spawn(async move {
            let (peer, (rx, tx)) = <TcpSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(
                &listener,
            )
            .await
            .expect("accept");
            // TCP listener does not learn the peer's authority pubkey.
            assert!(peer.authority_pubkey.is_none(), "TCP listener peer should be anonymous");
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
        let (rx, tx) = <TcpSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
            &connector, &target,
        )
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

    /// `TcpSv2Connector` cannot dial a pure-iroh target; the dial must fail
    /// with [`Error::WrongTargetForTransport`] rather than silently doing
    /// something else.
    #[cfg(feature = "iroh-transport")]
    #[tokio::test]
    async fn tcp_connector_rejects_iroh_target() {
        use ::iroh::{EndpointAddr, SecretKey};

        let secret = SecretKey::generate();
        let node_id = secret.public();
        let node_addr = EndpointAddr::new(node_id);

        let connector = TcpSv2Connector::new();
        let target = Sv2Target::Iroh {
            node_addr,
            authority_pubkey: None,
        };

        let res = <TcpSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
            &connector, &target,
        )
        .await;

        match res {
            Err(Error::WrongTargetForTransport(_)) => {}
            other => panic!("expected WrongTargetForTransport, got {other:?}"),
        }
    }

}
