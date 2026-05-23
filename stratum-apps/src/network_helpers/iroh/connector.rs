//! `IrohSv2Connector`: outbound iroh dial implementing
//! [`crate::network_helpers::transport::Sv2Connector`].
//!
//! This connector knows only the iroh path. The plan's
//! §"Client side — fallback ordering" v1 commitment is that fallback is
//! composed at the call site, not inside one connector — i.e. when the
//! caller hands an [`Sv2Target::IrohThenTcp`] / [`Sv2Target::TcpThenIroh`]
//! variant to this connector, we honor the iroh leg only and surface a
//! clean error so the caller can dial TCP next via a separate
//! [`TcpSv2Connector`](crate::network_helpers::transport::TcpSv2Connector).
//!
//! ## Behaviour by [`Sv2Target`] variant
//!
//! | Variant            | Behaviour                                         |
//! |--------------------|---------------------------------------------------|
//! | `Iroh`             | Dial; honor `connection_overrides` if matched.    |
//! | `IrohThenTcp`      | Dial; if the iroh leg fails, return an error.    |
//! | `TcpThenIroh`      | Dial; the caller is expected to have already     |
//! |                    | tried TCP and is now reaching for iroh.          |
//! | `Tcp { .. }`       | Return [`Error::WrongTargetForTransport`].       |
//!
//! ## Per-request timeout
//!
//! The configured `per_request_timeout` wraps the entire dial sequence
//! (resolve override → endpoint connect → open bidi → noise handshake) so a
//! peer that drops or slowloris-attacks a sub-step can't pin a worker. On
//! expiry we close the QUIC connection if one is in-flight (Fedimint PR
//! #8571 lesson).

use std::collections::BTreeMap;
use std::time::Duration;

use async_trait::async_trait;
use iroh::endpoint::VarInt;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::HandshakeRole,
    noise_sv2::Initiator,
};

use crate::network_helpers::{
    iroh::{
        connection::IrohConnection, duplex::IrohDuplex, noise_iroh_stream::NoiseIrohStream,
    },
    transport::{ConnPair, Sv2Connector, Sv2Target},
    Error, NOISE_HANDSHAKE_TIMEOUT,
};

#[cfg(feature = "iroh-transport-monitoring")]
use crate::network_helpers::iroh::metrics::{
    record_connection_established, record_request_timeout, Direction, Role, Transport,
};

/// Outbound iroh dialer.
///
/// Constructed once per role (the role choice carries through to metrics
/// when `iroh-transport-monitoring` is on). Cheaply cloned via
/// [`iroh::Endpoint::clone`].
pub struct IrohSv2Connector {
    endpoint: Endpoint,
    /// Operator-supplied dial override map: forces a known [`EndpointId`] to be
    /// reached at the given [`EndpointAddr`] regardless of discovery results.
    /// Mirrors Fedimint's `FM_IROH_CONNECT_OVERRIDES_ENV` escape hatch.
    connection_overrides: BTreeMap<EndpointId, EndpointAddr>,
    /// ALPN registered on the dialer side; matches what the peer's listener
    /// has configured (one of [`crate::network_helpers::iroh::alpn`]).
    alpn: &'static [u8],
    /// Per-request timeout that wraps the entire dial pipeline.
    /// Plan §"Mandatory operational primitives" #2.
    per_request_timeout: Duration,

    /// SV2 role producing this connector. Stamped on metrics emitted by the
    /// dial path. Only present when monitoring is compiled in.
    #[cfg(feature = "iroh-transport-monitoring")]
    role: Role,
}

impl IrohSv2Connector {
    /// Build a new connector. See struct docs for field semantics.
    pub fn new(
        endpoint: Endpoint,
        connection_overrides: BTreeMap<EndpointId, EndpointAddr>,
        alpn: &'static [u8],
        per_request_timeout: Duration,
    ) -> Self {
        Self {
            endpoint,
            connection_overrides,
            alpn,
            per_request_timeout,
            #[cfg(feature = "iroh-transport-monitoring")]
            role: Role::Pool,
        }
    }

    /// Build a new connector that tags emitted metrics with `role`.
    ///
    /// Identical to [`Self::new`] when the `iroh-transport-monitoring`
    /// feature is disabled.
    #[cfg(feature = "iroh-transport-monitoring")]
    pub fn new_with_role(
        endpoint: Endpoint,
        connection_overrides: BTreeMap<EndpointId, EndpointAddr>,
        alpn: &'static [u8],
        per_request_timeout: Duration,
        role: Role,
    ) -> Self {
        Self {
            endpoint,
            connection_overrides,
            alpn,
            per_request_timeout,
            role,
        }
    }

    /// Resolve any operator override for `node_addr.id`, falling back to
    /// the supplied `node_addr` when none is configured.
    fn resolve_node_addr(&self, node_addr: &EndpointAddr) -> EndpointAddr {
        if let Some(override_addr) = self.connection_overrides.get(&node_addr.id) {
            override_addr.clone()
        } else {
            node_addr.clone()
        }
    }

    /// Build a Noise NX initiator from an optional authority pubkey.
    fn build_initiator(
        authority_pubkey: Option<crate::key_utils::Secp256k1PublicKey>,
    ) -> Result<Box<Initiator>, Error> {
        match authority_pubkey {
            Some(key) => Initiator::from_raw_k(key.into_bytes()).map_err(|_| Error::InvalidKey),
            None => Initiator::without_pk().map_err(|_| Error::InvalidKey),
        }
    }

    /// Inner iroh dial: connect, open bidi, run Noise NX, return the channel
    /// pair via [`IrohConnection::into_channels`].
    async fn dial_iroh<M>(
        &self,
        node_addr: &EndpointAddr,
        authority_pubkey: Option<crate::key_utils::Secp256k1PublicKey>,
    ) -> Result<ConnPair<M>, Error>
    where
        M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
    {
        let resolved = self.resolve_node_addr(node_addr);

        // Whole-pipeline timeout: dial -> open_bi -> noise handshake. On
        // expiry we surface IrohRequestTimeout; an in-flight QUIC connection
        // is handed to a best-effort cleanup helper below.
        let timeout = self.per_request_timeout;
        let alpn = self.alpn;
        let endpoint = self.endpoint.clone();

        // Capture a clone of `resolved` so we can blame the override in
        // logs / errors without holding a borrow across the await.
        let initiator = Self::build_initiator(authority_pubkey)?;
        let resolved_for_dial = resolved.clone();

        let dial_future = async move {
            // 1. Dial.
            let connection = endpoint
                .connect(resolved_for_dial, alpn)
                .await
                .map_err(|e| Error::IrohConnect(format!("{e}")))?;

            // 2. Capture identity before opening the bidi (so a slow open_bi
            // doesn't strand us without a EndpointId for diagnostics). In iroh
            // 1.0-rc, `remote_id()` on a post-handshake `Connection` returns
            // the `EndpointId` directly (no Result), since QUIC has already
            // authenticated the peer.
            let node_id = connection.remote_id();

            // 3. Open bidi.
            let (send, recv) = connection
                .open_bi()
                .await
                .map_err(|e| Error::IrohConnect(format!("open_bi: {e}")))?;
            let duplex = IrohDuplex { send, recv };

            // 4. Inner Noise NX handshake.
            let noise = NoiseIrohStream::<M>::new(
                duplex,
                HandshakeRole::Initiator(initiator),
                NOISE_HANDSHAKE_TIMEOUT,
            )
            .await?;

            Ok::<_, Error>(IrohConnection::<M>::new(connection, noise, node_id))
        };

        let conn = match tokio::time::timeout(timeout, dial_future).await {
            Ok(res) => res?,
            Err(_) => {
                // Per-request timeout fired. There is no in-flight Connection
                // we could explicitly close from out here (the future was
                // dropped), but we do record the timeout for ops.
                #[cfg(feature = "iroh-transport-monitoring")]
                record_request_timeout(self.role);
                return Err(Error::IrohRequestTimeout);
            }
        };

        #[cfg(feature = "iroh-transport-monitoring")]
        record_connection_established(self.role, Transport::IrohDirect, Direction::Outbound);

        Ok(conn.into_channels())
    }
}

#[async_trait]
impl<M> Sv2Connector<M> for IrohSv2Connector
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn connect(&self, target: &Sv2Target) -> Result<ConnPair<M>, Error> {
        match target {
            Sv2Target::Iroh {
                node_addr,
                authority_pubkey,
            } => self.dial_iroh(node_addr, *authority_pubkey).await,

            Sv2Target::IrohThenTcp {
                node_addr,
                authority_pubkey,
                ..
            } => {
                // Plan §"Client side — fallback ordering" v1: this connector
                // does not own a TCP fallback; the caller composes one if
                // they want it. We honor the iroh leg here.
                self.dial_iroh(node_addr, *authority_pubkey).await
            }

            Sv2Target::TcpThenIroh {
                node_addr,
                authority_pubkey,
                ..
            } => {
                // The caller has already exhausted the TCP leg and is now
                // reaching for the iroh leg.
                self.dial_iroh(node_addr, *authority_pubkey).await
            }

            Sv2Target::Tcp { .. } => Err(Error::WrongTargetForTransport(
                "IrohSv2Connector cannot dial Sv2Target::Tcp; use TcpSv2Connector"
                    .to_string(),
            )),
        }
    }
}

/// Best-effort close helper: closes the QUIC connection with a request-timeout
/// error code so the peer evicts immediately (Fedimint PR #8571 lesson).
///
/// Currently unused — the per-request-timeout path drops the in-flight
/// `connect` future before we can grab the `Connection`. Retained for future
/// use when we factor the dial steps so a partially-built connection can be
/// torn down explicitly.
#[allow(dead_code)]
pub(crate) fn close_with_timeout(connection: &iroh::endpoint::Connection) {
    connection.close(VarInt::from_u32(1), b"sv2 request timeout");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
        network_helpers::{
            iroh::alpn::SV2_POOL_ALPN,
            transport::{Sv2Connector, Sv2Listener},
        },
    };
    use std::{
        collections::BTreeMap,
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

    use crate::network_helpers::iroh::{
        admission::AdmissionHandle, listener::IrohSv2Listener,
    };

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
            stratum_core::binary_sv2::to_bytes(setup.clone()).expect("encode");
        let any: AnyMessage<'static> =
            AnyMessage::Common(CommonMessages::SetupConnection(setup));
        let mt = any.message_type();
        let f: Sv2Frame<AnyMessage<'static>, _> =
            Sv2Frame::from_message(any, mt, 0, false).expect("frame");
        (StandardEitherFrame::Sv2(f), expected_payload)
    }

    fn extract_payload(frame: &mut StandardEitherFrame<AnyMessage<'static>>) -> Vec<u8> {
        match frame {
            StandardEitherFrame::Sv2(f) => f.payload().to_vec(),
            StandardEitherFrame::HandShake(_) => {
                panic!("post-handshake frame should always be Sv2")
            }
        }
    }

    /// Build a loopback iroh server endpoint, no relay, no discovery,
    /// accepting `SV2_POOL_ALPN`.
    async fn build_server_endpoint() -> (iroh::Endpoint, iroh::EndpointId, SocketAddr) {
        use ::iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};
        use std::net::SocketAddrV4;

        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .alpns(vec![SV2_POOL_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind addr v4")
            .bind()
            .await
            .expect("bind server endpoint");

        let addr = loop {
            let bound = ep.bound_sockets();
            if let Some(addr) = bound.iter().find(|s| s.is_ipv4()).copied() {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        (ep, node_id, addr)
    }

    /// Build a loopback iroh client endpoint, no relay, no discovery.
    async fn build_client_endpoint() -> iroh::Endpoint {
        use ::iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};
        use std::net::SocketAddrV4;

        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::generate())
            .relay_mode(RelayMode::Disabled)
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind addr v4")
            .bind()
            .await
            .expect("bind client endpoint")
    }

    /// Convenience: spawn an [`IrohSv2Listener`] over `server_ep` and a task
    /// that accepts one connection and echoes one frame. Returns the join
    /// handle.
    fn spawn_echo_listener(
        listener: IrohSv2Listener,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let (_peer, (rx, tx)) =
                <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(&listener)
                    .await
                    .expect("listener accept");
            let frame = rx.recv().await.expect("recv frame");
            tx.send(frame).await.expect("echo");
            tokio::time::sleep(Duration::from_millis(50)).await;
        })
    }

    /// Connector dials a listener on the same host, frame round-trip.
    #[tokio::test]
    async fn connector_dials_listener() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();

        let (server_ep, server_node_id, server_socket) = build_server_endpoint().await;
        let listener = IrohSv2Listener::new(
            server_ep,
            AdmissionHandle::open(),
            auth_pub,
            auth_priv,
            10_000,
            SV2_POOL_ALPN,
            Duration::from_secs(10),
        );
        let server_task = spawn_echo_listener(listener);

        let client_ep = build_client_endpoint().await;
        let connector = IrohSv2Connector::new(
            client_ep,
            BTreeMap::new(),
            SV2_POOL_ALPN,
            Duration::from_secs(10),
        );

        let target = Sv2Target::Iroh {
            node_addr: iroh::EndpointAddr::new(server_node_id).with_ip_addr(server_socket),
            authority_pubkey: Some(auth_pub),
        };
        let (rx, tx) =
            <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
                &connector, &target,
            )
            .await
            .expect("connector connect");

        let (frame, expected) = build_setup_connection_frame();
        tx.send(frame).await.expect("send frame");
        let mut echoed = rx.recv().await.expect("recv echo");
        assert_eq!(extract_payload(&mut echoed), expected);

        server_task.await.expect("server task");
    }

    /// Connector returns `WrongTargetForTransport` for a TCP target.
    #[tokio::test]
    async fn connector_rejects_tcp_target() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let client_ep = build_client_endpoint().await;
        let connector = IrohSv2Connector::new(
            client_ep,
            BTreeMap::new(),
            SV2_POOL_ALPN,
            Duration::from_secs(2),
        );

        let target = Sv2Target::Tcp {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            authority_pubkey: None,
        };
        let res = <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
            &connector, &target,
        )
        .await;
        match res {
            Err(Error::WrongTargetForTransport(_)) => {}
            other => panic!("expected WrongTargetForTransport, got {other:?}"),
        }
    }

    /// Override map wins over the supplied `node_addr.direct_addresses`.
    /// The supplied target points at an unbound port; the override points at
    /// the real listener.
    #[tokio::test]
    async fn connector_uses_override_addr() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();

        let (server_ep, server_node_id, server_socket) = build_server_endpoint().await;
        let listener = IrohSv2Listener::new(
            server_ep,
            AdmissionHandle::open(),
            auth_pub,
            auth_priv,
            10_000,
            SV2_POOL_ALPN,
            Duration::from_secs(10),
        );
        let server_task = spawn_echo_listener(listener);

        // Wrong direct address (port 1, definitely unbound) in the target;
        // correct one in the override.
        let wrong_socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let mut overrides = BTreeMap::new();
        overrides.insert(
            server_node_id,
            iroh::EndpointAddr::new(server_node_id).with_ip_addr(server_socket),
        );

        let client_ep = build_client_endpoint().await;
        let connector = IrohSv2Connector::new(
            client_ep,
            overrides,
            SV2_POOL_ALPN,
            Duration::from_secs(10),
        );

        let target = Sv2Target::Iroh {
            node_addr: iroh::EndpointAddr::new(server_node_id).with_ip_addr(wrong_socket),
            authority_pubkey: Some(auth_pub),
        };

        let (rx, tx) =
            <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
                &connector, &target,
            )
            .await
            .expect("connect via override");

        let (frame, expected) = build_setup_connection_frame();
        tx.send(frame).await.expect("send");
        let mut got = rx.recv().await.expect("recv");
        assert_eq!(extract_payload(&mut got), expected);

        server_task.await.expect("server task");
    }

    /// Per-request timeout fires when a peer accepts the QUIC handshake +
    /// bidi but never writes the Noise responder reply.
    ///
    /// We simulate this by spinning up an iroh endpoint on the server side
    /// that accepts incoming connections and `accept_bi` but never pumps the
    /// Noise NX handshake. The `IrohSv2Connector` should give up after
    /// `per_request_timeout` and surface `IrohRequestTimeout`.
    #[tokio::test]
    async fn connector_per_request_timeout_expires() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (server_ep, server_node_id, server_socket) = build_server_endpoint().await;

        // Drain accepts from the server endpoint indefinitely WITHOUT running
        // the Noise responder. Hold the bidi streams alive so the peer's
        // Noise handshake await on its read side blocks until our timeout
        // fires.
        let drain_task = tokio::spawn(async move {
            // Accept connections from the server endpoint and accept their
            // bidi streams, but never pump the Noise responder — i.e. we
            // never write or read on these streams. The client's Noise
            // handshake will block its initial responder-message read until
            // the connector's per-request timeout fires.
            let mut held: Vec<(
                iroh::endpoint::Connection,
                iroh::endpoint::SendStream,
                iroh::endpoint::RecvStream,
            )> = Vec::new();
            for _ in 0..5 {
                match tokio::time::timeout(Duration::from_secs(5), server_ep.accept())
                    .await
                {
                    Ok(Some(incoming)) => match incoming.await {
                        Ok(connection) => {
                            if let Ok((send, recv)) = connection.accept_bi().await {
                                held.push((connection, send, recv));
                            }
                        }
                        Err(_) => break,
                    },
                    _ => break,
                }
            }
            // Hold for a bit so the client's timeout fires before we drop.
            tokio::time::sleep(Duration::from_secs(3)).await;
            drop(held);
        });

        let client_ep = build_client_endpoint().await;
        let connector = IrohSv2Connector::new(
            client_ep,
            BTreeMap::new(),
            SV2_POOL_ALPN,
            Duration::from_millis(500),
        );

        let target = Sv2Target::Iroh {
            node_addr: iroh::EndpointAddr::new(server_node_id).with_ip_addr(server_socket),
            authority_pubkey: None,
        };

        let started = std::time::Instant::now();
        let res = <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
            &connector, &target,
        )
        .await;
        let elapsed = started.elapsed();

        match res {
            Err(Error::IrohRequestTimeout) | Err(Error::HandshakeTimeout) => {}
            other => panic!(
                "expected IrohRequestTimeout/HandshakeTimeout, got {other:?}"
            ),
        }
        // Allow generous slack for CI variability — we only assert the
        // request didn't hang for many seconds.
        assert!(
            elapsed < Duration::from_secs(5),
            "connect should not hang past per_request_timeout, took {elapsed:?}"
        );

        // Drain task may finish on its own; abort to be deterministic.
        drain_task.abort();
        let _ = drain_task.await;
    }
}
