//! `IrohSv2Listener`: inbound iroh accept implementing
//! [`crate::network_helpers::transport::Sv2Listener`].
//!
//! Accept flow (matches plan §"Two-layer identity model"):
//!
//! 1. `endpoint.accept()` yields the next QUIC handshake attempt.
//! 2. Awaiting the `Connecting` produces an [`iroh::endpoint::Connection`].
//! 3. We extract the remote EndpointId from the peer certificate.
//! 4. **Admission check.** No SV2 bytes flow before this. Denials close the
//!    QUIC connection with a clear reason.
//! 5. ALPN check. iroh enforces ALPN at the QUIC layer for any ALPN
//!    configured on the endpoint, but we additionally compare against
//!    `self.alpn` so a misconfigured endpoint that registers multiple ALPNs
//!    cannot leak a connection cross-role.
//! 6. `accept_bi()` produces the (send, recv) bidi pair the initiator opens.
//! 7. Run the SV2 Noise NX responder handshake inside the bidi stream.
//! 8. Build an [`IrohConnection`] and convert it to a channel pair.
//!
//! The whole pipeline (steps 2..7) is wrapped in `per_request_timeout` so a
//! peer that opens QUIC but never writes the Noise initiator-message can't
//! pin a worker (Fedimint PR #8571 lesson).

use std::time::Duration;

use async_trait::async_trait;
use iroh::endpoint::VarInt;
use iroh::Endpoint;
use stratum_core::{
    binary_sv2::{Deserialize, GetSize, Serialize},
    codec_sv2::HandshakeRole,
    noise_sv2::Responder,
};
use tracing::{debug, warn};

use crate::{
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::{
        iroh::{
            admission::AdmissionHandle, connection::IrohConnection, duplex::IrohDuplex,
            noise_iroh_stream::NoiseIrohStream,
        },
        transport::{ConnPair, PeerIdentity, Sv2Listener},
        Error, NOISE_HANDSHAKE_TIMEOUT,
    },
};

#[cfg(feature = "iroh-transport-monitoring")]
use crate::network_helpers::iroh::metrics::{
    record_admission_denied, record_connection_established, record_connection_rejected,
    record_request_timeout, AdmissionDenyReason, Direction, RejectReason, Role, Transport,
};

/// Inbound iroh listener.
pub struct IrohSv2Listener {
    endpoint: Endpoint,
    admission: AdmissionHandle,
    sv2_pub: Secp256k1PublicKey,
    sv2_priv: Secp256k1SecretKey,
    cert_validity: u64,
    /// ALPN this listener is willing to terminate. Unmatched ALPNs (when an
    /// endpoint is configured with more than one) are closed with an
    /// AlpnMismatch reason.
    alpn: &'static [u8],
    per_request_timeout: Duration,

    /// SV2 role producing this listener. Stamped on metrics emitted by the
    /// accept path. Only present when monitoring is compiled in.
    #[cfg(feature = "iroh-transport-monitoring")]
    role: Role,
}

impl IrohSv2Listener {
    /// Build a new listener.
    pub fn new(
        endpoint: Endpoint,
        admission: AdmissionHandle,
        sv2_pub: Secp256k1PublicKey,
        sv2_priv: Secp256k1SecretKey,
        cert_validity: u64,
        alpn: &'static [u8],
        per_request_timeout: Duration,
    ) -> Self {
        Self {
            endpoint,
            admission,
            sv2_pub,
            sv2_priv,
            cert_validity,
            alpn,
            per_request_timeout,
            #[cfg(feature = "iroh-transport-monitoring")]
            role: Role::Pool,
        }
    }

    /// Build a new listener that tags emitted metrics with `role`.
    ///
    /// Identical to [`Self::new`] when the `iroh-transport-monitoring`
    /// feature is disabled.
    #[cfg(feature = "iroh-transport-monitoring")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_role(
        endpoint: Endpoint,
        admission: AdmissionHandle,
        sv2_pub: Secp256k1PublicKey,
        sv2_priv: Secp256k1SecretKey,
        cert_validity: u64,
        alpn: &'static [u8],
        per_request_timeout: Duration,
        role: Role,
    ) -> Self {
        Self {
            endpoint,
            admission,
            sv2_pub,
            sv2_priv,
            cert_validity,
            alpn,
            per_request_timeout,
            role,
        }
    }

    /// Cheaply-cloned admission handle for runtime whitelist updates.
    ///
    /// All clones share a single underlying [`arc_swap::ArcSwap`], so any
    /// caller can mutate the whitelist and the change is visible on the
    /// next accept.
    pub fn admission(&self) -> AdmissionHandle {
        self.admission.clone()
    }
}

#[async_trait]
impl<M> Sv2Listener<M> for IrohSv2Listener
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    async fn accept(&self) -> Result<(PeerIdentity, ConnPair<M>), Error> {
        // Step 1: take the next incoming attempt. `accept` returns `None`
        // when the endpoint is closed.
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(Error::SocketClosed)?;

        // Wrap steps 2..7 in the per-request timeout so a slow / slowloris
        // peer can't pin our accept loop.
        let pipeline = async {
            // Step 2: complete the QUIC handshake.
            let connection = incoming.await.map_err(|e| {
                #[cfg(feature = "iroh-transport-monitoring")]
                record_connection_rejected(
                    self.role,
                    Direction::Inbound,
                    RejectReason::QuicFailed,
                );
                Error::IrohAccept(format!("quic handshake: {e}"))
            })?;

            // Step 3: derive remote EndpointId. iroh extracts this from the peer
            // TLS certificate. In iroh 1.0-rc, `remote_id()` on a post-handshake
            // `Connection` returns the `EndpointId` directly (no Result), since
            // the QUIC handshake already authenticated the peer.
            let node_id = connection.remote_id();

            // Step 4: admission check. Denials close with a clear reason;
            // *no SV2 bytes flow before this.*
            if !self.admission.admits(&node_id) {
                debug!(
                    %node_id,
                    "iroh listener: admission denied; closing QUIC connection"
                );
                connection.close(VarInt::from_u32(2), b"node not in whitelist");
                #[cfg(feature = "iroh-transport-monitoring")]
                {
                    record_admission_denied(
                        self.role,
                        AdmissionDenyReason::NotInWhitelist,
                    );
                    record_connection_rejected(
                        self.role,
                        Direction::Inbound,
                        RejectReason::Admission,
                    );
                }
                return Err(Error::IrohAdmissionDenied);
            }

            // Step 5: ALPN check. iroh enforces ALPN at the QUIC handshake
            // for any ALPN configured on the endpoint; this extra check
            // catches the case where an endpoint is configured with
            // multiple ALPNs (see `Endpoint::builder().alpns`) and a
            // listener instance only wants its own role's ALPN.
            //
            // In iroh 1.0-rc, `Connection<HandshakeCompleted>::alpn()` returns
            // `&[u8]` directly (post-handshake the ALPN is always known).
            let observed = connection.alpn();
            if observed != self.alpn {
                warn!(
                    observed = %String::from_utf8_lossy(observed),
                    expected = %String::from_utf8_lossy(self.alpn),
                    "iroh listener: ALPN mismatch; closing connection"
                );
                connection.close(VarInt::from_u32(3), b"alpn mismatch");
                #[cfg(feature = "iroh-transport-monitoring")]
                record_connection_rejected(
                    self.role,
                    Direction::Inbound,
                    RejectReason::AlpnMismatch,
                );
                return Err(Error::IrohAccept(format!(
                    "ALPN mismatch: observed={:?} expected={:?}",
                    observed, self.alpn
                )));
            }

            // Step 6: accept the bidi stream the initiator will open.
            let (send, recv) = connection.accept_bi().await.map_err(|e| {
                #[cfg(feature = "iroh-transport-monitoring")]
                record_connection_rejected(
                    self.role,
                    Direction::Inbound,
                    RejectReason::QuicFailed,
                );
                Error::IrohAccept(format!("accept_bi: {e}"))
            })?;
            let duplex = IrohDuplex { send, recv };

            // Step 7: SV2 Noise NX responder handshake.
            let responder = Responder::from_authority_kp(
                &self.sv2_pub.into_bytes(),
                &self.sv2_priv.into_bytes(),
                Duration::from_secs(self.cert_validity),
            )
            .map_err(|_| Error::InvalidKey)?;
            let noise = NoiseIrohStream::<M>::new(
                duplex,
                HandshakeRole::Responder(responder),
                NOISE_HANDSHAKE_TIMEOUT,
            )
            .await
            .inspect_err(|_e| {
                // Try to close the QUIC connection cleanly so the peer
                // gets a meaningful CONNECTION_CLOSE rather than an
                // idle-timeout.
                connection.close(VarInt::from_u32(4), b"sv2 noise failed");
                #[cfg(feature = "iroh-transport-monitoring")]
                record_connection_rejected(
                    self.role,
                    Direction::Inbound,
                    RejectReason::NoiseFailed,
                );
            })?;

            // Step 8: bundle and convert to the channel pair.
            let conn = IrohConnection::<M>::new(connection, noise, node_id);
            Ok::<_, Error>((node_id, conn))
        };

        let (node_id, conn) = match tokio::time::timeout(
            self.per_request_timeout,
            pipeline,
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => {
                #[cfg(feature = "iroh-transport-monitoring")]
                record_request_timeout(self.role);
                return Err(Error::IrohRequestTimeout);
            }
        };

        let pair = conn.into_channels();

        #[cfg(feature = "iroh-transport-monitoring")]
        record_connection_established(self.role, Transport::IrohDirect, Direction::Inbound);

        // PeerIdentity: Noise NX is server-only auth; the client doesn't
        // present an authority pubkey to us. Surface only the QUIC-layer
        // EndpointId.
        let peer = PeerIdentity {
            authority_pubkey: None,
            iroh_node_id: Some(node_id),
        };
        Ok((peer, pair))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
        network_helpers::{
            iroh::{alpn::SV2_POOL_ALPN, connector::IrohSv2Connector},
            transport::{Sv2Connector, Sv2Listener, Sv2Target},
        },
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };
    use stratum_core::{
        binary_sv2::{Str0255, B0255},
        codec_sv2::StandardEitherFrame,
        common_messages_sv2::{Protocol, SetupConnection},
        framing_sv2::framing::Sv2Frame,
        parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message},
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
    /// Returns the endpoint and its EndpointId.
    async fn build_client_endpoint() -> (iroh::Endpoint, iroh::EndpointId) {
        use ::iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};

        let secret = SecretKey::generate();
        let node_id = secret.public();
        let ep = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .relay_mode(RelayMode::Disabled)
            .bind_addr(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind addr v4")
            .bind()
            .await
            .expect("bind client endpoint");
        (ep, node_id)
    }

    /// Whitelist mode: a known EndpointId is admitted and a frame round-trips.
    #[tokio::test]
    async fn listener_admits_known_node_id() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();
        let (server_ep, server_node_id, server_socket) = build_server_endpoint().await;
        let (client_ep, client_node_id) = build_client_endpoint().await;

        let mut allowed = BTreeSet::new();
        allowed.insert(client_node_id);
        let admission = AdmissionHandle::whitelist(allowed);

        let listener = IrohSv2Listener::new(
            server_ep,
            admission,
            auth_pub,
            auth_priv,
            10_000,
            SV2_POOL_ALPN,
            Duration::from_secs(10),
        );

        let server_task = tokio::spawn(async move {
            let (peer, (rx, tx)) =
                <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(&listener)
                    .await
                    .expect("accept admitted peer");
            assert_eq!(peer.iroh_node_id, Some(client_node_id));
            assert!(peer.authority_pubkey.is_none(), "Noise NX is server-only auth");
            let frame = rx.recv().await.expect("recv");
            tx.send(frame).await.expect("echo");
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

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
            .expect("connect");

        let (frame, expected) = build_setup_connection_frame();
        tx.send(frame).await.expect("send");
        let mut got = rx.recv().await.expect("recv");
        assert_eq!(extract_payload(&mut got), expected);

        server_task.await.expect("server task");
    }

    /// Whitelist mode: an unknown EndpointId is rejected and the dialer's
    /// follow-on traffic fails because the QUIC connection was closed
    /// before any SV2 bytes flowed.
    #[tokio::test]
    async fn listener_rejects_unknown_node_id() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let (auth_pub, auth_priv) = test_keypair();
        let (server_ep, server_node_id, server_socket) = build_server_endpoint().await;
        let (client_ep, _client_node_id) = build_client_endpoint().await;

        // Whitelist some OTHER node id; the real client is not on the list.
        let other = ::iroh::SecretKey::generate().public();
        let mut allowed = BTreeSet::new();
        allowed.insert(other);
        let admission = AdmissionHandle::whitelist(allowed);

        let listener = IrohSv2Listener::new(
            server_ep,
            admission,
            auth_pub,
            auth_priv,
            10_000,
            SV2_POOL_ALPN,
            Duration::from_secs(2),
        );

        // Server task: expect IrohAdmissionDenied. (If the dialer aborts
        // its half of the QUIC handshake before the listener gets to the
        // admission check, an `IrohAccept(quic handshake)` is also a
        // legitimate outcome — the listener still didn't admit the peer
        // and no SV2 bytes flowed; what matters for this test is that the
        // accept did not produce a successful (PeerIdentity, ConnPair).)
        let server_task = tokio::spawn(async move {
            let res = <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(
                &listener,
            )
            .await;
            match res {
                Err(Error::IrohAdmissionDenied) => {}
                Err(Error::IrohAccept(_)) | Err(Error::IrohRequestTimeout) => {}
                Ok(_) => panic!("listener must NOT admit unknown EndpointId"),
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        });

        // Client: dial and observe failure. The connector tries to dial,
        // open_bi, run noise — depending on timing, any of those may fail
        // because the listener closed the QUIC connection before
        // accepting the bidi.
        let connector = IrohSv2Connector::new(
            client_ep,
            BTreeMap::new(),
            SV2_POOL_ALPN,
            Duration::from_secs(2),
        );
        let target = Sv2Target::Iroh {
            node_addr: iroh::EndpointAddr::new(server_node_id).with_ip_addr(server_socket),
            authority_pubkey: Some(auth_pub),
        };
        let res = <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
            &connector, &target,
        )
        .await;
        // The dial MUST NOT succeed (listener closed the QUIC connection
        // before SV2 bytes flowed). It can fail in various ways depending
        // on which step lost the race; assert any error variant.
        assert!(res.is_err(), "expected connect to fail after admission denial");

        server_task.await.expect("server task");
    }

    /// Open mode admits any EndpointId — confirm two distinct dialers both
    /// connect successfully against the same listener (sequentially).
    #[tokio::test]
    async fn listener_open_admits_all() {
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

        // Run twice: each iteration uses a fresh client endpoint with a
        // fresh EndpointId.
        for i in 0..2 {
            let (client_ep, _client_node_id) = build_client_endpoint().await;
            let server_handle = {
                let l = &listener;
                async move {
                    let (peer, (rx, tx)) =
                        <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(l)
                            .await
                            .expect("accept");
                    assert!(peer.iroh_node_id.is_some());
                    let frame = rx.recv().await.expect("recv");
                    tx.send(frame).await.expect("echo");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };

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

            let client_handle = async {
                let (rx, tx) =
                    <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
                        &connector, &target,
                    )
                    .await
                    .expect("connect");
                let (frame, expected) = build_setup_connection_frame();
                tx.send(frame).await.expect("send");
                let mut got = rx.recv().await.expect("recv");
                assert_eq!(
                    extract_payload(&mut got),
                    expected,
                    "iter {i}: round-trip"
                );
            };

            tokio::join!(server_handle, client_handle);
        }
    }

    /// Switching the admission policy at runtime affects subsequent dials
    /// without disturbing in-flight connections.
    ///
    /// We dial once under [`AdmissionPolicy::Open`], hold the resulting
    /// channel pair open, then mutate the listener's whitelist to exclude
    /// the next dialer. The original connection keeps round-tripping; the
    /// next dial fails.
    #[tokio::test]
    async fn listener_runtime_whitelist_update() {
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
        let admission = listener.admission();

        // First connection: open policy admits everyone.
        let (client_ep_1, _client_node_id_1) = build_client_endpoint().await;
        let listener_arc = std::sync::Arc::new(listener);
        let l1 = listener_arc.clone();
        let server1 = tokio::spawn(async move {
            let (_peer, (rx, tx)) =
                <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(
                    l1.as_ref(),
                )
                .await
                .expect("accept first");
            // Echo loop: keep it alive across the whitelist mutation below.
            for _ in 0..3 {
                match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                    Ok(Ok(frame)) => {
                        tx.send(frame).await.ok();
                    }
                    _ => break,
                }
            }
        });

        let connector_1 = IrohSv2Connector::new(
            client_ep_1,
            BTreeMap::new(),
            SV2_POOL_ALPN,
            Duration::from_secs(10),
        );
        let target_1 = Sv2Target::Iroh {
            node_addr: iroh::EndpointAddr::new(server_node_id).with_ip_addr(server_socket),
            authority_pubkey: Some(auth_pub),
        };
        let (rx_1, tx_1) =
            <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
                &connector_1, &target_1,
            )
            .await
            .expect("first dial under Open");

        // Round-trip one frame to confirm liveness.
        let (frame, expected) = build_setup_connection_frame();
        tx_1.send(frame).await.expect("send 1");
        let mut got = rx_1.recv().await.expect("recv 1");
        assert_eq!(extract_payload(&mut got), expected);

        // Mutate whitelist to exclude any future dialer (we set a list with
        // some random EndpointId that doesn't match our second client).
        let stranger = ::iroh::SecretKey::generate().public();
        let mut wl = BTreeSet::new();
        wl.insert(stranger);
        admission.set_policy(crate::network_helpers::iroh::admission::AdmissionPolicy::Whitelist(wl));

        // Existing connection still works.
        let (frame_b, expected_b) = build_setup_connection_frame();
        tx_1.send(frame_b).await.expect("send after whitelist change");
        let mut got_b = rx_1.recv().await.expect("recv after whitelist change");
        assert_eq!(
            extract_payload(&mut got_b),
            expected_b,
            "in-flight connection must be unaffected by admission change"
        );

        // New dial must fail (listener task accepts and finds the new
        // dialer not in whitelist).
        let (client_ep_2, _client_node_id_2) = build_client_endpoint().await;
        let l2 = listener_arc.clone();
        let server2 = tokio::spawn(async move {
            let res = <IrohSv2Listener as Sv2Listener<AnyMessage<'static>>>::accept(
                l2.as_ref(),
            )
            .await;
            match res {
                Err(Error::IrohAdmissionDenied) => {}
                Err(Error::IrohAccept(_)) | Err(Error::IrohRequestTimeout) => {}
                Ok(_) => panic!("listener must NOT admit non-whitelisted EndpointId"),
                Err(other) => panic!("unexpected error on 2nd accept: {other:?}"),
            }
        });

        let connector_2 = IrohSv2Connector::new(
            client_ep_2,
            BTreeMap::new(),
            SV2_POOL_ALPN,
            Duration::from_secs(5),
        );
        let target_2 = Sv2Target::Iroh {
            node_addr: iroh::EndpointAddr::new(server_node_id).with_ip_addr(server_socket),
            authority_pubkey: Some(auth_pub),
        };
        let res2 = <IrohSv2Connector as Sv2Connector<AnyMessage<'static>>>::connect(
            &connector_2, &target_2,
        )
        .await;
        assert!(res2.is_err(), "second dial must fail");

        server2.await.expect("server2");
        // Drop tx_1/rx_1 so the first echo loop's recv unblocks.
        drop(tx_1);
        drop(rx_1);
        let _ = tokio::time::timeout(Duration::from_secs(2), server1).await;
    }
}
