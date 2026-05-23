use crate::{
    interceptor::{InterceptAction, MessageDirection},
    message_aggregator::MessagesAggregator,
    sniffer_error::SnifferError,
    types::{MessageFrame, MsgType},
};
use async_channel::{Receiver, Sender};
use once_cell::sync::Lazy;
use std::{
    collections::HashSet,
    convert::TryInto,
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
};
use stratum_apps::{
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::noise_connection::Connection,
    stratum_core::{
        codec_sv2::{HandshakeRole, StandardEitherFrame},
        framing_sv2::framing::{Frame, Sv2Frame},
        noise_sv2::{Initiator, Responder},
        parsers_sv2::{
            message_type_to_name, parse_message_frame_with_tlvs, AnyMessage, CommonMessages,
            IsSv2Message,
            JobDeclaration::{
                AllocateMiningJobToken, AllocateMiningJobTokenSuccess, DeclareMiningJob,
                DeclareMiningJobError, DeclareMiningJobSuccess, ProvideMissingTransactions,
                ProvideMissingTransactionsSuccess, PushSolution,
            },
            TemplateDistribution,
            TemplateDistribution::CoinbaseOutputConstraints,
            Tlv,
        },
    },
};

// prevents get_available_port from ever returning the same port twice
static UNIQUE_PORTS: Lazy<Mutex<HashSet<u16>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub fn get_available_address() -> SocketAddr {
    let port = get_available_port();
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn get_available_port() -> u16 {
    let mut unique_ports = UNIQUE_PORTS.lock().unwrap();

    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        if !unique_ports.contains(&port) {
            unique_ports.insert(port);
            return port;
        }
    }
}
pub async fn wait_for_client(listen_socket: SocketAddr) -> tokio::net::TcpStream {
    let listener = tokio::net::TcpListener::bind(listen_socket)
        .await
        .expect("Impossible to listen on given address");
    if let Ok((stream, _)) = listener.accept().await {
        stream
    } else {
        panic!("Impossible to accept dowsntream connection")
    }
}

pub async fn create_downstream(
    stream: tokio::net::TcpStream,
) -> Option<(Receiver<MessageFrame>, Sender<MessageFrame>)> {
    let pub_key = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
        .to_string()
        .parse::<Secp256k1PublicKey>()
        .unwrap()
        .into_bytes();
    let prv_key = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
        .to_string()
        .parse::<Secp256k1SecretKey>()
        .unwrap()
        .into_bytes();
    let responder =
        Responder::from_authority_kp(&pub_key, &prv_key, std::time::Duration::from_secs(10000))
            .unwrap();

    if let Ok((receiver_from_client, sender_to_client)) =
        Connection::new::<AnyMessage<'static>>(stream, HandshakeRole::Responder(responder)).await
    {
        Some((receiver_from_client, sender_to_client))
    } else {
        None
    }
}

pub async fn create_upstream(
    stream: tokio::net::TcpStream,
) -> Option<(Receiver<MessageFrame>, Sender<MessageFrame>)> {
    let initiator = Initiator::without_pk().expect("This fn call can not fail");
    if let Ok((receiver_from_server, sender_to_server)) =
        Connection::new::<AnyMessage<'static>>(stream, HandshakeRole::Initiator(initiator)).await
    {
        Some((receiver_from_server, sender_to_server))
    } else {
        None
    }
}

pub async fn recv_from_down_send_to_up(
    recv: Receiver<MessageFrame>,
    send: Sender<MessageFrame>,
    downstream_messages: MessagesAggregator,
    action: Vec<InterceptAction>,
    identifier: &str,
    negotiated_extensions: Arc<Mutex<Vec<u16>>>,
) -> Result<(), SnifferError> {
    while let Ok(mut frame) = recv.recv().await {
        let extensions = negotiated_extensions.lock().unwrap().clone();
        let (msg_type, msg, tlv_fields) = message_from_frame_with_tlvs(&mut frame, &extensions);

        // Track extension negotiation
        if let AnyMessage::Extensions(ref ext_msg) = msg {
            use stratum_apps::stratum_core::parsers_sv2::{Extensions, ExtensionsNegotiation};
            if let Extensions::ExtensionsNegotiation(
                ExtensionsNegotiation::RequestExtensionsSuccess(ref success),
            ) = ext_msg
            {
                let mut exts = negotiated_extensions.lock().unwrap();
                *exts = success.supported_extensions.clone().into_inner();
                tracing::info!(
                    "🔍 Sniffer {} | Tracked negotiated extensions: {:?}",
                    identifier,
                    *exts
                );
            }
        }

        let action = action.iter().find(|action| {
            action
                .find_matching_action(msg_type, MessageDirection::ToUpstream)
                .is_some()
        });
        if let Some(action) = action {
            match action {
                InterceptAction::IgnoreMessage(_) => {
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Ignored: {} | Direction: ⬆",
                        identifier,
                        message_type_to_name(msg_type)
                    );
                    continue;
                }
                InterceptAction::ReplaceMessage(intercept_message) => {
                    let intercept_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(
                            intercept_message.replacement_message.clone(),
                            intercept_message.replacement_message.message_type(),
                            0,
                            false,
                        )
                        .expect("Failed to create the frame"),
                    );
                    downstream_messages.add_message_with_tlvs(
                        intercept_message.replacement_message.message_type(),
                        intercept_message.replacement_message.clone(),
                        None,
                    );
                    send.send(intercept_frame)
                        .await
                        .map_err(|_| SnifferError::UpstreamClosed)?;
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Replaced: {} with {} | Direction: ⬆",
                        identifier,
                        message_type_to_name(msg_type),
                        message_type_to_name(intercept_message.replacement_message.message_type())
                    );
                }
            }
        } else {
            downstream_messages.add_message_with_tlvs(msg_type, msg.clone(), tlv_fields);
            send.send(frame)
                .await
                .map_err(|_| SnifferError::UpstreamClosed)?;
            tracing::info!(
                "🔍 Sv2 Sniffer {} | Forwarded: {} | Direction: ⬆ | Data: {}",
                identifier,
                message_type_to_name(msg_type),
                msg
            );
        }
    }
    Err(SnifferError::DownstreamClosed)
}

pub async fn recv_from_up_send_to_down(
    recv: Receiver<MessageFrame>,
    send: Sender<MessageFrame>,
    upstream_messages: MessagesAggregator,
    action: Vec<InterceptAction>,
    identifier: &str,
    negotiated_extensions: std::sync::Arc<std::sync::Mutex<Vec<u16>>>,
) -> Result<(), SnifferError> {
    while let Ok(mut frame) = recv.recv().await {
        let extensions = negotiated_extensions.lock().unwrap().clone();
        let (msg_type, msg, tlv_fields) = message_from_frame_with_tlvs(&mut frame, &extensions);

        // Track extension negotiation
        if let AnyMessage::Extensions(ref ext_msg) = msg {
            use stratum_apps::stratum_core::parsers_sv2::{Extensions, ExtensionsNegotiation};
            if let Extensions::ExtensionsNegotiation(
                ExtensionsNegotiation::RequestExtensionsSuccess(ref success),
            ) = ext_msg
            {
                let mut exts = negotiated_extensions.lock().unwrap();
                *exts = success.supported_extensions.clone().into_inner();
                tracing::info!(
                    "🔍 Sniffer {} | Tracked negotiated extensions: {:?}",
                    identifier,
                    *exts
                );
            }
        }

        let action = action.iter().find(|action| {
            action
                .find_matching_action(msg_type, MessageDirection::ToDownstream)
                .is_some()
        });

        if let Some(action) = action {
            match action {
                InterceptAction::IgnoreMessage(_) => {
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Ignored: {} | Direction: ⬇",
                        identifier,
                        message_type_to_name(msg_type)
                    );
                    continue;
                }
                InterceptAction::ReplaceMessage(intercept_message) => {
                    let intercept_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(
                            intercept_message.replacement_message.clone(),
                            intercept_message.replacement_message.message_type(),
                            0,
                            false,
                        )
                        .expect("Failed to create the frame"),
                    );
                    upstream_messages.add_message_with_tlvs(
                        intercept_message.replacement_message.message_type(),
                        intercept_message.replacement_message.clone(),
                        None,
                    );
                    send.send(intercept_frame)
                        .await
                        .map_err(|_| SnifferError::DownstreamClosed)?;
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Replaced: {} with {} | Direction: ⬇",
                        identifier,
                        message_type_to_name(msg_type),
                        message_type_to_name(intercept_message.replacement_message.message_type())
                    );
                }
            }
        } else {
            upstream_messages.add_message_with_tlvs(msg_type, msg.clone(), tlv_fields);
            send.send(frame)
                .await
                .map_err(|_| SnifferError::DownstreamClosed)?;
            tracing::info!(
                "🔍 Sv2 Sniffer {} | Forwarded: {} | Direction: ⬇ | Data: {}",
                identifier,
                message_type_to_name(msg_type),
                msg
            );
        }
    }
    Err(SnifferError::UpstreamClosed)
}

pub fn message_from_frame(frame: &mut MessageFrame) -> (MsgType, AnyMessage<'static>) {
    let (msg_type, msg, _) = message_from_frame_with_tlvs(frame, &[]);
    (msg_type, msg)
}

pub fn message_from_frame_with_tlvs(
    frame: &mut MessageFrame,
    negotiated_extensions: &[u16],
) -> (MsgType, AnyMessage<'static>, Option<Vec<Tlv>>) {
    match frame {
        Frame::Sv2(frame) => {
            if let Some(header) = frame.get_header() {
                let payload = frame.payload();

                // Try to parse with TLV support if extensions are negotiated
                if !negotiated_extensions.is_empty() {
                    match parse_message_frame_with_tlvs(header, payload, negotiated_extensions) {
                        Ok((message, tlv_fields)) => {
                            let message = into_static(message);
                            return (header.msg_type(), message, tlv_fields);
                        }
                        Err(e) => {
                            println!("Failed to parse frame with TLVs: {e:?}, falling back to standard parsing");
                        }
                    }
                }

                // Fallback to standard parsing without TLV support
                let mut payload = frame.payload().to_vec();
                let message: Result<AnyMessage<'_>, _> =
                    (header, payload.as_mut_slice()).try_into();
                match message {
                    Ok(message) => {
                        let message = into_static(message);
                        (header.msg_type(), message, None)
                    }
                    _ => {
                        println!("Received frame with invalid payload or message type: {frame:?}");
                        panic!();
                    }
                }
            } else {
                println!("Received frame with invalid header: {frame:?}");
                panic!();
            }
        }
        Frame::HandShake(f) => {
            println!("Received unexpected handshake frame: {f:?}");
            panic!();
        }
    }
}

pub fn into_static(m: AnyMessage<'_>) -> AnyMessage<'static> {
    match m {
        AnyMessage::Mining(m) => AnyMessage::Mining(m.into_static()),
        AnyMessage::Common(m) => match m {
            CommonMessages::ChannelEndpointChanged(m) => {
                AnyMessage::Common(CommonMessages::ChannelEndpointChanged(m.into_static()))
            }
            CommonMessages::SetupConnection(m) => {
                AnyMessage::Common(CommonMessages::SetupConnection(m.into_static()))
            }
            CommonMessages::SetupConnectionError(m) => {
                AnyMessage::Common(CommonMessages::SetupConnectionError(m.into_static()))
            }
            CommonMessages::SetupConnectionSuccess(m) => {
                AnyMessage::Common(CommonMessages::SetupConnectionSuccess(m.into_static()))
            }
            CommonMessages::Reconnect(m) => {
                AnyMessage::Common(CommonMessages::Reconnect(m.into_static()))
            }
        },
        AnyMessage::JobDeclaration(m) => match m {
            AllocateMiningJobToken(m) => {
                AnyMessage::JobDeclaration(AllocateMiningJobToken(m.into_static()))
            }
            AllocateMiningJobTokenSuccess(m) => {
                AnyMessage::JobDeclaration(AllocateMiningJobTokenSuccess(m.into_static()))
            }
            DeclareMiningJob(m) => AnyMessage::JobDeclaration(DeclareMiningJob(m.into_static())),
            DeclareMiningJobError(m) => {
                AnyMessage::JobDeclaration(DeclareMiningJobError(m.into_static()))
            }
            DeclareMiningJobSuccess(m) => {
                AnyMessage::JobDeclaration(DeclareMiningJobSuccess(m.into_static()))
            }
            ProvideMissingTransactions(m) => {
                AnyMessage::JobDeclaration(ProvideMissingTransactions(m.into_static()))
            }
            ProvideMissingTransactionsSuccess(m) => {
                AnyMessage::JobDeclaration(ProvideMissingTransactionsSuccess(m.into_static()))
            }
            PushSolution(m) => AnyMessage::JobDeclaration(PushSolution(m.into_static())),
        },
        AnyMessage::TemplateDistribution(m) => match m {
            CoinbaseOutputConstraints(m) => {
                AnyMessage::TemplateDistribution(CoinbaseOutputConstraints(m.into_static()))
            }
            TemplateDistribution::NewTemplate(m) => {
                AnyMessage::TemplateDistribution(TemplateDistribution::NewTemplate(m.into_static()))
            }
            TemplateDistribution::RequestTransactionData(m) => AnyMessage::TemplateDistribution(
                TemplateDistribution::RequestTransactionData(m.into_static()),
            ),
            TemplateDistribution::RequestTransactionDataError(m) => {
                AnyMessage::TemplateDistribution(TemplateDistribution::RequestTransactionDataError(
                    m.into_static(),
                ))
            }
            TemplateDistribution::RequestTransactionDataSuccess(m) => {
                AnyMessage::TemplateDistribution(
                    TemplateDistribution::RequestTransactionDataSuccess(m.into_static()),
                )
            }
            TemplateDistribution::SetNewPrevHash(m) => AnyMessage::TemplateDistribution(
                TemplateDistribution::SetNewPrevHash(m.into_static()),
            ),
            TemplateDistribution::SubmitSolution(m) => AnyMessage::TemplateDistribution(
                TemplateDistribution::SubmitSolution(m.into_static()),
            ),
        },
        AnyMessage::Extensions(extensions) => AnyMessage::Extensions(extensions.into_static()),
    }
}

pub mod http {
    /// Make a GET request that returns both the HTTP status code and the response body.
    /// Unlike `make_get_request`, this does NOT panic on non-2xx status codes (e.g. 404),
    /// making it suitable for testing API error responses.
    /// Only retries on 5xx errors or connection failures.
    ///
    /// `request_timeout` is the per-request timeout applied to each attempt; `None`
    /// leaves the underlying client default (which is effectively unbounded).
    pub fn make_get_request_with_status(
        url: &str,
        retries: usize,
        request_timeout: Option<std::time::Duration>,
    ) -> (i32, Vec<u8>) {
        for attempt in 1..=retries {
            let mut req = minreq::get(url);
            if let Some(t) = request_timeout {
                req = req.with_timeout(t.as_secs().max(1));
            }
            let response = req.send();
            match response {
                Ok(res) => {
                    let status_code = res.status_code;
                    if (500..600).contains(&status_code) {
                        eprintln!(
                            "Attempt {attempt}: URL {url} returned a server error code {status_code}"
                        );
                    } else {
                        return (status_code, res.as_bytes().to_vec());
                    }
                }
                Err(err) => {
                    eprintln!(
                        "Attempt {}: Failed to fetch URL {}: {:?}",
                        attempt + 1,
                        url,
                        err
                    );
                }
            }

            if attempt < retries {
                let delay = 1u64 << (attempt - 1);
                eprintln!("Retrying in {delay} seconds (exponential backoff)...");
                std::thread::sleep(std::time::Duration::from_secs(delay));
            }
        }
        panic!("Cannot reach URL {url} after {retries} attempts");
    }

    pub fn make_get_request(download_url: &str, retries: usize) -> Vec<u8> {
        for attempt in 1..=retries {
            let response = minreq::get(download_url).send();
            match response {
                Ok(res) => {
                    let status_code = res.status_code;
                    if (200..300).contains(&status_code) {
                        return res.as_bytes().to_vec();
                    } else if (500..600).contains(&status_code) {
                        eprintln!(
                            "Attempt {attempt}: URL {download_url} returned a server error code {status_code}"
                        );
                    } else {
                        panic!(
                            "URL {download_url} returned unexpected status code {status_code}. Aborting."
                        );
                    }
                }
                Err(err) => {
                    eprintln!(
                        "Attempt {}: Failed to fetch URL {}: {:?}",
                        attempt + 1,
                        download_url,
                        err
                    );
                }
            }

            if attempt < retries {
                let delay = 1u64 << (attempt - 1);
                eprintln!("Retrying in {delay} seconds (exponential backoff)...");
                std::thread::sleep(std::time::Duration::from_secs(delay));
            }
        }
        // If all retries fail, panic with an error message
        panic!("Cannot reach URL {download_url} after {retries} attempts");
    }
}

pub mod tarball {
    use std::{
        fs::File,
        io::{BufReader, Read},
        path::Path,
    };

    pub fn read_from_file(path: &str) -> Vec<u8> {
        let file = File::open(path).unwrap_or_else(|_| {
            panic!("Cannot find {path:?} specified with env var BITCOIND_TARBALL_FILE")
        });
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).unwrap();
        buffer
    }

    pub fn unpack(tarball_bytes: &[u8], destination: &Path) {
        use std::{io::Write as IoWrite, process::Command};

        // Write tarball bytes to a temp file
        let temp_tarball = destination.join("temp.tar.gz");
        let mut temp_file = File::create(&temp_tarball).unwrap();
        temp_file.write_all(tarball_bytes).unwrap();
        drop(temp_file);

        // Use system tar command to extract, which properly handles GNU sparse files
        let output = Command::new("tar")
            .arg("-xzf")
            .arg(&temp_tarball)
            .arg("-C")
            .arg(destination)
            .arg("--strip-components=0")
            .output()
            .expect("Failed to execute tar command");

        if !output.status.success() {
            eprintln!("tar stderr: {}", String::from_utf8_lossy(&output.stderr));
            panic!("tar extraction failed");
        }

        // Clean up temp tarball
        std::fs::remove_file(&temp_tarball).ok();
    }
}

pub mod fs_utils {
    use std::{fs, path::Path};

    /// Recursively copy all contents from source directory to destination directory
    pub fn copy_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
        if !dst.exists() {
            fs::create_dir_all(dst)?;
        }

        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                copy_dir_contents(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }
}

// =====================================================================
//  Iroh-transport test fixtures (gated on `iroh-transport` feature)
// =====================================================================
//
// These helpers are mirrors of the TCP fixtures above (`get_available_address`,
// `wait_for_client`, `create_downstream`, `create_upstream`) for the iroh
// transport. They match the same usage shape so per-role iroh integration
// tests can drop them in without learning a new contract.
//
// The only thing callers must understand that's not present in the TCP path:
// iroh requires a NodeId at dial time. Endpoints generated by
// `create_iroh_endpoint` carry their NodeId on their `NodeAddr` return value;
// pass that to your peer's `Sv2Target::Iroh { node_addr, .. }`.

#[cfg(feature = "iroh-transport")]
pub use iroh_fixtures::*;

#[cfg(feature = "iroh-transport")]
mod iroh_fixtures {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        path::{Path, PathBuf},
        time::Duration,
    };

    use iroh::{Endpoint, NodeAddr, NodeId, RelayMode, SecretKey};
    use stratum_apps::network_helpers::iroh::{
        admission::AdmissionPolicy,
        config::{AdmissionConfig, AdmissionMode, IrohRoleConfig},
        discovery::DiscoveryConfigToml,
    };

    /// Build a fresh `iroh::Endpoint` bound to `127.0.0.1:0` with discovery
    /// fully disabled (no relay, no pkarr, no DHT, no n0). The endpoint
    /// registers a single ALPN, generates a fresh Ed25519 secret key, and
    /// returns alongside its `NodeAddr` (with the bound socket baked in) so
    /// callers can hand it directly to a peer's `Sv2Target::Iroh { node_addr,
    /// .. }`.
    ///
    /// Mirrors the connector/listener test setup in
    /// `stratum_apps::network_helpers::iroh::*` so behavior matches what the
    /// production code under test exercises.
    pub async fn create_iroh_endpoint(alpn: &'static [u8]) -> (Endpoint, NodeAddr) {
        let secret = SecretKey::generate(rand::rngs::OsRng);
        let node_id = secret.public();
        let endpoint = Endpoint::builder()
            .secret_key(secret)
            .alpns(vec![alpn.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .bind()
            .await
            .expect("bind iroh test endpoint");

        // Wait for the bind to settle so the returned NodeAddr carries a real
        // direct address (iroh binds asynchronously).
        let socket = loop {
            let bound = endpoint.bound_sockets();
            if let Some(addr) = bound.iter().find(|s| s.is_ipv4()).copied() {
                break addr;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };

        let node_addr = NodeAddr::from_parts(node_id, None, std::iter::once(socket));
        (endpoint, node_addr)
    }

    /// Test-side admission policy choice. Mirrors the role-config TOML's two
    /// admission modes without forcing tests to construct the typed
    /// `AdmissionConfig` directly.
    #[derive(Debug, Clone)]
    pub enum AdmissionTestConfig {
        /// Admit any peer (matches production default).
        Open,
        /// Admit only the listed `NodeId`s. Empty list = "admit nothing".
        Whitelist(Vec<NodeId>),
    }

    impl AdmissionTestConfig {
        /// Render this test policy into the TOML-deserializable
        /// [`AdmissionConfig`] that `IrohRoleConfig` carries.
        pub fn into_admission_config(self) -> AdmissionConfig {
            match self {
                AdmissionTestConfig::Open => AdmissionConfig {
                    mode: AdmissionMode::Open,
                    allowed_node_ids: Vec::new(),
                },
                AdmissionTestConfig::Whitelist(ids) => AdmissionConfig {
                    mode: AdmissionMode::Whitelist,
                    allowed_node_ids: ids.into_iter().map(|id| id.to_string()).collect(),
                },
            }
        }

        /// Convenience: produce the resolved-runtime [`AdmissionPolicy`] for
        /// the rare test that wants to bypass the TOML round-trip and inspect
        /// the runtime form directly.
        pub fn into_runtime_policy(self) -> AdmissionPolicy {
            match self {
                AdmissionTestConfig::Open => AdmissionPolicy::Open,
                AdmissionTestConfig::Whitelist(ids) => {
                    AdmissionPolicy::Whitelist(ids.into_iter().collect())
                }
            }
        }
    }

    /// Build an `IrohRoleConfig` value suitable for a per-role test fixture.
    ///
    /// The returned config:
    /// - Binds on `127.0.0.1:<port>` (caller-chosen so tests can reuse a port
    ///   across runs if they wish; pass `0` to let the OS pick).
    /// - Uses the supplied `secret_key_path` (typically a `tempfile::TempDir`
    ///   entry).
    /// - Disables every discovery mechanism (relay, pkarr publisher / resolver,
    ///   DHT, n0). Tests run on direct loopback addresses only.
    /// - Sets keepalive/timeout values short enough that misbehaving peers
    ///   surface within the test's wall-clock budget but long enough that a
    ///   slow CI host doesn't false-trigger.
    /// - Carries the supplied admission policy.
    ///
    /// Plug the result into a role config's `iroh` field — e.g.
    /// `pool_config.iroh = Some(iroh_role_config_for_test(...))`.
    pub fn iroh_role_config_for_test(
        port: u16,
        secret_key_path: &Path,
        admission: AdmissionTestConfig,
    ) -> IrohRoleConfig {
        IrohRoleConfig {
            listen_address: std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            secret_key_path: PathBuf::from(secret_key_path),
            discovery: DiscoveryConfigToml {
                discovery_relay_enable: Some(false),
                discovery_pkarr_pub_enable: Some(false),
                discovery_pkarr_res_enable: Some(false),
                discovery_dht_enable: Some(false),
                discovery_n0_enable: Some(false),
                relay_url: None,
                connection_overrides: None,
            },
            // Plan defaults; explicit so tests are robust to a default change.
            max_idle_timeout_secs: 60,
            keep_alive_interval_secs: 30,
            // Shorter than the plan default (30s) so a stuck peer in a test
            // surfaces quickly without hanging the suite.
            per_request_timeout_secs: 10,
            admission: admission.into_admission_config(),
        }
    }

    /// Wait until an iroh-capable client can successfully connect to a peer's
    /// listener. Polls `Endpoint::connect(node_addr, alpn)` with backoff up to
    /// `timeout`.
    ///
    /// Returns `Ok(())` on the first successful dial; the underlying QUIC
    /// connection is dropped immediately, so this only proves the listener is
    /// reachable at the QUIC layer (analogous to the TCP `wait_for_client`
    /// helper just confirming a TCP accept works).
    ///
    /// Mirrors the existing `wait_for_client` shape with one difference:
    /// `wait_for_client` is a TCP server-side helper (binds and waits for an
    /// incoming connection), while iroh tests need the inverse — a probe that
    /// confirms a peer's iroh listener is actually accepting. That's the more
    /// useful primitive for the integration tests this module supports.
    pub async fn wait_for_iroh_client(
        endpoint: &Endpoint,
        node_addr: NodeAddr,
        alpn: &'static [u8],
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = std::time::Instant::now() + timeout;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            match endpoint.connect(node_addr.clone(), alpn).await {
                Ok(connection) => {
                    // Drop immediately; the caller only wanted to confirm
                    // reachability.
                    drop(connection);
                    return Ok(());
                }
                Err(e) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(format!(
                            "wait_for_iroh_client: still failing after {timeout:?} \
                             ({attempt} attempts): {e}"
                        ));
                    }
                    // Exponential-ish backoff capped at 200ms so total
                    // behavior is similar to a tight retry loop on healthy
                    // listeners but doesn't hammer on a stuck one.
                    let delay_ms = (50u64 << attempt.min(2)).min(200);
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
            }
        }
    }
}
