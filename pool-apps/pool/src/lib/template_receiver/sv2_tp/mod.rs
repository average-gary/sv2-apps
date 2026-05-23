use std::sync::Arc;
mod common_message_handler;
use async_channel::{unbounded, Receiver, Sender};
#[cfg(feature = "iroh-transport")]
use stratum_apps::network_helpers::iroh::{
    alpn::SV2_TP_ALPN, connector::IrohSv2Connector, Endpoint as IrohEndpoint,
    ResolvedIrohRoleConfig,
};
use stratum_apps::{
    bitcoin_core_sv2::common::template_distribution_protocol::CancellationToken,
    channel_utils::ReceiverCleanup,
    key_utils::Secp256k1PublicKey,
    network_helpers::{
        self, resolve_host_port,
        transport::{CompositeSv2Connector, Sv2Connector, Sv2Target},
    },
    stratum_core::{
        framing_sv2,
        handlers_sv2::HandleCommonMessagesFromServerAsync,
        parsers_sv2::{AnyMessage, TemplateDistribution},
    },
    task_manager::TaskManager,
    utils::{
        protocol_message_type::{protocol_message_type, MessageType},
        types::{Message, Sv2Frame},
    },
};
use tracing::{debug, error, info, warn};

#[cfg(feature = "iroh-transport")]
use crate::config::Sv2TpIrohExt;
use crate::{
    error::{self, Action, LoopControl, PoolError, PoolErrorKind, PoolResult},
    io_task::spawn_conn_pair_bridge_tasks,
    utils::get_setup_connection_message_tp,
};

#[derive(Clone)]
pub struct Sv2TpIo {
    channel_manager_sender: Sender<TemplateDistribution<'static>>,
    channel_manager_receiver: Receiver<TemplateDistribution<'static>>,
    tp_sender: Sender<Sv2Frame>,
    tp_receiver: Receiver<Sv2Frame>,
}

impl Sv2TpIo {
    fn close(&self) {
        self.channel_manager_sender.close();
        self.tp_sender.close();
        self.channel_manager_receiver.close_and_drain();
        self.tp_receiver.close_and_drain();
    }
}

#[derive(Clone)]
pub struct Sv2Tp {
    sv2_tp_io: Sv2TpIo,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl Sv2Tp {
    fn handle_error_action(
        context: &str,
        e: &PoolError<error::TemplateProvider>,
        cancellation_token: &CancellationToken,
    ) -> LoopControl {
        if cancellation_token.is_cancelled() {
            debug!(
                error_kind = ?e.kind,
                "{context} returned an error after shutdown was requested"
            );
            return LoopControl::Continue;
        }
        match e.action {
            Action::Log => {
                warn!(error_kind = ?e.kind, "{context} returned a log-only error");
                LoopControl::Continue
            }
            Action::Shutdown => {
                warn!(error_kind = ?e.kind, "{context} requested shutdown");
                cancellation_token.cancel();
                LoopControl::Break
            }
            other => {
                warn!(action = ?other, error_kind = ?e.kind, "{context} returned an unhandled action");
                LoopControl::Continue
            }
        }
    }

    /// Establish a new connection to a Sv2 Template Provider.
    ///
    /// - Builds a [`CompositeSv2Connector`] that owns a TCP+Noise connector
    ///   and (when the `iroh-transport` feature is on AND the per-peer iroh
    ///   extension config supplies a NodeId) an iroh+Noise connector sharing
    ///   the pool's iroh [`Endpoint`].
    /// - Resolves the per-peer [`Sv2Target`] from the configured
    ///   `prefer_transport` order: TCP-only when no iroh fields are
    ///   configured; combined `IrohThenTcp` / `TcpThenIroh` variants when
    ///   the operator opts in. The `CompositeSv2Connector` applies the
    ///   fallback ordering encoded by the variant per the plan's
    ///   §"Client side — fallback ordering" table.
    /// - Spawns transport-agnostic bridge tasks via
    ///   [`spawn_conn_pair_bridge_tasks`].
    ///
    /// Retries up to 3 times before returning [`PoolError::Shutdown`].
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        tp_address: String,
        public_key: Option<Secp256k1PublicKey>,
        channel_manager_receiver: Receiver<TemplateDistribution<'static>>,
        channel_manager_sender: Sender<TemplateDistribution<'static>>,
        cancellation_token: CancellationToken,
        task_manager: Arc<TaskManager>,
        #[cfg(feature = "iroh-transport")] iroh_tp_ext: Option<Sv2TpIrohExt>,
        #[cfg(feature = "iroh-transport")] shared_iroh: Option<(
            IrohEndpoint,
            ResolvedIrohRoleConfig,
        )>,
    ) -> PoolResult<Sv2Tp, error::TemplateProvider> {
        const MAX_RETRIES: usize = 3;

        // Build the composite connector once (cheap to clone iroh::Endpoint
        // internally). When iroh-transport is off, this is just a TCP-only
        // composite — behavior identical to today's TCP-only dial.
        let connector = build_connector(
            #[cfg(feature = "iroh-transport")]
            iroh_tp_ext.as_ref(),
            #[cfg(feature = "iroh-transport")]
            shared_iroh.as_ref(),
        );

        // Build the target once: resolves the TCP `host:port` and (when
        // applicable) parses the iroh NodeId / RelayUrl into a NodeAddr.
        let target = build_target(
            tp_address.as_str(),
            public_key,
            #[cfg(feature = "iroh-transport")]
            iroh_tp_ext.as_ref(),
        )
        .await?;

        for attempt in 1..=MAX_RETRIES {
            info!(attempt, MAX_RETRIES, ?target, "Connecting to template provider");

            tokio::select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    info!("Shutdown received during dial, aborting");
                    return Err(PoolError::shutdown(PoolErrorKind::CouldNotInitiateSystem));
                }
                result = <CompositeSv2Connector as Sv2Connector<Message>>::connect(&connector, &target) => {
                    match result {
                        Ok(conn_pair) => {
                            info!(attempt, "Sv2Connector::connect succeeded");

                            let (inbound_tx, inbound_rx) = unbounded::<Sv2Frame>();
                            let (outbound_tx, outbound_rx) = unbounded::<Sv2Frame>();

                            info!(attempt, "Spawning IO bridge tasks for template receiver");

                            spawn_conn_pair_bridge_tasks(
                                task_manager.clone(),
                                conn_pair,
                                outbound_rx,
                                inbound_tx,
                                cancellation_token.clone(),
                            );

                            let sv2_tp_io = Sv2TpIo {
                                channel_manager_receiver,
                                channel_manager_sender,
                                tp_receiver: inbound_rx,
                                tp_sender: outbound_tx,
                            };

                            info!(attempt, "TemplateReceiver initialized successfully");
                            return Ok(Sv2Tp { sv2_tp_io });
                        }
                        Err(network_helpers::Error::InvalidKey) => {
                            return Err(PoolError::shutdown(PoolErrorKind::InvalidKey));
                        }
                        Err(e) => {
                            warn!(attempt, MAX_RETRIES, error = ?e, "Sv2Connector::connect failed");
                        }
                    }
                }
            }

            if attempt < MAX_RETRIES {
                debug!(attempt, "Retrying connection after backoff");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        error!("Exhausted all connection attempts, shutting down TemplateReceiver");
        Err(PoolError::shutdown(PoolErrorKind::CouldNotInitiateSystem))
    }

    /// Start unified message loop for Sv2Tp.
    ///
    /// Responsibilities:
    /// - Run handshake (`setup_connection`)
    /// - Handle:
    ///   - Messages from Template Provider
    ///   - Messages from ChannelManager
    ///   - Shutdown signals (upstream/job-declarator fallback)
    pub async fn start(
        mut self,
        socket_address: String,
        cancellation_token: CancellationToken,
        task_manager: Arc<TaskManager>,
    ) -> PoolResult<(), error::TemplateProvider> {
        info!("Initialized state for starting template receiver");
        if let Err(e) = self.setup_connection(socket_address).await {
            self.sv2_tp_io.close();
            return Err(e);
        }

        info!("Setup Connection done. connection with template receiver is now done");
        task_manager.spawn(async move {
            loop {
                let mut self_clone_1 = self.clone();
                let self_clone_2 = self.clone();
                tokio::select! {
                    biased;
                    _ = cancellation_token.cancelled() => {
                        info!("Template Receiver: received shutdown signal");
                        break;
                    }
                    res = self_clone_1.handle_template_provider_message() => {
                        if let Err(e) = res {
                            error!("TemplateReceiver template provider handler failed: {e:?}");
                            if let LoopControl::Break = Self::handle_error_action(
                                "Sv2Tp::handle_template_provider_message",
                                &e,
                                &cancellation_token,
                            ) {
                                break;
                            }
                        }
                    }
                    res = self_clone_2.handle_channel_manager_message() => {
                        if let Err(e) = res {
                            error!("TemplateReceiver channel manager handler failed: {e:?}");
                            if let LoopControl::Break = Self::handle_error_action(
                                "Sv2Tp::handle_channel_manager_message",
                                &e,
                                &cancellation_token,
                            ) {
                                break;
                            }
                        }
                    },
                }
            }
            self.sv2_tp_io.close();
            warn!("TemplateReceiver: unified message loop exited.");
        });
        Ok(())
    }

    /// Handle inbound messages from the template provider.
    ///
    /// Routes:
    /// - `Common` messages → handled locally
    /// - `TemplateDistribution` messages → forwarded to ChannelManager
    /// - Unsupported messages → logged and ignored
    pub async fn handle_template_provider_message(
        &mut self,
    ) -> PoolResult<(), error::TemplateProvider> {
        let mut sv2_frame = self
            .sv2_tp_io
            .tp_receiver
            .recv()
            .await
            .map_err(PoolError::shutdown)?;
        debug!("Received SV2 frame from Template provider.");
        let header = sv2_frame.get_header().ok_or_else(|| {
            error!("SV2 frame missing header");
            PoolError::shutdown(framing_sv2::Error::MissingHeader)
        })?;

        match protocol_message_type(header.ext_type(), header.msg_type()) {
            MessageType::Common => {
                info!(
                    ext_type = ?header.ext_type(),
                    msg_type = ?header.msg_type(),
                    "Handling common message from Template provider."
                );

                self.handle_common_message_frame_from_server(None, header, sv2_frame.payload())
                    .await?;
            }
            MessageType::TemplateDistribution => {
                let message =
                    TemplateDistribution::try_from((header.msg_type(), sv2_frame.payload()))
                        .map_err(PoolError::shutdown)?
                        .into_static();

                self.sv2_tp_io
                    .channel_manager_sender
                    .send(message)
                    .await
                    .map_err(|e| {
                        error!(error=?e, "Failed to send template distribution message to channel manager.");
                        PoolError::shutdown(PoolErrorKind::ChannelErrorSender)
                    })?;
            }
            _ => {
                warn!(
                    ext_type = ?header.ext_type(),
                    msg_type = ?header.msg_type(),
                    "Received unsupported message type from template provider."
                );
            }
        }
        Ok(())
    }

    /// Handle messages from channel manager → template provider.
    ///
    /// Forwards outbound frames upstream
    pub async fn handle_channel_manager_message(&self) -> PoolResult<(), error::TemplateProvider> {
        let msg = self
            .sv2_tp_io
            .channel_manager_receiver
            .recv()
            .await
            .map_err(PoolError::shutdown)?;
        let message = AnyMessage::TemplateDistribution(msg).into_static();
        let frame: Sv2Frame = message.try_into().map_err(PoolError::shutdown)?;

        debug!("Forwarding message from channel manager to outbound_tx");
        self.sv2_tp_io
            .tp_sender
            .send(frame)
            .await
            .map_err(|_| PoolError::shutdown(PoolErrorKind::ChannelErrorSender))?;

        Ok(())
    }

    // Performs the initial handshake with Template Provider.
    pub async fn setup_connection(
        &mut self,
        addr: String,
    ) -> PoolResult<(), error::TemplateProvider> {
        let socket = resolve_host_port(&addr).await.map_err(|e| {
            error!(%addr, "Failed to resolve template provider address: {e}");
            PoolError::shutdown(PoolErrorKind::InvalidSocketAddress(addr.clone()))
        })?;

        debug!(%socket, "Building SetupConnection message to the Template Provider");
        let setup_msg = get_setup_connection_message_tp(socket).map_err(PoolError::shutdown)?;
        let frame: Sv2Frame = Message::Common(setup_msg.into())
            .try_into()
            .map_err(PoolError::shutdown)?;

        info!("Sending SetupConnection message to the Template Provider");
        self.sv2_tp_io.tp_sender.send(frame).await.map_err(|_| {
            error!("Failed to send setup connection message upstream");
            PoolError::shutdown(PoolErrorKind::ChannelErrorSender)
        })?;

        info!("Waiting for upstream handshake response");
        let mut incoming: Sv2Frame = self.sv2_tp_io.tp_receiver.recv().await.map_err(|e| {
            error!(?e, "Upstream connection closed during handshake");
            PoolError::shutdown(e)
        })?;

        let header = incoming.get_header().ok_or_else(|| {
            error!("Handshake frame missing header");
            PoolError::shutdown(framing_sv2::Error::MissingHeader)
        })?;
        debug!(
            ext_type = ?header.ext_type(),
            msg_type = ?header.msg_type(),
            "Received upstream handshake response"
        );

        self.handle_common_message_frame_from_server(None, header, incoming.payload())
            .await?;
        info!("Handshake with upstream completed successfully");
        Ok(())
    }
}

/// Build the [`CompositeSv2Connector`] used by [`Sv2Tp::new`].
///
/// When `iroh-transport` is off, returns a TCP-only composite. When the
/// feature is on, the iroh leg is wired iff the per-peer extension config
/// provides an `iroh_node_id` AND the pool has built a shared iroh
/// [`Endpoint`] at startup. Otherwise the composite stays TCP-only and the
/// dial degrades gracefully.
fn build_connector(
    #[cfg(feature = "iroh-transport")] iroh_tp_ext: Option<&Sv2TpIrohExt>,
    #[cfg(feature = "iroh-transport")] shared_iroh: Option<&(IrohEndpoint, ResolvedIrohRoleConfig)>,
) -> CompositeSv2Connector {
    #[cfg(feature = "iroh-transport")]
    {
        // We attach an iroh leg only when (a) the operator opted in via the
        // per-peer config block, (b) they supplied a NodeId, and (c) the pool
        // has a shared Endpoint to dial through. Anything missing => TCP-only
        // composite (the caller's prefer_transport ordering can still pin
        // a TCP-only target via [`Sv2Target::Tcp`]).
        let want_iroh = iroh_tp_ext
            .map(|ext| ext.iroh_node_id.as_deref().is_some_and(|s| !s.is_empty()))
            .unwrap_or(false);

        if let (true, Some((endpoint, resolved))) = (want_iroh, shared_iroh) {
            let iroh_connector = IrohSv2Connector::new(
                endpoint.clone(),
                resolved.connection_overrides.clone(),
                SV2_TP_ALPN,
                resolved.per_request_timeout,
            );
            return CompositeSv2Connector::new(iroh_connector);
        }
    }

    CompositeSv2Connector::tcp_only()
}

/// Build the [`Sv2Target`] used by [`Sv2Tp::new`].
///
/// Always resolves the TCP `host:port` first since fallback paths may need
/// it. When the iroh extension config supplies a parseable `iroh_node_id`,
/// pairs that with the configured `prefer_transport` to choose a combined
/// target variant. An invalid NodeId or RelayUrl logs a warning and falls
/// back to TCP-only — the dial site stays usable rather than refusing to
/// start.
async fn build_target(
    tp_address: &str,
    authority_pubkey: Option<Secp256k1PublicKey>,
    #[cfg(feature = "iroh-transport")] iroh_tp_ext: Option<&Sv2TpIrohExt>,
) -> PoolResult<Sv2Target, error::TemplateProvider> {
    let tcp_addr = resolve_host_port(tp_address).await.map_err(|e| {
        error!(%tp_address, "Failed to resolve template provider address: {e}");
        PoolError::shutdown(PoolErrorKind::InvalidSocketAddress(tp_address.to_string()))
    })?;

    #[cfg(feature = "iroh-transport")]
    {
        use stratum_apps::network_helpers::iroh::{NodeAddr, NodeId, RelayUrl};
        use stratum_apps::network_helpers::transport::PreferTransport;

        if let Some(ext) = iroh_tp_ext {
            // Resolve iroh leg only if a non-empty NodeId is supplied.
            let iroh_leg: Option<NodeAddr> = match ext.iroh_node_id.as_deref() {
                Some(s) if !s.is_empty() => match s.parse::<NodeId>() {
                    Ok(node_id) => {
                        let relay = ext
                            .iroh_relay_url
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .and_then(|url| match url.parse::<RelayUrl>() {
                                Ok(r) => Some(r),
                                Err(e) => {
                                    warn!(
                                        url,
                                        error = %e,
                                        "Sv2Tp: invalid iroh_relay_url; ignoring (using \
                                         discovery instead)"
                                    );
                                    None
                                }
                            });
                        Some(NodeAddr::from_parts(node_id, relay, std::iter::empty()))
                    }
                    Err(e) => {
                        warn!(
                            node_id = %s,
                            error = %e,
                            "Sv2Tp: invalid iroh_node_id; falling back to TCP-only target"
                        );
                        None
                    }
                },
                _ => None,
            };

            let target = match (ext.prefer_transport, iroh_leg) {
                (PreferTransport::Tcp, _) => Sv2Target::Tcp {
                    addr: tcp_addr,
                    authority_pubkey,
                },
                (PreferTransport::Iroh, Some(node_addr)) => Sv2Target::Iroh {
                    node_addr,
                    authority_pubkey,
                },
                (PreferTransport::Iroh, None) => {
                    warn!(
                        "Sv2Tp: prefer_transport=iroh but no iroh_node_id configured; \
                         falling back to TCP-only target"
                    );
                    Sv2Target::Tcp {
                        addr: tcp_addr,
                        authority_pubkey,
                    }
                }
                (PreferTransport::IrohThenTcp, Some(node_addr)) => Sv2Target::IrohThenTcp {
                    node_addr,
                    tcp_addr,
                    authority_pubkey,
                },
                (PreferTransport::IrohThenTcp, None) => Sv2Target::Tcp {
                    addr: tcp_addr,
                    authority_pubkey,
                },
                (PreferTransport::TcpThenIroh, Some(node_addr)) => Sv2Target::TcpThenIroh {
                    tcp_addr,
                    node_addr,
                    authority_pubkey,
                },
                (PreferTransport::TcpThenIroh, None) => Sv2Target::Tcp {
                    addr: tcp_addr,
                    authority_pubkey,
                },
            };
            return Ok(target);
        }
    }

    Ok(Sv2Target::Tcp {
        addr: tcp_addr,
        authority_pubkey,
    })
}
