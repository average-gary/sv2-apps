use std::{
    collections::HashMap,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

#[cfg(feature = "monitoring")]
use std::net::IpAddr;

use async_channel::{unbounded, Receiver, Sender};
use stratum_apps::{
    bitcoin_core_sv2::common::template_distribution_protocol::CancellationToken,
    channel_utils::ReceiverCleanup,
    custom_mutex::Mutex,
    fallback_coordinator::FallbackCoordinator,
    network_helpers::transport::ConnPair,
    stratum_core::{
        channels_sv2::server::{
            extended::ExtendedChannel, group::GroupChannel, standard::StandardChannel,
        },
        codec_sv2::StandardEitherFrame,
        common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION,
        handlers_sv2::{HandleCommonMessagesFromClientAsync, HandleExtensionsFromClientAsync},
        parsers_sv2::{parse_message_frame_with_tlvs, AnyMessage, Mining, Tlv},
    },
    task_manager::TaskManager,
    utils::types::{DownstreamId, Message, Sv2Frame},
};
use tracing::{debug, error, trace, warn, Instrument as _};

use crate::error::{self, Action, JDCError, JDCErrorKind, JDCResult, LoopControl};

use stratum_apps::utils::types::ChannelId;

mod common_message_handler;
mod extensions_message_handler;

/// Holds state related to a downstream connection's mining channels.
///
/// This includes:
/// - Whether the downstream requires a standard job (`require_std_job`).
/// - An optional [`GroupChannel`] if group channeling is used.
/// - Active [`ExtendedChannel`]s keyed by channel ID.
/// - Active [`StandardChannel`]s keyed by channel ID.
pub struct DownstreamData {
    #[cfg(feature = "monitoring")]
    pub connection_ip: IpAddr,
    pub require_std_job: bool,
    pub group_channel: GroupChannel<'static>,
    pub extended_channels: HashMap<ChannelId, ExtendedChannel<'static>>,
    pub standard_channels: HashMap<ChannelId, StandardChannel<'static>>,
    pub channel_id_factory: AtomicU32,
    /// Extensions that have been successfully negotiated with this client
    pub negotiated_extensions: Vec<u16>,
    /// Extensions that the JDC supports
    pub supported_extensions: Vec<u16>,
    /// Extensions that the JDC requires
    pub required_extensions: Vec<u16>,
}

/// Communication layer for a downstream connection.
///
/// Provides the messaging primitives for interacting with the
/// channel manager and the downstream peer:
/// - `channel_manager_sender`: sends frames to the channel manager.
/// - `channel_manager_receiver`: receives messages from the channel manager.
/// - `downstream_sender`: sends frames to the downstream.
/// - `downstream_receiver`: receives frames from the downstream.
#[derive(Clone)]
pub struct DownstreamIo {
    channel_manager_sender: Sender<(DownstreamId, Mining<'static>, Option<Vec<Tlv>>)>,
    channel_manager_receiver: Receiver<(Mining<'static>, Option<Vec<Tlv>>)>,
    downstream_sender: Sender<Sv2Frame>,
    downstream_receiver: Receiver<Sv2Frame>,
}

impl DownstreamIo {
    fn close(&self) {
        self.downstream_sender.close();
        self.channel_manager_receiver.close_and_drain();
        self.downstream_receiver.close_and_drain();
    }
}

/// Represents a downstream client connected to this node.
#[derive(Clone)]
pub struct Downstream {
    pub downstream_data: Arc<Mutex<DownstreamData>>,
    downstream_io: DownstreamIo,
    pub downstream_id: DownstreamId,
    /// Per-connection cancellation token (child of the global token).
    /// Cancelled when this downstream's message loop exits, causing
    /// the associated I/O tasks to shut down.
    pub downstream_cancellation_token: CancellationToken,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl Downstream {
    fn handle_error_action(
        &self,
        context: &str,
        e: &JDCError<error::Downstream>,
        cancellation_token: &CancellationToken,
        fallback_token: &CancellationToken,
    ) -> LoopControl {
        if cancellation_token.is_cancelled() {
            debug!(
                downstream_id = self.downstream_id,
                error_kind = ?e.kind,
                "{context} returned an error after shutdown was requested"
            );
            return LoopControl::Continue;
        }

        if fallback_token.is_cancelled() {
            debug!(
                downstream_id = self.downstream_id,
                error_kind = ?e.kind,
                "{context} returned an error during fallback"
            );
            return LoopControl::Continue;
        }

        match e.action {
            Action::Log => {
                warn!(
                    downstream_id = self.downstream_id,
                    error_kind = ?e.kind,
                    "{context} returned a log-only error"
                );
                LoopControl::Continue
            }
            Action::Disconnect(_) => {
                warn!(
                    downstream_id = self.downstream_id,
                    error_kind = ?e.kind,
                    "{context} requested disconnect; cancelling downstream token"
                );
                self.downstream_cancellation_token.cancel();
                LoopControl::Break
            }
            Action::Shutdown => {
                warn!(
                    downstream_id = self.downstream_id,
                    error_kind = ?e.kind,
                    "{context} requested shutdown; cancelling global token"
                );
                cancellation_token.cancel();
                LoopControl::Break
            }
            other => {
                warn!(
                    downstream_id = self.downstream_id,
                    action = ?other,
                    error_kind = ?e.kind,
                    "{context} returned an unhandled action"
                );
                LoopControl::Continue
            }
        }
    }

    /// Creates a new [`Downstream`] instance and spawns the necessary I/O tasks.
    ///
    /// `conn_pair` is the post-handshake, post-codec channel pair produced by
    /// the role's [`Sv2Listener`](stratum_apps::network_helpers::transport::Sv2Listener)
    /// (TCP+Noise or iroh+Noise). The transport-specific reader/writer tasks
    /// already run inside the listener's `Connection`/`IrohConnection`; here we
    /// only spawn a thin bridge pair that:
    ///
    /// * filters out the post-Noise [`Frame::HandShake`] case (which should
    ///   never appear on a properly handshaken stream — treated as a hard
    ///   error, matching the prior `spawn_io_tasks` behavior),
    /// * funnels [`Frame::Sv2`] frames into `inbound_tx`,
    /// * pulls [`Sv2Frame`]s from `outbound_rx` and re-wraps them as
    ///   [`StandardEitherFrame::Sv2`] for the listener-side writer,
    /// * registers each side with the [`FallbackCoordinator`] so a fallback
    ///   tear-down completes deterministically.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        downstream_id: DownstreamId,
        channel_id_factory: AtomicU32,
        group_channel: GroupChannel<'static>,
        channel_manager_sender: Sender<(DownstreamId, Mining<'static>, Option<Vec<Tlv>>)>,
        channel_manager_receiver: Receiver<(Mining<'static>, Option<Vec<Tlv>>)>,
        conn_pair: ConnPair<Message>,
        cancellation_token: CancellationToken,
        fallback_coordinator: FallbackCoordinator,
        task_manager: Arc<TaskManager>,
        supported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
        #[cfg(feature = "monitoring")] connection_ip: IpAddr,
    ) -> Self {
        let (transport_rx, transport_tx) = conn_pair;
        let (inbound_tx, inbound_rx) = unbounded::<Sv2Frame>();
        let (outbound_tx, outbound_rx) = unbounded::<Sv2Frame>();

        // Create a per-connection child token so we can cancel this
        // connection's I/O tasks independently of the global shutdown.
        let downstream_cancellation_token = cancellation_token.child_token();
        spawn_bridge_tasks(
            task_manager,
            transport_rx,
            transport_tx,
            outbound_rx,
            inbound_tx,
            downstream_cancellation_token.clone(),
            fallback_coordinator.clone(),
        );

        let downstream_io = DownstreamIo {
            channel_manager_receiver,
            channel_manager_sender,
            downstream_sender: outbound_tx,
            downstream_receiver: inbound_rx,
        };

        let downstream_data = Arc::new(Mutex::new(DownstreamData {
            #[cfg(feature = "monitoring")]
            connection_ip,
            require_std_job: false,
            extended_channels: HashMap::new(),
            standard_channels: HashMap::new(),
            group_channel,
            channel_id_factory,
            negotiated_extensions: vec![],
            supported_extensions,
            required_extensions,
        }));

        Downstream {
            downstream_io,
            downstream_data,
            downstream_id,
            downstream_cancellation_token,
        }
    }

    /// Starts the downstream loop.
    ///
    /// Responsibilities:
    /// - Performs the initial `SetupConnection` handshake with the downstream.
    /// - Forwards mining-related messages to the channel manager.
    /// - Forwards channel manager messages back to the downstream peer.
    pub async fn start(
        mut self,
        cancellation_token: CancellationToken,
        fallback_coordinator: FallbackCoordinator,
        task_manager: Arc<TaskManager>,
        on_disconnect: impl FnOnce(DownstreamId) + Send + 'static,
    ) {
        let fallback_handler = fallback_coordinator.register();
        let fallback_token = fallback_coordinator.token();
        // Setup initial connection
        if let Err(e) = self.setup_connection_with_downstream().await {
            error!(?e, "Failed to set up downstream connection");

            // sleep to make sure SetupConnectionError is sent
            // before we break the TCP connection
            tokio::time::sleep(Duration::from_secs(1)).await;

            _ = self.handle_error_action(
                "Downstream::setup_connection_with_downstream",
                &e,
                &cancellation_token,
                &fallback_token,
            );
            on_disconnect(self.downstream_id);
            self.downstream_io.close();
            fallback_handler.done();
            return;
        }

        task_manager.spawn(async move {
            loop {
                let self_clone_1 = self.clone();
                let downstream_id = self_clone_1.downstream_id;
                let self_clone_2 = self.clone();
                tokio::select! {
                    biased;
                    _ = cancellation_token.cancelled() => {
                        debug!("Downstream {downstream_id}: received shutdown signal");
                        break;
                    }
                    _ = fallback_token.cancelled() => {
                        debug!("Downstream {downstream_id}: received fallback signal");
                        break;
                    }
                    res = self_clone_1.handle_downstream_message() => {
                        if let Err(e) = res {
                            error!(?e, "Error handling downstream message for {downstream_id}");
                            if let LoopControl::Break = self.handle_error_action(
                                "Downstream::handle_downstream_message",
                                &e,
                                &cancellation_token,
                                &fallback_token,
                            ) {
                                break;
                            }
                        }
                    }
                    res = self_clone_2.handle_channel_manager_message() => {
                        if let Err(e) = res {
                            error!(?e, "Error handling channel manager message for {downstream_id}");
                            if let LoopControl::Break = self.handle_error_action(
                                "Downstream::handle_channel_manager_message",
                                &e,
                                &cancellation_token,
                                &fallback_token,
                            ) {
                                break;
                            }
                        }
                    }

                }
            }
            if !cancellation_token.is_cancelled() && !fallback_token.is_cancelled() {
                // Only remove downstream when system is not going through shutdown
                // or fallback. As in those cases we initialize new set of subsystems
                // and free old allocated memory.
                on_disconnect(self.downstream_id);
            }
            self.downstream_cancellation_token.cancel();
            self.downstream_io.close();
            warn!("Downstream: unified message loop exited.");
            fallback_handler.done();
        });
    }

    // Performs the initial handshake with a downstream peer.
    async fn setup_connection_with_downstream(&mut self) -> JDCResult<(), error::Downstream> {
        let mut frame = self
            .downstream_io
            .downstream_receiver
            .recv()
            .await
            .map_err(|error| JDCError::disconnect(error, self.downstream_id))?;
        let header = frame.get_header().expect("frame header must be present");
        if header.msg_type() == MESSAGE_TYPE_SETUP_CONNECTION {
            self.handle_common_message_frame_from_client(None, header, frame.payload())
                .await?;
            return Ok(());
        }
        Err(JDCError::disconnect(
            JDCErrorKind::UnexpectedMessage(header.ext_type(), header.msg_type()),
            self.downstream_id,
        ))
    }

    // Handles messages sent from the channel manager to this downstream.
    async fn handle_channel_manager_message(self) -> JDCResult<(), error::Downstream> {
        let (message, _tlv_fields) = match self.downstream_io.channel_manager_receiver.recv().await
        {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    ?e,
                    "Channel manager receiver closed - disconnecting downstream"
                );
                return Err(JDCError::disconnect(
                    JDCErrorKind::ChannelErrorReceiver(e),
                    self.downstream_id,
                ));
            }
        };

        let message = AnyMessage::Mining(message);
        let sv2_frame: Sv2Frame = message.try_into().map_err(JDCError::shutdown)?;

        self.downstream_io
            .downstream_sender
            .send(sv2_frame)
            .await
            .map_err(|e| {
                error!(?e, "Downstream send failed");
                JDCError::disconnect(JDCErrorKind::ChannelErrorSender, self.downstream_id)
            })?;

        Ok(())
    }

    // Handles incoming messages from the downstream peer.
    async fn handle_downstream_message(mut self) -> JDCResult<(), error::Downstream> {
        let mut sv2_frame = self
            .downstream_io
            .downstream_receiver
            .recv()
            .await
            .map_err(|error| JDCError::disconnect(error, self.downstream_id))?;
        let header = sv2_frame
            .get_header()
            .expect("frame header must be present");
        let payload = sv2_frame.payload();
        let negotiated_extensions = self
            .downstream_data
            .super_safe_lock(|data| data.negotiated_extensions.clone());
        let (any_message, tlv_fields) =
            parse_message_frame_with_tlvs(header, payload, &negotiated_extensions)
                .map_err(|error| JDCError::disconnect(error, self.downstream_id))?;
        match any_message {
            AnyMessage::Mining(message) => {
                self.downstream_io
                    .channel_manager_sender
                    .send((self.downstream_id, message, tlv_fields))
                    .await
                    .map_err(|e| {
                        error!(?e, "Failed to send mining message to channel manager.");
                        JDCError::shutdown(JDCErrorKind::ChannelErrorSender)
                    })?;
            }
            AnyMessage::Extensions(message) => {
                self.handle_extensions_message_from_client(None, message, tlv_fields.as_deref())
                    .await?;
            }
            _ => {
                warn!(
                    "Received unsupported message type from downstream: {}",
                    header.msg_type()
                );
                return Ok(());
            }
        }
        Ok(())
    }
}

/// Bridges a transport-agnostic [`ConnPair`] into the per-downstream
/// [`Sv2Frame`] channels that the rest of the JDC pipeline consumes.
///
/// Replaces the legacy `spawn_io_tasks` reader/writer pair for the downstream
/// listener after the move to the
/// [`Sv2Listener`](stratum_apps::network_helpers::transport::Sv2Listener)
/// abstraction. The Noise reader/writer themselves now live inside the
/// listener's transport-specific connection (TCP `Connection::new` or
/// `IrohConnection`); this only translates between
/// [`StandardEitherFrame`]\<Message\> on the listener side and [`Sv2Frame`]
/// on the downstream-handler side, while preserving the original fallback /
/// cancellation semantics.
#[track_caller]
fn spawn_bridge_tasks(
    task_manager: Arc<TaskManager>,
    transport_rx: Receiver<StandardEitherFrame<Message>>,
    transport_tx: Sender<StandardEitherFrame<Message>>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
    fallback_coordinator: FallbackCoordinator,
) {
    let caller = std::panic::Location::caller();

    // Reader bridge: transport_rx -> inbound_tx (Sv2 only, drop handshake).
    {
        let cancellation_token_clone = cancellation_token.clone();
        let fallback_coordinator_clone = fallback_coordinator.clone();
        let inbound_tx_clone = inbound_tx.clone();
        let outbound_rx_clone = outbound_rx.clone();
        task_manager.spawn(
            async move {
                let fallback_handler = fallback_coordinator_clone.register();
                let fallback_token = fallback_coordinator_clone.token();

                trace!("Downstream reader bridge started");

                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token_clone.cancelled() => {
                            trace!("Downstream reader bridge: received shutdown signal");
                            break;
                        }
                        _ = fallback_token.cancelled() => {
                            trace!("Downstream reader bridge: received fallback signal");
                            break;
                        }
                        res = transport_rx.recv() => {
                            match res {
                                Ok(StandardEitherFrame::Sv2(sv2_frame)) => {
                                    trace!("Downstream reader bridge: forwarding inbound frame");
                                    if let Err(e) = inbound_tx_clone.send(sv2_frame).await {
                                        error!(error = ?e, "Downstream reader bridge: failed to forward inbound frame");
                                        break;
                                    }
                                }
                                Ok(StandardEitherFrame::HandShake(frame)) => {
                                    error!(?frame, "Downstream reader bridge: unexpected handshake frame");
                                    drop(frame);
                                    break;
                                }
                                Err(_) => {
                                    warn!("Downstream reader bridge: transport receiver closed");
                                    break;
                                }
                            }
                        }
                    }
                }

                inbound_tx_clone.close();
                outbound_rx_clone.close_and_drain();
                drop(inbound_tx_clone);
                drop(outbound_rx_clone);
                fallback_handler.done();
                trace!("Downstream reader bridge exited");
            }
            .instrument(tracing::trace_span!(
                "downstream_reader_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    // Writer bridge: outbound_rx -> transport_tx (re-wrap as EitherFrame).
    {
        let cancellation_token_clone = cancellation_token;
        let inbound_tx_clone = inbound_tx;
        task_manager.spawn(
            async move {
                let fallback_handler = fallback_coordinator.register();
                let fallback_token = fallback_coordinator.token();

                trace!("Downstream writer bridge started");

                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token_clone.cancelled() => {
                            trace!("Downstream writer bridge: received shutdown signal");
                            break;
                        }
                        _ = fallback_token.cancelled() => {
                            trace!("Downstream writer bridge: received fallback signal");
                            break;
                        }
                        res = outbound_rx.recv() => {
                            match res {
                                Ok(frame) => {
                                    trace!("Downstream writer bridge: sending outbound frame");
                                    let either: StandardEitherFrame<Message> =
                                        StandardEitherFrame::Sv2(frame);
                                    if let Err(e) = transport_tx.send(either).await {
                                        error!(error = ?e, "Downstream writer bridge: transport send failed");
                                        break;
                                    }
                                }
                                Err(_) => {
                                    warn!("Downstream writer bridge: outbound channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }

                outbound_rx.close_and_drain();
                inbound_tx_clone.close();
                transport_tx.close();
                drop(outbound_rx);
                drop(inbound_tx_clone);
                drop(transport_tx);
                fallback_handler.done();
                trace!("Downstream writer bridge exited");
            }
            .instrument(tracing::trace_span!(
                "downstream_writer_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}
