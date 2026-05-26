//! I/O bridge tasks for transport-agnostic [`ConnPair`]s.
//!
//! [`spawn_conn_pair_bridge_tasks`] creates a matched pair of reader and
//! writer tasks that bridge between the
//! [`stratum_apps::stratum_core::codec_sv2::StandardEitherFrame`] channels
//! returned by [`stratum_apps::network_helpers::transport::Sv2Listener::accept`]
//! / [`stratum_apps::network_helpers::transport::Sv2Connector::connect`] and
//! the [`Sv2Frame`] channels consumed by the rest of the JDC's downstream /
//! upstream / JDS / TP code.
//!
//! Unlike pool/jd-server, JDC participates in **fallback coordination**: when
//! an upstream fault triggers a fallback, the bridge tasks must register with
//! the [`FallbackCoordinator`] so the fallback driver can wait for them to
//! drain before re-binding the listening port and dialing the next upstream.
//! This mirrors the registration that the legacy `spawn_io_tasks` performed
//! against [`NoiseTcpReadHalf`] / [`NoiseTcpWriteHalf`] before this module
//! switched to the transport-agnostic [`ConnPair`].

use std::sync::Arc;

use async_channel::{Receiver, Sender};
use bitcoin_core_sv2::template_distribution_protocol::CancellationToken;
use stratum_apps::{
    channel_utils::ReceiverCleanup,
    fallback_coordinator::{FallbackCoordinator, FallbackHandler},
    network_helpers::transport::ConnPair,
    stratum_core::codec_sv2::StandardEitherFrame,
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tracing::{error, trace, warn, Instrument as _};

/// Optional registration with a [`FallbackCoordinator`].
///
/// Each bridge task acquires its own [`FallbackRegistration`] so the fallback
/// driver can `register()` two handlers (one per task) and observe them both
/// `done()` before considering the bridge fully drained.
struct FallbackRegistration {
    handler: Option<FallbackHandler>,
    token: Option<CancellationToken>,
}

impl FallbackRegistration {
    fn new(fallback_coordinator: Option<FallbackCoordinator>) -> Self {
        match fallback_coordinator {
            Some(fallback_coordinator) => Self {
                handler: Some(fallback_coordinator.register()),
                token: Some(fallback_coordinator.token()),
            },
            None => Self {
                handler: None,
                token: None,
            },
        }
    }

    fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    async fn cancelled(&self) {
        if let Some(token) = &self.token {
            token.cancelled().await;
        }
    }

    fn done(self) {
        if let Some(handler) = self.handler {
            handler.done();
        }
    }
}

/// Spawns I/O bridge tasks for a transport-agnostic [`ConnPair`].
///
/// `Sv2Listener::accept()` and `Sv2Connector::connect()` return the framed
/// channel pair already pumped by the transport's own reader/writer tasks
/// (see `noise_connection::Connection::new`). To slot that pair into the
/// existing JDC code without changing the inner [`Sv2Frame`] channel shape
/// consumed by the message handlers, we spawn two thin bridge tasks that
/// translate between [`StandardEitherFrame<Message>`] (what the transport
/// speaks) and [`Sv2Frame`] (what the rest of the JDC code speaks).
/// Handshake frames must never appear post-handshake; they are logged and
/// dropped.
///
/// If a [`FallbackCoordinator`] is provided, both tasks register with it and
/// listen for the fallback cancellation token in addition to the
/// per-connection [`CancellationToken`]. This preserves the fallback-rebind
/// semantics that the legacy `spawn_io_tasks` had on the JDC's three outbound
/// connections (Pool, JDS) and downstream listener.
#[track_caller]
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), hotpath::measure)]
pub fn spawn_conn_pair_bridge_tasks(
    task_manager: Arc<TaskManager>,
    conn_pair: ConnPair<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
    fallback_coordinator: Option<FallbackCoordinator>,
) {
    let caller = std::panic::Location::caller();
    let (transport_rx, transport_tx) = conn_pair;
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    {
        let cancellation_token = cancellation_token.clone();
        let fallback_coordinator_clone = fallback_coordinator.clone();
        task_manager.spawn(
            async move {
                let fallback = FallbackRegistration::new(fallback_coordinator_clone);

                trace!("ConnPair reader bridge started");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token.cancelled() => {
                            trace!("ConnPair reader bridge: shutdown");
                            inbound_tx.close();
                            break;
                        }
                        _ = fallback.cancelled(), if fallback.is_enabled() => {
                            trace!("ConnPair reader bridge: fallback");
                            inbound_tx.close();
                            break;
                        }
                        res = transport_rx.recv() => {
                            match res {
                                Ok(StandardEitherFrame::Sv2(sv2_frame)) => {
                                    trace!("ConnPair reader bridge: forwarding sv2 frame");
                                    if let Err(e) = inbound_tx.send(sv2_frame).await {
                                        inbound_tx.close();
                                        error!(error=?e, "ConnPair reader bridge: forward failed");
                                        break;
                                    }
                                }
                                Ok(StandardEitherFrame::HandShake(frame)) => {
                                    error!(?frame, "ConnPair reader bridge: unexpected handshake frame post-handshake");
                                    drop(frame);
                                    break;
                                }
                                Err(e) => {
                                    error!(error=?e, "ConnPair reader bridge: transport closed");
                                    inbound_tx.close();
                                    break;
                                }
                            }
                        }
                    }
                }
                inbound_tx.close();
                outbound_rx_clone.close_and_drain();
                drop(inbound_tx);
                drop(outbound_rx_clone);

                fallback.done();

                warn!("ConnPair reader bridge exited.");
            }
            .instrument(tracing::trace_span!(
                "conn_pair_reader_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    {
        let cancellation_token = cancellation_token.clone();
        let fallback_coordinator_clone = fallback_coordinator.clone();
        task_manager.spawn(
            async move {
                let fallback = FallbackRegistration::new(fallback_coordinator_clone);

                trace!("ConnPair writer bridge started");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token.cancelled() => {
                            trace!("ConnPair writer bridge: shutdown");
                            outbound_rx.close_and_drain();
                            break;
                        }
                        _ = fallback.cancelled(), if fallback.is_enabled() => {
                            trace!("ConnPair writer bridge: fallback");
                            outbound_rx.close_and_drain();
                            break;
                        }
                        res = outbound_rx.recv() => {
                            match res {
                                Ok(frame) => {
                                    trace!("ConnPair writer bridge: forwarding outbound frame");
                                    let either: StandardEitherFrame<Message> =
                                        StandardEitherFrame::Sv2(frame);
                                    if let Err(e) = transport_tx.send(either).await {
                                        error!(error=?e, "ConnPair writer bridge: send failed");
                                        outbound_rx.close_and_drain();
                                        break;
                                    }
                                }
                                Err(_) => {
                                    outbound_rx.close_and_drain();
                                    warn!("ConnPair writer bridge: outbound channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }
                outbound_rx.close_and_drain();
                inbound_tx_clone.close();
                drop(outbound_rx);
                drop(inbound_tx_clone);

                fallback.done();

                warn!("ConnPair writer bridge exited.");
            }
            .instrument(tracing::trace_span!(
                "conn_pair_writer_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}
