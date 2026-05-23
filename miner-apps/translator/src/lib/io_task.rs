use std::sync::Arc;

use async_channel::{Receiver, Sender};
use stratum_apps::{
    channel_utils::ReceiverCleanup,
    fallback_coordinator::FallbackCoordinator,
    network_helpers::transport::ConnPair,
    stratum_core::codec_sv2::StandardEitherFrame,
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tokio_util::sync::CancellationToken;
use tracing::{error, trace, warn, Instrument as _};

/// Bridges a transport-agnostic [`ConnPair`]\<Message\> into the per-upstream
/// [`Sv2Frame`] channels that the rest of the translator consumes.
///
/// Replaces the legacy `tokio::net::TcpStream` + `NoiseTcpStream::into_split` +
/// `read_frame` / `write_frame` reader/writer pair. The Noise reader/writer
/// themselves now live inside the transport-specific connection
/// (`Connection::new` for TCP or `IrohConnection` for iroh — both spawned
/// by the [`Sv2Connector`](stratum_apps::network_helpers::transport::Sv2Connector)
/// implementation that produced the [`ConnPair`]). This bridge only
/// translates between [`StandardEitherFrame`]<Message> on the transport
/// side and [`Sv2Frame`] on the upstream-handler side, while preserving the
/// original fallback / cancellation semantics that the prior
/// `spawn_io_tasks` provided.
#[cfg_attr(not(test), hotpath::measure)]
#[track_caller]
#[allow(clippy::too_many_arguments)]
pub fn spawn_io_tasks(
    task_manager: Arc<TaskManager>,
    conn_pair: ConnPair<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
    fallback_coordinator: FallbackCoordinator,
) {
    let (transport_rx, transport_tx) = conn_pair;
    let caller = std::panic::Location::caller();
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    // Reader bridge: transport_rx -> inbound_tx (Sv2 only, drop handshake).
    {
        let cancellation_token_clone = cancellation_token.clone();
        let fallback_coordinator_clone = fallback_coordinator.clone();
        task_manager.spawn(
            async move {
                // we just spawned a new task that's relevant to fallback coordination
                // so register it with the fallback coordinator
                let fallback_handler = fallback_coordinator_clone.register();

                // get the cancellation token that signals fallback
                let fallback_token = fallback_coordinator_clone.token();

                trace!("Reader bridge task started");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token_clone.cancelled() => {
                            trace!("Received app shutdown signal");
                            inbound_tx.close();
                            break;
                        }
                        _ = fallback_token.cancelled() => {
                            trace!("Received fallback signal");
                            inbound_tx.close();
                            break;
                        }
                        res = transport_rx.recv() => {
                            match res {
                                Ok(StandardEitherFrame::Sv2(sv2_frame)) => {
                                    trace!("Received inbound frame");
                                    if let Err(e) = inbound_tx.send(sv2_frame).await {
                                        inbound_tx.close();
                                        error!(error=?e, "Failed to forward inbound frame");
                                        break;
                                    }
                                }
                                Ok(StandardEitherFrame::HandShake(frame)) => {
                                    error!(?frame, "Received handshake frame post-handshake");
                                    drop(frame);
                                    break;
                                }
                                Err(e) => {
                                    warn!(error=?e, "Reader bridge: transport receiver closed");
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

                // signal fallback coordinator that this task has completed its cleanup
                fallback_handler.done();
                warn!("Reader bridge task exited.");
            }
            .instrument(tracing::trace_span!(
                "reader_bridge_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    // Writer bridge: outbound_rx -> transport_tx (re-wrap as EitherFrame).
    {
        let fallback_coordinator_clone = fallback_coordinator.clone();
        task_manager.spawn(
            async move {
                // we just spawned a new task that's relevant to fallback coordination
                // so register it with the fallback coordinator
                let fallback_handler = fallback_coordinator_clone.register();

                // get the cancellation token that signals fallback
                let fallback_token = fallback_coordinator_clone.token();

                trace!("Writer bridge task started");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token.cancelled() => {
                            trace!("Received app shutdown signal");
                            inbound_tx_clone.close();
                            break;
                        }
                        _ = fallback_token.cancelled() => {
                            trace!("Received fallback signal");
                            inbound_tx_clone.close();
                            break;
                        }
                        res = outbound_rx.recv() => {
                            match res {
                                Ok(frame) => {
                                    trace!("Sending outbound frame");
                                    let either: StandardEitherFrame<Message> =
                                        StandardEitherFrame::Sv2(frame);
                                    if let Err(e) = transport_tx.send(either).await {
                                        error!(error=?e, "Writer bridge: transport send failed");
                                        outbound_rx.close_and_drain();
                                        break;
                                    }
                                }
                                Err(_) => {
                                    outbound_rx.close_and_drain();
                                    warn!("Writer bridge: outbound channel closed");
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

                // signal fallback coordinator that this task has completed its cleanup
                fallback_handler.done();
                warn!("Writer bridge task exited.");
            }
            .instrument(tracing::trace_span!(
                "writer_bridge_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

}
