use std::sync::Arc;

use async_channel::{Receiver, Sender};
use stratum_apps::{
    bitcoin_core_sv2::common::template_distribution_protocol::CancellationToken,
    channel_utils::ReceiverCleanup,
    network_helpers::{
        noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf},
        transport::ConnPair,
    },
    stratum_core::{codec_sv2::StandardEitherFrame, framing_sv2::framing::Frame},
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tracing::{error, trace, warn, Instrument as _};

/// Spawns async reader and writer tasks for handling framed I/O with shutdown support.
///
/// Currently unused inside the pool crate after Phase 4a — the Sv2Tp dial site
/// migrated to [`spawn_conn_pair_bridge_tasks`]. Kept here for downstream
/// consumers / future call sites that still operate on a pre-split
/// [`NoiseTcpStream`] reader/writer pair.
#[allow(dead_code)]
#[track_caller]
#[cfg_attr(not(test), hotpath::measure)]
pub fn spawn_io_tasks(
    task_manager: Arc<TaskManager>,
    mut reader: NoiseTcpReadHalf<Message>,
    mut writer: NoiseTcpWriteHalf<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
) {
    let caller = std::panic::Location::caller();
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    {
        let cancellation_token = cancellation_token.clone();

        task_manager.spawn(
            async move {
                trace!("Reader task started");
                loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("Received shutdown");
                            inbound_tx.close();
                            break;
                        }
                        res = reader.read_frame() => {
                            match res {
                                Ok(frame) => {
                                    match frame {
                                        Frame::HandShake(frame) => {
                                            error!(?frame, "Received handshake frame");
                                            drop(frame);
                                            break;
                                        },
                                        Frame::Sv2(sv2_frame) => {
                                            trace!("Received inbound frame");
                                            if let Err(e) = inbound_tx.send(sv2_frame).await {
                                                inbound_tx.close();
                                                error!(error=?e, "Failed to forward inbound frame");
                                                break;
                                            }
                                        },
                                    }
                                }
                                Err(e) => {
                                    error!(error=?e, "Reader error");
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
                warn!("Reader task exited.");
            }
            .instrument(tracing::trace_span!(
                "reader_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    {
        let cancellation_token = cancellation_token.clone();
        task_manager.spawn(
            async move {
                trace!("Writer task started");
                loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("Received shutdown");
                            outbound_rx.close_and_drain();
                            break;
                        }
                        res = outbound_rx.recv() => {
                            match res {
                                Ok(frame) => {
                                    trace!("Sending outbound frame");
                                    if let Err(e) = writer.write_frame(frame.into()).await {
                                        error!(error=?e, "Writer error");
                                        outbound_rx.close_and_drain();
                                        break;
                                    }
                                }
                                Err(_) => {
                                    outbound_rx.close_and_drain();
                                    warn!("Outbound channel closed");
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
                warn!("Writer task exited.");
            }
            .instrument(tracing::trace_span!(
                "writer_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}

/// Spawns I/O bridge tasks for a transport-agnostic [`ConnPair`].
///
/// `Sv2Listener::accept()` returns the framed channel pair already pumped by
/// the transport's own reader/writer tasks (e.g.
/// `noise_connection::Connection::new` or `iroh::IrohConnection::into_channels`).
/// To slot that pair into [`super::downstream::Downstream`] without changing
/// the existing inner [`Sv2Frame`] channel shape, we spawn two thin bridge
/// tasks that translate between [`StandardEitherFrame<Message>`] (what the
/// transport speaks) and [`Sv2Frame`] (what the rest of the downstream code
/// speaks). Handshake frames must never appear post-handshake; they are logged
/// and dropped.
///
/// Mirrors the cancellation-token / task-manager wiring of
/// [`spawn_io_tasks`] so a downstream's I/O is shut down deterministically
/// when its child cancellation token fires.
#[track_caller]
#[cfg_attr(not(test), hotpath::measure)]
pub fn spawn_conn_pair_bridge_tasks(
    task_manager: Arc<TaskManager>,
    conn_pair: ConnPair<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
) {
    let caller = std::panic::Location::caller();
    let (transport_rx, transport_tx) = conn_pair;
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    {
        let cancellation_token = cancellation_token.clone();
        task_manager.spawn(
            async move {
                trace!("ConnPair reader bridge started");
                loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("ConnPair reader bridge: shutdown");
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
        task_manager.spawn(
            async move {
                trace!("ConnPair writer bridge started");
                loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("ConnPair writer bridge: shutdown");
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
                warn!("ConnPair writer bridge exited.");
            }
            .instrument(tracing::trace_span!(
                "conn_pair_writer_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}
