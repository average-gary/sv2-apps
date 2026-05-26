//! Low-level I/O bridge tasks.
//!
//! [`spawn_conn_pair_bridge_tasks`] creates a matched pair of reader and writer tasks
//! that bridge a transport-agnostic [`ConnPair<Message>`] (yielded by
//! [`stratum_apps::network_helpers::transport::Sv2Listener::accept`]) to in-process
//! `async_channel` endpoints typed with the JDS-internal [`Sv2Frame`] alias. Both
//! tasks honour a [`CancellationToken`] for graceful shutdown.
//!
//! The bridge performs the [`StandardEitherFrame`] ↔ [`Sv2Frame`] conversion that
//! the JDS message handlers expect — `HandShake` frames received post-handshake are
//! treated as a fatal error (matching the original Noise-only path that produced
//! `Frame::HandShake` only on a misbehaving peer).

use std::sync::Arc;

use async_channel::{Receiver, Sender};
use bitcoin_core_sv2::job_declaration_protocol::CancellationToken;
use stratum_apps::{
    network_helpers::transport::ConnPair,
    stratum_core::codec_sv2::StandardEitherFrame,
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tracing::{error, trace, warn, Instrument as _};

/// Spawns I/O bridge tasks for a transport-agnostic [`ConnPair`].
///
/// `Sv2Listener::accept()` returns the framed channel pair already pumped by
/// the transport's own reader/writer tasks (see
/// `noise_connection::Connection::new`). To slot that pair into the existing
/// JDS downstream code without changing the inner [`Sv2Frame`] channel shape
/// consumed by the message handlers, we spawn two thin bridge tasks that
/// translate between [`StandardEitherFrame<Message>`] (what the transport
/// speaks) and [`Sv2Frame`] (what the rest of the JDS code speaks). Handshake
/// frames must never appear post-handshake; they are logged and the bridge
/// tears down.
///
/// The bridge mirrors the cancellation-token / task-manager wiring of the
/// previous noise-stream pump tasks so a downstream's I/O is shut down
/// deterministically when its child cancellation token fires.
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
                outbound_rx_clone.close();
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
                            outbound_rx.close();
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
                                        outbound_rx.close();
                                        break;
                                    }
                                }
                                Err(_) => {
                                    outbound_rx.close();
                                    warn!("ConnPair writer bridge: outbound channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }
                outbound_rx.close();
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
