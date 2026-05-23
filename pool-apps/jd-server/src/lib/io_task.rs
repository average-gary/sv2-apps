//! Low-level I/O adapter tasks.
//!
//! [`spawn_io_tasks`] creates a matched pair of reader and writer tasks that bridge a
//! transport-agnostic [`ConnPair<Message>`] (yielded by
//! [`stratum_apps::network_helpers::transport::Sv2Listener::accept`]) to in-process
//! `async_channel` endpoints typed with the JDS-internal [`Sv2Frame`] alias. Both
//! tasks honour a [`CancellationToken`] for graceful shutdown.
//!
//! The adapter performs the [`StandardEitherFrame`] ↔ [`Sv2Frame`] conversion that
//! the JDS message handlers expect — `HandShake` frames received post-handshake are
//! treated as a fatal error (matching the original Noise-only path that produced
//! `Frame::HandShake` only on a misbehaving peer).

use std::sync::Arc;

use async_channel::{Receiver, Sender};
use stratum_apps::{
    bitcoin_core_sv2::common::job_declaration_protocol::CancellationToken,
    network_helpers::transport::ConnPair,
    stratum_core::framing_sv2::framing::Frame,
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tracing::{error, trace, warn, Instrument as _};

/// Spawns a reader task and a writer task that bridge a transport-agnostic
/// [`ConnPair<Message>`] to JDS's internal `Sv2Frame` channel pair.
///
/// The reader drains `transport_rx` (the inbound side of the
/// [`ConnPair`]), unwraps each `StandardEitherFrame::Sv2(_)` into an
/// `Sv2Frame`, and forwards it on `inbound_tx`. Receiving a `HandShake`
/// variant post-handshake is fatal and tears the tasks down.
///
/// The writer drains `outbound_rx` (Sv2Frame from the message handler) and
/// forwards each frame as `StandardEitherFrame::Sv2(_)` over the transport's
/// `transport_tx` (the outbound side of the [`ConnPair`]).
///
/// Both tasks exit (and close their channels) when the [`CancellationToken`]
/// fires or the underlying channel errors.
#[track_caller]
#[cfg_attr(not(test), hotpath::measure)]
pub fn spawn_io_tasks(
    task_manager: Arc<TaskManager>,
    conn_pair: ConnPair<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
) {
    let (transport_rx, transport_tx) = conn_pair;
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
                        res = transport_rx.recv() => {
                            match res {
                                Ok(frame) => match frame {
                                    Frame::HandShake(frame) => {
                                        error!(?frame, "Received handshake frame");
                                        drop(frame);
                                        break;
                                    }
                                    Frame::Sv2(sv2_frame) => {
                                        trace!("Received inbound frame");
                                        if let Err(e) = inbound_tx.send(sv2_frame).await {
                                            inbound_tx.close();
                                            error!(error=?e, "Failed to forward inbound frame");
                                            break;
                                        }
                                    }
                                },
                                Err(e) => {
                                    error!(error=?e, "Reader error (transport channel closed)");
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
                            outbound_rx.close();
                            break;
                        }
                        res = outbound_rx.recv() => {
                            match res {
                                Ok(frame) => {
                                    trace!("Sending outbound frame");
                                    if let Err(e) = transport_tx.send(frame.into()).await {
                                        error!(error=?e, "Writer error (transport channel closed)");
                                        outbound_rx.close();
                                        break;
                                    }
                                }
                                Err(_) => {
                                    outbound_rx.close();
                                    warn!("Outbound channel closed");
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
                warn!("Writer task exited.");
            }
            .instrument(tracing::trace_span!(
                "writer_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}
