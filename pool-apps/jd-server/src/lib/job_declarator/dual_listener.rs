//! Local dual-transport listener helper for JDS.
//!
//! Composes a [`TcpSv2Listener`] (always present) with an optional
//! `IrohSv2Listener` (when the `iroh-transport` feature is enabled and a
//! `[jds.iroh]` block is configured). Both inner listeners are driven by
//! detached accept tasks that fan their results into a single
//! `mpsc::channel`; consumers see a uniform
//! `(PeerIdentity, ConnPair<Message>)` stream regardless of which transport
//! produced the connection.
//!
//! Per the iroh-transport plan §"Phase 3 — Server-side dual transport" and
//! the Phase 3b task brief, this helper is intentionally NOT exported from
//! `stratum-apps` — each role (Pool, JDS, JDC) replicates the same shape
//! locally so a rebase conflict in one role's listener bootstrap doesn't
//! ripple across the others. JDS's copy mirrors the structure of pool's
//! `pool-apps/pool/src/lib/channel_manager::DualSv2Listener`.

use std::sync::Arc;

use stratum_apps::{
    network_helpers::{
        transport::{ConnPair, PeerIdentity, Sv2Listener, TcpSv2Listener},
        Error,
    },
    utils::types::Message,
};
use tokio::sync::mpsc;
use tracing::{debug, info};

#[cfg(feature = "iroh-transport")]
use stratum_apps::network_helpers::iroh::listener::IrohSv2Listener;

/// Outcome of a single accept call, fanned through the inner channel.
type AcceptResult = Result<(PeerIdentity, ConnPair<Message>), Error>;

/// Dual-transport listener implementing
/// [`Sv2Listener`](stratum_apps::network_helpers::transport::Sv2Listener) over
/// the JDS message type.
pub(super) struct DualSv2Listener {
    rx: tokio::sync::Mutex<mpsc::Receiver<AcceptResult>>,
}

impl DualSv2Listener {
    /// Channel buffer sized for short bursts of concurrent handshake
    /// completions; the consumer drains in a tight loop so back-pressure
    /// is not a concern in practice.
    const ACCEPT_BUFFER: usize = 64;

    /// Spawn the per-transport accept tasks and return a handle that fans them
    /// into a single `accept()` channel.
    ///
    /// When `iroh` is `Some`, both transports run concurrently; otherwise the
    /// helper degenerates to a TCP-only fan-in (still going through the
    /// channel, so call-site code is uniform across config shapes).
    pub(super) fn spawn(
        tcp: TcpSv2Listener,
        #[cfg(feature = "iroh-transport")] iroh: Option<IrohSv2Listener>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<AcceptResult>(Self::ACCEPT_BUFFER);

        let tcp_arc: Arc<dyn Sv2Listener<Message>> = Arc::new(tcp);
        Self::spawn_accept_loop(tcp_arc, tx.clone(), "tcp");

        #[cfg(feature = "iroh-transport")]
        if let Some(iroh) = iroh {
            let iroh_arc: Arc<dyn Sv2Listener<Message>> = Arc::new(iroh);
            Self::spawn_accept_loop(iroh_arc, tx.clone(), "iroh");
        }

        // Drop the original sender so the fan-in channel closes once every
        // per-transport task has exited. Without this a consumer could hang
        // forever after both accept loops drop out.
        drop(tx);

        Self {
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    fn spawn_accept_loop(
        listener: Arc<dyn Sv2Listener<Message>>,
        tx: mpsc::Sender<AcceptResult>,
        transport_label: &'static str,
    ) {
        tokio::spawn(async move {
            loop {
                let res = listener.accept().await;
                let is_fatal = matches!(&res, Err(Error::SocketClosed));
                if let Err(e) = tx.send(res).await {
                    debug!(
                        transport = transport_label,
                        error = ?e,
                        "Dual listener fan-in: receiver dropped, stopping accept loop"
                    );
                    break;
                }
                if is_fatal {
                    info!(
                        transport = transport_label,
                        "Dual listener fan-in: inner listener closed, stopping accept loop"
                    );
                    break;
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Sv2Listener<Message> for DualSv2Listener {
    async fn accept(&self) -> Result<(PeerIdentity, ConnPair<Message>), Error> {
        let mut rx = self.rx.lock().await;
        match rx.recv().await {
            Some(res) => res,
            None => Err(Error::SocketClosed),
        }
    }
}
