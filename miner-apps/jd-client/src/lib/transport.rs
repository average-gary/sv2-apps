//! JDC outbound transport plumbing — Phase 4b of the iroh-transport plan.
//!
//! Wraps the three outbound dial sites (JDC→Pool, JDC→JDS, JDC→TP) behind a
//! single [`JdcConnectors`] handle that owns:
//!
//! * a [`TcpSv2Connector`] (always present),
//! * an optional [`IrohSv2Connector`] per dial site (one per ALPN: pool, JDS,
//!   TP) when the `iroh-transport` feature is on AND the JDC config has an
//!   `[iroh]` block.
//!
//! Three connectors share the same `iroh::Endpoint` clone — the same endpoint
//! that JDC's downstream listener was built with in Phase 3c, so the JDC has
//! exactly one UDP socket regardless of how many roles it speaks to.
//!
//! Per-dial-site fallback is composed locally here (`dial_with_fallback`)
//! rather than inside `IrohSv2Connector` — the connector honors the iroh leg
//! of any `Sv2Target` variant and surfaces a clean error so the caller can try
//! TCP next. This keeps the change surface in `stratum-apps/` to a single ALPN
//! constant.

use std::sync::Arc;

use stratum_apps::{
    network_helpers::{
        transport::{ConnPair, Sv2Connector, Sv2Target, TcpSv2Connector},
        Error as TransportError,
    },
    stratum_core::{
        binary_sv2::{Deserialize, GetSize, Serialize},
        codec_sv2::StandardEitherFrame,
    },
    utils::types::Message,
};
use tracing::warn;

#[cfg(feature = "iroh-transport")]
use std::net::SocketAddr;
#[cfg(feature = "iroh-transport")]
use stratum_apps::key_utils::Secp256k1PublicKey;
#[cfg(feature = "iroh-transport")]
use tracing::{debug, info};

#[cfg(feature = "iroh-transport")]
use iroh::{Endpoint, NodeAddr, NodeId, RelayUrl};
#[cfg(feature = "iroh-transport")]
use std::str::FromStr;
#[cfg(feature = "iroh-transport")]
use stratum_apps::network_helpers::iroh::{
    alpn::{SV2_JDS_ALPN, SV2_POOL_ALPN, SV2_TP_ALPN},
    connector::IrohSv2Connector,
    endpoint::build_endpoint,
    IrohRoleConfig,
};

#[cfg(feature = "iroh-transport")]
use crate::config::PreferTransport;

/// Owned bundle of outbound connectors used by JDC's three dial sites.
///
/// One [`TcpSv2Connector`] is shared across all three roles (it carries no
/// per-role state). Each iroh role gets its own [`IrohSv2Connector`] because
/// `IrohSv2Connector` is bound to a single ALPN at construction time and the
/// three roles use distinct ALPNs (`sv2/pool/0`, `sv2/jds/0`, `sv2/tp/0`).
/// All three iroh connectors share the same underlying `iroh::Endpoint` clone.
#[derive(Clone)]
pub struct JdcConnectors {
    tcp: Arc<TcpSv2Connector>,
    #[cfg(feature = "iroh-transport")]
    pool_iroh: Option<Arc<IrohSv2Connector>>,
    #[cfg(feature = "iroh-transport")]
    jds_iroh: Option<Arc<IrohSv2Connector>>,
    #[cfg(feature = "iroh-transport")]
    tp_iroh: Option<Arc<IrohSv2Connector>>,
    /// Endpoint kept alive for as long as any iroh connector is in use.
    /// Dropped when [`JdcConnectors`] is dropped.
    #[cfg(feature = "iroh-transport")]
    _endpoint: Option<Endpoint>,
}

impl JdcConnectors {
    /// Construct a TCP-only [`JdcConnectors`] — used when the JDC config has
    /// no `[iroh]` block, when the `iroh-transport` feature is off, or when
    /// the iroh endpoint failed to build (we still want JDC to come up over
    /// TCP).
    pub fn tcp_only() -> Self {
        Self {
            tcp: Arc::new(TcpSv2Connector::new()),
            #[cfg(feature = "iroh-transport")]
            pool_iroh: None,
            #[cfg(feature = "iroh-transport")]
            jds_iroh: None,
            #[cfg(feature = "iroh-transport")]
            tp_iroh: None,
            #[cfg(feature = "iroh-transport")]
            _endpoint: None,
        }
    }

    /// Build a [`JdcConnectors`] from the JDC's `[iroh]` config block,
    /// constructing one [`IrohSv2Connector`] per role.
    ///
    /// On any failure (endpoint build, secret-key load, etc.) this falls
    /// back to [`Self::tcp_only`] and logs a warning. JDC's outbound dials
    /// will then go over TCP — operators see the warning at startup.
    #[cfg(feature = "iroh-transport")]
    pub async fn build(iroh_config: Option<&IrohRoleConfig>) -> Self {
        let Some(cfg) = iroh_config else {
            return Self::tcp_only();
        };

        let resolved = match cfg.resolve() {
            Ok(r) => r,
            Err(e) => {
                warn!(error = ?e, "[iroh-transport] JDC iroh config resolve failed; outbound dials will use TCP only");
                return Self::tcp_only();
            }
        };

        // The endpoint we build here is also used by JDC's downstream
        // listener. Phase 3c builds the listener separately (because it
        // needs the listener-specific ALPN registered up-front); here we
        // build a second one solely for outbound dials. Both endpoints
        // share the same persistent secret key on disk, so they share the
        // same NodeId — what differs is the registered ALPNs. For dials we
        // register all three outbound ALPNs so we can dispatch any of the
        // three roles through this single endpoint.
        let mut endpoint_cfg = resolved.endpoint_config.clone();
        endpoint_cfg.alpns = vec![
            SV2_POOL_ALPN.to_vec(),
            SV2_JDS_ALPN.to_vec(),
            SV2_TP_ALPN.to_vec(),
        ];

        let endpoint = match build_endpoint(&endpoint_cfg).await {
            Ok(ep) => ep,
            Err(e) => {
                warn!(error = ?e, "[iroh-transport] failed to build outbound iroh endpoint; outbound dials will use TCP only");
                return Self::tcp_only();
            }
        };

        info!(
            listen_address = %endpoint_cfg.listen_address,
            "[iroh-transport] JDC outbound iroh endpoint bound"
        );

        let overrides = resolved.connection_overrides.clone();
        let timeout = resolved.per_request_timeout;

        let pool_iroh = Arc::new(IrohSv2Connector::new(
            endpoint.clone(),
            overrides.clone(),
            SV2_POOL_ALPN,
            timeout,
        ));
        let jds_iroh = Arc::new(IrohSv2Connector::new(
            endpoint.clone(),
            overrides.clone(),
            SV2_JDS_ALPN,
            timeout,
        ));
        let tp_iroh = Arc::new(IrohSv2Connector::new(
            endpoint.clone(),
            overrides,
            SV2_TP_ALPN,
            timeout,
        ));

        Self {
            tcp: Arc::new(TcpSv2Connector::new()),
            pool_iroh: Some(pool_iroh),
            jds_iroh: Some(jds_iroh),
            tp_iroh: Some(tp_iroh),
            _endpoint: Some(endpoint),
        }
    }

    /// Dial JDC→Pool with the configured fallback ordering.
    pub async fn connect_pool<M>(
        &self,
        target: &Sv2Target,
    ) -> Result<ConnPair<M>, TransportError>
    where
        M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
    {
        #[cfg(feature = "iroh-transport")]
        {
            return dial_with_fallback(&self.tcp, self.pool_iroh.as_deref(), target).await;
        }
        #[cfg(not(feature = "iroh-transport"))]
        {
            return self.tcp.connect(target).await;
        }
    }

    /// Dial JDC→JDS with the configured fallback ordering.
    pub async fn connect_jds<M>(
        &self,
        target: &Sv2Target,
    ) -> Result<ConnPair<M>, TransportError>
    where
        M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
    {
        #[cfg(feature = "iroh-transport")]
        {
            return dial_with_fallback(&self.tcp, self.jds_iroh.as_deref(), target).await;
        }
        #[cfg(not(feature = "iroh-transport"))]
        {
            return self.tcp.connect(target).await;
        }
    }

    /// Dial JDC→TP with the configured fallback ordering.
    pub async fn connect_tp<M>(
        &self,
        target: &Sv2Target,
    ) -> Result<ConnPair<M>, TransportError>
    where
        M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
    {
        #[cfg(feature = "iroh-transport")]
        {
            return dial_with_fallback(&self.tcp, self.tp_iroh.as_deref(), target).await;
        }
        #[cfg(not(feature = "iroh-transport"))]
        {
            return self.tcp.connect(target).await;
        }
    }
}

/// Local fallback composer.
///
/// The [`Sv2Target`] variant tells us the requested order:
///
/// | Variant         | Try first | Try on first failure |
/// |-----------------|-----------|---------------------|
/// | `Tcp`           | TCP       | -                   |
/// | `Iroh`          | iroh      | -                   |
/// | `IrohThenTcp`   | iroh      | TCP                 |
/// | `TcpThenIroh`   | TCP       | iroh                |
///
/// When the iroh leg is requested but no iroh connector is available (feature
/// off, or endpoint failed to build), we degrade to the TCP leg of any
/// combined variant. A pure-iroh `Sv2Target::Iroh` with no iroh connector
/// surfaces [`TransportError::WrongTargetForTransport`] so misconfigurations
/// don't silently fall through.
#[cfg(feature = "iroh-transport")]
async fn dial_with_fallback<M>(
    tcp: &TcpSv2Connector,
    iroh: Option<&IrohSv2Connector>,
    target: &Sv2Target,
) -> Result<ConnPair<M>, TransportError>
where
    M: Serialize + Deserialize<'static> + GetSize + Send + 'static,
{
    match target {
        Sv2Target::Tcp { .. } => tcp.connect(target).await,
        Sv2Target::Iroh { .. } => match iroh {
            Some(c) => c.connect(target).await,
            None => Err(TransportError::WrongTargetForTransport(
                "no iroh connector available for pure-iroh target".to_string(),
            )),
        },
        Sv2Target::IrohThenTcp {
            node_addr,
            tcp_addr,
            authority_pubkey,
        } => {
            // Plan §"Client side — fallback ordering": try iroh, fall back
            // to TCP on failure.
            if let Some(c) = iroh {
                let iroh_target = Sv2Target::Iroh {
                    node_addr: node_addr.clone(),
                    authority_pubkey: *authority_pubkey,
                };
                match c.connect(&iroh_target).await {
                    Ok(pair) => {
                        info!(
                            "[iroh-transport] dialed via iroh (fallback target was IrohThenTcp)"
                        );
                        return Ok(pair);
                    }
                    Err(e) => {
                        warn!(
                            error = ?e,
                            "[iroh-transport] iroh leg failed, falling back to TCP"
                        );
                    }
                }
            } else {
                debug!(
                    "[iroh-transport] no iroh connector configured; \
                     skipping iroh leg of IrohThenTcp"
                );
            }
            let tcp_target = Sv2Target::Tcp {
                addr: *tcp_addr,
                authority_pubkey: *authority_pubkey,
            };
            tcp.connect(&tcp_target).await
        }
        Sv2Target::TcpThenIroh {
            tcp_addr,
            node_addr,
            authority_pubkey,
        } => {
            let tcp_target = Sv2Target::Tcp {
                addr: *tcp_addr,
                authority_pubkey: *authority_pubkey,
            };
            match tcp.connect(&tcp_target).await {
                Ok(pair) => Ok(pair),
                Err(tcp_err) => {
                    warn!(
                        error = ?tcp_err,
                        "[iroh-transport] TCP leg failed, falling back to iroh"
                    );
                    if let Some(c) = iroh {
                        let iroh_target = Sv2Target::Iroh {
                            node_addr: node_addr.clone(),
                            authority_pubkey: *authority_pubkey,
                        };
                        c.connect(&iroh_target).await
                    } else {
                        Err(tcp_err)
                    }
                }
            }
        }
    }
}

/// Build an [`Sv2Target`] for the JDC→Pool dial site, honoring per-upstream
/// preferences.
///
/// The returned target's variant encodes the runtime fallback choice:
/// `Sv2Target::Tcp` for "TCP only", `Sv2Target::Iroh` for "iroh only",
/// and the combined variants for fallback-eligible dials. The ALPN is
/// implicit in which connector the call site uses (see [`JdcConnectors`]).
#[cfg(feature = "iroh-transport")]
pub fn build_pool_target(
    tcp_addr: SocketAddr,
    authority_pubkey: Secp256k1PublicKey,
    iroh_node_id: Option<&str>,
    iroh_relay_url: Option<&str>,
    prefer: PreferTransport,
) -> Sv2Target {
    build_target(
        tcp_addr,
        Some(authority_pubkey),
        iroh_node_id,
        iroh_relay_url,
        prefer,
    )
}

/// Build an [`Sv2Target`] for the JDC→JDS dial site. Same shape as the pool
/// builder, exists separately so the call sites read cleanly.
#[cfg(feature = "iroh-transport")]
pub fn build_jds_target(
    tcp_addr: SocketAddr,
    authority_pubkey: Secp256k1PublicKey,
    iroh_node_id: Option<&str>,
    iroh_relay_url: Option<&str>,
    prefer: PreferTransport,
) -> Sv2Target {
    build_target(
        tcp_addr,
        Some(authority_pubkey),
        iroh_node_id,
        iroh_relay_url,
        prefer,
    )
}

/// Build an [`Sv2Target`] for the JDC→TP dial site. The TP authority pubkey
/// is optional (the existing TCP path already supports
/// `connect_with_noise(_, None)` for unauthenticated TPs).
#[cfg(feature = "iroh-transport")]
pub fn build_tp_target(
    tcp_addr: SocketAddr,
    authority_pubkey: Option<Secp256k1PublicKey>,
    iroh_node_id: Option<&str>,
    iroh_relay_url: Option<&str>,
    prefer: PreferTransport,
) -> Sv2Target {
    build_target(
        tcp_addr,
        authority_pubkey,
        iroh_node_id,
        iroh_relay_url,
        prefer,
    )
}

/// Inner builder shared by all three role-specific helpers.
#[cfg(feature = "iroh-transport")]
fn build_target(
    tcp_addr: SocketAddr,
    authority_pubkey: Option<Secp256k1PublicKey>,
    iroh_node_id: Option<&str>,
    iroh_relay_url: Option<&str>,
    prefer: PreferTransport,
) -> Sv2Target {
    let node_addr = iroh_node_id.and_then(|raw| parse_node_addr(raw, iroh_relay_url));

    match (prefer, node_addr) {
        // No iroh node id -> degrade to TCP regardless of preference.
        (_, None) => {
            if !matches!(prefer, PreferTransport::Tcp) {
                debug!(
                    ?prefer,
                    "[iroh-transport] no iroh_node_id configured for this target; using TCP"
                );
            }
            Sv2Target::Tcp {
                addr: tcp_addr,
                authority_pubkey,
            }
        }
        (PreferTransport::Tcp, _) => Sv2Target::Tcp {
            addr: tcp_addr,
            authority_pubkey,
        },
        (PreferTransport::Iroh, Some(na)) => Sv2Target::Iroh {
            node_addr: na,
            authority_pubkey,
        },
        (PreferTransport::IrohThenTcp, Some(na)) => Sv2Target::IrohThenTcp {
            node_addr: na,
            tcp_addr,
            authority_pubkey,
        },
        (PreferTransport::TcpThenIroh, Some(na)) => Sv2Target::TcpThenIroh {
            tcp_addr,
            node_addr: na,
            authority_pubkey,
        },
    }
}

/// Parse a base32-lowercase iroh `NodeId` plus an optional relay URL into a
/// [`NodeAddr`]. Returns `None` (and logs a warning) on malformed input so
/// the caller can degrade to the TCP leg.
#[cfg(feature = "iroh-transport")]
fn parse_node_addr(node_id_str: &str, relay_url: Option<&str>) -> Option<NodeAddr> {
    let node_id = match NodeId::from_str(node_id_str) {
        Ok(id) => id,
        Err(e) => {
            warn!(
                node_id = node_id_str,
                error = %e,
                "[iroh-transport] failed to parse iroh NodeId; falling back to TCP for this target"
            );
            return None;
        }
    };
    let relay = relay_url.and_then(|u| match RelayUrl::from_str(u) {
        Ok(parsed) => Some(parsed),
        Err(e) => {
            warn!(
                relay_url = u,
                error = %e,
                "[iroh-transport] failed to parse iroh relay URL; ignoring it"
            );
            None
        }
    });
    Some(NodeAddr::from_parts(node_id, relay, std::iter::empty()))
}

/// Spawn the read/write bridge tasks that translate between a transport-agnostic
/// [`ConnPair<Message>`] (`StandardEitherFrame<Message>` channels) and the
/// existing inbound/outbound `Sv2Frame` channel pair the rest of the JDC
/// pipeline consumes.
///
/// Mirrors the `spawn_io_tasks` shape (cancellation + fallback registration)
/// so existing callers don't have to change downstream wiring. Replaces the
/// legacy `NoiseTcp{Read,Write}Half` reader/writer pair at the three outbound
/// dial sites — the Noise pumping itself now lives inside the listener-side
/// transport (`Connection::new` for TCP, `IrohConnection` for iroh).
#[track_caller]
#[allow(clippy::too_many_arguments)]
pub fn spawn_conn_pair_io_tasks(
    task_manager: Arc<stratum_apps::task_manager::TaskManager>,
    conn_pair: ConnPair<Message>,
    outbound_rx: async_channel::Receiver<stratum_apps::utils::types::Sv2Frame>,
    inbound_tx: async_channel::Sender<stratum_apps::utils::types::Sv2Frame>,
    cancellation_token: bitcoin_core_sv2::template_distribution_protocol::CancellationToken,
    fallback_coordinator: Option<stratum_apps::fallback_coordinator::FallbackCoordinator>,
) {
    use stratum_apps::channel_utils::ReceiverCleanup;
    use tracing::{error, trace, Instrument as _};

    let caller = std::panic::Location::caller();
    let (transport_rx, transport_tx) = conn_pair;
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    // Reader bridge: transport_rx -> inbound_tx (Sv2 only).
    {
        let cancellation_token = cancellation_token.clone();
        let fallback = FallbackRegistration::new(fallback_coordinator.clone());
        let inbound_tx_inner = inbound_tx;
        let outbound_rx_inner = outbound_rx_clone;

        task_manager.spawn(
            async move {
                trace!("Outbound conn-pair reader bridge started");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token.cancelled() => {
                            trace!("Outbound reader bridge: shutdown");
                            break;
                        }
                        _ = fallback.cancelled(), if fallback.is_enabled() => {
                            trace!("Outbound reader bridge: fallback");
                            break;
                        }
                        res = transport_rx.recv() => {
                            match res {
                                Ok(StandardEitherFrame::Sv2(sv2_frame)) => {
                                    if let Err(e) = inbound_tx_inner.send(sv2_frame).await {
                                        error!(error = ?e, "Outbound reader bridge: forward failed");
                                        break;
                                    }
                                }
                                Ok(StandardEitherFrame::HandShake(frame)) => {
                                    error!(?frame, "Outbound reader bridge: unexpected handshake frame");
                                    drop(frame);
                                    break;
                                }
                                Err(e) => {
                                    error!(error = ?e, "Outbound reader bridge: transport closed");
                                    break;
                                }
                            }
                        }
                    }
                }
                inbound_tx_inner.close();
                outbound_rx_inner.close_and_drain();
                fallback.done();
                warn!("Outbound conn-pair reader bridge exited.");
            }
            .instrument(tracing::trace_span!(
                "outbound_reader_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    // Writer bridge: outbound_rx -> transport_tx (re-wrap as EitherFrame).
    {
        let cancellation_token = cancellation_token;
        let fallback = FallbackRegistration::new(fallback_coordinator);
        let outbound_rx_inner = outbound_rx;
        let inbound_tx_inner = inbound_tx_clone;

        task_manager.spawn(
            async move {
                trace!("Outbound conn-pair writer bridge started");
                loop {
                    tokio::select! {
                        biased;
                        _ = cancellation_token.cancelled() => {
                            trace!("Outbound writer bridge: shutdown");
                            break;
                        }
                        _ = fallback.cancelled(), if fallback.is_enabled() => {
                            trace!("Outbound writer bridge: fallback");
                            break;
                        }
                        res = outbound_rx_inner.recv() => {
                            match res {
                                Ok(frame) => {
                                    let either: StandardEitherFrame<Message> =
                                        StandardEitherFrame::Sv2(frame);
                                    if let Err(e) = transport_tx.send(either).await {
                                        error!(error = ?e, "Outbound writer bridge: send failed");
                                        break;
                                    }
                                }
                                Err(_) => {
                                    warn!("Outbound writer bridge: outbound channel closed");
                                    break;
                                }
                            }
                        }
                    }
                }
                outbound_rx_inner.close_and_drain();
                inbound_tx_inner.close();
                transport_tx.close();
                fallback.done();
                warn!("Outbound conn-pair writer bridge exited.");
            }
            .instrument(tracing::trace_span!(
                "outbound_writer_bridge",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}

/// Local copy of `io_task::FallbackRegistration` — kept private to this module
/// so `io_task.rs` stays untouched on the existing Noise reader/writer code
/// path used by the legacy listener bootstrap.
struct FallbackRegistration {
    handler: Option<stratum_apps::fallback_coordinator::FallbackHandler>,
    token: Option<bitcoin_core_sv2::template_distribution_protocol::CancellationToken>,
}

impl FallbackRegistration {
    fn new(
        fallback_coordinator: Option<stratum_apps::fallback_coordinator::FallbackCoordinator>,
    ) -> Self {
        match fallback_coordinator {
            Some(fc) => Self {
                handler: Some(fc.register()),
                token: Some(fc.token()),
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
