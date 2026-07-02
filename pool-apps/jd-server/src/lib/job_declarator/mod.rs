//! Core Job Declaration engine.
//!
//! [`JobDeclarator`] is the central type: it owns the [`TokenManager`], a
//! [`JobValidationEngine`] backend, and the I/O channels that connect it to downstream
//! clients. Its lifecycle follows a `new` -> `start` / `start_downstream_server` -> `shutdown`
//! pattern.

use crate::{
    error,
    error::{JDSError, JDSErrorKind, JDSResult, LoopControl},
    job_declarator::{
        downstream::Downstream,
        job_validation::{JobValidationEngine, SetCustomMiningJobResult},
        token_management::{TokenManager, TokenPayoutEvictor},
    },
};
use async_channel::{unbounded, Receiver, Sender};
use bitcoin_core_sv2::job_declaration_protocol::CancellationToken;
use dashmap::DashMap;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use stratum_apps::{
    config_helpers::CoinbaseRewardScript,
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::accept_noise_connection,
    stratum_core::{
        handlers_sv2::HandleJobDeclarationMessagesFromClientAsync,
        mining_sv2::{
            SetCustomMiningJob, SetCustomMiningJobError, SetCustomMiningJobSuccess,
            ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MINING_JOB_TOKEN,
        },
        parsers_sv2::{JobDeclaration, Tlv},
    },
    task_manager::TaskManager,
    utils::types::{DownstreamId, JdToken},
};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

// see https://github.com/stratum-mining/sv2-apps/issues/335
const TEMPORARY_TIMEOUT_MULTIPLIER: u64 = 144;

/// Timeout for allocated tokens that haven't yet been activated.
/// Ideally 10 minutes, temporarily 24h. see https://github.com/stratum-mining/sv2-apps/issues/335
const ALLOCATED_TOKEN_TIMEOUT_SECS: u64 = TEMPORARY_TIMEOUT_MULTIPLIER * 60 * 10;

/// Timeout for active tokens (10 seconds).
const ACTIVE_TOKEN_TIMEOUT_SECS: u64 = 10;

/// How often the janitor tasks run to clean up expired tokens and pending jobs (seconds).
const JANITOR_INTERVAL_SECS: u64 = 10;

mod downstream;
mod job_declaration_message_handler;
pub mod job_validation;
pub mod token_management;

/// Shared JDP payload exchanged between Job Declarator and downstreams.
type JobDeclarationMessage = (JobDeclaration<'static>, Option<Vec<Tlv>>);

/// Shared JDP payload sent from downstreams to Job Declarator, tagged with downstream id.
type DownstreamJobDeclarationMessage = (DownstreamId, JobDeclaration<'static>, Option<Vec<Tlv>>);

/// The response produced by [`JobDeclarator::handle_set_custom_mining_job`].
///
/// This is a Mining Protocol (MP) message, not a JDP message — it is returned to the
/// caller (typically the Pool) rather than sent over the JDP TCP socket.
#[derive(Debug)]
pub enum SetCustomMiningJobResponse<'a> {
    Ok(SetCustomMiningJobSuccess),
    Error(SetCustomMiningJobError<'a>),
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl SetCustomMiningJobResponse<'_> {
    fn error(request_id: u32, channel_id: u32, error_code: &str) -> Self {
        SetCustomMiningJobResponse::Error(SetCustomMiningJobError {
            request_id,
            channel_id,
            error_code: error_code
                .to_string()
                .try_into()
                .expect("error code must be valid Str0255"),
        })
    }
}

/// Channel endpoints that connect `JobDeclarator` to its downstream clients.
///
/// - `downstream_client_senders`: per-downstream senders for JDP responses.
/// - `job_declarator_sender/receiver`: fan-in channel carrying JDP requests from all downstreams to
///   the central message loop.
/// - `disconnect_sender/receiver`: channel through which downstreams signal disconnection.
#[derive(Clone)]
pub struct JobDeclaratorIo {
    downstream_client_senders: DashMap<DownstreamId, Sender<JobDeclarationMessage>>,
    job_declarator_sender: Sender<DownstreamJobDeclarationMessage>,
    job_declarator_receiver: Receiver<DownstreamJobDeclarationMessage>,
}

/// Central engine for the Job Declaration Protocol.
///
/// Owns the [`TokenManager`], shared data, I/O channels, and delegates block-level
/// validation to the backend.
#[derive(Clone)]
pub struct JobDeclarator {
    token_manager: TokenManager,
    job_validator: Arc<dyn JobValidationEngine>,
    job_declarator_io: Arc<JobDeclaratorIo>,
    coinbase_reward_script: CoinbaseRewardScript,
    downstream_clients: Arc<DashMap<DownstreamId, Downstream>>,
    downstream_id_factory: Arc<AtomicUsize>,
}

/// Constructor of `JobDeclarator` with a pluggable [`JobValidationEngine`] backend.
#[cfg_attr(not(test), hotpath::measure_all)]
impl JobDeclarator {
    pub async fn new(
        engine: Arc<dyn JobValidationEngine>,
        cancellation_token: CancellationToken,
        coinbase_reward_script: CoinbaseRewardScript,
        task_manager: Arc<TaskManager>,
    ) -> Result<Self, JDSErrorKind> {
        Self::new_with_payout_evictor(
            engine,
            cancellation_token,
            coinbase_reward_script,
            task_manager,
            None,
        )
        .await
    }

    /// Construct a `JobDeclarator` and install a
    /// [`TokenPayoutEvictor`] on its internal `TokenManager` before any
    /// allocation happens.
    ///
    /// Mirrors `JobDeclarator::new` but lets callers (e.g. binaries
    /// that maintain per-token side-state in their
    /// `JobValidationEngine`) receive eviction callbacks for every
    /// token the JDS evicts — explicitly (via `deallocate`,
    /// `deactivate`, `remove_downstream`, `clear`) or implicitly by
    /// the janitor expiring it. See the `TokenPayoutEvictor` trait
    /// doc-comment for the contract.
    pub async fn new_with_payout_evictor(
        engine: Arc<dyn JobValidationEngine>,
        cancellation_token: CancellationToken,
        coinbase_reward_script: CoinbaseRewardScript,
        task_manager: Arc<TaskManager>,
        payout_evictor: Option<Arc<dyn TokenPayoutEvictor>>,
    ) -> Result<Self, JDSErrorKind> {
        let (job_declarator_sender, job_declarator_receiver) =
            unbounded::<DownstreamJobDeclarationMessage>();
        let job_declarator_io = Arc::new(JobDeclaratorIo {
            job_declarator_sender,
            job_declarator_receiver,
            downstream_client_senders: DashMap::new(),
        });

        let mut token_manager =
            TokenManager::new(cancellation_token.clone(), Arc::clone(&task_manager));
        if let Some(evictor) = payout_evictor {
            token_manager.set_payout_evictor(evictor);
        }

        Ok(Self {
            token_manager,
            job_validator: engine,
            job_declarator_io,
            coinbase_reward_script,
            downstream_clients: Arc::new(DashMap::new()),
            downstream_id_factory: Arc::new(AtomicUsize::new(0)),
        })
    }
}

/// Generic implementation for all [`JobValidationEngine`] types.
impl JobDeclarator {
    fn handle_error_action(
        &self,
        context: &str,
        e: &JDSError<error::JobDeclarator>,
    ) -> LoopControl {
        match e.action {
            error::Action::Log => {
                warn!(error_kind = ?e.kind, "{context} returned a log-only error");
                LoopControl::Continue
            }
            error::Action::Disconnect(downstream_id) => {
                warn!(
                    downstream_id,
                    error_kind = ?e.kind,
                    "{context} requested downstream disconnect"
                );
                self.cleanup_downstream(downstream_id);
                LoopControl::Continue
            }
            error::Action::Shutdown => {
                warn!(error_kind = ?e.kind, "{context} requested shutdown");
                LoopControl::Break
            }
        }
    }

    /// Binds a TCP listener and spawns the accept loop that creates a `Downstream`
    /// for every new Noise-encrypted connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_downstream_server(
        self,
        authority_public_key: Secp256k1PublicKey,
        authority_secret_key: Secp256k1SecretKey,
        cert_validity_sec: u64,
        listening_address: SocketAddr,
        task_manager: Arc<TaskManager>,
        cancellation_token: CancellationToken,
        supported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
    ) -> JDSResult<(), error::JobDeclarator> {
        info!("Starting downstream server at {listening_address}");
        let server = TcpListener::bind(listening_address)
            .await
            .map_err(|e| {
                error!(error = ?e, "Failed to bind downstream server at {listening_address}");
                e
            })
            .map_err(JDSError::shutdown)?;

        let task_manager_clone = task_manager.clone();
        let cancellation_token_clone = cancellation_token.clone();
        task_manager.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token_clone.cancelled() => {
                        info!("Job Declarator: cancellation token triggered");
                        break;
                    }
                    res = server.accept() => {
                        match res {
                            Ok((stream, socket_address)) => {
                                info!(%socket_address, "New downstream connection");

                                let this = self.clone();
                                let cancellation_token_inner = cancellation_token_clone.clone();
                                let task_manager_inner = task_manager_clone.clone();
                                let supported_extensions_inner = supported_extensions.clone();
                                let required_extensions_inner = required_extensions.clone();

                                task_manager_clone.spawn(async move {
                                    let noise_stream = tokio::select! {
                                        result = accept_noise_connection(
                                            stream,
                                            authority_public_key,
                                            authority_secret_key,
                                            cert_validity_sec,
                                        ) => {
                                            match result {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    error!(error = ?e, "Noise handshake failed");
                                                    return;
                                                }
                                            }
                                        }
                                        _ = cancellation_token_inner.cancelled() => {
                                            info!("Shutdown received during handshake, dropping connection");
                                            return;
                                        }
                                    };

                                    let downstream_id = this
                                        .downstream_id_factory
                                        .fetch_add(1, Ordering::SeqCst);

                                    let (to_downstream_sender, to_downstream_receiver) =
                                        unbounded::<JobDeclarationMessage>();
                                    let to_job_declarator_sender =
                                        this.job_declarator_io.job_declarator_sender.clone();

                                    let downstream = Downstream::new(
                                        downstream_id,
                                        noise_stream,
                                        to_job_declarator_sender,
                                        to_downstream_receiver,
                                        supported_extensions_inner,
                                        required_extensions_inner,
                                        task_manager_inner.clone(),
                                        cancellation_token_inner.clone(),
                                    );

                                    this.downstream_clients
                                        .insert(downstream_id, downstream.clone());

                                    this.job_declarator_io
                                        .downstream_client_senders
                                        .insert(downstream_id, to_downstream_sender);

                                    let jd = this.clone();
                                    downstream
                                        .start(task_manager_inner, move |downstream_id| jd.cleanup_downstream(downstream_id))
                                        .await;

                                });
                            }
                            Err(e) => {
                                error!(error = ?e, "Failed to accept new downstream connection");
                            }
                        }
                    }
                }
            }
            info!("Downstream server: Unified loop break");
        });

        Ok(())
    }

    /// Spawns the central JDP message loop.
    ///
    /// The loop multiplexes over:
    /// - Incoming JDP messages from all downstreams.
    /// - Disconnect notifications from individual downstreams.
    /// - The global cancellation token.
    pub async fn start(
        mut self,
        cancellation_token: CancellationToken,
        task_manager: Arc<TaskManager>,
    ) -> JDSResult<(), error::JobDeclarator> {
        task_manager.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        info!("Job Declarator: cancellation token triggered");
                        break;
                    }
                    res = self.handle_jdp_message() => {
                        if let Err(e) = res {
                            error!(?e, "Error handling Job Declaration message");
                            if let LoopControl::Break = self.handle_error_action(
                                "JobDeclarator::handle_jdp_message",
                                &e,
                            ) {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Graceful shutdown helper.
    ///
    /// Closes internal fan-in/fan-out channels and clears downstream maps so spawned
    /// JDS tasks can drain quickly. We intentionally avoid `token_manager.clear()` here
    /// because it can contend with concurrent downstream cleanup during shutdown.
    pub fn shutdown(&self) {
        info!("JobDeclarator: shutting down");

        self.job_declarator_io.job_declarator_sender.close();
        self.job_declarator_io.job_declarator_receiver.close();
        self.job_declarator_io.downstream_client_senders.clear();
        self.downstream_clients.clear();

        // Let the validation backend tear down any dedicated resources/threads.
        self.job_validator.shutdown();

        info!("JobDeclarator: shutdown complete");
    }

    /// Forward a share-chain tip-change notification to the
    /// [`JobValidationEngine`] backend.
    ///
    /// This is a thin pass-through hosted on `JobDeclarator` so callers that
    /// only hold a `JobDeclarator` (rather than a separate
    /// `Arc<dyn JobValidationEngine>` clone) can still drive the hook. The
    /// default trait implementation is a no-op for backends that do not track
    /// a share-chain (e.g. `BitcoinCoreIPCEngine`).
    pub async fn notify_share_chain_reorg(
        &self,
        new_tip: stratum_apps::stratum_core::bitcoin::BlockHash,
    ) {
        self.job_validator.notify_share_chain_reorg(new_tip).await;
    }

    /// Removes a downstream from all internal maps and cleans up its tokens.
    fn cleanup_downstream(&self, downstream_id: DownstreamId) {
        info!(downstream_id, "Cleaning up disconnected downstream");

        let removed_downstream =
            if let Some((_, mut downstream)) = self.downstream_clients.remove(&downstream_id) {
                downstream.shutdown();
                true
            } else {
                false
            };

        let removed_sender = self
            .job_declarator_io
            .downstream_client_senders
            .remove(&downstream_id)
            .is_some();

        self.token_manager.remove_downstream(downstream_id);

        debug!(
            downstream_id,
            removed_downstream, removed_sender, "Downstream cleanup complete"
        );
    }

    /// Receives and dispatches a single JDP message from the fan-in channel.
    async fn handle_jdp_message(&mut self) -> JDSResult<(), error::JobDeclarator> {
        let receiver = self.job_declarator_io.job_declarator_receiver.clone();
        let (downstream_id, jd_message, tlv_fields) = match receiver.recv().await {
            Ok(msg) => msg,
            Err(e) => {
                error!("Error receiving message: {:?}", e);
                return Err(error::JDSError::shutdown(e));
            }
        };

        self.handle_job_declaration_message_from_client(
            Some(downstream_id),
            jd_message,
            tlv_fields.as_deref(),
        )
        .await?;

        Ok(())
    }

    /// Validates a `SetCustomMiningJob` message via the JDS token manager and job validator.
    ///
    /// This method sends a request to the job validator to validate a SetCustomMiningJob message.
    /// It returns a `SetCustomMiningJobResponse` indicating the result of the operation.
    ///
    /// Remember: `jd_server_sv2` TCP sockets only operate JDP messages, and SetCustomMiningJob is
    /// MP message.
    ///
    /// Therefore, this method is key when `jd_server_sv2` crate is used as a library, where Pool
    /// app uses it to validate incoming SetCustomMiningJob messages. It has no usage on a
    /// standalone JDS app, where JobValidationEngine should be persisted into some shared DB with
    /// Pool app.
    ///
    /// Note: `SetCustomMiningJob.Success.job_id` is not handled here.
    /// It is the caller's responsibility to set it.
    ///
    /// Concurrency: the `&mut self` receiver rules out concurrent `SetCustomMiningJob`
    /// races on the same `JobDeclarator` — no other task can observe the intermediate
    /// state between the validator's `.await` and `token_manager.deactivate(..)` below.
    pub async fn handle_set_custom_mining_job(
        &mut self,
        set_custom_mining_job: SetCustomMiningJob<'static>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> JDSResult<SetCustomMiningJobResponse<'_>, error::JobDeclarator> {
        let request_id = set_custom_mining_job.request_id;
        let channel_id = set_custom_mining_job.channel_id;

        let active_token: JdToken = match set_custom_mining_job.token.inner_as_ref().try_into() {
            Ok(token_bytes) => {
                let token = u64::from_le_bytes(token_bytes);
                debug!(
                    request_id,
                    channel_id,
                    active_token = token,
                    "SetCustomMiningJob: parsed active token"
                );
                token
            }
            Err(_) => {
                debug!(
                    request_id,
                    channel_id, "SetCustomMiningJob: failed to parse active token"
                );
                return Ok(SetCustomMiningJobResponse::error(
                    request_id,
                    channel_id,
                    ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MINING_JOB_TOKEN,
                ));
            }
        };

        // this allows JobValidationEngine to lookup the corresponding DeclareMiningJob
        let allocated_token = match self.token_manager.allocated_from_active(active_token) {
            Some(token) => {
                debug!(
                    request_id,
                    channel_id,
                    active_token,
                    allocated_token = token,
                    "SetCustomMiningJob: active token mapped to allocated token"
                );
                token
            }
            None => {
                debug!(
                    request_id,
                    channel_id,
                    active_token,
                    "SetCustomMiningJob: active token not found in TokenManager"
                );
                return Ok(SetCustomMiningJobResponse::error(
                    request_id,
                    channel_id,
                    ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MINING_JOB_TOKEN,
                ));
            }
        };

        // Validate before deactivate so the active->allocated binding is still readable to
        // the validator and to any downstream `TokenPayoutEvictor` consumers.
        let result = self
            .job_validator
            .handle_set_custom_mining_job(set_custom_mining_job, allocated_token)
            .await;
        // NOTE: cancellation between validate and deactivate leaks `active_token` until
        // the 10s janitor TTL; a full fix requires a drop guard.
        self.token_manager.deactivate(active_token);
        match result {
            SetCustomMiningJobResult::Success => {
                Ok(SetCustomMiningJobResponse::Ok(SetCustomMiningJobSuccess {
                    channel_id,
                    request_id,
                    job_id: 0, // caller responsibility to set it
                }))
            }
            SetCustomMiningJobResult::Error(error_code) => Ok(SetCustomMiningJobResponse::error(
                request_id, channel_id, error_code,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests locking in the `deactivate-after-validate` ordering established by
    //! `handle_set_custom_mining_job`. See the doc-comment on that method.
    //!
    //! The `MockJobValidationEngine` here records observations into an
    //! `Arc<Mutex<..>>` sidechannel; it does NOT mutate the `TokenManager`.
    //! Tests build a `TokenManager` with an explicit `CancellationToken` that
    //! they fire in `Drop` to stop the janitor task.
    use super::*;
    use crate::job_declarator::job_validation::{DeclareMiningJobResult, JobValidationEngine};
    use async_trait::async_trait;
    use std::{sync::Mutex as StdMutex, time::Instant};
    use stratum_apps::stratum_core::{
        binary_sv2::{Seq0255, U256},
        job_declaration_sv2::{DeclareMiningJob, ProvideMissingTransactionsSuccess, PushSolution},
    };

    /// RAII drop-guard that cancels the janitor task so tests don't leak spawned tasks.
    struct CancelOnDrop(CancellationToken);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }

    /// Sidechannel populated by the mock validator during
    /// `handle_set_custom_mining_job` — proves ordering without mutating the
    /// `TokenManager` itself.
    #[derive(Default)]
    struct ValidatorObservation {
        /// `Some(true)` if the active->allocated lookup returned `Some(_)` at
        /// validator call time; `Some(false)` if `None`; `None` if the mock
        /// was never called.
        binding_live_at_call: Option<bool>,
        /// Monotonic tick captured at the end of the validator body.
        validator_tick: Option<Instant>,
    }

    /// Mock [`JobValidationEngine`] returning a configured result and recording
    /// call-time state via a shared sidechannel.
    struct MockJobValidationEngine {
        result: StdMutex<Option<SetCustomMiningJobResult>>,
        token_manager: TokenManager,
        expected_active_token: JdToken,
        observation: Arc<StdMutex<ValidatorObservation>>,
    }

    #[async_trait]
    impl JobValidationEngine for MockJobValidationEngine {
        async fn handle_declare_mining_job(
            &self,
            _declare_mining_job: DeclareMiningJob<'_>,
            _provide_missing_transactions_success: Option<ProvideMissingTransactionsSuccess<'_>>,
        ) -> DeclareMiningJobResult {
            DeclareMiningJobResult::Success
        }

        async fn handle_push_solution(&self, _push_solution: PushSolution<'_>) {}

        async fn handle_set_custom_mining_job(
            &self,
            _set_custom_mining_job: SetCustomMiningJob<'_>,
            _allocated_token: JdToken,
        ) -> SetCustomMiningJobResult {
            // Observation 1: is the active->allocated binding still live?
            let binding_live = self
                .token_manager
                .allocated_from_active(self.expected_active_token)
                .is_some();
            // Yield so any hypothetical concurrent deactivate would have a
            // chance to run before we record — belt-and-braces against a
            // future reordering that violates the invariant.
            tokio::task::yield_now().await;
            let tick = Instant::now();
            let mut obs = self.observation.lock().unwrap();
            obs.binding_live_at_call = Some(binding_live);
            obs.validator_tick = Some(tick);
            drop(obs);

            self.result
                .lock()
                .unwrap()
                .take()
                .expect("mock result must be set before the call")
        }
    }

    /// TokenPayoutEvictor test double that records monotonic ticks whenever
    /// `on_active_evicted` fires.
    #[derive(Default)]
    struct RecordingEvictor {
        evictor_tick: StdMutex<Option<Instant>>,
        active_evictions: StdMutex<Vec<(JdToken, JdToken)>>,
    }

    impl TokenPayoutEvictor for RecordingEvictor {
        fn on_active_evicted(&self, active_token: JdToken, allocated_token: JdToken) {
            *self.evictor_tick.lock().unwrap() = Some(Instant::now());
            self.active_evictions
                .lock()
                .unwrap()
                .push((active_token, allocated_token));
        }
    }

    fn test_coinbase_reward_script() -> CoinbaseRewardScript {
        CoinbaseRewardScript::from_descriptor("addr(1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2)")
            .expect("valid mainnet address descriptor")
    }

    fn build_set_custom_mining_job(active_token: JdToken) -> SetCustomMiningJob<'static> {
        SetCustomMiningJob {
            channel_id: 1,
            request_id: 7,
            token: active_token.to_le_bytes().to_vec().try_into().unwrap(),
            version: 0,
            prev_hash: U256::Owned(vec![0_u8; 32]),
            min_ntime: 0,
            nbits: 0,
            coinbase_tx_version: 0,
            coinbase_prefix: Vec::<u8>::new().try_into().unwrap(),
            coinbase_tx_input_n_sequence: 0,
            coinbase_tx_outputs: Vec::<u8>::new().try_into().unwrap(),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255::new(Vec::new()).unwrap(),
        }
    }

    /// Table-driven over both `SetCustomMiningJobResult` arms.
    ///
    /// Proves the ordering invariant AND that `deactivate` runs unconditionally:
    /// - Inside the validator body, `allocated_from_active(active_token)` returns `Some(_)`.
    /// - After `handle_set_custom_mining_job` returns, the same lookup returns `None`.
    #[tokio::test]
    async fn validator_observes_binding_and_deactivate_runs_after() {
        for result in [
            SetCustomMiningJobResult::Success,
            SetCustomMiningJobResult::Error("boom"),
        ] {
            let cancellation_token = CancellationToken::new();
            let _guard = CancelOnDrop(cancellation_token.clone());
            let task_manager = Arc::new(TaskManager::new());

            // Bootstrap a real TokenManager -> allocate -> activate so the
            // active->allocated mapping is live.
            let token_manager =
                TokenManager::new(cancellation_token.clone(), Arc::clone(&task_manager));
            let downstream_id: DownstreamId = 0;
            let allocated_token = token_manager.allocate(downstream_id);
            let active_token = token_manager.activate(allocated_token, downstream_id);
            assert_eq!(
                token_manager.allocated_from_active(active_token),
                Some(allocated_token),
                "sanity: active token must map to allocated token before the call"
            );

            let observation = Arc::new(StdMutex::new(ValidatorObservation::default()));
            let engine: Arc<dyn JobValidationEngine> = Arc::new(MockJobValidationEngine {
                result: StdMutex::new(Some(result)),
                token_manager: token_manager.clone(),
                expected_active_token: active_token,
                observation: Arc::clone(&observation),
            });

            // Build the JobDeclarator via its public constructor, then swap in
            // our pre-populated TokenManager so the allocation is visible to
            // the code under test. Both TokenManager values share their inner
            // Arc<DashMap>s so this "swap" is really just picking one clone
            // to hand to JobDeclarator.
            let mut jd = JobDeclarator::new(
                Arc::clone(&engine),
                cancellation_token.clone(),
                test_coinbase_reward_script(),
                Arc::clone(&task_manager),
            )
            .await
            .expect("JobDeclarator::new must succeed with a test engine");
            jd.token_manager = token_manager.clone();

            let scmj = build_set_custom_mining_job(active_token);
            let _ = jd
                .handle_set_custom_mining_job(scmj, None)
                .await
                .expect("outer call must succeed on both result arms");

            let obs = observation.lock().unwrap();
            assert_eq!(
                obs.binding_live_at_call,
                Some(true),
                "validator must observe a live active->allocated binding at call time",
            );
            drop(obs);
            assert_eq!(
                token_manager.allocated_from_active(active_token),
                None,
                "deactivate must have run unconditionally after the validator returned",
            );
        }
    }

    /// Locks the strict ordering: the evictor tick is captured after the
    /// validator tick. A future re-inversion of the reorder fails this test
    /// mechanically.
    #[tokio::test]
    async fn evictor_fires_after_validator_returns() {
        let cancellation_token = CancellationToken::new();
        let _guard = CancelOnDrop(cancellation_token.clone());
        let task_manager = Arc::new(TaskManager::new());

        let mut token_manager =
            TokenManager::new(cancellation_token.clone(), Arc::clone(&task_manager));
        let evictor: Arc<RecordingEvictor> = Arc::new(RecordingEvictor::default());
        token_manager.set_payout_evictor(Arc::clone(&evictor) as Arc<dyn TokenPayoutEvictor>);

        let downstream_id: DownstreamId = 0;
        let allocated_token = token_manager.allocate(downstream_id);
        let active_token = token_manager.activate(allocated_token, downstream_id);

        let observation = Arc::new(StdMutex::new(ValidatorObservation::default()));
        let engine: Arc<dyn JobValidationEngine> = Arc::new(MockJobValidationEngine {
            result: StdMutex::new(Some(SetCustomMiningJobResult::Success)),
            token_manager: token_manager.clone(),
            expected_active_token: active_token,
            observation: Arc::clone(&observation),
        });

        let mut jd = JobDeclarator::new_with_payout_evictor(
            Arc::clone(&engine),
            cancellation_token.clone(),
            test_coinbase_reward_script(),
            Arc::clone(&task_manager),
            Some(Arc::clone(&evictor) as Arc<dyn TokenPayoutEvictor>),
        )
        .await
        .expect("JobDeclarator::new_with_payout_evictor must succeed");
        jd.token_manager = token_manager.clone();

        // Nudge the recorded validator tick strictly forward so tick equality
        // on very fast machines still resolves the strict-lt assertion below.
        // The evictor tick is captured after the validator returns, so any
        // real-clock progress guarantees strict-lt; the sleep is defensive.
        let scmj = build_set_custom_mining_job(active_token);
        let _ = jd
            .handle_set_custom_mining_job(scmj, None)
            .await
            .expect("outer call must succeed");

        let obs = observation.lock().unwrap();
        let validator_tick = obs
            .validator_tick
            .expect("validator must record a tick during the call");
        drop(obs);
        let evictor_tick = evictor
            .evictor_tick
            .lock()
            .unwrap()
            .expect("evictor must fire when deactivate runs on the active token");
        assert!(
            validator_tick < evictor_tick,
            "validator tick ({:?}) must strictly precede evictor tick ({:?})",
            validator_tick,
            evictor_tick,
        );
        let active_evictions = evictor.active_evictions.lock().unwrap();
        assert_eq!(
            active_evictions.as_slice(),
            &[(active_token, allocated_token)],
            "evictor must record exactly the (active, allocated) pair we set up",
        );
    }
}
