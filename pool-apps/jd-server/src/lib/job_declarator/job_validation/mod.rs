//! Module for validating Custom Jobs.

use stratum_apps::{
    stratum_core::{
        bitcoin::{BlockHash, TxOut, Wtxid},
        job_declaration_sv2::{DeclareMiningJob, ProvideMissingTransactionsSuccess, PushSolution},
        mining_sv2::SetCustomMiningJob,
    },
    utils::types::JdToken,
};

pub mod bitcoin_core_ipc;

/// The trait that JDS will use to validate and propagate solutions for Custom Jobs.
/// This allows for modularity with regards to:
/// - different Bitcoin Node implementations.
/// - different ways to connect to the Bitcoin Node.
///
/// Please note that while this is a trait with some similarities with
/// `handlers_sv2::job_declaration::HandleJobDeclarationMessagesFromClientAsync`,
/// this has a different purpose.
///
/// More specifically, we diverge from
/// `handlers_sv2::job_declaration::HandleJobDeclarationMessagesFromClientAsync` in the following
/// ways:
/// - we do not handle the `AllocateMiningJobToken` message
/// - we handle `SetCustomMiningJob` message
#[async_trait::async_trait]
pub trait JobValidationEngine: Send + Sync {
    /// Handles a declare mining job request.
    async fn handle_declare_mining_job(
        &self,
        declare_mining_job: DeclareMiningJob<'_>,
        provide_missing_transactions_success: Option<ProvideMissingTransactionsSuccess<'_>>,
    ) -> DeclareMiningJobResult;

    /// Submits a mining solution to the backend.
    async fn handle_push_solution(&self, push_solution: PushSolution<'_>);

    /// Validates a `SetCustomMiningJob` (Mining Protocol) against the previously declared job
    /// identified by `allocated_token`.
    async fn handle_set_custom_mining_job(
        &self,
        set_custom_mining_job: SetCustomMiningJob<'_>,
        allocated_token: JdToken,
    ) -> SetCustomMiningJobResult;

    /// Allow the engine to attach a custom `TxOut` to an `AllocateMiningJobToken`
    /// before the JDS responds with `AllocateMiningJobTokenSuccess`.
    ///
    /// Backends that want to route the coinbase reward to a per-miner payout
    /// script (rather than the single pool-wide `coinbase_reward_script` held by
    /// `JobDeclarator`) override this method to return `Some(tx_out)`. When the
    /// engine returns `None` the JDS falls back to its existing pool-wide
    /// behavior — i.e. a zero-value `TxOut` whose `script_pubkey` comes from the
    /// `coinbase_reward_script` field on `JobDeclarator`. The default
    /// implementation returns `None`, preserving the upstream behavior for
    /// engines that do not need per-token payout binding (e.g.
    /// `BitcoinCoreIPCEngine`).
    ///
    /// # `user_identifier` normalization
    ///
    /// The `user_identifier` passed here is the raw `Str0_255` payload from the
    /// `AllocateMiningJobToken` message decoded with the following rules, and
    /// engines MUST treat input matching these rules as canonical:
    ///
    /// - **UTF-8 strict.** Bytes that are not valid UTF-8 are rejected by the
    ///   caller before this method is invoked (the caller returns `None` rather
    ///   than passing a non-UTF-8 byte string).
    /// - **NFKC normalization.** The caller normalizes the decoded string with
    ///   Unicode Normalization Form KC before passing it here, so visually
    ///   equivalent code-point sequences map to the same key.
    /// - **ASCII-whitespace trim.** Leading and trailing ASCII whitespace
    ///   (` `, `\t`, `\n`, `\r`, vertical-tab, form-feed) is stripped by the
    ///   caller before normalization. Interior whitespace is preserved as-is.
    ///
    /// Engines may impose additional restrictions (e.g. character allowlists,
    /// length caps below 255 bytes) on top of this normalization, but MUST NOT
    /// assume any further canonicalization has happened upstream.
    ///
    /// # `coinbase_output_max_additional_size`
    ///
    /// Engines that produce a custom `TxOut` MUST ensure the serialized size of
    /// the returned output fits within `coinbase_output_max_additional_size`
    /// bytes (in the standard `bitcoin::consensus` encoding). If the engine
    /// cannot satisfy this constraint it MUST return `None` so the JDS uses the
    /// pool-wide fallback rather than produce an oversize coinbase.
    ///
    /// The default implementation returns `None`.
    async fn handle_allocate_mining_job_token(
        &self,
        _token: JdToken,
        _user_identifier: &str,
        _coinbase_output_max_additional_size: usize,
    ) -> Option<TxOut> {
        None
    }

    /// Performs backend-specific shutdown work.
    ///
    /// Default implementation is a no-op so non-threaded engines do not need to
    /// implement custom teardown.
    fn shutdown(&self) {}

    /// Notify the engine that the underlying share-chain tip has changed.
    ///
    /// Backends that don't track a share-chain ignore this. Backends that
    /// cache validated declared jobs against a specific tip should invalidate
    /// any in-flight tokens whose ancestry no longer matches the new tip.
    ///
    /// The default implementation is a no-op; only p2pool-style engines that
    /// build coinbases against a side-chain tip need to override it.
    /// `BitcoinCoreIPCEngine` does not need to override because it tracks the
    /// Bitcoin chain tip via `validation_context_drifted` on each
    /// `DeclareMiningJob` round, not via an external share-chain.
    async fn notify_share_chain_reorg(&self, _new_tip: BlockHash) {}
}

/// Result of a [`JobValidationEngine::handle_declare_mining_job`] call.
pub enum DeclareMiningJobResult {
    Success,
    Error(&'static str),
    MissingTransactions(Vec<Wtxid>),
}

/// Result of a [`JobValidationEngine::handle_set_custom_mining_job`] call.
pub enum SetCustomMiningJobResult {
    Success,
    Error(&'static str),
}
