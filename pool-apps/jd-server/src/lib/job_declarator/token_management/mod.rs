//! Module for managing the tokens used in the Job Declaration process.
//!
//! There's two types of tokens:
//! - Allocated tokens: allocated into a `AllocateMiningJobToken.Success` message.
//! - Active tokens: tokens that were previously allocated and are then activated into a
//!   `DeclareMiningJob.Success` message.
//!
//! The process of "activating" an "allocated" token consists of:
//! - Removing the allocated token from the allocated tokens set.
//! - Creating a corresponding active token and adding it to the active tokens set.
//! - Returning the active token.
//!
//! Both kinds of token are managed via [`TokenManager`]. It is responsible for:
//! - Allocating new tokens.
//! - Deallocating allocated tokens after a configurable timeout.
//! - Activating tokens that are allocated.
//! - Deactivating active tokens after a configurable timeout.
//! - Checking if a token is allocated.
//! - Checking if a token is active.

use super::{ACTIVE_TOKEN_TIMEOUT_SECS, ALLOCATED_TOKEN_TIMEOUT_SECS, JANITOR_INTERVAL_SECS};
use bitcoin_core_sv2::job_declaration_protocol::CancellationToken;
use dashmap::DashMap;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use stratum_apps::{
    task_manager::TaskManager,
    utils::types::{DownstreamId, JdToken},
};
use tracing::debug;

/// Hook invoked by [`TokenManager`] whenever a token is removed from the
/// allocated/active sets — explicitly (via `deallocate`, `deactivate`,
/// `remove_downstream`, `clear`) or implicitly by the janitor expiring it.
///
/// Engines that maintain side-state keyed by `JdToken` (for example, a
/// per-miner payout-script map populated by
/// `JobValidationEngine::handle_allocate_mining_job_token`) register a
/// `TokenPayoutEvictor` so they can drop the corresponding entries when the
/// `TokenManager` evicts a token. Without this hook, a per-token map could
/// outlive the JDS's own knowledge of the token and leak memory across the
/// 10-minute (allocated) and 10-second (active) TTL windows.
///
/// Implementations must be cheap and non-blocking — they run inside the
/// janitor's `retain` closure as well as on the JDP message-handling path.
pub trait TokenPayoutEvictor: Send + Sync {
    /// Called when an allocated token (one that was returned to a JDC by
    /// `AllocateMiningJobTokenSuccess` but never activated) is evicted.
    fn on_allocated_evicted(&self, _token: JdToken) {}

    /// Called when an active token (one that was activated by
    /// `DeclareMiningJobSuccess`) is evicted. `allocated_token` is the
    /// originally allocated `JdToken` the active token was derived from, so
    /// engines that key their side-state on the *allocated* token can still
    /// find the entry to drop.
    fn on_active_evicted(&self, _active_token: JdToken, _allocated_token: JdToken) {}
}

/// Data associated with an allocated token.
/// - Instant is the allocation timestamp
/// - DownstreamId is the downstream ID that allocated the token
pub type AllocatedTokenData = (Instant, DownstreamId);
/// Data associated with an active token.
/// - JdToken is the corresponding allocated token
/// - Instant is the activation timestamp
/// - DownstreamId is the downstream ID that activated the token
pub type ActiveTokenData = (JdToken, Instant, DownstreamId);

/// Manager for the tokens used in the Job Declaration process.
#[derive(Clone)]
pub struct TokenManager {
    token_factory: Arc<AtomicU64>,
    allocated_tokens: Arc<DashMap<JdToken, AllocatedTokenData>>,
    active_tokens: Arc<DashMap<JdToken, ActiveTokenData>>,
    cancellation_token: CancellationToken,
    task_manager: Arc<TaskManager>,
    /// Optional listener notified whenever a token is evicted from
    /// `allocated_tokens` or `active_tokens` (explicitly or via the janitor).
    /// See [`TokenPayoutEvictor`] for the contract.
    payout_evictor: Option<Arc<dyn TokenPayoutEvictor>>,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl TokenManager {
    /// Constructor of [`TokenManager`]. Also spawns the janitor task.
    ///
    /// Please note that "token" in `CancellationToken` has a different meaning in this context.
    /// It is meant to kill the janitor tasks, and has nothing to do with the `JdToken`s.
    pub fn new(cancellation_token: CancellationToken, task_manager: Arc<TaskManager>) -> Self {
        let token_manager = Self {
            token_factory: Arc::new(AtomicU64::new(0)),
            allocated_tokens: Arc::new(DashMap::new()),
            active_tokens: Arc::new(DashMap::new()),
            cancellation_token,
            task_manager,
            payout_evictor: None,
        };
        token_manager.spawn_janitor_task();
        token_manager
    }

    /// Register a [`TokenPayoutEvictor`] to be notified on every eviction.
    ///
    /// Must be called before the first allocation if the caller wants to
    /// receive notifications for tokens evicted by the janitor — the janitor
    /// task captures the evictor by clone at spawn time. The typical wiring is
    /// to construct a `TokenManager`, immediately call
    /// `set_payout_evictor(...)`, and then proceed to drive allocations.
    pub fn set_payout_evictor(&mut self, evictor: Arc<dyn TokenPayoutEvictor>) {
        self.payout_evictor = Some(evictor);
        // Re-spawn the janitor so it picks up the newly-installed evictor.
        // Safe to spawn another janitor here because each janitor reads its
        // own captured `evictor` Option; the older janitor will exit on
        // cancellation alongside the rest of the JDS task graph.
        self.spawn_janitor_task();
    }

    /// Allocates a new token and adds it to the allocated tokens set.
    pub fn allocate(&self, downstream_id: DownstreamId) -> JdToken {
        let token = self.token_factory.fetch_add(1, Ordering::Relaxed);
        self.allocated_tokens
            .insert(token, (Instant::now(), downstream_id));
        token
    }

    /// Removes a token from the allocated tokens set.
    pub fn deallocate(&self, token: JdToken) {
        if self.allocated_tokens.remove(&token).is_some() {
            if let Some(evictor) = &self.payout_evictor {
                evictor.on_allocated_evicted(token);
            }
        }
    }

    /// Checks if a token is allocated.
    pub fn is_allocated(&self, token: JdToken, downstream_id: DownstreamId) -> bool {
        if let Some(allocation_info) = self.allocated_tokens.get(&token) {
            allocation_info.1 == downstream_id
        } else {
            false
        }
    }

    /// Takes an allocated token and removes it from the internal set.
    /// Creates a corresponding active token and adds it to the internal set.
    ///
    /// Note: `activate` removes the *allocated* token from `allocated_tokens`
    /// but does NOT fire `on_allocated_evicted`. This is intentional —
    /// activation is a transfer of the token's side-state from the allocated
    /// stage to the active stage, not an eviction. Engines that track payout
    /// side-state should keep their entry keyed by the original allocated
    /// `JdToken` so that `on_active_evicted` can locate it later.
    pub fn activate(&self, allocated_token: JdToken, downstream_id: DownstreamId) -> JdToken {
        let removed_allocated = self.allocated_tokens.remove(&allocated_token).is_some();

        let activated_token = self.token_factory.fetch_add(1, Ordering::Relaxed);
        self.active_tokens.insert(
            activated_token,
            (allocated_token, Instant::now(), downstream_id),
        );

        debug!(
            event = "token_activation",
            allocated_token,
            activated_token,
            downstream_id,
            allocated_token_was_present = removed_allocated,
            allocated_tokens_len = self.allocated_tokens.len(),
            active_tokens_len = self.active_tokens.len(),
            "TokenManager: activated token"
        );

        activated_token
    }

    /// Removes an active token from the internal set.
    pub fn deactivate(&self, active_token: JdToken) {
        let removed = self.active_tokens.remove(&active_token);
        debug!(
            active_token,
            removed = removed.is_some(),
            mapped_allocated_token = removed.as_ref().map(|(_, (allocated, _, _))| *allocated),
            mapped_downstream_id = removed
                .as_ref()
                .map(|(_, (_, _, downstream_id))| *downstream_id),
            active_tokens_len = self.active_tokens.len(),
            "TokenManager::deactivate"
        );
        if let Some((_, (allocated_token, _, _))) = removed {
            if let Some(evictor) = &self.payout_evictor {
                evictor.on_active_evicted(active_token, allocated_token);
            }
        }
    }

    /// Returns the allocated token that corresponds to an active token.
    /// Returns `None` if the active token is not found.
    pub fn allocated_from_active(&self, active_token: JdToken) -> Option<JdToken> {
        let mapped = self.active_tokens.get(&active_token).map(|entry| entry.0);
        debug!(
            active_token,
            mapped_allocated_token = mapped,
            found = mapped.is_some(),
            active_tokens_len = self.active_tokens.len(),
            allocated_tokens_len = self.allocated_tokens.len(),
            "TokenManager::allocated_from_active lookup"
        );
        mapped
    }

    /// Clears all allocated and active tokens.
    pub fn clear(&self) {
        if let Some(evictor) = &self.payout_evictor {
            // Notify per-token so evictors can drop side-state precisely.
            for entry in self.allocated_tokens.iter() {
                evictor.on_allocated_evicted(*entry.key());
            }
            for entry in self.active_tokens.iter() {
                let active_token = *entry.key();
                let allocated_token = entry.value().0;
                evictor.on_active_evicted(active_token, allocated_token);
            }
        }
        self.allocated_tokens.clear();
        self.active_tokens.clear();
    }

    /// Removes allocated tokens belonging to a given downstream.
    ///
    /// Active tokens are intentionally retained here and can still be consumed by
    /// `SetCustomMiningJob` or evicted later by the janitor timeout.
    pub fn remove_downstream(&self, downstream_id: DownstreamId) {
        let allocated_tokens_before = self.allocated_tokens.len();
        let active_tokens_before = self.active_tokens.len();

        let evictor = self.payout_evictor.clone();
        self.allocated_tokens.retain(|token, (_, owner)| {
            let keep = *owner != downstream_id;
            if !keep {
                if let Some(ev) = &evictor {
                    ev.on_allocated_evicted(*token);
                }
            }
            keep
        });

        let allocated_tokens_after = self.allocated_tokens.len();
        let active_tokens_after = self.active_tokens.len();

        debug!(
            event = "token_cleanup_downstream",
            downstream_id,
            removed_allocated_tokens =
                allocated_tokens_before.saturating_sub(allocated_tokens_after),
            allocated_tokens_before,
            allocated_tokens_after,
            active_tokens_before,
            active_tokens_after,
            "TokenManager: removed downstream-allocated tokens and retained active tokens"
        );
    }

    /// Spawns a janitor task that removes expired allocated and active tokens.
    fn spawn_janitor_task(&self) {
        let cancellation_token = self.cancellation_token.clone();
        let allocated_tokens = Arc::clone(&self.allocated_tokens);
        let active_tokens = Arc::clone(&self.active_tokens);
        let evictor = self.payout_evictor.clone();
        let allocated_token_timeout = Duration::from_secs(ALLOCATED_TOKEN_TIMEOUT_SECS);
        let active_token_timeout = Duration::from_secs(ACTIVE_TOKEN_TIMEOUT_SECS);
        let janitor_interval = Duration::from_secs(JANITOR_INTERVAL_SECS);
        self.task_manager.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        break;
                    }
                    _ = tokio::time::sleep(janitor_interval) => {
                        // Avoid removing while iterating the same DashMap, which can block.
                        let now = Instant::now();

                        let allocated_before = allocated_tokens.len();
                        let active_before = active_tokens.len();

                        allocated_tokens.retain(|token, (timestamp, _)| {
                            let keep = now.duration_since(*timestamp) <= allocated_token_timeout;
                            if !keep {
                                if let Some(ev) = &evictor {
                                    ev.on_allocated_evicted(*token);
                                }
                            }
                            keep
                        });
                        active_tokens.retain(|token, (allocated, timestamp, _)| {
                            let keep = now.duration_since(*timestamp) <= active_token_timeout;
                            if !keep {
                                if let Some(ev) = &evictor {
                                    ev.on_active_evicted(*token, *allocated);
                                }
                            }
                            keep
                        });

                        let allocated_after = allocated_tokens.len();
                        let active_after = active_tokens.len();
                        let removed_allocated = allocated_before.saturating_sub(allocated_after);
                        let removed_active = active_before.saturating_sub(active_after);

                        if removed_allocated > 0 || removed_active > 0 {
                            debug!(
                                event = "token_janitor_eviction",
                                removed_allocated,
                                removed_active,
                                allocated_before,
                                allocated_after,
                                active_before,
                                active_after,
                                "TokenManager janitor: evicted expired tokens"
                            );
                        }
                    }
                }
            }
        });
    }
}
