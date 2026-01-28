use std::{
    sync::atomic::{AtomicBool, AtomicU8},
    time::Instant,
};
use stratum_apps::{
    stratum_core::{
        bitcoin::Target,
        sv1_api::{
            json_rpc,
            utils::{Extranonce, HexU32Be},
        },
    },
    utils::types::{ChannelId, DownstreamId, Hashrate},
};
use tracing::debug;

use super::SubmitShareWithChannelId;

/// Maximum number of failed authorization attempts before disconnecting
/// in public solo mode. After this many failures, the downstream will be disconnected.
pub const MAX_FAILED_AUTH_ATTEMPTS: u8 = 2;

#[derive(Debug)]
pub struct DownstreamData {
    pub channel_id: Option<ChannelId>,
    pub extranonce1: Extranonce<'static>,
    pub extranonce2_len: usize,
    pub target: Target,
    pub hashrate: Option<Hashrate>,
    pub version_rolling_mask: Option<HexU32Be>,
    pub version_rolling_min_bit: Option<HexU32Be>,
    pub last_job_version_field: Option<u32>,
    pub authorized_worker_name: String,
    pub user_identity: String,
    pub cached_set_difficulty: Option<json_rpc::Message>,
    pub cached_notify: Option<json_rpc::Message>,
    pub pending_target: Option<Target>,
    pub pending_hashrate: Option<Hashrate>,
    // Queue of Sv1 handshake messages received while waiting for SV2 channel to open
    pub queued_sv1_handshake_messages: Vec<json_rpc::Message>,
    // Stores pending shares to be sent to the sv1_server
    pub pending_share: Option<SubmitShareWithChannelId>,
    // Tracks the upstream target for this downstream, used for vardiff target comparison
    pub upstream_target: Option<Target>,
    // Timestamp of when the last job was received by this downstream, used for keepalive check
    pub last_job_received_time: Option<Instant>,
    /// Counter for failed authorization attempts in public solo mode.
    /// After MAX_FAILED_AUTH_ATTEMPTS, the downstream will be disconnected.
    pub failed_auth_attempts: AtomicU8,
    /// Flag to indicate this downstream should be disconnected due to too many failed auth attempts.
    pub should_disconnect: AtomicBool,
}

impl DownstreamData {
    pub fn new(hashrate: Option<Hashrate>, target: Target) -> Self {
        DownstreamData {
            channel_id: None,
            extranonce1: vec![0; 8]
                .try_into()
                .expect("8-byte extranonce is always valid"),
            extranonce2_len: 4,
            target,
            hashrate,
            version_rolling_mask: None,
            version_rolling_min_bit: None,
            last_job_version_field: None,
            authorized_worker_name: String::new(),
            user_identity: String::new(),
            cached_set_difficulty: None,
            cached_notify: None,
            pending_target: None,
            pending_hashrate: None,
            queued_sv1_handshake_messages: Vec::new(),
            pending_share: None,
            upstream_target: None,
            last_job_received_time: None,
            failed_auth_attempts: AtomicU8::new(0),
            should_disconnect: AtomicBool::new(false),
        }
    }

    /// Increments the failed authorization attempts counter.
    /// Returns true if the downstream should be disconnected.
    pub fn increment_failed_auth_attempts(&self) -> bool {
        use std::sync::atomic::Ordering;
        let attempts = self.failed_auth_attempts.fetch_add(1, Ordering::SeqCst) + 1;
        if attempts >= MAX_FAILED_AUTH_ATTEMPTS {
            self.should_disconnect.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    /// Returns true if this downstream should be disconnected.
    pub fn should_disconnect(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.should_disconnect.load(Ordering::SeqCst)
    }

    pub fn set_pending_target(&mut self, new_target: Target, downstream_id: DownstreamId) {
        self.pending_target = Some(new_target);
        debug!("Downstream {downstream_id}: Set pending target");
    }

    pub fn set_pending_hashrate(
        &mut self,
        new_hashrate: Option<Hashrate>,
        downstream_id: DownstreamId,
    ) {
        self.pending_hashrate = new_hashrate;
        debug!("Downstream {downstream_id}: Set pending hashrate");
    }

    pub fn set_upstream_target(&mut self, upstream_target: Target, downstream_id: DownstreamId) {
        self.upstream_target = Some(upstream_target);
        debug!(
            "Downstream {downstream_id}: Set upstream target to {:?}",
            upstream_target
        );
    }
}
