//! Monitoring integration for Translation Proxy (tProxy)
//!
//! This module implements the ServerMonitoring trait on `ChannelManager`.
//! tProxy has server channels (upstream to pool) but no SV2 clients
//! (SV1 clients are handled separately in sv1_monitoring.rs).

use stratum_apps::monitoring::server::{ServerExtendedChannelInfo, ServerInfo, ServerMonitoring};

use crate::sv2::channel_manager::{data::ChannelMode, ChannelManager};

impl ServerMonitoring for ChannelManager {
    fn get_server(&self) -> ServerInfo {
        let mut extended_channels = Vec::new();
        let standard_channels = Vec::new(); // tProxy only uses extended channels

        if let Ok(_) = self.channel_manager_data.safe_lock(|d| {
            match d.mode {
                ChannelMode::Aggregated => {
                    // In Aggregated mode: one shared upstream channel to the server
                    if let Some(upstream_channel) = &d.upstream_extended_channel {
                        if let Ok(channel_lock) = upstream_channel.read() {
                            let channel_id = channel_lock.get_channel_id();
                            let target = channel_lock.get_target();
                            let extranonce_prefix = channel_lock.get_extranonce_prefix();
                            let user_identity = channel_lock.get_user_identity();
                            let share_accounting = channel_lock.get_share_accounting();

                            extended_channels.push(ServerExtendedChannelInfo {
                                channel_id,
                                user_identity: user_identity.clone(),
                                nominal_hashrate: channel_lock.get_nominal_hashrate(),
                                target_hex: hex::encode(target.to_be_bytes()),
                                extranonce_prefix_hex: hex::encode(extranonce_prefix),
                                full_extranonce_size: channel_lock.get_full_extranonce_size(),
                                rollable_extranonce_size: channel_lock
                                    .get_rollable_extranonce_size(),
                                version_rolling: channel_lock.is_version_rolling(),
                                shares_accepted: share_accounting.get_shares_accepted(),
                                share_work_sum: share_accounting.get_share_work_sum(),
                                last_share_sequence_number: share_accounting
                                    .get_last_share_sequence_number(),
                                best_diff: share_accounting.get_best_diff(),
                            });
                        }
                    }
                }
                ChannelMode::NonAggregated => {
                    // In NonAggregated mode: each downstream Sv1 miner has its own upstream Sv2
                    // channel to the server
                    for (_channel_id, extended_channel) in d.extended_channels.iter() {
                        if let Ok(channel_lock) = extended_channel.read() {
                            let channel_id = channel_lock.get_channel_id();
                            let target = channel_lock.get_target();
                            let extranonce_prefix = channel_lock.get_extranonce_prefix();
                            let user_identity = channel_lock.get_user_identity();
                            let share_accounting = channel_lock.get_share_accounting();

                            extended_channels.push(ServerExtendedChannelInfo {
                                channel_id,
                                user_identity: user_identity.clone(),
                                nominal_hashrate: channel_lock.get_nominal_hashrate(),
                                target_hex: hex::encode(target.to_be_bytes()),
                                extranonce_prefix_hex: hex::encode(extranonce_prefix),
                                full_extranonce_size: channel_lock.get_full_extranonce_size(),
                                rollable_extranonce_size: channel_lock
                                    .get_rollable_extranonce_size(),
                                version_rolling: channel_lock.is_version_rolling(),
                                shares_accepted: share_accounting.get_shares_accepted(),
                                share_work_sum: share_accounting.get_share_work_sum(),
                                last_share_sequence_number: share_accounting
                                    .get_last_share_sequence_number(),
                                best_diff: share_accounting.get_best_diff(),
                            });
                        }
                    }
                }
            }
        }) {
            // Successfully acquired lock and populated extended_channels
        } else {
            // Mutex poisoned - log warning and return empty monitoring data
            tracing::warn!("Monitoring mutex poisoned in translator, returning empty server info");
        }

        ServerInfo {
            extended_channels,
            standard_channels,
        }
    }
}
