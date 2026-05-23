//! ## Configuration Module
//!
//! Defines [`PoolConfig`], the configuration structure for the Pool, along with its supporting
//! types.
//!
//! This module handles:
//! - Initializing [`PoolConfig`]
//! - Managing [`TemplateProviderConfig`], [`AuthorityConfig`], [`CoinbaseOutput`], and
//!   [`ConnectionConfig`]
//! - Validating and converting coinbase outputs
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub use jd_server_sv2::config::{JDSConfig, JDSPartialConfig};
#[cfg(feature = "iroh-transport")]
use stratum_apps::network_helpers::transport::PreferTransport;
use stratum_apps::{
    config_helpers::{opt_path_from_toml, CoinbaseRewardScript},
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    stratum_core::bitcoin::{Amount, TxOut},
    tp_type::TemplateProviderType,
    utils::types::{SharesBatchSize, SharesPerMinute},
};

use crate::error::PoolErrorKind;

/// Configuration for the Pool, including connection, authority, and coinbase settings.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct PoolConfig {
    listen_address: SocketAddr,
    template_provider_type: TemplateProviderType,
    authority_public_key: Secp256k1PublicKey,
    authority_secret_key: Secp256k1SecretKey,
    cert_validity_sec: u64,
    coinbase_reward_script: CoinbaseRewardScript,
    pool_signature: String,
    shares_per_minute: SharesPerMinute,
    share_batch_size: SharesBatchSize,
    #[serde(default, deserialize_with = "opt_path_from_toml")]
    log_file: Option<PathBuf>,
    #[serde(default)]
    server_id: u8,
    #[serde(default)]
    supported_extensions: Vec<u16>,
    #[serde(default)]
    required_extensions: Vec<u16>,
    #[serde(default)]
    monitoring_address: Option<SocketAddr>,
    #[serde(default)]
    jds: Option<JDSPartialConfig>,
    #[serde(default)]
    monitoring_cache_refresh_secs: Option<u64>,
    /// Optional iroh-transport configuration. When present, the pool listens on
    /// TCP AND iroh simultaneously; downstream clients can connect over either
    /// transport. See plan §"Per-role `[iroh]` section" for the full schema.
    ///
    /// `PoolConfig` does NOT use `#[serde(deny_unknown_fields)]`, so when the
    /// `iroh-transport` feature is disabled the `[iroh]` TOML section is
    /// silently ignored rather than rejected.
    #[cfg(feature = "iroh-transport")]
    #[serde(default)]
    pub iroh: Option<stratum_apps::network_helpers::iroh::IrohRoleConfig>,
    /// Optional iroh-extension config for the upstream Sv2 Template Provider
    /// dial. When `template_provider_type = Sv2Tp` and this section is present
    /// the pool can dial the TP over iroh (with TCP fallback per
    /// `prefer_transport`). The Sv2 authority pubkey and TCP address still
    /// come from `[template_provider_type.Sv2Tp]` so TCP fallback works
    /// unchanged when iroh is disabled.
    ///
    /// This field is pool-local rather than embedded in the
    /// [`TemplateProviderType::Sv2Tp`] variant so the stratum-apps `tp_type`
    /// crate does not gain a per-feature shape. Phase 4b's JDC dial sites
    /// will follow the same pattern.
    #[cfg(feature = "iroh-transport")]
    #[serde(default)]
    pub iroh_tp: Option<Sv2TpIrohExt>,
}

/// Iroh-transport extension fields for the upstream Sv2 Template Provider.
/// Optional sibling to `[template_provider_type.Sv2Tp]` in the pool TOML.
///
/// When this section is omitted the pool dials its TP over plain TCP (the
/// behavior pre-iroh, identical to today).
#[cfg(feature = "iroh-transport")]
#[derive(Clone, Debug, serde::Deserialize, Default)]
pub struct Sv2TpIrohExt {
    /// Base32-lowercase NodeId of the TP. Required to enable iroh dialing.
    /// When `None`, the pool falls back to TCP regardless of
    /// `prefer_transport`.
    #[serde(default)]
    pub iroh_node_id: Option<String>,
    /// Optional relay URL for the TP. Empty / `None` means rely on the
    /// connector endpoint's discovery to locate the TP.
    #[serde(default)]
    pub iroh_relay_url: Option<String>,
    /// Per-peer transport preference. Defaults to `iroh_then_tcp`.
    #[serde(default)]
    pub prefer_transport: PreferTransport,
}

impl PoolConfig {
    /// Creates a new instance of the [`PoolConfig`].
    ///
    /// # Panics
    ///
    /// Panics if `coinbase_reward_script` is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_connection: ConnectionConfig,
        template_provider_type: TemplateProviderType,
        authority_config: AuthorityConfig,
        coinbase_reward_script: CoinbaseRewardScript,
        shares_per_minute: SharesPerMinute,
        share_batch_size: SharesBatchSize,
        server_id: u8,
        supported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
        monitoring_address: Option<SocketAddr>,
        monitoring_cache_refresh_secs: Option<u64>,
        jds: Option<JDSPartialConfig>,
    ) -> Self {
        Self {
            listen_address: pool_connection.listen_address,
            template_provider_type,
            authority_public_key: authority_config.public_key,
            authority_secret_key: authority_config.secret_key,
            cert_validity_sec: pool_connection.cert_validity_sec,
            coinbase_reward_script,
            pool_signature: pool_connection.signature,
            shares_per_minute,
            share_batch_size,
            log_file: None,
            server_id,
            supported_extensions,
            required_extensions,
            monitoring_address,
            monitoring_cache_refresh_secs,
            jds,
            #[cfg(feature = "iroh-transport")]
            iroh: None,
            #[cfg(feature = "iroh-transport")]
            iroh_tp: None,
        }
    }

    /// Returns the coinbase output.
    pub fn coinbase_reward_script(&self) -> &CoinbaseRewardScript {
        &self.coinbase_reward_script
    }

    /// Returns Pool listenining address.
    pub fn listen_address(&self) -> &SocketAddr {
        &self.listen_address
    }

    /// Returns the authority public key.
    pub fn authority_public_key(&self) -> &Secp256k1PublicKey {
        &self.authority_public_key
    }

    /// Returns the authority secret key.
    pub fn authority_secret_key(&self) -> &Secp256k1SecretKey {
        &self.authority_secret_key
    }

    /// Returns the certificate validity in seconds.
    pub fn cert_validity_sec(&self) -> u64 {
        self.cert_validity_sec
    }

    /// Returns the Pool signature.
    pub fn pool_signature(&self) -> &String {
        &self.pool_signature
    }

    /// Returns the Template Provider type.
    pub fn template_provider_type(&self) -> &TemplateProviderType {
        &self.template_provider_type
    }

    /// Returns the share batch size.
    pub fn share_batch_size(&self) -> usize {
        self.share_batch_size
    }

    /// Sets the coinbase output.
    pub fn set_coinbase_reward_script(&mut self, coinbase_output: CoinbaseRewardScript) {
        self.coinbase_reward_script = coinbase_output;
    }

    /// Returns the shares per minute.
    pub fn shares_per_minute(&self) -> f32 {
        self.shares_per_minute
    }

    /// Returns the supported extensions.
    pub fn supported_extensions(&self) -> &[u16] {
        &self.supported_extensions
    }

    /// Returns the required extensions.
    pub fn required_extensions(&self) -> &[u16] {
        &self.required_extensions
    }

    /// Sets the log directory.
    pub fn set_log_dir(&mut self, log_dir: Option<PathBuf>) {
        if let Some(dir) = log_dir {
            self.log_file = Some(dir);
        }
    }
    /// Returns the log directory.
    pub fn log_dir(&self) -> Option<&Path> {
        self.log_file.as_deref()
    }

    /// Returns the server id.
    pub fn server_id(&self) -> u8 {
        self.server_id
    }

    pub fn get_txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey: self.coinbase_reward_script.script_pubkey().to_owned(),
        }
    }

    /// Returns the monitoring address (optional).
    pub fn monitoring_address(&self) -> Option<SocketAddr> {
        self.monitoring_address
    }

    /// Returns the monitoring cache refresh interval in seconds.
    pub fn monitoring_cache_refresh_secs(&self) -> Option<u64> {
        self.monitoring_cache_refresh_secs
    }

    /// Returns the optional iroh transport configuration.
    #[cfg(feature = "iroh-transport")]
    pub fn iroh(&self) -> Option<&stratum_apps::network_helpers::iroh::IrohRoleConfig> {
        self.iroh.as_ref()
    }

    /// Returns the optional iroh-extension config for the upstream Sv2
    /// Template Provider dial. `None` keeps the pool on the legacy TCP-only
    /// dial path.
    #[cfg(feature = "iroh-transport")]
    pub fn iroh_tp(&self) -> Option<&Sv2TpIrohExt> {
        self.iroh_tp.as_ref()
    }

    /// Builds a complete [`JDSConfig`] from the partial `[jds]` TOML section
    /// plus shared fields inherited from Pool config.
    ///
    /// Returns `Ok(None)` when the `[jds]` TOML section is absent.
    #[allow(clippy::result_large_err)]
    pub fn build_jds_config(&self) -> Result<Option<JDSConfig>, PoolErrorKind> {
        let Some(jds_partial) = self.jds.clone() else {
            return Ok(None);
        };

        let jds_config = JDSConfig::from_partial(
            jds_partial,
            self.authority_public_key,
            self.authority_secret_key,
            self.cert_validity_sec,
            self.coinbase_reward_script.clone(),
        );

        Ok(Some(jds_config))
    }
}

/// Pool's authority public and secret keys.
pub struct AuthorityConfig {
    pub public_key: Secp256k1PublicKey,
    pub secret_key: Secp256k1SecretKey,
}

impl AuthorityConfig {
    pub fn new(public_key: Secp256k1PublicKey, secret_key: Secp256k1SecretKey) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }
}

/// Connection settings for the Pool listener.
pub struct ConnectionConfig {
    listen_address: SocketAddr,
    cert_validity_sec: u64,
    signature: String,
}

impl ConnectionConfig {
    pub fn new(listen_address: SocketAddr, cert_validity_sec: u64, signature: String) -> Self {
        Self {
            listen_address,
            cert_validity_sec,
            signature,
        }
    }
}
