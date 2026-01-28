//! Configuration management helpers for SV2 applications
//!
//! This module provides utilities for:
//! - Parsing configuration files (TOML, etc.)
//! - Handling coinbase output specifications
//! - Setting up logging and tracing
//! - Address validation for public solo mining mode
//!
//! Originally from the `config_helpers_sv2` crate.

mod coinbase_output;
pub use coinbase_output::{CoinbaseRewardScript, Error as CoinbaseOutputError};

pub mod address_validation;
pub use address_validation::{
    extract_address_from_username, generate_random_channel_tag, validate_solo_address,
    AddressValidationError, PublicSoloModeConfig,
};

pub mod logging;

mod toml;
pub use toml::{duration_from_toml, opt_path_from_toml};
