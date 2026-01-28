//! Address validation for public solo mining mode.
//!
//! This module provides utilities for validating Bitcoin addresses in the context
//! of public solo mining, where miners provide their reward address as the
//! stratum username.
//!
//! # Security
//!
//! - Mainnet addresses are **always rejected** to prevent accidental mainnet mining
//! - Network validation ensures addresses match the configured network
//! - Only testnet4, signet, and regtest networks are supported

use super::CoinbaseRewardScript;
use miniscript::bitcoin::ScriptBuf;
use serde::Deserialize;
use std::fmt;

/// Errors that can occur during address validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressValidationError {
    /// The address format is invalid or could not be parsed.
    InvalidFormat(String),
    /// Mainnet addresses are not allowed in public solo mode.
    MainnetNotAllowed,
    /// The address is for a different network than configured.
    WrongNetwork { expected: String, detected: String },
    /// The configured network is not supported.
    UnsupportedNetwork(String),
}

impl fmt::Display for AddressValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressValidationError::InvalidFormat(msg) => {
                write!(f, "invalid address format: {}", msg)
            }
            AddressValidationError::MainnetNotAllowed => {
                write!(f, "mainnet addresses not allowed")
            }
            AddressValidationError::WrongNetwork { expected, detected } => {
                write!(
                    f,
                    "address must be for {} (detected: {})",
                    expected, detected
                )
            }
            AddressValidationError::UnsupportedNetwork(network) => {
                write!(f, "unsupported network: {}", network)
            }
        }
    }
}

impl std::error::Error for AddressValidationError {}

/// Configuration for public solo mining mode.
///
/// When enabled, miners must provide a valid Bitcoin address as their
/// stratum username. The address is used as the coinbase reward destination.
#[derive(Debug, Deserialize, Clone)]
pub struct PublicSoloModeConfig {
    /// The Bitcoin network to validate addresses against.
    ///
    /// Valid values: `"testnet4"`, `"signet"`, `"regtest"`
    ///
    /// Mainnet is **never** allowed in public solo mode for safety.
    pub network: String,
}

/// Validates a Bitcoin address for public solo mining mode.
///
/// Supports optional worker suffix in the format `address.worker_name`.
/// The worker suffix is stripped before validation and returned separately.
///
/// # Arguments
///
/// * `username` - The stratum username, either a bare address (e.g., `tb1q...`)
///   or address with worker suffix (e.g., `tb1q....bitaxe`)
/// * `expected_network` - The network the address should be valid for
///
/// # Returns
///
/// * `Ok(ScriptBuf)` - The script pubkey if the address is valid
/// * `Err(AddressValidationError)` - If validation fails
///
/// # Security
///
/// - Mainnet addresses are **always** rejected, regardless of `expected_network`
/// - This prevents accidental mainnet mining through configuration errors
///
/// # Example
///
/// ```ignore
/// use stratum_apps::config_helpers::address_validation::validate_solo_address;
///
/// // Valid testnet4 address
/// let script = validate_solo_address(
///     "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
///     "testnet4"
/// ).unwrap();
///
/// // Valid testnet4 address with worker suffix
/// let script = validate_solo_address(
///     "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.bitaxe",
///     "testnet4"
/// ).unwrap();
///
/// // Mainnet address - always rejected
/// let err = validate_solo_address(
///     "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
///     "testnet4"
/// ).unwrap_err();
/// assert!(matches!(err, AddressValidationError::MainnetNotAllowed));
/// ```
pub fn validate_solo_address(
    username: &str,
    expected_network: &str,
) -> Result<ScriptBuf, AddressValidationError> {
    // Extract the address part (before the first '.' if present)
    // Format: "address" or "address.worker_name"
    let address = username.split('.').next().unwrap_or(username);

    // 1. Try to parse as a Bitcoin address descriptor
    let descriptor = format!("addr({})", address);
    let parsed = CoinbaseRewardScript::from_descriptor(&descriptor)
        .map_err(|e| AddressValidationError::InvalidFormat(e.to_string()))?;

    // 2. CRITICAL: Reject mainnet addresses (safety check)
    // ok_for_mainnet() returns true if the address could be used on mainnet
    if parsed.ok_for_mainnet() {
        return Err(AddressValidationError::MainnetNotAllowed);
    }

    // 3. Validate network prefix matches expected network
    let valid_for_network = match expected_network.to_lowercase().as_str() {
        "testnet4" | "testnet" | "signet" => {
            // Testnet/signet addresses:
            // - tb1... (bech32/bech32m)
            // - m... or n... (legacy P2PKH)
            // - 2... (legacy P2SH)
            address.starts_with("tb1")
                || address.starts_with("m")
                || address.starts_with("n")
                || address.starts_with("2")
        }
        "regtest" => {
            // Regtest addresses:
            // - bcrt1... (bech32/bech32m)
            // - m... or n... (legacy P2PKH)
            address.starts_with("bcrt1") || address.starts_with("m") || address.starts_with("n")
        }
        other => {
            return Err(AddressValidationError::UnsupportedNetwork(
                other.to_string(),
            ))
        }
    };

    if !valid_for_network {
        return Err(AddressValidationError::WrongNetwork {
            expected: expected_network.to_string(),
            detected: detect_network_from_address(address),
        });
    }

    Ok(parsed.script_pubkey())
}

/// Attempts to detect which network an address belongs to based on its prefix.
///
/// This is a best-effort detection used for error messages.
fn detect_network_from_address(address: &str) -> String {
    if address.starts_with("bc1") || address.starts_with("1") || address.starts_with("3") {
        "mainnet".to_string()
    } else if address.starts_with("tb1") {
        "testnet/signet".to_string()
    } else if address.starts_with("bcrt1") {
        "regtest".to_string()
    } else if address.starts_with("m") || address.starts_with("n") {
        "testnet/regtest (legacy)".to_string()
    } else if address.starts_with("2") {
        "testnet (P2SH)".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Extracts the Bitcoin address from a stratum username.
///
/// Supports optional worker suffix in the format `address.worker_name`.
/// Returns just the address part.
///
/// # Arguments
///
/// * `username` - The stratum username, either a bare address (e.g., `tb1q...`)
///   or address with worker suffix (e.g., `tb1q....bitaxe`)
///
/// # Returns
///
/// The address portion of the username (everything before the first `.`)
///
/// # Example
///
/// ```ignore
/// use stratum_apps::config_helpers::address_validation::extract_address_from_username;
///
/// assert_eq!(
///     extract_address_from_username("tb1q...abc.bitaxe"),
///     "tb1q...abc"
/// );
/// assert_eq!(
///     extract_address_from_username("tb1q...abc"),
///     "tb1q...abc"
/// );
/// ```
pub fn extract_address_from_username(username: &str) -> &str {
    username.split('.').next().unwrap_or(username)
}

/// Generates a random tag for channel disambiguation.
///
/// When multiple miners use the same reward address, each channel needs
/// a unique coinbase signature to avoid duplicate block submissions.
/// This function generates a random hex string between 4-32 characters.
///
/// # Returns
///
/// A random hex string with length between 4 and 32 characters (inclusive).
pub fn generate_random_channel_tag() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    // Generate between 2-16 bytes (4-32 hex characters)
    let len = rng.gen_range(2..=16);
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Valid Address Tests ====================

    #[test]
    fn test_valid_testnet4_bech32_address() {
        let result =
            validate_solo_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "testnet4");
        assert!(
            result.is_ok(),
            "Should accept valid testnet4 bech32 address"
        );
    }

    #[test]
    fn test_valid_testnet4_bech32m_address() {
        // P2TR (taproot) address
        let result = validate_solo_address(
            "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
            "testnet4",
        );
        assert!(
            result.is_ok(),
            "Should accept valid testnet4 bech32m (taproot) address"
        );
    }

    #[test]
    fn test_valid_testnet_legacy_p2pkh_m() {
        let result = validate_solo_address("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", "testnet4");
        assert!(
            result.is_ok(),
            "Should accept valid testnet legacy P2PKH (m prefix)"
        );
    }

    #[test]
    fn test_valid_testnet_legacy_p2pkh_n() {
        let result = validate_solo_address("n3ZddxzLvAY9o7184TB4c6FJasAybsw4HZ", "testnet4");
        assert!(
            result.is_ok(),
            "Should accept valid testnet legacy P2PKH (n prefix)"
        );
    }

    #[test]
    fn test_valid_testnet_legacy_p2sh() {
        let result = validate_solo_address("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", "testnet4");
        assert!(result.is_ok(), "Should accept valid testnet P2SH address");
    }

    #[test]
    fn test_valid_regtest_bech32_address() {
        let result =
            validate_solo_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "regtest");
        assert!(result.is_ok(), "Should accept valid regtest bech32 address");
    }

    #[test]
    fn test_valid_signet_address() {
        // Signet uses the same address format as testnet
        let result = validate_solo_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "signet");
        assert!(result.is_ok(), "Should accept valid signet address");
    }

    // ==================== Invalid Address Tests ====================

    #[test]
    fn test_reject_mainnet_bech32() {
        let result =
            validate_solo_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "testnet4");
        assert!(
            matches!(result, Err(AddressValidationError::MainnetNotAllowed)),
            "Should reject mainnet bech32 address"
        );
    }

    #[test]
    fn test_reject_mainnet_legacy_p2pkh() {
        let result = validate_solo_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", "testnet4");
        assert!(
            matches!(result, Err(AddressValidationError::MainnetNotAllowed)),
            "Should reject mainnet legacy P2PKH address"
        );
    }

    #[test]
    fn test_reject_mainnet_legacy_p2sh() {
        let result = validate_solo_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "testnet4");
        assert!(
            matches!(result, Err(AddressValidationError::MainnetNotAllowed)),
            "Should reject mainnet P2SH address"
        );
    }

    #[test]
    fn test_reject_regtest_address_on_testnet4() {
        let result =
            validate_solo_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080", "testnet4");
        assert!(
            matches!(result, Err(AddressValidationError::WrongNetwork { .. })),
            "Should reject regtest address on testnet4"
        );
    }

    #[test]
    fn test_reject_testnet_address_on_regtest() {
        let result = validate_solo_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "regtest");
        assert!(
            matches!(result, Err(AddressValidationError::WrongNetwork { .. })),
            "Should reject testnet address on regtest"
        );
    }

    #[test]
    fn test_reject_invalid_format() {
        let result = validate_solo_address("not_an_address", "testnet4");
        assert!(
            matches!(result, Err(AddressValidationError::InvalidFormat(_))),
            "Should reject invalid address format"
        );
    }

    #[test]
    fn test_reject_empty_address() {
        let result = validate_solo_address("", "testnet4");
        assert!(
            matches!(result, Err(AddressValidationError::InvalidFormat(_))),
            "Should reject empty address"
        );
    }

    #[test]
    fn test_reject_unsupported_network() {
        let result = validate_solo_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "unknown_network",
        );
        assert!(
            matches!(result, Err(AddressValidationError::UnsupportedNetwork(_))),
            "Should reject unsupported network"
        );
    }

    // ==================== Worker Suffix Tests ====================

    #[test]
    fn test_valid_address_with_worker_suffix() {
        let result = validate_solo_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.bitaxe",
            "testnet4",
        );
        assert!(
            result.is_ok(),
            "Should accept valid testnet4 address with worker suffix"
        );
    }

    #[test]
    fn test_valid_address_with_multiple_dots_in_worker() {
        // The address is before the first dot, worker name can contain dots
        let result = validate_solo_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.worker.1",
            "testnet4",
        );
        assert!(
            result.is_ok(),
            "Should accept address with multiple dots in worker suffix"
        );
    }

    #[test]
    fn test_extract_address_basic() {
        assert_eq!(
            extract_address_from_username("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.bitaxe"),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    #[test]
    fn test_extract_address_no_suffix() {
        assert_eq!(
            extract_address_from_username("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    #[test]
    fn test_extract_address_multiple_dots() {
        assert_eq!(
            extract_address_from_username("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx.worker.1"),
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        );
    }

    // ==================== Random Tag Tests ====================

    #[test]
    fn test_random_tag_length() {
        for _ in 0..100 {
            let tag = generate_random_channel_tag();
            assert!(
                tag.len() >= 4 && tag.len() <= 32,
                "Tag length {} should be between 4 and 32",
                tag.len()
            );
        }
    }

    #[test]
    fn test_random_tag_is_hex() {
        for _ in 0..10 {
            let tag = generate_random_channel_tag();
            assert!(
                tag.chars().all(|c| c.is_ascii_hexdigit()),
                "Tag should only contain hex characters"
            );
        }
    }

    #[test]
    fn test_reject_mainnet_even_if_configured() {
        // Even if someone tries to configure mainnet, it should be rejected
        // The mainnet address check happens BEFORE network validation,
        // so we get MainnetNotAllowed
        let result = validate_solo_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "mainnet");
        assert!(
            matches!(result, Err(AddressValidationError::MainnetNotAllowed)),
            "Should reject mainnet address before checking network config"
        );
    }

    #[test]
    fn test_reject_mainnet_network_config() {
        // Test that even configuring "mainnet" as the network is rejected
        // Using a testnet address to bypass the mainnet address check
        let result = validate_solo_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "mainnet");
        assert!(
            matches!(result, Err(AddressValidationError::UnsupportedNetwork(_))),
            "Should reject mainnet as unsupported network configuration"
        );
    }

    // ==================== Network Detection Tests ====================

    #[test]
    fn test_detect_mainnet_bech32() {
        assert_eq!(
            detect_network_from_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            "mainnet"
        );
    }

    #[test]
    fn test_detect_mainnet_legacy() {
        assert_eq!(
            detect_network_from_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"),
            "mainnet"
        );
    }

    #[test]
    fn test_detect_testnet_bech32() {
        assert_eq!(
            detect_network_from_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
            "testnet/signet"
        );
    }

    #[test]
    fn test_detect_regtest_bech32() {
        assert_eq!(
            detect_network_from_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
            "regtest"
        );
    }
}
