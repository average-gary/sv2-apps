// Integration tests for the public solo mining mode feature.
//
// These tests verify that:
// 1. Miners with valid testnet/regtest addresses can connect and mine
// 2. Miners with invalid addresses are rejected
// 3. Miners with mainnet addresses are always rejected (safety)
// 4. Worker suffix format (address.worker) is supported

use integration_tests_sv2::{
    interceptor::MessageDirection, sv1_sniffer::SV1MessageFilter,
    template_provider::DifficultyLevel, *,
};
use stratum_apps::stratum_core::sv1_api;

/// Test that a miner with a valid regtest address can connect and receive jobs.
///
/// This test:
/// 1. Starts a pool with regtest template provider
/// 2. Starts translator in public_solo_mode with network="regtest"
/// 3. Connects a miner with a valid regtest address as username
/// 4. Verifies the miner receives mining.notify jobs
#[tokio::test]
async fn test_public_solo_mode_valid_regtest_address() {
    start_tracing();

    // Start template provider and pool
    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (_pool, pool_addr) = start_pool(sv2_tp_config(tp_addr), vec![], vec![]).await;

    // Start translator with public_solo_mode enabled for regtest
    let (_, tproxy_addr) = start_sv2_translator_public_solo_mode(&[pool_addr], "regtest").await;

    // Start SV1 sniffer to capture messages
    let (sniffer_sv1, sniffer_sv1_addr) = start_sv1_sniffer(tproxy_addr);

    // Valid regtest bech32 address
    let regtest_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080".to_string();

    // Start minerd with valid regtest address as username
    let (_minerd_process, _minerd_addr) =
        start_minerd(sniffer_sv1_addr, Some(regtest_address), None, false).await;

    // Verify mining.subscribe is sent
    sniffer_sv1
        .wait_for_message(&["mining.subscribe"], MessageDirection::ToUpstream)
        .await;

    // Verify mining.authorize is sent and succeeds
    sniffer_sv1
        .wait_for_message(&["mining.authorize"], MessageDirection::ToUpstream)
        .await;

    // Verify mining.set_difficulty is received (indicates successful authorization)
    sniffer_sv1
        .wait_for_message(&["mining.set_difficulty"], MessageDirection::ToDownstream)
        .await;

    // Verify mining.notify is received (miner is receiving jobs)
    sniffer_sv1
        .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
        .await;
}

/// Test that a miner with an address and worker suffix can connect.
///
/// Common miner configurations use format: address.worker_name
/// The translator should extract the address and accept it.
#[tokio::test]
async fn test_public_solo_mode_address_with_worker_suffix() {
    start_tracing();

    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (_pool, pool_addr) = start_pool(sv2_tp_config(tp_addr), vec![], vec![]).await;
    let (_, tproxy_addr) = start_sv2_translator_public_solo_mode(&[pool_addr], "regtest").await;
    let (sniffer_sv1, sniffer_sv1_addr) = start_sv1_sniffer(tproxy_addr);

    // Address with worker suffix (common for bitaxe and other miners)
    let username_with_worker = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080.worker1".to_string();

    let (_minerd_process, _minerd_addr) =
        start_minerd(sniffer_sv1_addr, Some(username_with_worker), None, false).await;

    sniffer_sv1
        .wait_for_message(&["mining.subscribe"], MessageDirection::ToUpstream)
        .await;
    sniffer_sv1
        .wait_for_message(&["mining.authorize"], MessageDirection::ToUpstream)
        .await;
    sniffer_sv1
        .wait_for_message(&["mining.set_difficulty"], MessageDirection::ToDownstream)
        .await;
    sniffer_sv1
        .wait_for_message(&["mining.notify"], MessageDirection::ToDownstream)
        .await;
}

/// Test that a miner with an invalid address format is rejected.
///
/// The translator should send an error response to mining.authorize.
#[tokio::test]
async fn test_public_solo_mode_invalid_address_rejected() {
    start_tracing();

    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (_pool, pool_addr) = start_pool(sv2_tp_config(tp_addr), vec![], vec![]).await;
    let (_, tproxy_addr) = start_sv2_translator_public_solo_mode(&[pool_addr], "regtest").await;
    let (sniffer_sv1, sniffer_sv1_addr) = start_sv1_sniffer(tproxy_addr);

    // Invalid address format
    let invalid_address = "not_a_valid_address".to_string();

    let (_minerd_process, _minerd_addr) =
        start_minerd(sniffer_sv1_addr, Some(invalid_address), None, false).await;

    sniffer_sv1
        .wait_for_message(&["mining.subscribe"], MessageDirection::ToUpstream)
        .await;

    // Capture the authorize request ID
    let authorize_id = {
        let mut extracted_id = None;
        sniffer_sv1
            .wait_and_assert(
                SV1MessageFilter::WithMessageName("mining.authorize"),
                MessageDirection::ToUpstream,
                |msg| {
                    if let sv1_api::Message::StandardRequest(req) = msg {
                        extracted_id = Some(req.id);
                    }
                },
            )
            .await;
        extracted_id.expect("Failed to extract authorize ID")
    };

    // Wait for the error response to mining.authorize
    sniffer_sv1
        .wait_and_assert(
            SV1MessageFilter::WithMessageId(authorize_id),
            MessageDirection::ToDownstream,
            |msg| {
                match msg {
                    sv1_api::Message::ErrorResponse(err) => {
                        // Verify the error contains "invalid" or similar message
                        let error_msg = format!("{:?}", err.error);
                        assert!(
                            error_msg.to_lowercase().contains("invalid"),
                            "Error should indicate invalid address: {}",
                            error_msg
                        );
                    }
                    sv1_api::Message::OkResponse(res) => {
                        // Check if result is false (authorization failed)
                        if let Some(result) = res.result.as_bool() {
                            assert!(!result, "Authorization should fail for invalid address");
                        } else {
                            panic!("Expected boolean result or error response");
                        }
                    }
                    _ => panic!("Expected error or ok response for authorize"),
                }
            },
        )
        .await;
}

/// Test that mainnet addresses are ALWAYS rejected, even when network is testnet/regtest.
///
/// This is a critical safety feature to prevent accidental mainnet mining.
#[tokio::test]
async fn test_public_solo_mode_mainnet_address_always_rejected() {
    start_tracing();

    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (_pool, pool_addr) = start_pool(sv2_tp_config(tp_addr), vec![], vec![]).await;
    let (_, tproxy_addr) = start_sv2_translator_public_solo_mode(&[pool_addr], "regtest").await;
    let (sniffer_sv1, sniffer_sv1_addr) = start_sv1_sniffer(tproxy_addr);

    // Valid mainnet bech32 address - should be rejected even though it's valid format
    let mainnet_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();

    let (_minerd_process, _minerd_addr) =
        start_minerd(sniffer_sv1_addr, Some(mainnet_address), None, false).await;

    sniffer_sv1
        .wait_for_message(&["mining.subscribe"], MessageDirection::ToUpstream)
        .await;

    let authorize_id = {
        let mut extracted_id = None;
        sniffer_sv1
            .wait_and_assert(
                SV1MessageFilter::WithMessageName("mining.authorize"),
                MessageDirection::ToUpstream,
                |msg| {
                    if let sv1_api::Message::StandardRequest(req) = msg {
                        extracted_id = Some(req.id);
                    }
                },
            )
            .await;
        extracted_id.expect("Failed to extract authorize ID")
    };

    // Mainnet addresses must be rejected
    sniffer_sv1
        .wait_and_assert(
            SV1MessageFilter::WithMessageId(authorize_id),
            MessageDirection::ToDownstream,
            |msg| match msg {
                sv1_api::Message::ErrorResponse(err) => {
                    let error_msg = format!("{:?}", err.error);
                    assert!(
                        error_msg.to_lowercase().contains("mainnet"),
                        "Error should mention mainnet: {}",
                        error_msg
                    );
                }
                sv1_api::Message::OkResponse(res) => {
                    if let Some(result) = res.result.as_bool() {
                        assert!(!result, "Authorization should fail for mainnet address");
                    } else {
                        panic!("Expected boolean result or error response");
                    }
                }
                _ => panic!("Expected error or ok response for authorize"),
            },
        )
        .await;
}

/// Test that wrong network addresses are rejected.
///
/// A testnet address should be rejected when the translator is configured for regtest.
#[tokio::test]
async fn test_public_solo_mode_wrong_network_rejected() {
    start_tracing();

    let (_tp, tp_addr) = start_template_provider(None, DifficultyLevel::Low);
    let (_pool, pool_addr) = start_pool(sv2_tp_config(tp_addr), vec![], vec![]).await;
    // Translator configured for regtest
    let (_, tproxy_addr) = start_sv2_translator_public_solo_mode(&[pool_addr], "regtest").await;
    let (sniffer_sv1, sniffer_sv1_addr) = start_sv1_sniffer(tproxy_addr);

    // Valid testnet address (tb1...) but translator expects regtest (bcrt1...)
    let testnet_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();

    let (_minerd_process, _minerd_addr) =
        start_minerd(sniffer_sv1_addr, Some(testnet_address), None, false).await;

    sniffer_sv1
        .wait_for_message(&["mining.subscribe"], MessageDirection::ToUpstream)
        .await;

    let authorize_id = {
        let mut extracted_id = None;
        sniffer_sv1
            .wait_and_assert(
                SV1MessageFilter::WithMessageName("mining.authorize"),
                MessageDirection::ToUpstream,
                |msg| {
                    if let sv1_api::Message::StandardRequest(req) = msg {
                        extracted_id = Some(req.id);
                    }
                },
            )
            .await;
        extracted_id.expect("Failed to extract authorize ID")
    };

    // Wrong network address should be rejected
    sniffer_sv1
        .wait_and_assert(
            SV1MessageFilter::WithMessageId(authorize_id),
            MessageDirection::ToDownstream,
            |msg| {
                match msg {
                    sv1_api::Message::ErrorResponse(_) => {
                        // Error response is expected
                    }
                    sv1_api::Message::OkResponse(res) => {
                        if let Some(result) = res.result.as_bool() {
                            assert!(
                                !result,
                                "Authorization should fail for wrong network address"
                            );
                        } else {
                            panic!("Expected boolean result or error response");
                        }
                    }
                    _ => panic!("Expected error or ok response for authorize"),
                }
            },
        )
        .await;
}
