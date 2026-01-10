//! Adaptor Signatures Example
//!
//! Demonstrates adaptor signature types (Single, And, Or) using the SDK:
//! 1. Create KeyMeldClient for coordinator and participants
//! 2. Coordinator creates keygen session, participants join
//! 3. Create signing session with adaptor configs, approve, get adaptor signatures
//! 4. Adapt signatures with revealed secrets and broadcast

use anyhow::{anyhow, Result};
use keymeld_examples::{
    adapt_signatures_and_get_valid_signature, create_test_adaptor_configs, print_success_summary,
    validate_adaptor_signatures, AdaptorTestConfig, ExampleConfig, KeyMeldE2ETest,
};
use keymeld_sdk::prelude::*;
use std::fs::read_to_string;
use tracing::{error, info};

pub async fn run_with_args(
    config_path: String,
    amount: u64,
    destination: Option<String>,
    single_only: bool,
    and_only: bool,
    or_only: bool,
    skip_regular_signing: bool,
) -> Result<()> {
    let config_content = read_to_string(&config_path)?;
    let config = serde_yaml::from_str::<ExampleConfig>(&config_content)?;

    let mut adaptor_config = AdaptorTestConfig::default();
    if single_only {
        adaptor_config.test_single = true;
        adaptor_config.test_and = false;
        adaptor_config.test_or = false;
    } else if and_only {
        adaptor_config.test_single = false;
        adaptor_config.test_and = true;
        adaptor_config.test_or = false;
    } else if or_only {
        adaptor_config.test_single = false;
        adaptor_config.test_and = false;
        adaptor_config.test_or = true;
    }
    adaptor_config.skip_regular_signing = skip_regular_signing;

    info!("Loaded configuration for adaptor signatures test");

    if destination.is_none() {
        info!("No destination address provided, will generate from coordinator wallet");
    }

    let mut test = KeyMeldE2ETest::new(config, amount, destination).await?;

    tokio::select! {
        result = run_adaptor_signatures_test(&mut test, adaptor_config) => {
            match result {
                Ok(()) => {
                    println!("\n✅ KeyMeld adaptor signatures test completed successfully!");
                }
                Err(e) => {
                    error!("Adaptor signatures test failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\n🛑 Received Ctrl+C, shutting down gracefully...");
            std::process::exit(0);
        }
    }

    Ok(())
}

async fn run_adaptor_signatures_test(
    test: &mut KeyMeldE2ETest,
    adaptor_config: AdaptorTestConfig,
) -> Result<()> {
    info!("🔧 KeyMeld Adaptor Signatures E2E Test (SDK)");
    info!("=============================================");
    info!("Network: {}", test.config.network);
    info!("Gateway: {}", test.config.gateway_url);
    info!("Participants: {}", test.config.num_signers);
    info!("Test Configuration:");
    info!("  - Single adaptor: {}", adaptor_config.test_single);
    info!("  - And adaptor: {}", adaptor_config.test_and);
    info!("  - Or adaptor: {}", adaptor_config.test_or);
    info!(
        "  - Skip regular signing: {}",
        adaptor_config.skip_regular_signing
    );

    test.load_participants().await?;
    test.fund_coordinator_from_master().await?;

    // Create SDK clients
    let coordinator_credentials =
        UserCredentials::from_private_key(&test.coordinator_derived_private_key.secret_bytes())?;

    let coordinator_client =
        KeyMeldClient::builder(&test.config.gateway_url, test.coordinator_user_id.clone())
            .credentials(coordinator_credentials)
            .build()?;

    let mut participant_clients = Vec::new();
    for participant in &test.participants {
        let credentials =
            UserCredentials::from_private_key(&participant.derived_private_key.secret_bytes())?;
        let client = KeyMeldClient::builder(&test.config.gateway_url, UserId::new_v7())
            .credentials(credentials)
            .build()?;
        participant_clients.push(client);
    }

    // Phase 1: Keygen using SDK
    info!("🔑 Starting Phase 1: Keygen Session (SDK)");

    let all_participants: Vec<UserId> = std::iter::once(coordinator_client.user_id().clone())
        .chain(participant_clients.iter().map(|c| c.user_id().clone()))
        .collect();

    let mut keygen_session = coordinator_client
        .keygen()
        .create_session(
            all_participants,
            KeygenOptions::default()
                .timeout(3600)
                .max_signings(10)
                .require_approval(),
        )
        .await?;

    let session_id = keygen_session.session_id().clone();
    let session_secret = keygen_session.export_session_secret();
    info!("Created keygen session: {}", session_id);

    keygen_session
        .register_self(RegisterOptions::default().require_approval())
        .await?;
    info!("Coordinator registered");

    for (idx, client) in participant_clients.iter().enumerate() {
        let requires_approval = idx == 0;

        client
            .keygen()
            .join_session(
                session_id.clone(),
                &session_secret,
                JoinOptions::default().approval(requires_approval),
            )
            .await?;

        info!("Participant {} joined", idx);
    }

    keygen_session.wait_for_completion().await?;
    let aggregate_key = keygen_session.decrypt_aggregate_key()?;
    let aggregate_key_hex = hex::encode(&aggregate_key);
    info!("✅ Keygen complete: {}", aggregate_key_hex);

    // Fund the aggregate key address and create PSBT
    let aggregate_utxo = test
        .fund_aggregate_key_address(&aggregate_key_hex, &session_id)
        .await?;
    let psbt = test
        .create_musig2_transaction(&aggregate_key_hex, &session_id, &aggregate_utxo)
        .await?;

    // Create adaptor configurations
    info!("🔧 Starting Adaptor Signatures Test");
    let (adaptor_configs, adaptor_secrets) = create_test_adaptor_configs(&adaptor_config)?;
    info!(
        "📝 Created {} adaptor configurations with {} secrets",
        adaptor_configs.len(),
        adaptor_secrets.len()
    );

    for (i, config) in adaptor_configs.iter().enumerate() {
        info!(
            "  Config {}: {:?} with {} points",
            i + 1,
            config.adaptor_type,
            config.adaptor_points.len()
        );
    }

    // Phase 2: Signing with adaptor signatures using SDK
    info!("✍️ Starting Phase 2: Signing Session with Adaptor Signatures (SDK)");

    let message_hash = test.calculate_taproot_sighash(&psbt)?;
    let expected_message = message_hash;

    // Restore keygen session for signing
    let keygen_session = coordinator_client
        .keygen()
        .restore_session(
            session_id.clone(),
            SessionCredentials::from_session_secret(&session_secret)?,
        )
        .await?;

    // Create signing session with adaptor configs using SDK
    let mut signing_session = coordinator_client
        .signer()
        .sign_adaptor(
            &keygen_session,
            message_hash,
            adaptor_configs.clone(),
            SigningOptions::default().timeout(1800),
        )
        .await?;

    let signing_session_id = signing_session.session_id().clone();
    info!(
        "✅ Signing session {} created with adaptor configurations",
        signing_session_id
    );

    // Validate: Before approving, verify the message matches what we expect to sign
    info!(
        "🔍 Validating message before approval: {}",
        hex::encode(&expected_message)
    );

    // Approve using SDK
    signing_session.approve().await?;
    info!("✅ Coordinator approved");

    // Approve for first participant (requires approval)
    if !participant_clients.is_empty() {
        let client = &participant_clients[0];

        let participant_keygen = client
            .keygen()
            .restore_session(
                session_id.clone(),
                SessionCredentials::from_session_secret(&session_secret)?,
            )
            .await?;

        let mut participant_signing = client
            .signer()
            .restore_session(signing_session_id.clone(), &participant_keygen)
            .await?;

        info!("🔍 Participant 0 validating message before approval");
        participant_signing.approve().await?;
        info!("✅ Participant 0 approved");
    }

    info!("✅ All required approvals completed - signing can now proceed");

    // Wait for signing completion using SDK
    info!("⏳ Waiting for signing completion with adaptor processing...");
    let signature_results = signing_session.wait_for_completion().await?;

    // Get adaptor signatures from results
    let first_result = signature_results
        .first()
        .ok_or(anyhow!("Signing completed but no results found"))?;

    let adaptor_signatures = first_result
        .adaptor_signatures
        .as_ref()
        .ok_or(anyhow!("Signing completed but no adaptor signatures found"))?;

    info!(
        "✅ Adaptor signing completed! Received {} adaptor signatures",
        adaptor_signatures.len()
    );

    validate_adaptor_signatures(&adaptor_configs, adaptor_signatures)?;

    // Demonstrate the complete adaptor signature flow
    if !adaptor_config.skip_regular_signing {
        info!("🎭 Demonstrating complete adaptor signature flow...");
        info!("🔑 Step 1: Revealing adaptor secrets (in real scenarios, this happens through external events)");

        // Parse the aggregate key for verification
        let aggregate_pubkey = musig2::secp256k1::PublicKey::from_slice(&aggregate_key)
            .map_err(|e| anyhow::anyhow!("Invalid aggregate key: {e}"))?;

        info!("🔑 Step 2: Adapting signatures using revealed secrets...");
        let adapted_signature = adapt_signatures_and_get_valid_signature(
            &adaptor_configs,
            adaptor_signatures,
            &adaptor_secrets,
            aggregate_pubkey,
            &message_hash,
        )?;

        // Validate: Before broadcasting, verify the message matches what was signed
        let verified_message = test.calculate_taproot_sighash(&psbt)?;
        if verified_message != expected_message {
            return Err(anyhow!(
                "Message mismatch! Expected {} but got {}",
                hex::encode(&expected_message),
                hex::encode(&verified_message)
            ));
        }
        info!("✅ Message verified before broadcast");

        info!("🔑 Step 3: Broadcasting transaction with adapted signature...");
        let signed_tx = test
            .apply_signature_and_broadcast(psbt, &adapted_signature)
            .await?;
        info!(
            "✅ Transaction broadcast with adapted signature: {}",
            signed_tx.compute_txid()
        );
    } else {
        info!("✅ Skipping transaction broadcast as configured");
        info!(
            "💡 In real scenarios, adaptor signatures would be adapted when secrets are revealed"
        );
    }

    print_success_summary(&adaptor_configs, adaptor_signatures, &aggregate_key_hex);

    Ok(())
}
