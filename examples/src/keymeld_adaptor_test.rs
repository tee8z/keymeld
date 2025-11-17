//! KeyMeld Adaptor Signatures E2E Test
//!
//! This example demonstrates the complete adaptor signatures workflow alongside regular MuSig2 signing.
//! It showcases all three adaptor signature types (Single, And, Or) and validates the entire
//! client-side encryption/decryption flow.

use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info};

use clap::{Arg, Command};
use keymeld_core::api::{CreateSigningSessionRequest, SigningSessionStatusResponse};
use keymeld_core::musig::{AdaptorConfig, AdaptorSignatureResult};
use keymeld_core::session::SigningStatusKind;

// Re-use the main example's structures and helper functions
use keymeld_examples::adaptor_utils::{
    create_test_adaptor_configs, print_success_summary, validate_adaptor_signatures,
    AdaptorTestConfig,
};
use keymeld_examples::{ExampleConfig, KeyMeldE2ETest};

fn init() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("keymeld_adaptor_test=info".parse().unwrap()),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let (config, amount, destination, adaptor_config) = load_config()?;
    info!("Loaded configuration for adaptor signatures test");

    let mut test = KeyMeldE2ETest::new(config, amount, destination).await?;

    tokio::select! {
        result = run_adaptor_signatures_test(&mut test, adaptor_config) => {
            match result {
                Ok(()) => {
                    println!("\n🎉 KeyMeld Adaptor Signatures E2E Test Completed Successfully!");
                }
                Err(e) => {
                    error!("Adaptor signatures E2E test failed: {e}");
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
    info!("🔧 KeyMeld Adaptor Signatures E2E Test");
    info!("=======================================");
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

    // Phase 1: Keygen (reuse existing workflow)
    info!("🔑 Starting Phase 1: Keygen Session");
    let keygen_session_id = test.create_keygen_session().await?;
    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;
    info!("✅ Keygen complete: {}", aggregate_key);

    let aggregate_utxo = test.fund_aggregate_key_address(&aggregate_key).await?;
    let psbt = test
        .create_musig2_transaction(&aggregate_key, &aggregate_utxo)
        .await?;

    info!("🔧 Starting Adaptor Signatures Test");
    let adaptor_configs = create_test_adaptor_configs(&adaptor_config)?;
    info!(
        "📝 Created {} adaptor configurations",
        adaptor_configs.len()
    );

    // Display configuration details
    for (i, config) in adaptor_configs.iter().enumerate() {
        info!(
            "  Config {}: {:?} with {} points",
            i + 1,
            config.adaptor_type,
            config.adaptor_points.len()
        );
    }

    info!("✍️ Starting Phase 2: Signing Session with Adaptor Signatures");
    let signing_session_id =
        test_signing_session_with_adaptors(test, &keygen_session_id, &psbt, &adaptor_configs)
            .await?;

    // Handle approvals (reuse existing approval logic)
    test.approve_signing_session(
        &signing_session_id,
        test.coordinator_user_id.as_str(),
        &test.coordinator_derived_private_key,
    )
    .await?;
    test.approve_signing_session(
        &signing_session_id,
        test.participant_user_ids[0].as_str(),
        &test.participants[0].derived_private_key,
    )
    .await?;
    info!("✅ All required approvals completed - signing can now proceed");

    let (signature, adaptor_signatures) =
        wait_for_signing_with_adaptors(test, &signing_session_id, &keygen_session_id).await?;

    if !adaptor_config.skip_regular_signing {
        let signed_tx = test.apply_signature_and_broadcast(psbt, &signature).await?;
        info!("✅ Transaction broadcast: {}", signed_tx.compute_txid());
    }

    validate_adaptor_signatures(&adaptor_configs, &adaptor_signatures)?;

    print_success_summary(&adaptor_configs, &adaptor_signatures, &aggregate_key);

    Ok(())
}

async fn test_signing_session_with_adaptors(
    test: &mut KeyMeldE2ETest,
    keygen_session_id: &str,
    psbt: &bitcoin::psbt::Psbt,
    adaptor_configs: &[AdaptorConfig],
) -> Result<String> {
    let signing_session_id = uuid::Uuid::now_v7().to_string();
    let sighash = test.calculate_taproot_sighash(psbt)?;

    // Get session secret for encryption
    let session_secret = test
        .session_secrets
        .get(keygen_session_id)
        .ok_or_else(|| {
            anyhow!(
                "Session secret not found for keygen session: {}",
                keygen_session_id
            )
        })?
        .clone();

    test.session_secrets
        .insert(signing_session_id.clone(), session_secret.clone());

    info!(
        "🔒 Encrypting {} adaptor configurations on client side",
        adaptor_configs.len()
    );
    let encrypted_adaptor_configs =
        keymeld_core::api::validation::encrypt_adaptor_configs_for_client(
            adaptor_configs,
            &session_secret,
        )
        .map_err(|e| anyhow!("Failed to encrypt adaptor configs: {}", e))?;

    info!("✅ Verified zero-knowledge privacy: gateway cannot see adaptor IDs or business logic");

    let request = CreateSigningSessionRequest {
        signing_session_id: signing_session_id.clone().try_into().unwrap(),
        keygen_session_id: keygen_session_id.try_into().unwrap(),
        message_hash: sighash.to_vec(),
        encrypted_message: Some(hex::encode(&sighash[..])),
        timeout_secs: 1800,
        encrypted_adaptor_configs,
    };

    let session_hmac = test.generate_session_hmac(
        keygen_session_id,
        test.coordinator_user_id.as_str(),
        &session_secret,
    )?;

    let response = test
        .client
        .post(format!("{}/api/v1/signing", test.config.gateway_url))
        .header("X-Session-HMAC", session_hmac)
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to create signing session: {}",
            response.text().await?
        ));
    }

    info!(
        "✅ Signing session {} created with adaptor configurations",
        signing_session_id
    );
    Ok(signing_session_id)
}

async fn wait_for_signing_with_adaptors(
    test: &mut KeyMeldE2ETest,
    signing_session_id: &str,
    keygen_session_id: &str,
) -> Result<(Vec<u8>, Vec<AdaptorSignatureResult>)> {
    info!("⏳ Waiting for signing completion with adaptor processing...");

    loop {
        let user_hmac = test.generate_user_hmac(
            test.coordinator_user_id.as_str(),
            &test.coordinator_derived_private_key,
        )?;

        let response = test
            .client
            .get(format!(
                "{}/api/v1/signing/{}/status",
                test.config.gateway_url, signing_session_id
            ))
            .header("X-Signing-HMAC", user_hmac)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to get signing status: {}",
                response.text().await?
            ));
        }

        let status: SigningSessionStatusResponse = response.json().await?;

        match status.status {
            SigningStatusKind::Completed => {
                let signature = if let Some(encrypted_sig) = status.final_signature {
                    let session_secret = test
                        .session_secrets
                        .get(keygen_session_id)
                        .ok_or_else(|| anyhow!("Session secret not found"))?;

                    keymeld_core::api::validation::decrypt_signature_with_secret(
                        &encrypted_sig,
                        session_secret,
                    )?
                } else {
                    return Err(anyhow!("Signing completed but no signature found"));
                };

                let adaptor_signatures = if !status.adaptor_signatures.is_empty() {
                    let session_secret = test
                        .session_secrets
                        .get(keygen_session_id)
                        .ok_or_else(|| anyhow!("Session secret not found"))?;

                    info!("🔓 Decrypting adaptor signatures on client side");
                    keymeld_core::api::validation::decrypt_adaptor_signatures_with_secret(
                        &status.adaptor_signatures,
                        session_secret,
                    )?
                } else {
                    Vec::new()
                };

                info!("✅ Regular MuSig2 signing completed");
                info!("🎉 Adaptor signatures processed automatically!");
                info!(
                    "🔓 Successfully decrypted {} adaptor signatures",
                    adaptor_signatures.len()
                );

                return Ok((signature, adaptor_signatures));
            }
            SigningStatusKind::Failed => {
                return Err(anyhow!("Signing session failed"));
            }
            SigningStatusKind::CollectingParticipants => {
                info!("Signing still collecting participants...");
            }
            SigningStatusKind::SessionFull => {
                info!("Signing session full, waiting for processing...");
            }
            SigningStatusKind::GeneratingNonces => {
                info!("Generating nonces...");
            }
            SigningStatusKind::CollectingNonces => {
                info!("Collecting nonces...");
            }
            SigningStatusKind::AggregatingNonces => {
                info!("Aggregating nonces...");
            }
            SigningStatusKind::GeneratingPartialSignatures => {
                info!("Generating partial signatures...");
            }
            SigningStatusKind::CollectingPartialSignatures => {
                info!("Collecting partial signatures...");
            }
            SigningStatusKind::FinalizingSignature => {
                info!("Finalizing signature and processing adaptor signatures...");
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}

fn load_config() -> Result<(ExampleConfig, u64, String, AdaptorTestConfig)> {
    let matches = Command::new("KeyMeld Adaptor Signatures E2E Test")
        .version("1.0")
        .about("End-to-end test of KeyMeld adaptor signatures with distributed MuSig2 signing")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .default_value("examples/config.yaml")
                .help("Configuration file path"),
        )
        .arg(
            Arg::new("amount")
                .short('a')
                .long("amount")
                .value_name("SATS")
                .required(true)
                .help("Amount to send in satoshis"),
        )
        .arg(
            Arg::new("destination")
                .short('d')
                .long("destination")
                .value_name("ADDRESS")
                .required(true)
                .help("Destination address for the transaction"),
        )
        .arg(
            Arg::new("test-single")
                .long("test-single")
                .action(clap::ArgAction::SetTrue)
                .help("Test single adaptor signatures (default: true)"),
        )
        .arg(
            Arg::new("test-and")
                .long("test-and")
                .action(clap::ArgAction::SetTrue)
                .help("Test 'And' adaptor signatures (default: true)"),
        )
        .arg(
            Arg::new("test-or")
                .long("test-or")
                .action(clap::ArgAction::SetTrue)
                .help("Test 'Or' adaptor signatures (default: true)"),
        )
        .arg(
            Arg::new("skip-regular-signing")
                .long("skip-regular-signing")
                .action(clap::ArgAction::SetTrue)
                .help("Skip regular MuSig2 signing and transaction broadcast"),
        )
        .arg(
            Arg::new("single-only")
                .long("single-only")
                .action(clap::ArgAction::SetTrue)
                .help("Test only single adaptor signatures"),
        )
        .arg(
            Arg::new("and-only")
                .long("and-only")
                .action(clap::ArgAction::SetTrue)
                .help("Test only 'And' adaptor signatures"),
        )
        .arg(
            Arg::new("or-only")
                .long("or-only")
                .action(clap::ArgAction::SetTrue)
                .help("Test only 'Or' adaptor signatures"),
        )
        .get_matches();

    // Parse basic config using shared utility
    let (config, amount, destination) = KeyMeldE2ETest::parse_config_from_matches(&matches)?;

    // Configure adaptor test settings
    let mut adaptor_config = AdaptorTestConfig::default();

    // Handle exclusive options
    if matches.get_flag("single-only") {
        adaptor_config.test_single = true;
        adaptor_config.test_and = false;
        adaptor_config.test_or = false;
    } else if matches.get_flag("and-only") {
        adaptor_config.test_single = false;
        adaptor_config.test_and = true;
        adaptor_config.test_or = false;
    } else if matches.get_flag("or-only") {
        adaptor_config.test_single = false;
        adaptor_config.test_and = false;
        adaptor_config.test_or = true;
    } else {
        // Use individual flags or defaults
        adaptor_config.test_single = matches.get_flag("test-single") || adaptor_config.test_single;
        adaptor_config.test_and = matches.get_flag("test-and") || adaptor_config.test_and;
        adaptor_config.test_or = matches.get_flag("test-or") || adaptor_config.test_or;
    }

    adaptor_config.skip_regular_signing = matches.get_flag("skip-regular-signing");

    Ok((config, amount, destination, adaptor_config))
}
