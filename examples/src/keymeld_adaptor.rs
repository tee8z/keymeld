use anyhow::{anyhow, Result};
use keymeld_examples::adaptor_utils::{
    adapt_signatures_and_get_valid_signature, create_test_adaptor_configs, print_success_summary,
    validate_adaptor_signatures, AdaptorTestConfig,
};
use keymeld_examples::ExampleConfig;
use keymeld_examples::KeyMeldE2ETest;
use keymeld_sdk::{
    validation::encrypt_adaptor_configs_for_client, CreateSigningSessionRequest, EncryptedData,
    SessionSecret, SigningSessionStatusResponse, SigningStatusKind,
};
use keymeld_sdk::{AdaptorConfig, AdaptorSignatureResult, SessionId};
use std::fs::read_to_string;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info};

fn init() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("keymeld_adaptor_test=info".parse().unwrap()),
        )
        .init();
}

pub async fn run_with_args(
    config_path: String,
    amount: u64,
    destination: Option<String>,
    single_only: bool,
    and_only: bool,
    or_only: bool,
    skip_regular_signing: bool,
) -> Result<()> {
    init();

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

    info!("🔑 Starting Phase 1: Keygen Session");
    let keygen_session_id = test.create_keygen_session().await?;
    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;
    info!("✅ Keygen complete: {}", aggregate_key);

    let aggregate_utxo = test
        .fund_aggregate_key_address(&aggregate_key, &keygen_session_id)
        .await?;
    let psbt = test
        .create_musig2_transaction(&aggregate_key, &keygen_session_id, &aggregate_utxo)
        .await?;

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

    info!("✍️ Starting Phase 2: Signing Session with Adaptor Signatures");
    let signing_session_id =
        test_signing_session_with_adaptors(test, &keygen_session_id, &psbt, &adaptor_configs)
            .await?;

    // Approve for coordinator (always requires approval)
    test.approve_signing_session(
        &signing_session_id,
        &test.coordinator_user_id,
        &test.coordinator_derived_private_key,
        &keygen_session_id,
    )
    .await?;

    // Approve only for participants that require approval
    for idx in &test.participants_requiring_approval {
        test.approve_signing_session(
            &signing_session_id,
            &test.participant_user_ids[*idx],
            &test.participants[*idx].derived_private_key,
            &keygen_session_id,
        )
        .await?;
    }
    info!("✅ All required approvals completed - signing can now proceed");

    let adaptor_signatures =
        wait_for_signing_with_adaptors(test, &signing_session_id, &keygen_session_id).await?;

    validate_adaptor_signatures(&adaptor_configs, &adaptor_signatures)?;

    // Demonstrate the complete adaptor signature flow
    if !adaptor_config.skip_regular_signing {
        info!("🎭 Demonstrating complete adaptor signature flow...");
        info!("🔑 Step 1: Revealing adaptor secrets (in real scenarios, this happens through external events)");

        // Decrypt the aggregate key using the session secret
        let session_secret_hex = test
            .session_secrets
            .get(&keygen_session_id)
            .ok_or_else(|| anyhow!("Session secret not found for keygen session"))?;
        let session_secret = SessionSecret::from_hex(session_secret_hex)?;
        let encrypted_data = EncryptedData::from_hex(&aggregate_key)
            .map_err(|e| anyhow!("Failed to decode encrypted aggregate key: {e}"))?;
        let key_bytes = session_secret
            .decrypt(&encrypted_data, "aggregate_public_key")
            .map_err(|e| anyhow!("Failed to decrypt aggregate key: {e}"))?;

        // Parse the aggregate key for verification
        let aggregate_pubkey = musig2::secp256k1::PublicKey::from_slice(&key_bytes)
            .map_err(|e| anyhow::anyhow!("Invalid aggregate key: {e}"))?;

        // Calculate the message hash for verification
        let message_hash = test.calculate_taproot_sighash(&psbt)?;

        info!("🔑 Step 2: Adapting signatures using revealed secrets...");
        let adapted_signature = adapt_signatures_and_get_valid_signature(
            &adaptor_configs,
            &adaptor_signatures,
            &adaptor_secrets,
            aggregate_pubkey,
            &message_hash,
        )?;

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

    let decrypted_aggregate_key =
        test.decrypt_aggregate_key_for_display(&aggregate_key, &keygen_session_id)?;
    print_success_summary(
        &adaptor_configs,
        &adaptor_signatures,
        &decrypted_aggregate_key,
    );

    Ok(())
}

async fn test_signing_session_with_adaptors(
    test: &mut KeyMeldE2ETest,
    keygen_session_id: &SessionId,
    psbt: &bitcoin::psbt::Psbt,
    adaptor_configs: &[AdaptorConfig],
) -> Result<SessionId> {
    let signing_session_id: SessionId = uuid::Uuid::now_v7().into();
    let sighash = test.calculate_taproot_sighash(psbt)?;

    let session_secret = test
        .session_secrets
        .get(keygen_session_id)
        .ok_or(anyhow!(
            "Session secret not found for keygen session: {keygen_session_id}"
        ))?
        .clone();

    test.session_secrets
        .insert(signing_session_id.clone(), session_secret.clone());

    info!(
        "🔒 Encrypting {} adaptor configurations on client side",
        adaptor_configs.len()
    );

    let encrypted_adaptor_configs =
        encrypt_adaptor_configs_for_client(adaptor_configs, &session_secret)
            .map_err(|e| anyhow!("Failed to encrypt adaptor configs: {e}"))?;

    info!("✅ Verified zero-knowledge privacy: gateway cannot see adaptor IDs or business logic");

    // Encrypt the message with the session secret
    let encrypted_message =
        keymeld_sdk::validation::encrypt_session_data(&hex::encode(&sighash[..]), &session_secret)?;

    // Encrypt the taproot tweak
    let encrypted_taproot_tweak = keymeld_sdk::validation::encrypt_session_data(
        &serde_json::to_string(&keymeld_sdk::TaprootTweak::None)?,
        &session_secret,
    )?;

    // Create a batch item for the single message with adaptor configs
    let batch_item = keymeld_sdk::SigningBatchItem {
        batch_item_id: uuid::Uuid::now_v7(),
        message_hash: sighash.to_vec(),
        signing_mode: keymeld_sdk::SigningMode::Adaptor {
            encrypted_message,
            encrypted_adaptor_configs,
        },
        encrypted_taproot_tweak,
        subset_id: None, // Use full n-of-n aggregate key
    };

    let request = CreateSigningSessionRequest {
        signing_session_id: signing_session_id.clone(),
        keygen_session_id: keygen_session_id.clone(),
        timeout_secs: 1800,
        batch_items: vec![batch_item],
    };

    let session_signature = test.generate_session_signature(keygen_session_id)?;

    let response = test
        .client
        .post(format!("{}/api/v1/signing", test.config.gateway_url))
        .header("X-Session-Signature", session_signature)
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
    signing_session_id: &SessionId,
    keygen_session_id: &SessionId,
) -> Result<std::collections::BTreeMap<uuid::Uuid, AdaptorSignatureResult>> {
    info!("⏳ Waiting for signing completion with adaptor processing...");

    loop {
        let user_signature = test.generate_user_signature(
            signing_session_id,
            &test.coordinator_user_id,
            &test.coordinator_derived_private_key,
            keygen_session_id,
        )?;

        let response = test
            .client
            .get(format!(
                "{}/api/v1/signing/{}/status/{}",
                test.config.gateway_url, signing_session_id, test.coordinator_user_id
            ))
            .header("X-User-Signature", user_signature)
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
                // Get the first batch result (single message = batch of 1)
                let first_result = status
                    .batch_results
                    .first()
                    .ok_or(anyhow!("Signing completed but no batch results found"))?;

                if let Some(ref error) = first_result.error {
                    return Err(anyhow!("Signing failed: {}", error));
                }

                // For adaptor signing, we get adaptor signatures (not a regular signature)
                let adaptor_signatures =
                    if let Some(ref encrypted_adaptors) = first_result.adaptor_signatures {
                        let session_secret = test
                            .session_secrets
                            .get(keygen_session_id)
                            .ok_or(anyhow!("Session secret not found"))?;

                        info!("Decrypting adaptor signatures on client side");
                        keymeld_sdk::validation::decrypt_adaptor_signatures_with_secret(
                            encrypted_adaptors,
                            session_secret,
                        )?
                    } else {
                        return Err(anyhow!("Signing completed but no adaptor signatures found"));
                    };

                info!("Adaptor signing completed!");
                info!(
                    "Successfully decrypted {} adaptor signatures",
                    adaptor_signatures.len()
                );

                return Ok(adaptor_signatures);
            }
            SigningStatusKind::Failed => {
                return Err(anyhow!("Signing session failed"));
            }
            SigningStatusKind::CollectingParticipants => {
                info!("⏳ Signing still collecting participants...");
            }
            SigningStatusKind::InitializingSession => {
                info!("🔧 Initializing signing session and generating nonces...");
            }
            SigningStatusKind::DistributingNonces => {
                info!("📤 Distributing nonces and generating partial signatures...");
            }
            SigningStatusKind::FinalizingSignature => {
                info!("✍️  Finalizing signature and processing adaptor signatures...");
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}
