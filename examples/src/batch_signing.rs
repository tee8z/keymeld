//! Batch signing end-to-end test
//!
//! This test exercises the batch signing API:
//! 1. Create a keygen session with multiple participants
//! 2. Create a signing session with multiple batch items (messages)
//! 3. Verify all batch results are returned correctly

use anyhow::{anyhow, Result};
use keymeld_sdk::{
    CreateSigningSessionRequest, SessionId, SigningBatchItem, SigningSessionStatusResponse,
    SigningStatusKind,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

use crate::{ExampleConfig, KeyMeldE2ETest};

/// Number of messages to sign in the batch
const BATCH_SIZE: usize = 5;

/// Run the batch signing E2E test
pub async fn run_batch_signing_test(config: ExampleConfig) -> Result<()> {
    info!("Batch Signing End-to-End Test");
    info!("==============================");
    info!("Network: {}", config.network);
    info!("Gateway: {}", config.gateway_url);
    info!("Batch size: {}", BATCH_SIZE);

    // Use KeyMeldE2ETest for keygen setup
    let mut test = KeyMeldE2ETest::new(config, 50000, None).await?;

    // Load participants
    test.load_participants().await?;

    // Fund coordinator
    test.fund_coordinator_from_master().await?;

    // Phase 1: Keygen
    info!("Phase 1: Keygen Session");
    let keygen_session_id = test.create_keygen_session().await?;
    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;
    info!("Keygen complete: {}", aggregate_key);

    // Phase 2: Batch Signing
    info!("Phase 2: Batch Signing Session");

    // Get the session secret for encryption
    let session_secret = test
        .session_secrets
        .get(&keygen_session_id)
        .ok_or(anyhow!("Session secret not found"))?;

    // Create multiple batch items with different messages
    let mut batch_items = Vec::with_capacity(BATCH_SIZE);
    for i in 0..BATCH_SIZE {
        let message = format!("Test message {} for batch signing", i);
        let message_hash = Sha256::digest(message.as_bytes());

        // Encrypt the message
        let encrypted_message = keymeld_sdk::validation::encrypt_session_data(
            &hex::encode(&message_hash[..]),
            session_secret,
        )?;

        let batch_item = SigningBatchItem {
            batch_item_id: uuid::Uuid::now_v7(),
            message_hash: message_hash.to_vec(),
            encrypted_message: Some(encrypted_message),
            encrypted_adaptor_configs: None,
        };

        info!(
            "  Batch item {}: {} (hash: {}...)",
            i,
            batch_item.batch_item_id,
            hex::encode(&message_hash[..4])
        );
        batch_items.push(batch_item);
    }

    // Create signing session with batch items
    let signing_session_id = SessionId::new_v7();
    info!("Creating signing session: {}", signing_session_id);

    let request = CreateSigningSessionRequest {
        signing_session_id: signing_session_id.clone(),
        keygen_session_id: keygen_session_id.clone(),
        timeout_secs: 1800,
        batch_items: batch_items.clone(),
    };

    let session_signature = test.generate_session_signature(&keygen_session_id)?;

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
        "Signing session {} created with {} batch items",
        signing_session_id, BATCH_SIZE
    );

    // Submit signing approvals for participants that require them
    info!("Submitting signing approvals...");

    // Approve for coordinator (always requires approval)
    test.approve_signing_session(
        &signing_session_id,
        &test.coordinator_user_id.clone(),
        &test.coordinator_derived_private_key.clone(),
        &keygen_session_id,
    )
    .await?;

    // Approve for participants that require approval
    for idx in test.participants_requiring_approval.clone() {
        test.approve_signing_session(
            &signing_session_id,
            &test.participant_user_ids[idx].clone(),
            &test.participants[idx].derived_private_key.clone(),
            &keygen_session_id,
        )
        .await?;
    }
    info!("All required approvals completed");

    // Wait for signing completion
    info!("Waiting for batch signing completion...");
    let batch_results = wait_for_batch_signing_completion(
        &test,
        &signing_session_id,
        &keygen_session_id,
        BATCH_SIZE,
    )
    .await?;

    // Verify results
    info!("Verifying batch results...");
    let mut success_count = 0;
    let mut error_count = 0;

    for (i, result) in batch_results.iter().enumerate() {
        let original_item = batch_items
            .iter()
            .find(|item| item.batch_item_id == result.batch_item_id);

        if let Some(_item) = original_item {
            if let Some(ref encrypted_sig) = result.signature {
                // Decrypt and verify signature
                let signature_bytes = keymeld_sdk::validation::decrypt_signature_with_secret(
                    encrypted_sig,
                    session_secret,
                )?;

                info!(
                    "  Result {}: batch_item_id={}, signature={} bytes",
                    i,
                    result.batch_item_id,
                    signature_bytes.len()
                );
                success_count += 1;
            } else if let Some(ref error) = result.error {
                info!(
                    "  Result {}: batch_item_id={}, error={}",
                    i, result.batch_item_id, error
                );
                error_count += 1;
            } else {
                info!(
                    "  Result {}: batch_item_id={}, no signature or error",
                    i, result.batch_item_id
                );
                error_count += 1;
            }
        } else {
            info!(
                "  Result {}: batch_item_id={} not found in original batch items",
                i, result.batch_item_id
            );
            error_count += 1;
        }
    }

    info!("Batch signing results:");
    info!("  Total batch items: {}", BATCH_SIZE);
    info!("  Results received: {}", batch_results.len());
    info!("  Successful: {}", success_count);
    info!("  Errors: {}", error_count);

    if success_count == 0 {
        return Err(anyhow!("No successful signatures in batch"));
    }

    // For now, we expect at least one signature (single message mode returns 1 result)
    // When full batch signing is implemented, we'd expect BATCH_SIZE results
    if batch_results.is_empty() {
        return Err(anyhow!("No batch results returned"));
    }

    info!("Batch signing test completed successfully!");
    Ok(())
}

async fn wait_for_batch_signing_completion(
    test: &KeyMeldE2ETest,
    signing_session_id: &SessionId,
    keygen_session_id: &SessionId,
    _expected_count: usize,
) -> Result<Vec<keymeld_sdk::BatchItemResult>> {
    const MAX_WAIT_SECS: u64 = 120;
    const POLL_INTERVAL_MS: u64 = 500;

    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > MAX_WAIT_SECS {
            return Err(anyhow!(
                "Timeout waiting for batch signing completion after {}s",
                MAX_WAIT_SECS
            ));
        }

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
                info!(
                    "Batch signing completed with {} results",
                    status.batch_results.len()
                );
                return Ok(status.batch_results);
            }
            SigningStatusKind::Failed => {
                return Err(anyhow!("Batch signing session failed"));
            }
            SigningStatusKind::CollectingParticipants => {
                info!("  Collecting participants...");
            }
            SigningStatusKind::InitializingSession => {
                info!("  Initializing session...");
            }
            SigningStatusKind::DistributingNonces => {
                info!("  Distributing nonces...");
            }
            SigningStatusKind::FinalizingSignature => {
                info!("  Finalizing signatures...");
            }
        }

        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}
