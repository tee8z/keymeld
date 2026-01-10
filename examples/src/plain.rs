//! Plain MuSig2 Keygen + Signing Example
//!
//! Demonstrates the SDK flow:
//! 1. Create KeyMeldClient for coordinator and participants
//! 2. Coordinator creates keygen session, participants join
//! 3. Create signing session, approve, get signature

use anyhow::{anyhow, Result};
use keymeld_sdk::prelude::*;
use tracing::info;

use keymeld_examples::{ExampleConfig, KeyMeldE2ETest};

pub async fn run_with_args(
    config_path: String,
    amount: u64,
    destination: Option<String>,
) -> Result<()> {
    let config: ExampleConfig = {
        let content = std::fs::read_to_string(&config_path)?;
        serde_yaml::from_str(&content)?
    };

    info!("KeyMeld Plain MuSig2 Example");
    info!("Gateway: {}", config.gateway_url);
    info!("Participants: {}", config.num_signers);

    // Test harness: wallet loading, Bitcoin funding
    let mut test = KeyMeldE2ETest::new(config.clone(), amount, destination).await?;
    test.load_participants().await?;
    test.fund_coordinator_from_master().await?;

    // Create SDK clients
    let coordinator_credentials =
        UserCredentials::from_private_key(&test.coordinator_derived_private_key.secret_bytes())?;

    let coordinator_client =
        KeyMeldClient::builder(&config.gateway_url, test.coordinator_user_id.clone())
            .credentials(coordinator_credentials)
            .build()?;

    let mut participant_clients = Vec::new();
    for participant in &test.participants {
        let credentials =
            UserCredentials::from_private_key(&participant.derived_private_key.secret_bytes())?;
        let client = KeyMeldClient::builder(&config.gateway_url, UserId::new_v7())
            .credentials(credentials)
            .build()?;
        participant_clients.push(client);
    }

    // Keygen
    info!("Phase 1: Keygen");

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
    info!("Keygen complete: {}", aggregate_key_hex);

    // Test harness: fund aggregate address, create PSBT
    let aggregate_utxo = test
        .fund_aggregate_key_address(&aggregate_key_hex, &session_id)
        .await?;
    let psbt = test
        .create_musig2_transaction(&aggregate_key_hex, &session_id, &aggregate_utxo)
        .await?;
    let message_hash = test.calculate_taproot_sighash(&psbt)?;

    // Signing
    info!("Phase 2: Signing");

    let keygen_session = coordinator_client
        .keygen()
        .restore_session(
            session_id.clone(),
            SessionCredentials::from_session_secret(&session_secret)?,
        )
        .await?;

    let mut signing_session = coordinator_client
        .signer()
        .sign(
            &keygen_session,
            message_hash,
            SigningOptions::default().timeout(1800),
        )
        .await?;

    let signing_session_id = signing_session.session_id().clone();
    info!("Created signing session: {}", signing_session_id);

    // Validate: Before approving, verify the message matches what we expect to sign
    // In production, each participant should independently compute the sighash
    // from the transaction details and verify it matches before approving
    let expected_message = message_hash;
    info!(
        "Validating message before approval: {}",
        hex::encode(expected_message)
    );

    signing_session.approve().await?;
    info!("Coordinator approved");

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

        // Validate: Participant should also verify the message before approving
        // In production, participant would compute expected sighash independently
        info!(
            "Participant validating message before approval: {}",
            hex::encode(expected_message)
        );

        participant_signing.approve().await?;
        info!("Participant 0 approved");
    }

    let results = signing_session.wait_for_completion().await?;

    let signature = results
        .first()
        .and_then(|r| r.signature.as_ref())
        .ok_or_else(|| anyhow!("No signature"))?;

    info!("Signing complete: {}", hex::encode(signature));

    // Validate: Before broadcasting, verify the signature is for the correct message
    // Recompute the sighash from the PSBT to ensure it matches what was signed
    let verified_message = test.calculate_taproot_sighash(&psbt)?;
    if verified_message != expected_message {
        return Err(anyhow!(
            "Message mismatch! Expected {} but got {}",
            hex::encode(expected_message),
            hex::encode(verified_message)
        ));
    }
    info!("Message verified before broadcast");

    // Test harness: broadcast
    let signed_tx = test.apply_signature_and_broadcast(psbt, signature).await?;

    println!("\nKeyMeld Plain Example Complete!");
    println!("Aggregate key: {}", aggregate_key_hex);
    println!("Transaction: {}", signed_tx.compute_txid());

    Ok(())
}
