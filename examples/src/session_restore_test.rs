//! Session Restoration Test
//!
//! Tests that keygen sessions can be restored after enclave restart.
//! Two phases:
//! 1. Keygen: Create sessions, fund them, save session data
//! 2. Sign: After restart, restore sessions and complete signing

use anyhow::{anyhow, Result};
use bdk_wallet::bitcoin::{OutPoint, Txid};
use clap::{Parser, Subcommand};
use keymeld_examples::harness::single_signer::SingleSignerE2ETest;
use keymeld_examples::{ExampleConfig, KeyMeldE2ETest};
use keymeld_sdk::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::str::FromStr;
use tracing::{error, info};
use tracing_subscriber::fmt::init;

#[derive(Parser)]
#[command(name = "keymeld_session_test")]
#[command(version = "0.1.0")]
#[command(about = "KeyMeld Session Restoration Test")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create keygen sessions (plain and adaptor), fund them, and save session data
    Keygen {
        #[arg(long)]
        config: String,
        #[arg(long)]
        output: String,
        #[arg(long, default_value = "25000")]
        amount: u64,
        #[arg(long)]
        destination: Option<String>,
    },
    /// Sign using previously created keygen sessions (tests session restoration)
    Sign {
        #[arg(long)]
        config: String,
        #[arg(long)]
        input: String,
    },
}

/// Saved session data for restoration testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSessionData {
    // Plain session data
    pub plain_keygen_session_id: String,
    pub plain_aggregate_key_hex: String,
    pub plain_session_secret_hex: String,
    pub plain_utxo_txid: String,
    pub plain_utxo_vout: u32,
    pub plain_coordinator_user_id: String,
    pub plain_coordinator_private_key_hex: String,
    pub plain_participant_user_ids: Vec<String>,
    pub plain_participant_private_keys_hex: Vec<String>,

    // Adaptor session data
    pub adaptor_keygen_session_id: String,
    pub adaptor_aggregate_key_hex: String,
    pub adaptor_session_secret_hex: String,
    pub adaptor_utxo_txid: String,
    pub adaptor_utxo_vout: u32,
    pub adaptor_coordinator_user_id: String,
    pub adaptor_coordinator_private_key_hex: String,
    pub adaptor_participant_user_ids: Vec<String>,
    pub adaptor_participant_private_keys_hex: Vec<String>,

    // Single-signer session data
    pub single_signer_user_id: String,
    pub single_signer_key_id: String,
    pub single_signer_enclave_id: u32,
    pub single_signer_enclave_public_key: String,
    pub single_signer_private_key_hex: String,
    pub single_signer_public_key_hex: String,
    pub single_signer_auth_private_key_hex: String,
    pub single_signer_auth_public_key_hex: String,

    // Common data
    pub destination: String,
    pub amount: u64,
}

pub async fn run() -> Result<()> {
    init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen {
            config,
            output,
            amount,
            destination,
        } => run_keygen(config, output, amount, destination).await,
        Commands::Sign { config, input } => run_sign(config, input).await,
    }
}

async fn run_keygen(
    config_path: String,
    output_path: String,
    amount: u64,
    destination: Option<String>,
) -> Result<()> {
    info!("===========================================");
    info!("KeyMeld Session Restoration Test - Keygen");
    info!("===========================================");

    let config: ExampleConfig = {
        let content = fs::read_to_string(&config_path)?;
        serde_yaml::from_str(&content)?
    };
    info!("Loaded configuration from {}", config_path);

    let dest =
        destination.unwrap_or_else(|| "bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80".to_string());

    // ========================================
    // Plain Session Keygen
    // ========================================
    info!("");
    info!("========================================");
    info!("Creating plain keygen session...");
    info!("========================================");

    let mut test = KeyMeldE2ETest::new(config.clone(), amount, Some(dest.clone())).await?;
    test.load_participants().await?;
    test.fund_coordinator_from_master().await?;

    // Create SDK clients
    let plain_coordinator_credentials =
        UserCredentials::from_private_key(&test.coordinator_derived_private_key.secret_bytes())?;
    let plain_coordinator_client =
        KeyMeldClient::builder(&config.gateway_url, test.coordinator_user_id.clone())
            .credentials(plain_coordinator_credentials)
            .build()?;

    let mut plain_participant_clients = Vec::new();
    for participant in &test.participants {
        let credentials =
            UserCredentials::from_private_key(&participant.derived_private_key.secret_bytes())?;
        let client = KeyMeldClient::builder(&config.gateway_url, UserId::new_v7())
            .credentials(credentials)
            .build()?;
        plain_participant_clients.push(client);
    }

    // Create keygen session
    let all_participants: Vec<UserId> = std::iter::once(plain_coordinator_client.user_id().clone())
        .chain(
            plain_participant_clients
                .iter()
                .map(|c| c.user_id().clone()),
        )
        .collect();

    let mut plain_keygen_session = plain_coordinator_client
        .keygen()
        .create_session(
            all_participants,
            KeygenOptions::default()
                .timeout(3600)
                .max_signings(10)
                .require_approval(),
        )
        .await?;

    let plain_session_id = plain_keygen_session.session_id().clone();
    let plain_session_secret = plain_keygen_session.export_session_secret();
    info!("Created keygen session: {}", plain_session_id);

    plain_keygen_session
        .register_self(RegisterOptions::default().require_approval())
        .await?;
    info!("Coordinator registered");

    for (idx, client) in plain_participant_clients.iter().enumerate() {
        let requires_approval = idx == 0;
        client
            .keygen()
            .join_session(
                plain_session_id.clone(),
                &plain_session_secret,
                JoinOptions::default().approval(requires_approval),
            )
            .await?;
        info!("Participant {} joined", idx);
    }

    plain_keygen_session.wait_for_completion().await?;
    let plain_aggregate_key = plain_keygen_session.decrypt_aggregate_key()?;
    let plain_aggregate_key_hex = hex::encode(&plain_aggregate_key);
    info!("Plain keygen complete: {}", &plain_aggregate_key_hex[..32]);

    // Fund plain aggregate key
    let plain_utxo = test
        .fund_aggregate_key_address(&plain_aggregate_key_hex, &plain_session_id)
        .await?;
    info!("Plain UTXO: {}:{}", plain_utxo.txid, plain_utxo.vout);

    // ========================================
    // Adaptor Session Keygen
    // ========================================
    info!("");
    info!("========================================");
    info!("Creating adaptor keygen session...");
    info!("========================================");

    let mut adaptor_test = KeyMeldE2ETest::new(config.clone(), amount, Some(dest.clone())).await?;
    adaptor_test.load_participants().await?;

    let adaptor_coordinator_credentials = UserCredentials::from_private_key(
        &adaptor_test.coordinator_derived_private_key.secret_bytes(),
    )?;
    let adaptor_coordinator_client = KeyMeldClient::builder(
        &config.gateway_url,
        adaptor_test.coordinator_user_id.clone(),
    )
    .credentials(adaptor_coordinator_credentials)
    .build()?;

    let mut adaptor_participant_clients = Vec::new();
    for participant in &adaptor_test.participants {
        let credentials =
            UserCredentials::from_private_key(&participant.derived_private_key.secret_bytes())?;
        let client = KeyMeldClient::builder(&config.gateway_url, UserId::new_v7())
            .credentials(credentials)
            .build()?;
        adaptor_participant_clients.push(client);
    }

    let adaptor_all_participants: Vec<UserId> =
        std::iter::once(adaptor_coordinator_client.user_id().clone())
            .chain(
                adaptor_participant_clients
                    .iter()
                    .map(|c| c.user_id().clone()),
            )
            .collect();

    let mut adaptor_keygen_session = adaptor_coordinator_client
        .keygen()
        .create_session(
            adaptor_all_participants,
            KeygenOptions::default()
                .timeout(3600)
                .max_signings(10)
                .require_approval(),
        )
        .await?;

    let adaptor_session_id = adaptor_keygen_session.session_id().clone();
    let adaptor_session_secret = adaptor_keygen_session.export_session_secret();
    info!("Created keygen session: {}", adaptor_session_id);

    adaptor_keygen_session
        .register_self(RegisterOptions::default().require_approval())
        .await?;
    info!("Coordinator registered");

    for (idx, client) in adaptor_participant_clients.iter().enumerate() {
        let requires_approval = idx == 0;
        client
            .keygen()
            .join_session(
                adaptor_session_id.clone(),
                &adaptor_session_secret,
                JoinOptions::default().approval(requires_approval),
            )
            .await?;
        info!("Participant {} joined", idx);
    }

    adaptor_keygen_session.wait_for_completion().await?;
    let adaptor_aggregate_key = adaptor_keygen_session.decrypt_aggregate_key()?;
    let adaptor_aggregate_key_hex = hex::encode(&adaptor_aggregate_key);
    info!(
        "Adaptor keygen complete: {}",
        &adaptor_aggregate_key_hex[..32]
    );

    // Fund adaptor aggregate key
    let adaptor_utxo = adaptor_test
        .fund_aggregate_key_address(&adaptor_aggregate_key_hex, &adaptor_session_id)
        .await?;
    info!("Adaptor UTXO: {}:{}", adaptor_utxo.txid, adaptor_utxo.vout);

    // ========================================
    // Single-Signer Key
    // ========================================
    info!("");
    info!("========================================");
    info!("Creating single-signer key...");
    info!("========================================");

    let mut single_signer_test = SingleSignerE2ETest::new(config.clone()).await?;
    single_signer_test.reserve_key_slot().await?;
    single_signer_test.import_key().await?;

    let keys = single_signer_test.list_keys().await?;
    if keys.keys.is_empty() {
        return Err(anyhow!("Single-signer key import failed"));
    }

    info!(
        "Single-signer key created: {}",
        single_signer_test.key_id.as_ref().unwrap()
    );

    // Test signing before restart
    let test_message = b"Pre-restart test message";
    let pre_restart_sig = single_signer_test.sign_schnorr(test_message).await?;
    info!(
        "Pre-restart signing successful: {} bytes",
        pre_restart_sig.len()
    );

    // ========================================
    // Save Session Data
    // ========================================
    let saved_data = SavedSessionData {
        plain_keygen_session_id: plain_session_id.to_string(),
        plain_aggregate_key_hex,
        plain_session_secret_hex: hex::encode(plain_session_secret),
        plain_utxo_txid: plain_utxo.txid.to_string(),
        plain_utxo_vout: plain_utxo.vout,
        plain_coordinator_user_id: plain_coordinator_client.user_id().to_string(),
        plain_coordinator_private_key_hex: hex::encode(
            test.coordinator_derived_private_key.secret_bytes(),
        ),
        plain_participant_user_ids: plain_participant_clients
            .iter()
            .map(|c| c.user_id().to_string())
            .collect(),
        plain_participant_private_keys_hex: test
            .participants
            .iter()
            .map(|p| hex::encode(p.derived_private_key.secret_bytes()))
            .collect(),

        adaptor_keygen_session_id: adaptor_session_id.to_string(),
        adaptor_aggregate_key_hex,
        adaptor_session_secret_hex: hex::encode(adaptor_session_secret),
        adaptor_utxo_txid: adaptor_utxo.txid.to_string(),
        adaptor_utxo_vout: adaptor_utxo.vout,
        adaptor_coordinator_user_id: adaptor_coordinator_client.user_id().to_string(),
        adaptor_coordinator_private_key_hex: hex::encode(
            adaptor_test.coordinator_derived_private_key.secret_bytes(),
        ),
        adaptor_participant_user_ids: adaptor_participant_clients
            .iter()
            .map(|c| c.user_id().to_string())
            .collect(),
        adaptor_participant_private_keys_hex: adaptor_test
            .participants
            .iter()
            .map(|p| hex::encode(p.derived_private_key.secret_bytes()))
            .collect(),

        single_signer_user_id: single_signer_test.user_id.to_string(),
        single_signer_key_id: single_signer_test.key_id.as_ref().unwrap().to_string(),
        single_signer_enclave_id: single_signer_test.enclave_id.unwrap(),
        single_signer_enclave_public_key: single_signer_test.enclave_public_key.clone().unwrap(),
        single_signer_private_key_hex: hex::encode(single_signer_test.private_key.secret_bytes()),
        single_signer_public_key_hex: hex::encode(single_signer_test.public_key.serialize()),
        single_signer_auth_private_key_hex: hex::encode(single_signer_test.auth_private_key_bytes),
        single_signer_auth_public_key_hex: hex::encode(&single_signer_test.auth_public_key_bytes),

        destination: dest,
        amount,
    };

    let json_data = serde_json::to_string_pretty(&saved_data)?;
    fs::write(&output_path, &json_data)?;

    info!("");
    info!("========================================");
    info!("Keygen phase complete");
    info!("========================================");
    info!("Plain session:       {}", plain_session_id);
    info!("Adaptor session:     {}", adaptor_session_id);
    info!(
        "Single-signer key:   {}",
        single_signer_test.key_id.as_ref().unwrap()
    );
    info!("Session data saved to: {}", output_path);
    info!("");
    info!("Now restart enclaves and run 'sign' command.");

    Ok(())
}

async fn run_sign(config_path: String, input_path: String) -> Result<()> {
    info!("==========================================");
    info!("KeyMeld Session Restoration Test - Sign");
    info!("==========================================");

    let config: ExampleConfig = {
        let content = fs::read_to_string(&config_path)?;
        serde_yaml::from_str(&content)?
    };
    info!("Loaded configuration from {}", config_path);

    let saved_data: SavedSessionData = {
        let content = fs::read_to_string(&input_path)?;
        serde_json::from_str(&content)?
    };
    info!("Loaded session data from {}", input_path);

    // Test plain session restoration
    info!("");
    info!("========================================");
    info!("Testing plain session restoration...");
    info!("========================================");

    let plain_result = test_signing_with_sdk(
        &config,
        &saved_data.plain_keygen_session_id,
        &saved_data.plain_aggregate_key_hex,
        &saved_data.plain_session_secret_hex,
        &saved_data.plain_utxo_txid,
        saved_data.plain_utxo_vout,
        &saved_data.destination,
        saved_data.amount,
        &saved_data.plain_coordinator_user_id,
        &saved_data.plain_coordinator_private_key_hex,
        &saved_data.plain_participant_user_ids,
        &saved_data.plain_participant_private_keys_hex,
        "PLAIN",
    )
    .await;

    match &plain_result {
        Ok(txid) => info!("Plain session restoration: success (txid: {})", txid),
        Err(e) => error!("Plain session restoration: failed - {}", e),
    }

    // Test adaptor session restoration
    info!("");
    info!("========================================");
    info!("Testing adaptor session restoration...");
    info!("========================================");

    let adaptor_result = test_signing_with_sdk(
        &config,
        &saved_data.adaptor_keygen_session_id,
        &saved_data.adaptor_aggregate_key_hex,
        &saved_data.adaptor_session_secret_hex,
        &saved_data.adaptor_utxo_txid,
        saved_data.adaptor_utxo_vout,
        &saved_data.destination,
        saved_data.amount,
        &saved_data.adaptor_coordinator_user_id,
        &saved_data.adaptor_coordinator_private_key_hex,
        &saved_data.adaptor_participant_user_ids,
        &saved_data.adaptor_participant_private_keys_hex,
        "ADAPTOR",
    )
    .await;

    match &adaptor_result {
        Ok(txid) => info!("Adaptor session restoration: success (txid: {})", txid),
        Err(e) => error!("Adaptor session restoration: failed - {}", e),
    }

    // Test single-signer restoration
    info!("");
    info!("========================================");
    info!("Testing single-signer key restoration...");
    info!("========================================");

    let single_signer_result = test_single_signer_restoration(&config, &saved_data).await;

    match &single_signer_result {
        Ok(()) => info!("Single-signer restoration: success"),
        Err(e) => error!("Single-signer restoration: failed - {}", e),
    }

    // Summary
    info!("");
    info!("========================================");
    info!("Session Restoration Test Results");
    info!("========================================");

    let plain_ok = plain_result.is_ok();
    let adaptor_ok = adaptor_result.is_ok();
    let single_signer_ok = single_signer_result.is_ok();

    info!(
        "Plain session:     {}",
        if plain_ok { "passed" } else { "failed" }
    );
    info!(
        "Adaptor session:   {}",
        if adaptor_ok { "passed" } else { "failed" }
    );
    info!(
        "Single-signer key: {}",
        if single_signer_ok { "passed" } else { "failed" }
    );

    if plain_ok && adaptor_ok && single_signer_ok {
        info!("");
        info!("All session restoration tests passed!");
        Ok(())
    } else {
        Err(anyhow!("Some session restoration tests failed"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn test_signing_with_sdk(
    config: &ExampleConfig,
    keygen_session_id_str: &str,
    aggregate_key_hex: &str,
    session_secret_hex: &str,
    utxo_txid: &str,
    utxo_vout: u32,
    destination: &str,
    amount: u64,
    coordinator_user_id_str: &str,
    coordinator_private_key_hex: &str,
    participant_user_ids: &[String],
    participant_private_keys_hex: &[String],
    session_type: &str,
) -> Result<String> {
    let keygen_session_id = SessionId::parse(keygen_session_id_str)
        .map_err(|e| anyhow!("Invalid session ID: {}", e))?;

    let session_secret: [u8; 32] = hex::decode(session_secret_hex)
        .map_err(|e| anyhow!("Invalid session secret hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow!("Session secret must be 32 bytes"))?;

    let coordinator_user_id = UserId::parse(coordinator_user_id_str)
        .map_err(|e| anyhow!("Invalid coordinator user ID: {}", e))?;

    let coordinator_private_key_bytes = hex::decode(coordinator_private_key_hex)
        .map_err(|e| anyhow!("Invalid coordinator key hex: {}", e))?;

    // Create SDK clients with restored credentials AND original user IDs
    let coordinator_credentials =
        UserCredentials::from_private_key(&coordinator_private_key_bytes)?;
    let coordinator_client = KeyMeldClient::builder(&config.gateway_url, coordinator_user_id)
        .credentials(coordinator_credentials)
        .build()?;

    let mut participant_clients = Vec::new();
    for (idx, key_hex) in participant_private_keys_hex.iter().enumerate() {
        let user_id = UserId::parse(&participant_user_ids[idx])
            .map_err(|e| anyhow!("Invalid participant user ID: {}", e))?;
        let key_bytes =
            hex::decode(key_hex).map_err(|e| anyhow!("Invalid participant key hex: {}", e))?;
        let credentials = UserCredentials::from_private_key(&key_bytes)?;
        let client = KeyMeldClient::builder(&config.gateway_url, user_id)
            .credentials(credentials)
            .build()?;
        participant_clients.push(client);
    }

    // Restore keygen session using SDK
    info!("{}: Restoring keygen session...", session_type);
    let keygen_session = coordinator_client
        .keygen()
        .restore_session(
            keygen_session_id.clone(),
            SessionCredentials::from_session_secret(&session_secret)?,
        )
        .await?;
    info!("{}: Keygen session restored", session_type);

    // Create test harness for PSBT creation and broadcast
    let mut test =
        KeyMeldE2ETest::new(config.clone(), amount, Some(destination.to_string())).await?;
    test.load_participants().await?;

    // Recreate the UTXO
    let txid = Txid::from_str(utxo_txid).map_err(|e| anyhow!("Invalid txid: {}", e))?;
    let utxo = OutPoint::new(txid, utxo_vout);

    // Create PSBT
    info!("{}: Creating PSBT...", session_type);
    let psbt = test
        .create_musig2_transaction(aggregate_key_hex, &keygen_session_id, &utxo)
        .await?;
    let message_hash = test.calculate_taproot_sighash(&psbt)?;

    // Create signing session using SDK
    info!("{}: Creating signing session...", session_type);
    let mut signing_session = coordinator_client
        .signer()
        .sign(
            &keygen_session,
            message_hash,
            SigningOptions::default().timeout(1800),
        )
        .await?;

    let signing_session_id = signing_session.session_id().clone();
    info!(
        "{}: Signing session created: {}",
        session_type, signing_session_id
    );

    // Coordinator approves
    signing_session.approve().await?;
    info!("{}: Coordinator approved", session_type);

    // First participant approves (requires approval)
    if !participant_clients.is_empty() {
        let client = &participant_clients[0];

        let participant_keygen = client
            .keygen()
            .restore_session(
                keygen_session_id.clone(),
                SessionCredentials::from_session_secret(&session_secret)?,
            )
            .await?;

        let mut participant_signing = client
            .signer()
            .restore_session(signing_session_id.clone(), &participant_keygen)
            .await?;

        participant_signing.approve().await?;
        info!("{}: Participant 0 approved", session_type);
    }

    // Wait for signing completion
    info!("{}: Waiting for signing completion...", session_type);
    let results = signing_session.wait_for_completion().await?;

    let signature = results
        .first()
        .and_then(|r| r.signature.as_ref())
        .ok_or_else(|| anyhow!("No signature in result"))?;

    info!("{}: Signing complete!", session_type);

    // Broadcast transaction
    let signed_tx = test.apply_signature_and_broadcast(psbt, signature).await?;
    let final_txid = signed_tx.compute_txid();

    info!(
        "{}: Transaction broadcast successfully: {}",
        session_type, final_txid
    );

    Ok(final_txid.to_string())
}

async fn test_single_signer_restoration(
    config: &ExampleConfig,
    saved_data: &SavedSessionData,
) -> Result<()> {
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use keymeld_sdk::KeyId;

    let user_id = UserId::parse(&saved_data.single_signer_user_id)
        .map_err(|e| anyhow!("Invalid user ID: {}", e))?;
    let key_id = KeyId::parse(&saved_data.single_signer_key_id)
        .map_err(|e| anyhow!("Invalid key ID: {}", e))?;

    let private_key_bytes = hex::decode(&saved_data.single_signer_private_key_hex)?;
    let private_key = SecretKey::from_slice(&private_key_bytes)?;

    let public_key_bytes = hex::decode(&saved_data.single_signer_public_key_hex)?;
    let public_key = PublicKey::from_slice(&public_key_bytes)?;

    let auth_private_key_bytes: [u8; 32] =
        hex::decode(&saved_data.single_signer_auth_private_key_hex)?
            .try_into()
            .map_err(|_| anyhow!("Auth key not 32 bytes"))?;

    let auth_public_key_bytes = hex::decode(&saved_data.single_signer_auth_public_key_hex)?;

    info!("Restoring single-signer context...");
    info!("  User ID: {}", user_id);
    info!("  Key ID: {}", key_id);

    let restored_test = SingleSignerE2ETest {
        config: config.clone(),
        client: reqwest::Client::new(),
        user_id,
        private_key,
        public_key,
        auth_private_key_bytes,
        auth_public_key_bytes,
        key_id: Some(key_id),
        enclave_id: Some(saved_data.single_signer_enclave_id),
        enclave_public_key: Some(saved_data.single_signer_enclave_public_key.clone()),
        rpc_client: None,
        rpc_client_with_wallet: None,
        network: config.network,
        destination: saved_data.destination.clone(),
        amount: saved_data.amount,
    };

    // Verify key exists
    info!("Step 1: Verifying key exists after restart...");
    let keys = restored_test.list_keys().await?;
    let key_exists = keys
        .keys
        .iter()
        .any(|k| k.key_id.to_string() == saved_data.single_signer_key_id);

    if !key_exists {
        return Err(anyhow!("Key not found after restart"));
    }
    info!("  Key found in database");

    // Test Schnorr signing
    info!("Step 2: Testing Schnorr signing...");
    let schnorr_sig = restored_test
        .sign_schnorr(b"Post-restart Schnorr test")
        .await?;
    if schnorr_sig.len() != 64 {
        return Err(anyhow!("Invalid Schnorr signature length"));
    }
    info!("  Schnorr signature: {} bytes", schnorr_sig.len());

    // Test ECDSA signing
    info!("Step 3: Testing ECDSA signing...");
    let ecdsa_sig = restored_test.sign_ecdsa(b"Post-restart ECDSA test").await?;
    if ecdsa_sig.len() != 64 {
        return Err(anyhow!("Invalid ECDSA signature length"));
    }
    info!("  ECDSA signature: {} bytes", ecdsa_sig.len());

    info!("Single-signer key restoration verified!");
    info!("  - Key exists in database after restart");
    info!("  - Schnorr (BIP-340) signing works");
    info!("  - ECDSA signing works");

    Ok(())
}
