use anyhow::{anyhow, Result};
use bdk_wallet::bitcoin::{OutPoint, Txid};
use clap::{Parser, Subcommand};
use keymeld_examples::single_signer::SingleSignerE2ETest;
use keymeld_examples::{ExampleConfig, KeyMeldE2ETest};
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
        /// Configuration file path
        #[arg(long)]
        config: String,
        /// Output file to save session data for later signing
        #[arg(long)]
        output: String,
        /// Amount in satoshis for funding
        #[arg(long, default_value = "25000")]
        amount: u64,
        /// Destination Bitcoin address for signing test
        #[arg(long)]
        destination: Option<String>,
    },
    /// Sign using previously created keygen sessions (tests session restoration)
    Sign {
        /// Configuration file path
        #[arg(long)]
        config: String,
        /// Input file with session data from keygen step
        #[arg(long)]
        input: String,
    },
}

/// Saved session data for restoration testing
/// Includes all data needed to perform signing after restart
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSessionData {
    // Plain session data
    pub plain_keygen_session_id: String,
    pub plain_aggregate_key: String,
    pub plain_session_secret: String,
    pub plain_utxo_txid: String,
    pub plain_utxo_vout: u32,

    // Adaptor session data
    pub adaptor_keygen_session_id: String,
    pub adaptor_aggregate_key: String,
    pub adaptor_session_secret: String,
    pub adaptor_utxo_txid: String,
    pub adaptor_utxo_vout: u32,

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

    // Coordinator key file path (to reload the same keys)
    pub key_files_dir: String,

    // User IDs for plain session restoration (needed to approve signing)
    pub plain_coordinator_user_id: String,
    pub plain_participant_user_ids: Vec<String>,

    // User IDs for adaptor session restoration (needed to approve signing)
    pub adaptor_coordinator_user_id: String,
    pub adaptor_participant_user_ids: Vec<String>,
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

    let config_content = fs::read_to_string(&config_path)?;
    let config: ExampleConfig = serde_yaml::from_str(&config_content)?;
    info!("Loaded configuration from {}", config_path);

    let dest =
        destination.unwrap_or_else(|| "bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80".to_string());

    // Create test instance for plain session
    let mut test = KeyMeldE2ETest::new(config.clone(), amount, Some(dest.clone())).await?;
    test.load_participants().await?;
    test.fund_coordinator_from_master().await?;

    // Create plain keygen session and fund it
    info!("");
    info!("========================================");
    info!("Creating plain keygen session...");
    info!("========================================");

    let plain_keygen_session_id = test.create_keygen_session().await?;
    test.register_keygen_participants(&plain_keygen_session_id)
        .await?;
    let plain_aggregate_key = test
        .wait_for_keygen_completion(&plain_keygen_session_id)
        .await?;

    let plain_session_secret = test
        .session_secrets
        .get(&plain_keygen_session_id)
        .ok_or_else(|| anyhow!("Plain session secret not found"))?
        .clone();

    info!("Plain keygen session created: {}", plain_keygen_session_id);
    info!("Plain aggregate key: {}...", &plain_aggregate_key[..32]);

    // Fund the plain aggregate key address
    info!("Funding plain aggregate key address...");
    let plain_utxo = test
        .fund_aggregate_key_address(&plain_aggregate_key, &plain_keygen_session_id)
        .await?;
    info!("Plain UTXO: {}:{}", plain_utxo.txid, plain_utxo.vout);

    // Create adaptor keygen session and fund it
    info!("");
    info!("========================================");
    info!("Creating adaptor keygen session...");
    info!("========================================");

    // Create a new test instance for adaptor session (fresh user IDs)
    let mut adaptor_test = KeyMeldE2ETest::new(config.clone(), amount, Some(dest.clone())).await?;
    adaptor_test.load_participants().await?;

    let adaptor_keygen_session_id = adaptor_test.create_keygen_session().await?;
    adaptor_test
        .register_keygen_participants(&adaptor_keygen_session_id)
        .await?;
    let adaptor_aggregate_key = adaptor_test
        .wait_for_keygen_completion(&adaptor_keygen_session_id)
        .await?;

    let adaptor_session_secret = adaptor_test
        .session_secrets
        .get(&adaptor_keygen_session_id)
        .ok_or_else(|| anyhow!("Adaptor session secret not found"))?
        .clone();

    info!(
        "Adaptor keygen session created: {}",
        adaptor_keygen_session_id
    );
    info!("Adaptor aggregate key: {}...", &adaptor_aggregate_key[..32]);

    // Fund the adaptor aggregate key address
    info!("Funding adaptor aggregate key address...");
    let adaptor_utxo = adaptor_test
        .fund_aggregate_key_address(&adaptor_aggregate_key, &adaptor_keygen_session_id)
        .await?;
    info!("Adaptor UTXO: {}:{}", adaptor_utxo.txid, adaptor_utxo.vout);

    // Create single-signer key
    info!("");
    info!("========================================");
    info!("Creating single-signer key...");
    info!("========================================");

    let mut single_signer_test = SingleSignerE2ETest::new(config.clone()).await?;

    // Reserve key slot
    single_signer_test.reserve_key_slot().await?;

    // Import key
    single_signer_test.import_key().await?;

    // List keys to verify
    let keys = single_signer_test.list_keys().await?;
    if keys.keys.is_empty() {
        return Err(anyhow!("Single-signer key import failed - no keys found"));
    }

    info!(
        "Single-signer key created: {}",
        single_signer_test.key_id.as_ref().unwrap()
    );
    info!("Single-signer user ID: {}", single_signer_test.user_id);

    // Test signing to verify the key works before restart
    info!("Testing single-signer signing before restart...");
    let test_message = b"Pre-restart test message";
    let pre_restart_sig = single_signer_test.sign_schnorr(test_message).await?;
    info!(
        "Pre-restart signing successful: {} bytes",
        pre_restart_sig.len()
    );

    // Save session data
    let saved_data = SavedSessionData {
        plain_keygen_session_id: plain_keygen_session_id.to_string(),
        plain_aggregate_key,
        plain_session_secret,
        plain_utxo_txid: plain_utxo.txid.to_string(),
        plain_utxo_vout: plain_utxo.vout,

        adaptor_keygen_session_id: adaptor_keygen_session_id.to_string(),
        adaptor_aggregate_key,
        adaptor_session_secret,
        adaptor_utxo_txid: adaptor_utxo.txid.to_string(),
        adaptor_utxo_vout: adaptor_utxo.vout,

        // Single-signer data
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
        key_files_dir: config.key_files_dir.clone(),

        plain_coordinator_user_id: test.coordinator_user_id.to_string(),
        plain_participant_user_ids: test
            .participant_user_ids
            .iter()
            .map(|id| id.to_string())
            .collect(),

        adaptor_coordinator_user_id: adaptor_test.coordinator_user_id.to_string(),
        adaptor_participant_user_ids: adaptor_test
            .participant_user_ids
            .iter()
            .map(|id| id.to_string())
            .collect(),
    };

    let json_data = serde_json::to_string_pretty(&saved_data)?;
    fs::write(&output_path, &json_data)?;

    info!("");
    info!("========================================");
    info!("Keygen phase complete");
    info!("========================================");
    info!("Plain session:       {}", plain_keygen_session_id);
    info!("Adaptor session:     {}", adaptor_keygen_session_id);
    info!(
        "Single-signer key:   {}",
        single_signer_test.key_id.as_ref().unwrap()
    );
    info!("All sessions created and ready for signing");
    info!("Session data saved to: {}", output_path);
    info!("");
    info!("Now restart enclaves and run the 'sign' command to test restoration.");

    Ok(())
}

async fn run_sign(config_path: String, input_path: String) -> Result<()> {
    info!("==========================================");
    info!("KeyMeld Session Restoration Test - Sign");
    info!("==========================================");

    let config_content = fs::read_to_string(&config_path)?;
    let config: ExampleConfig = serde_yaml::from_str(&config_content)?;
    info!("Loaded configuration from {}", config_path);

    let saved_data_content = fs::read_to_string(&input_path)?;
    let saved_data: SavedSessionData = serde_json::from_str(&saved_data_content)?;
    info!("Loaded session data from {}", input_path);

    info!(
        "Plain keygen session:   {}",
        saved_data.plain_keygen_session_id
    );
    info!(
        "Adaptor keygen session: {}",
        saved_data.adaptor_keygen_session_id
    );
    info!(
        "Single-signer key:      {}",
        saved_data.single_signer_key_id
    );

    // Test plain session - create and complete signing session
    info!("");
    info!("========================================");
    info!("Testing plain session restoration...");
    info!("Creating new signing session with restored keygen...");
    info!("========================================");

    let plain_result = test_signing_with_restored_session(
        &config,
        &saved_data.plain_keygen_session_id,
        &saved_data.plain_aggregate_key,
        &saved_data.plain_session_secret,
        &saved_data.plain_utxo_txid,
        saved_data.plain_utxo_vout,
        &saved_data.destination,
        saved_data.amount,
        &saved_data.key_files_dir,
        "plain",
        &saved_data.plain_coordinator_user_id,
        &saved_data.plain_participant_user_ids,
    )
    .await;

    match &plain_result {
        Ok(txid) => info!("Plain session restoration: success (txid: {})", txid),
        Err(e) => error!("Plain session restoration: failed - {}", e),
    }

    // Test adaptor session - create and complete signing session
    info!("");
    info!("========================================");
    info!("Testing adaptor session restoration...");
    info!("Creating new signing session with restored keygen...");
    info!("========================================");

    let adaptor_result = test_signing_with_restored_session(
        &config,
        &saved_data.adaptor_keygen_session_id,
        &saved_data.adaptor_aggregate_key,
        &saved_data.adaptor_session_secret,
        &saved_data.adaptor_utxo_txid,
        saved_data.adaptor_utxo_vout,
        &saved_data.destination,
        saved_data.amount,
        &saved_data.key_files_dir,
        "adaptor",
        &saved_data.adaptor_coordinator_user_id,
        &saved_data.adaptor_participant_user_ids,
    )
    .await;

    match &adaptor_result {
        Ok(txid) => info!("adaptor session restoration: success (txid: {})", txid),
        Err(e) => error!("adaptor session restoration: failed - {}", e),
    }

    // Test single-signer key restoration
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
        info!("Created and completed new signing sessions using restored keygen sessions.");
        info!("Single-signer key restored and signing verified.");
        Ok(())
    } else {
        Err(anyhow!("Some session restoration tests failed"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn test_signing_with_restored_session(
    config: &ExampleConfig,
    keygen_session_id_str: &str,
    aggregate_key: &str,
    session_secret: &str,
    utxo_txid: &str,
    utxo_vout: u32,
    destination: &str,
    amount: u64,
    key_files_dir: &str,
    session_type: &str,
    saved_coordinator_user_id: &str,
    saved_participant_user_ids: &[String],
) -> Result<String> {
    use keymeld_sdk::SessionId;

    let keygen_session_id = SessionId::parse(keygen_session_id_str)
        .map_err(|e| anyhow!("Invalid session ID: {}", e))?;

    // Create a new test instance that will reload the same coordinator/participant keys
    let mut config_with_keys = config.clone();
    config_with_keys.key_files_dir = key_files_dir.to_string();

    let mut test =
        KeyMeldE2ETest::new(config_with_keys, amount, Some(destination.to_string())).await?;
    test.load_participants().await?;

    // Override the test's user IDs with the saved ones from the original keygen session
    // This is critical because the gateway associates sessions with specific user IDs
    let saved_coordinator_user_id_parsed = keymeld_sdk::UserId::parse(saved_coordinator_user_id)
        .map_err(|e| anyhow!("Invalid saved coordinator user ID: {}", e))?;
    test.coordinator_user_id = saved_coordinator_user_id_parsed;

    // Override participant user IDs as well
    test.participant_user_ids = saved_participant_user_ids
        .iter()
        .map(|id| {
            keymeld_sdk::UserId::parse(id)
                .map_err(|e| anyhow!("Invalid saved participant user ID: {}", e))
        })
        .collect::<Result<Vec<_>>>()?;

    // Inject the saved session secret so signing can work
    test.session_secrets
        .insert(keygen_session_id.clone(), session_secret.to_string());

    // Also derive and inject the session private key from the session secret (seed)
    let seed = hex::decode(session_secret)
        .map_err(|e| anyhow!("Failed to decode session secret as hex: {}", e))?;
    let session_private_key = keymeld_sdk::SecureCrypto::derive_private_key_from_seed(&seed)
        .map_err(|e| anyhow!("Failed to derive private key from seed: {}", e))?;
    test.session_private_keys
        .insert(keygen_session_id.clone(), session_private_key);

    // Recreate the UTXO
    let txid = Txid::from_str(utxo_txid).map_err(|e| anyhow!("Invalid txid: {}", e))?;
    let utxo = OutPoint::new(txid, utxo_vout);

    info!(
        "{}: Creating PSBT for signing with restored keygen session...",
        session_type
    );

    // Create the transaction PSBT
    let psbt = test
        .create_musig2_transaction(aggregate_key, &keygen_session_id, &utxo)
        .await?;

    info!("{}: Creating signing session...", session_type);

    // Create the signing session - this is the key test!
    // If session restoration failed, this will fail because the enclave
    // won't have the keygen session in memory.
    let signing_session_id = test
        .create_signing_session(&keygen_session_id, &psbt)
        .await?;

    info!(
        "{}: Signing session created: {}",
        session_type, signing_session_id
    );

    // Approve the signing session (coordinator always requires approval)
    // We use the SAVED user IDs from the original keygen session, not the newly generated ones
    info!("{}: Approving signing session...", session_type);
    let saved_coordinator_user_id_parsed = keymeld_sdk::UserId::parse(saved_coordinator_user_id)
        .map_err(|e| anyhow!("Invalid saved coordinator user ID: {}", e))?;
    test.approve_signing_session(
        &signing_session_id,
        &saved_coordinator_user_id_parsed,
        &test.coordinator_derived_private_key,
        &keygen_session_id,
    )
    .await?;

    // Approve for participants that require approval
    // Map the saved participant user IDs to UserId type
    for idx in test.participants_requiring_approval.clone() {
        let saved_user_id = &saved_participant_user_ids[idx];
        let user_id = keymeld_sdk::UserId::parse(saved_user_id)
            .map_err(|e| anyhow!("Invalid saved participant user ID: {}", e))?;
        let private_key = test.participants[idx].derived_private_key;
        test.approve_signing_session(
            &signing_session_id,
            &user_id,
            &private_key,
            &keygen_session_id,
        )
        .await?;
    }

    info!("{}: Waiting for signing completion...", session_type);

    // Wait for signing to complete
    let signature = test
        .wait_for_signing_completion(&signing_session_id, &keygen_session_id)
        .await?;

    info!("{}: Signing completed! Applying signature...", session_type);

    // Apply signature and broadcast
    let signed_tx = test.apply_signature_and_broadcast(psbt, &signature).await?;
    let final_txid = signed_tx.compute_txid();

    info!(
        "{}: Transaction broadcast successfully: {}",
        session_type, final_txid
    );

    Ok(final_txid.to_string())
}

/// Test single-signer key restoration after enclave restart
async fn test_single_signer_restoration(
    config: &ExampleConfig,
    saved_data: &SavedSessionData,
) -> Result<()> {
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use keymeld_sdk::{KeyId, UserId};

    // Parse saved data
    let user_id = UserId::parse(&saved_data.single_signer_user_id)
        .map_err(|e| anyhow!("Invalid single-signer user ID: {}", e))?;
    let key_id = KeyId::parse(&saved_data.single_signer_key_id)
        .map_err(|e| anyhow!("Invalid single-signer key ID: {}", e))?;

    let private_key_bytes = hex::decode(&saved_data.single_signer_private_key_hex)
        .map_err(|e| anyhow!("Failed to decode private key hex: {}", e))?;
    let private_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

    let public_key_bytes = hex::decode(&saved_data.single_signer_public_key_hex)
        .map_err(|e| anyhow!("Failed to decode public key hex: {}", e))?;
    let public_key = PublicKey::from_slice(&public_key_bytes)
        .map_err(|e| anyhow!("Failed to parse public key: {}", e))?;

    let auth_private_key_bytes: [u8; 32] =
        hex::decode(&saved_data.single_signer_auth_private_key_hex)
            .map_err(|e| anyhow!("Failed to decode auth private key hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow!("Auth private key is not 32 bytes"))?;

    let auth_public_key_bytes = hex::decode(&saved_data.single_signer_auth_public_key_hex)
        .map_err(|e| anyhow!("Failed to decode auth public key hex: {}", e))?;

    info!("Restoring single-signer context...");
    info!("  User ID: {}", user_id);
    info!("  Key ID: {}", key_id);
    info!("  Enclave ID: {}", saved_data.single_signer_enclave_id);

    // Create a restored single-signer test instance
    // We need to manually reconstruct it with the saved data
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
        rpc_client: None,             // Not needed for signing test
        rpc_client_with_wallet: None, // Not needed for signing test
        network: config.network,
        destination: saved_data.destination.clone(),
        amount: saved_data.amount,
    };

    // Test 1: List keys - verify the key still exists in the database
    info!("Step 1: Verifying key exists after restart...");
    let keys = restored_test.list_keys().await?;
    let key_exists = keys
        .keys
        .iter()
        .any(|k| k.key_id.to_string() == saved_data.single_signer_key_id);

    if !key_exists {
        return Err(anyhow!(
            "Single-signer key {} not found after restart",
            saved_data.single_signer_key_id
        ));
    }
    info!("  Key found in database");

    // Test 2: Sign with Schnorr (BIP-340) - this tests that the enclave restored the key
    info!("Step 2: Testing Schnorr signing after restart...");
    let schnorr_message = b"Post-restart Schnorr test message";
    let schnorr_sig = restored_test.sign_schnorr(schnorr_message).await?;

    if schnorr_sig.len() != 64 {
        return Err(anyhow!(
            "Invalid Schnorr signature length: expected 64, got {}",
            schnorr_sig.len()
        ));
    }
    info!("  Schnorr signature: {} bytes", schnorr_sig.len());

    // Test 3: Sign with ECDSA - test the other signature type
    info!("Step 3: Testing ECDSA signing after restart...");
    let ecdsa_message = b"Post-restart ECDSA test message";
    let ecdsa_sig = restored_test.sign_ecdsa(ecdsa_message).await?;

    if ecdsa_sig.len() != 64 {
        return Err(anyhow!(
            "Invalid ECDSA signature length: expected 64, got {}",
            ecdsa_sig.len()
        ));
    }
    info!("  ECDSA signature: {} bytes", ecdsa_sig.len());

    info!("Single-signer key restoration verified successfully!");
    info!("  - Key exists in database after restart");
    info!("  - Schnorr (BIP-340) signing works");
    info!("  - ECDSA signing works");

    Ok(())
}
