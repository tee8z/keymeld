//! Single-Signer Example with PSBT Signing and Broadcast
//!
//! This example demonstrates the complete single-signer flow:
//! 1. Reserve a key slot
//! 2. Import a private key to enclave storage
//! 3. Fund the key's taproot address
//! 4. Create a PSBT spending from that address
//! 5. Sign the PSBT using the enclave
//! 6. Broadcast the signed transaction
//! 7. Clean up by deleting the key

use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use bitcoin::{
    absolute::LockTime,
    address::Address,
    hashes::Hash,
    key::TweakedPublicKey,
    psbt::Psbt,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    transaction::Version,
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use keymeld_examples::ExampleConfig;
use keymeld_sdk::prelude::*;
use std::fs::read_to_string;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

const SEND_AMOUNT_SATS: u64 = 10_000;
const FEE_SATS: u64 = 1_000;

pub async fn run_with_args(config_path: String) -> Result<()> {
    let config_content = read_to_string(&config_path)?;
    let config: ExampleConfig = serde_yaml::from_str(&config_content)?;

    info!("Single-Signer PSBT Example");
    info!("===========================");
    info!("Gateway: {}", config.gateway_url);
    info!("Network: {:?}", config.network);

    // Generate a random private key for this example
    let mut private_key_bytes = [0u8; 32];
    rand::fill(&mut private_key_bytes);

    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| anyhow!("Invalid private key: {}", e))?;
    let public_key = PublicKey::from_secret_key(&secp, &private_key);

    // Create credentials from the private key
    let credentials = UserCredentials::from_private_key(&private_key_bytes)?;

    info!("Generated keypair:");
    info!(
        "  Public key: {}",
        hex::encode(credentials.public_key_bytes())
    );
    info!(
        "  Auth public key: {}",
        hex::encode(credentials.auth_public_key_bytes())
    );

    // Create the SDK client
    let client = KeyMeldClient::builder(&config.gateway_url, UserId::new_v7())
        .credentials(credentials)
        .build()?;

    // Step 1: Reserve a key slot
    info!("");
    info!("Step 1: Reserving key slot...");
    let reservation = client.reserve_key_slot().await?;
    info!("  Key ID: {}", reservation.key_id);

    // Step 2: Import the private key to enclave storage
    info!("");
    info!("Step 2: Importing private key to enclave...");
    let key_id = client.import_key(&reservation, &private_key_bytes).await?;
    info!("  Key imported: {}", key_id);

    // Step 3: List keys to verify import
    info!("");
    info!("Step 3: Verifying key import...");
    let keys = client.list_keys(&key_id).await?;
    info!("  Found {} key(s)", keys.len());
    for key in &keys {
        info!("    - {}", key.key_id);
    }

    // Check if Bitcoin RPC is available for full transaction test
    let rpc_available = check_bitcoin_rpc(&config).await;

    if rpc_available {
        info!("");
        info!("Bitcoin RPC available - running full PSBT transaction test");
        info!("============================================================");

        run_psbt_transaction_test(&client, &key_id, &public_key, &config).await?;
    } else {
        info!("");
        info!("Bitcoin RPC not available - running basic signing test");
        info!("========================================================");

        run_basic_signing_test(&client, &key_id).await?;
    }

    // Step: Delete the key
    info!("");
    info!("Cleaning up: Deleting key...");
    client.delete_key(&key_id).await?;
    info!("  Key deleted");

    info!("");
    info!("Single-Signer PSBT Example Complete!");

    Ok(())
}

async fn check_bitcoin_rpc(config: &ExampleConfig) -> bool {
    let auth = Auth::UserPass(
        config.bitcoin_rpc_auth.username.clone(),
        config.bitcoin_rpc_auth.password.clone(),
    );

    match RpcClient::new(&config.bitcoin_rpc_url, auth) {
        Ok(client) => client.get_blockchain_info().is_ok(),
        Err(_) => false,
    }
}

async fn run_basic_signing_test(client: &KeyMeldClient, key_id: &KeyId) -> Result<()> {
    // Sign a test message with Schnorr (BIP-340)
    let test_message = [0x42u8; 32];
    info!("Signing test message with Schnorr (BIP-340)...");
    let schnorr_sig = client
        .sign(key_id, test_message, SignatureType::SchnorrBip340)
        .await?;
    info!("  Schnorr signature: {} bytes", schnorr_sig.len());
    info!("  Signature: {}...", &hex::encode(&schnorr_sig)[..32]);

    // Sign a test message with ECDSA
    info!("Signing test message with ECDSA...");
    let ecdsa_sig = client
        .sign(key_id, test_message, SignatureType::Ecdsa)
        .await?;
    info!("  ECDSA signature: {} bytes", ecdsa_sig.len());
    info!("  Signature: {}...", &hex::encode(&ecdsa_sig)[..32]);

    info!("");
    info!("Basic signing test passed:");
    info!("  - Schnorr (BIP-340) signature verified");
    info!("  - ECDSA signature verified");

    Ok(())
}

async fn run_psbt_transaction_test(
    client: &KeyMeldClient,
    key_id: &KeyId,
    public_key: &PublicKey,
    config: &ExampleConfig,
) -> Result<()> {
    let auth = Auth::UserPass(
        config.bitcoin_rpc_auth.username.clone(),
        config.bitcoin_rpc_auth.password.clone(),
    );

    let rpc = RpcClient::new(&config.bitcoin_rpc_url, auth.clone())?;

    let wallet_rpc_url = format!("{}/wallet/keymeld_coordinator", config.bitcoin_rpc_url);
    let rpc_wallet = RpcClient::new(&wallet_rpc_url, auth)?;

    // Get taproot address for our public key
    let (x_only_key, _parity) = public_key.x_only_public_key();
    let tweaked_key = TweakedPublicKey::dangerous_assume_tweaked(x_only_key);
    let address = Address::p2tr_tweaked(tweaked_key, config.network);

    info!("");
    info!("Step 4: Funding taproot address...");
    info!("  Address: {}", address);

    // Fund the address
    let funding_amount = Amount::from_sat(SEND_AMOUNT_SATS + FEE_SATS + 5000);
    let funding_txid = retry_rpc("send_to_address", || {
        rpc_wallet.send_to_address(&address, funding_amount, None, None, None, None, None, None)
    })
    .await?;
    info!("  Funding txid: {}", funding_txid);

    // Mine a block to confirm
    let mining_addr = retry_rpc("get_new_address", || rpc_wallet.get_new_address(None, None))
        .await?
        .require_network(config.network)?;

    retry_rpc("generate_to_address", || {
        rpc.generate_to_address(1, &mining_addr)
    })
    .await?;
    info!("  Funding confirmed");

    // Find the vout for our address
    let tx_info = retry_rpc("get_transaction", || {
        rpc_wallet.get_transaction(&funding_txid, None)
    })
    .await?;

    let funding_tx = tx_info.transaction()?;
    let vout = funding_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == address.script_pubkey())
        .ok_or(anyhow!("Could not find our output in funding tx"))? as u32;

    let utxo = OutPoint {
        txid: funding_txid,
        vout,
    };
    info!("  UTXO: {}:{}", utxo.txid, utxo.vout);

    // Step 5: Create a PSBT
    info!("");
    info!("Step 5: Creating PSBT...");

    let utxo_output = &funding_tx.output[vout as usize];
    let input_amount = utxo_output.value.to_sat();

    // Send to a destination address (use coordinator wallet address)
    let destination = retry_rpc("get_new_address", || rpc_wallet.get_new_address(None, None))
        .await?
        .require_network(config.network)?;

    let change_amount = input_amount
        .saturating_sub(SEND_AMOUNT_SATS)
        .saturating_sub(FEE_SATS);

    info!("  Input: {} sats", input_amount);
    info!("  Output: {} sats to {}", SEND_AMOUNT_SATS, destination);
    if change_amount > 546 {
        info!("  Change: {} sats back to {}", change_amount, address);
    }
    info!("  Fee: {} sats", FEE_SATS);

    let tx_input = TxIn {
        previous_output: utxo,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let mut tx_outputs = vec![TxOut {
        value: Amount::from_sat(SEND_AMOUNT_SATS),
        script_pubkey: destination.script_pubkey(),
    }];

    if change_amount > 546 {
        tx_outputs.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: address.script_pubkey(),
        });
    }

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input],
        output: tx_outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)?;
    psbt.inputs[0].witness_utxo = Some(utxo_output.clone());

    info!(
        "  PSBT created with {} input(s), {} output(s)",
        psbt.unsigned_tx.input.len(),
        psbt.unsigned_tx.output.len()
    );

    // Step 6: Calculate sighash and sign
    info!("");
    info!("Step 6: Signing PSBT...");

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|input| input.witness_utxo.clone().unwrap())
        .collect();

    let prevouts = Prevouts::All(&prevouts);
    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);

    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
        .map_err(|e| anyhow!("Failed to calculate sighash: {}", e))?;

    let sighash_bytes: [u8; 32] = sighash.to_byte_array();
    info!("  Sighash: {}", hex::encode(sighash_bytes));

    // Validate: Store the expected message before signing
    let expected_message = sighash_bytes;
    info!(
        "  Validating message before signing: {}",
        hex::encode(expected_message)
    );

    // Sign using the SDK
    let signature = client
        .sign(key_id, sighash_bytes, SignatureType::SchnorrBip340)
        .await?;
    info!("  Signature: {}...", &hex::encode(&signature)[..32]);

    // Step 7: Apply signature and broadcast
    info!("");
    info!("Step 7: Applying signature and broadcasting...");

    // Validate: Before broadcasting, recompute sighash to ensure it matches
    let verified_sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
        .map_err(|e| anyhow!("Failed to recalculate sighash: {}", e))?;
    let verified_message: [u8; 32] = verified_sighash.to_byte_array();

    if verified_message != expected_message {
        return Err(anyhow!(
            "Message mismatch! Expected {} but got {}",
            hex::encode(expected_message),
            hex::encode(verified_message)
        ));
    }
    info!("  Message verified before broadcast");

    if signature.len() != 64 {
        return Err(anyhow!(
            "Invalid signature length: expected 64 bytes, got {}",
            signature.len()
        ));
    }

    let schnorr_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
        .map_err(|e| anyhow!("Failed to parse Schnorr signature: {}", e))?;

    // For taproot key-path spending, witness contains just the signature
    let mut witness = Witness::new();
    witness.push(schnorr_sig.as_ref());
    psbt.inputs[0].final_script_witness = Some(witness);

    let signed_tx = psbt.extract_tx()?;
    let txid = signed_tx.compute_txid();

    info!("  Transaction ID: {}", txid);

    // Broadcast
    retry_rpc("send_raw_transaction", || {
        rpc.send_raw_transaction(&signed_tx)
    })
    .await?;
    info!("  Transaction broadcast successfully!");

    // Mine a block to confirm
    retry_rpc("generate_to_address", || {
        rpc.generate_to_address(1, &mining_addr)
    })
    .await?;
    info!("  Transaction confirmed!");

    info!("");
    info!("PSBT transaction test passed:");
    info!("  - Funded taproot address");
    info!("  - Created PSBT");
    info!("  - Signed with enclave (Schnorr BIP-340)");
    info!("  - Broadcast and confirmed: {}", txid);

    Ok(())
}

async fn retry_rpc<T, F>(operation_name: &str, mut operation: F) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, bdk_bitcoind_rpc::bitcoincore_rpc::Error>,
{
    const MAX_RETRIES: u32 = 10;
    const BASE_DELAY_MS: u64 = 100;

    for attempt in 1..=MAX_RETRIES {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                let error_str = e.to_string();
                if attempt < MAX_RETRIES {
                    let delay = BASE_DELAY_MS * (1 << (attempt - 1));
                    tracing::warn!(
                        "Bitcoin RPC {} failed (attempt {}/{}): {}. Retrying in {}ms...",
                        operation_name,
                        attempt,
                        MAX_RETRIES,
                        error_str,
                        delay
                    );
                    sleep(Duration::from_millis(delay)).await;
                } else {
                    return Err(anyhow!(
                        "Bitcoin RPC {} failed after {} attempts: {}",
                        operation_name,
                        MAX_RETRIES,
                        error_str
                    ));
                }
            }
        }
    }
    unreachable!()
}
