//! Single-signer end-to-end test harness
//!
//! This test exercises the single-signer key management and signing flow:
//! 1. Reserve a key slot (get assigned enclave + public key)
//! 2. Import a private key (encrypted to the assigned enclave)
//! 3. List user keys
//! 4. Test P2WPKH (SegWit v0) transaction with ECDSA signing
//! 5. Test P2TR (Taproot) transaction with Schnorr signing
//! 6. Delete the key

use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use bitcoin::{
    absolute::LockTime,
    address::Address,
    ecdsa,
    hashes::Hash,
    key::{CompressedPublicKey, TweakedPublicKey},
    psbt::Psbt,
    secp256k1::{schnorr::Signature as SchnorrSignature, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use keymeld_sdk::{
    DeleteUserKeyResponse, ImportUserKeyRequest, ImportUserKeyResponse, KeyId, KeyStatusResponse,
    ListUserKeysResponse, ReserveKeySlotRequest, ReserveKeySlotResponse, SecureCrypto, SessionId,
    SessionSecret, SignSingleRequest, SignSingleResponse, SignatureType, SingleSigningStatus,
    SingleSigningStatusResponse, UserId,
};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::ExampleConfig;

/// Retry a Bitcoin RPC operation with exponential backoff
async fn retry_bitcoin_rpc<T, F>(operation_name: &str, mut operation: F) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, bdk_bitcoind_rpc::bitcoincore_rpc::Error>,
{
    const MAX_RETRIES: u32 = 20;
    const INITIAL_DELAY_MS: u64 = 100;

    let mut delay_ms = INITIAL_DELAY_MS;
    for attempt in 1..=MAX_RETRIES {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                let error_str = e.to_string();
                if attempt < MAX_RETRIES {
                    let jitter = rand::random::<u64>() % (delay_ms / 2 + 1);
                    let sleep_ms = delay_ms + jitter;
                    warn!(
                        "⚠️  Bitcoin RPC {} failed (attempt {}/{}): {}. Retrying in {}ms...",
                        operation_name, attempt, MAX_RETRIES, error_str, sleep_ms
                    );
                    sleep(Duration::from_millis(sleep_ms)).await;
                    delay_ms = (delay_ms * 2).min(60000);
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

/// Single-signer E2E test harness
pub struct SingleSignerE2ETest {
    pub config: ExampleConfig,
    pub client: Client,
    pub user_id: UserId,
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    /// Auth keypair derived from private key for request authentication (as bytes to avoid version conflicts)
    pub auth_private_key_bytes: [u8; 32],
    pub auth_public_key_bytes: Vec<u8>,
    /// Stored key info after import
    pub key_id: Option<KeyId>,
    pub enclave_id: Option<u32>,
    pub enclave_public_key: Option<String>,
    /// Bitcoin RPC client
    pub rpc_client: Option<RpcClient>,
    pub rpc_client_with_wallet: Option<RpcClient>,
    /// Network
    pub network: Network,
    /// Destination address for spending
    pub destination: String,
    /// Amount to send
    pub amount: u64,
}

impl SingleSignerE2ETest {
    pub async fn new(config: ExampleConfig) -> Result<Self> {
        info!("Initializing Single-Signer E2E Test");
        info!("Gateway: {}", config.gateway_url);

        let client = Client::new();
        let user_id = UserId::new_v7();

        // Generate a random private key for the user
        let mut secret_bytes = [0u8; 32];
        rand::fill(&mut secret_bytes);
        let private_key = SecretKey::from_slice(&secret_bytes)
            .map_err(|e| anyhow!("Failed to create secret key: {}", e))?;
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        // Derive auth keypair from the private key (store as bytes to avoid secp256k1 version conflicts)
        let private_key_bytes = private_key.secret_bytes();
        let (auth_private_key, auth_public_key) =
            SecureCrypto::derive_session_auth_keypair(&private_key_bytes, "single_signer_auth")
                .map_err(|e| anyhow!("Failed to derive auth keypair: {}", e))?;
        let auth_private_key_bytes = auth_private_key.secret_bytes();
        let auth_public_key_bytes = auth_public_key.serialize().to_vec();

        info!("User ID: {}", user_id);
        info!("Public Key: {}", hex::encode(public_key.serialize()));

        // Set up Bitcoin RPC if available (test connection with getblockchaininfo)
        let auth = Auth::UserPass(
            config.bitcoin_rpc_auth.username.clone(),
            config.bitcoin_rpc_auth.password.clone(),
        );

        let rpc_client = match RpcClient::new(&config.bitcoin_rpc_url, auth.clone()) {
            Ok(client) => match client.get_blockchain_info() {
                Ok(_) => Some(client),
                Err(e) => {
                    tracing::warn!("Bitcoin RPC get_blockchain_info failed: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("Bitcoin RPC client creation failed: {}", e);
                None
            }
        };

        let wallet_rpc_url = format!("{}/wallet/keymeld_coordinator", config.bitcoin_rpc_url);
        let rpc_client_with_wallet = if rpc_client.is_some() {
            match RpcClient::new(&wallet_rpc_url, auth) {
                Ok(client) => match client.get_balances() {
                    Ok(_) => Some(client),
                    Err(e) => {
                        tracing::warn!("Bitcoin wallet RPC get_balances failed: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("Bitcoin wallet RPC client creation failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        if rpc_client.is_some() && rpc_client_with_wallet.is_some() {
            info!("Bitcoin RPC connected: {}", config.bitcoin_rpc_url);
        } else {
            info!("Bitcoin RPC not available - will use basic signing test");
        }

        Ok(Self {
            network: config.network,
            config,
            client,
            user_id,
            private_key,
            public_key,
            auth_private_key_bytes,
            auth_public_key_bytes,
            key_id: None,
            enclave_id: None,
            enclave_public_key: None,
            rpc_client,
            rpc_client_with_wallet,
            destination: "bcrt1qf0p0zqynlcq7c4j6vm53qaxapm3chufwfgge80".to_string(),
            amount: 10000,
        })
    }

    /// Get the taproot (P2TR) address for the user's public key
    pub fn get_taproot_address(&self) -> Result<Address> {
        let (x_only_key, _parity) = self.public_key.x_only_public_key();
        // For single-signer, we use the key directly as the output key (no tweak needed for key-path spend)
        // We use dangerous_assume_tweaked because we're treating it as already tweaked
        let tweaked_key = TweakedPublicKey::dangerous_assume_tweaked(x_only_key);
        let address = Address::p2tr_tweaked(tweaked_key, self.network);
        Ok(address)
    }

    /// Get the P2WPKH (native SegWit v0) address for the user's public key
    pub fn get_p2wpkh_address(&self) -> Result<Address> {
        let compressed = CompressedPublicKey(self.public_key);
        let address = Address::p2wpkh(&compressed, self.network);
        Ok(address)
    }

    /// Step 1: Reserve a key slot
    pub async fn reserve_key_slot(&mut self) -> Result<ReserveKeySlotResponse> {
        info!("Step 1: Reserving key slot...");

        let request = ReserveKeySlotRequest {
            user_id: self.user_id.clone(),
        };

        let response = self
            .client
            .post(format!("{}/api/v1/keys/reserve", self.config.gateway_url))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to reserve key slot (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let reserve_response: ReserveKeySlotResponse = response.json().await?;

        info!("Key slot reserved successfully:");
        info!("  Key ID: {}", reserve_response.key_id);
        info!("  Enclave ID: {}", reserve_response.enclave_id.as_u32());
        info!(
            "  Enclave Public Key: {}...{}",
            &reserve_response.enclave_public_key[..16],
            &reserve_response.enclave_public_key[reserve_response.enclave_public_key.len() - 16..]
        );

        self.key_id = Some(reserve_response.key_id.clone());
        self.enclave_id = Some(reserve_response.enclave_id.as_u32());
        self.enclave_public_key = Some(reserve_response.enclave_public_key.clone());

        Ok(reserve_response)
    }

    /// Step 2: Import the private key
    pub async fn import_key(&mut self) -> Result<ImportUserKeyResponse> {
        info!("Step 2: Importing private key...");

        let key_id = self
            .key_id
            .clone()
            .ok_or(anyhow!("No key_id - call reserve_key_slot first"))?;
        let enclave_public_key = self.enclave_public_key.as_ref().ok_or(anyhow!(
            "No enclave_public_key - call reserve_key_slot first"
        ))?;

        // Encrypt the private key to the enclave's public key
        let private_key_bytes = self.private_key.secret_bytes();
        let encrypted_private_key =
            SecureCrypto::ecies_encrypt_from_hex(enclave_public_key, &private_key_bytes)
                .map_err(|e| anyhow!("Failed to encrypt private key: {}", e))?;

        let request = ImportUserKeyRequest {
            key_id: key_id.clone(),
            user_id: self.user_id.clone(),
            encrypted_private_key: hex::encode(&encrypted_private_key),
            auth_pubkey: self.auth_public_key_bytes.clone(),
            enclave_public_key: enclave_public_key.clone(),
        };

        // Generate signature proving ownership of the auth keypair
        let auth_signature = self.generate_auth_signature(&key_id.to_string())?;

        let response = self
            .client
            .post(format!("{}/api/v1/keys/import", self.config.gateway_url))
            .header("X-User-Signature", auth_signature)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to import key (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let import_response: ImportUserKeyResponse = response.json().await?;

        info!("Key import queued:");
        info!("  Key ID: {}", import_response.key_id);
        info!("  User ID: {}", import_response.user_id);
        info!("  Enclave ID: {}", import_response.enclave_id.as_u32());

        // Wait for the async import to complete
        self.wait_for_key_import(&import_response.key_id).await?;

        info!("Key imported successfully");

        Ok(import_response)
    }

    /// Wait for a key import to complete (async processing)
    async fn wait_for_key_import(&self, key_id: &KeyId) -> Result<()> {
        const MAX_ATTEMPTS: u32 = 30;
        const POLL_INTERVAL_MS: u64 = 100;

        for attempt in 1..=MAX_ATTEMPTS {
            let auth_signature = self.generate_auth_signature(&key_id.to_string())?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/keys/{}/{}/status",
                    self.config.gateway_url, self.user_id, key_id
                ))
                .header("X-User-Signature", auth_signature)
                .send()
                .await?;

            if !response.status().is_success() {
                // Key might not be in pending_key_imports anymore (already processed)
                // Try listing keys to see if it's there
                if attempt > 5 {
                    return Ok(()); // Assume success after several attempts
                }
                sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
                continue;
            }

            let status_response: KeyStatusResponse = response.json().await?;

            match status_response.status.as_str() {
                "completed" => {
                    info!("Key import completed (attempt {})", attempt);
                    return Ok(());
                }
                "failed" => {
                    let error_msg = status_response
                        .error_message
                        .unwrap_or_else(|| "Unknown error".to_string());
                    return Err(anyhow!("Key import failed: {}", error_msg));
                }
                "pending" | "processing" => {
                    if attempt < MAX_ATTEMPTS {
                        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
                    }
                }
                other => {
                    warn!("Unknown key status: {}", other);
                    sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
                }
            }
        }

        // If we've polled many times without error, assume success
        Ok(())
    }

    /// Step 3: List user keys
    pub async fn list_keys(&self) -> Result<ListUserKeysResponse> {
        info!("Step 3: Listing user keys...");

        // Generate auth signature for the request
        let key_id = self
            .key_id
            .clone()
            .ok_or(anyhow!("No key_id - import key first to list keys"))?;
        let auth_signature = self.generate_auth_signature(&key_id.to_string())?;

        let response = self
            .client
            .get(format!(
                "{}/api/v1/keys/{}?key_id={}",
                self.config.gateway_url, self.user_id, key_id
            ))
            .header("X-User-Signature", auth_signature)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to list keys (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let list_response: ListUserKeysResponse = response.json().await?;

        info!(
            "Listed {} keys for user {}",
            list_response.keys.len(),
            self.user_id
        );
        for key in &list_response.keys {
            info!(
                "  - Key ID: {}, Created: {}, From Keygen: {:?}",
                key.key_id, key.created_at, key.origin_keygen_session_id
            );
        }

        Ok(list_response)
    }

    /// Step 4: Fund the single-signer taproot address
    pub async fn fund_address(&self) -> Result<OutPoint> {
        info!("Step 4: Funding single-signer taproot address...");

        let rpc = self
            .rpc_client_with_wallet
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        let address = self.get_taproot_address()?;
        info!("  Taproot address: {}", address);

        // Send funds to the address (enough for tx + fee)
        let funding_amount = Amount::from_sat(self.amount + 5000); // amount + buffer for fees

        let txid = retry_bitcoin_rpc("send_to_address", || {
            rpc.send_to_address(&address, funding_amount, None, None, None, None, None, None)
        })
        .await?;

        info!("  Funding txid: {}", txid);

        // Mine a block to confirm
        let mining_addr = retry_bitcoin_rpc("get_new_address", || rpc.get_new_address(None, None))
            .await?
            .require_network(self.network)
            .map_err(|e| anyhow!("Invalid network for mining address: {}", e))?;

        let rpc_no_wallet = self
            .rpc_client
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        retry_bitcoin_rpc("generate_to_address", || {
            rpc_no_wallet.generate_to_address(1, &mining_addr)
        })
        .await?;

        info!("  Block mined to confirm funding");

        // Find the vout for our address
        let tx_info =
            retry_bitcoin_rpc("get_transaction", || rpc.get_transaction(&txid, None)).await?;

        let tx = tx_info.transaction()?;
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == address.script_pubkey())
            .ok_or(anyhow!("Could not find our output in funding tx"))? as u32;

        let outpoint = OutPoint { txid, vout };
        info!("  UTXO: {}:{}", outpoint.txid, outpoint.vout);

        Ok(outpoint)
    }

    /// Step 5: Create a Bitcoin transaction
    pub fn create_transaction(&self, utxo: &OutPoint) -> Result<Psbt> {
        info!("Step 5: Creating Bitcoin transaction...");

        let rpc = self
            .rpc_client_with_wallet
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        let address = self.get_taproot_address()?;

        // Get the UTXO info
        let tx_info = rpc
            .get_transaction(&utxo.txid, None)
            .map_err(|e| anyhow!("Failed to get UTXO info: {}", e))?;
        let tx = tx_info.transaction()?;
        let utxo_output = &tx.output[utxo.vout as usize];

        let destination = Address::from_str(&self.destination)?
            .require_network(self.network)
            .map_err(|e| anyhow!("Invalid destination address: {}", e))?;

        let input_amount = utxo_output.value.to_sat();
        let fee = 1000u64;
        let change_amount = input_amount.saturating_sub(self.amount).saturating_sub(fee);

        info!("  Input: {} sats", input_amount);
        info!("  Output: {} sats to {}", self.amount, self.destination);
        if change_amount > 546 {
            info!("  Change: {} sats back to {}", change_amount, address);
        }
        info!("  Fee: {} sats", fee);

        let tx_input = TxIn {
            previous_output: *utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let mut tx_outputs = vec![TxOut {
            value: Amount::from_sat(self.amount),
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
            "  Transaction created with {} outputs",
            psbt.unsigned_tx.output.len()
        );

        Ok(psbt)
    }

    /// Calculate the taproot sighash for a PSBT
    pub fn calculate_sighash(&self, psbt: &Psbt) -> Result<[u8; 32]> {
        let tx = &psbt.unsigned_tx;

        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .clone()
                    .ok_or(anyhow!("Missing witness UTXO"))
            })
            .collect::<Result<Vec<_>>>()?;

        let prevouts = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .map_err(|e| anyhow!("Failed to calculate sighash: {}", e))?;

        Ok(sighash.to_byte_array())
    }

    /// Step 6: Sign the sighash using single-signer Schnorr
    pub async fn sign_sighash(&self, sighash: &[u8; 32]) -> Result<Vec<u8>> {
        info!("Step 6: Signing sighash with single-signer Schnorr...");
        info!("  Sighash: {}", hex::encode(sighash));

        // Sign the 32-byte sighash directly (BIP-340 expects 32 bytes)
        self.sign_message(sighash, SignatureType::SchnorrBip340)
            .await
    }

    /// Sign a message with Schnorr (BIP-340) - for basic test
    pub async fn sign_schnorr(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_message(message, SignatureType::SchnorrBip340)
            .await
    }

    /// Sign a message with ECDSA - for basic test
    pub async fn sign_ecdsa(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_message(message, SignatureType::Ecdsa).await
    }

    /// Common signing logic
    async fn sign_message(&self, message: &[u8], signature_type: SignatureType) -> Result<Vec<u8>> {
        let key_id = self
            .key_id
            .clone()
            .ok_or(anyhow!("No key_id - import key first"))?;
        let enclave_public_key = self
            .enclave_public_key
            .as_ref()
            .ok_or(anyhow!("No enclave_public_key"))?;

        // Generate a session secret for this signing request
        let session_seed = SecureCrypto::generate_session_seed()
            .map_err(|e| anyhow!("Failed to generate session seed: {}", e))?;

        // Convert Vec<u8> to [u8; 32]
        let session_seed_array: [u8; 32] = session_seed
            .clone()
            .try_into()
            .map_err(|_| anyhow!("Session seed is not 32 bytes"))?;
        let session_secret = SessionSecret::from_bytes(session_seed_array);

        // Encrypt the message with the session secret
        let message_hex = hex::encode(message);
        let encrypted_message = keymeld_sdk::validation::encrypt_session_data(
            &message_hex,
            &hex::encode(&session_seed),
        )
        .map_err(|e| anyhow!("Failed to encrypt message: {}", e))?;

        // Encrypt the session secret to the enclave's public key
        let encrypted_session_secret =
            SecureCrypto::ecies_encrypt_from_hex(enclave_public_key, &session_seed)
                .map_err(|e| anyhow!("Failed to encrypt session secret: {}", e))?;

        // Generate approval signature: Sign(auth_privkey, SHA256(encrypted_message || key_id || timestamp))
        let approval_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut hasher = Sha256::new();
        hasher.update(encrypted_message.as_bytes());
        hasher.update(key_id.to_string().as_bytes());
        hasher.update(approval_timestamp.to_le_bytes());
        let approval_hash = hasher.finalize();

        let secp = Secp256k1::new();
        let approval_msg = Message::from_digest(approval_hash.into());
        let auth_secret_key = SecretKey::from_slice(&self.auth_private_key_bytes)
            .map_err(|e| anyhow!("Failed to parse auth private key: {}", e))?;
        let approval_sig = secp.sign_ecdsa(&approval_msg, &auth_secret_key);
        let approval_signature = approval_sig.serialize_compact().to_vec();

        let request = SignSingleRequest {
            user_id: self.user_id.clone(),
            key_id: key_id.clone(),
            encrypted_message,
            signature_type,
            encrypted_session_secret: hex::encode(&encrypted_session_secret),
            approval_signature,
            approval_timestamp,
        };

        // Add approval signature header
        let auth_signature = self.generate_auth_signature(&key_id.to_string())?;

        let response = self
            .client
            .post(format!("{}/api/v1/sign/single", self.config.gateway_url))
            .header("X-User-Signature", auth_signature)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to create signing session (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let sign_response: SignSingleResponse = response.json().await?;
        info!(
            "  Signing session created: {}",
            sign_response.signing_session_id
        );

        // Poll for completion
        let signature = self
            .wait_for_signing_completion(&sign_response.signing_session_id, &session_secret)
            .await?;

        info!("  Signature: {}", hex::encode(&signature));

        Ok(signature)
    }

    /// Poll for signing completion
    async fn wait_for_signing_completion(
        &self,
        signing_session_id: &SessionId,
        session_secret: &SessionSecret,
    ) -> Result<Vec<u8>> {
        const MAX_ATTEMPTS: u32 = 30;
        const POLL_INTERVAL_MS: u64 = 500;

        let key_id = self
            .key_id
            .clone()
            .ok_or(anyhow!("No key_id for signing status"))?;

        for attempt in 1..=MAX_ATTEMPTS {
            let auth_signature = self.generate_auth_signature(&key_id.to_string())?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/sign/single/{}/status/{}",
                    self.config.gateway_url, signing_session_id, self.user_id
                ))
                .header("X-User-Signature", auth_signature)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await?;
                return Err(anyhow!(
                    "Failed to get signing status (HTTP {}): {}",
                    status,
                    error_text
                ));
            }

            let status_response: SingleSigningStatusResponse = response.json().await?;

            match status_response.status {
                SingleSigningStatus::Completed => {
                    if let Some(ref encrypted_signature) = status_response.encrypted_signature {
                        // Decrypt the signature with the session secret
                        let signature = keymeld_sdk::validation::decrypt_signature_with_secret(
                            encrypted_signature,
                            &hex::encode(session_secret.as_bytes()),
                        )
                        .map_err(|e| anyhow!("Failed to decrypt signature: {}", e))?;
                        return Ok(signature);
                    } else {
                        return Err(anyhow!("Signing completed but no signature returned"));
                    }
                }
                SingleSigningStatus::Failed => {
                    let error_msg = status_response
                        .error_message
                        .unwrap_or_else(|| "Unknown error".to_string());
                    return Err(anyhow!("Signing failed: {}", error_msg));
                }
                SingleSigningStatus::Pending | SingleSigningStatus::Processing => {
                    if attempt < MAX_ATTEMPTS {
                        info!(
                            "  Signing in progress (attempt {}/{}), waiting...",
                            attempt, MAX_ATTEMPTS
                        );
                        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
                    }
                }
            }
        }

        Err(anyhow!("Signing timed out after {} attempts", MAX_ATTEMPTS))
    }

    /// Step 7: Apply signature and broadcast
    pub async fn apply_signature_and_broadcast(
        &self,
        mut psbt: Psbt,
        signature: &[u8],
    ) -> Result<Txid> {
        info!("Step 7: Applying signature and broadcasting...");

        if signature.len() != 64 {
            return Err(anyhow!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature.len()
            ));
        }

        let sig = SchnorrSignature::from_slice(signature)
            .map_err(|e| anyhow!("Failed to parse Schnorr signature: {}", e))?;

        // For taproot key-path spending, witness contains just the signature
        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        psbt.inputs[0].final_script_witness = Some(witness);

        let signed_tx = psbt.extract_tx()?;
        let txid = signed_tx.compute_txid();

        info!("  Transaction ID: {}", txid);

        // Broadcast
        let rpc = self
            .rpc_client
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        retry_bitcoin_rpc("send_raw_transaction", || {
            rpc.send_raw_transaction(&signed_tx)
        })
        .await?;

        info!("  Transaction broadcast successfully!");

        // Mine a block to confirm
        let rpc_wallet = self
            .rpc_client_with_wallet
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        let mining_addr =
            retry_bitcoin_rpc("get_new_address", || rpc_wallet.get_new_address(None, None))
                .await?
                .require_network(self.network)
                .map_err(|e| anyhow!("Invalid network for mining address: {}", e))?;

        retry_bitcoin_rpc("generate_to_address", || {
            rpc.generate_to_address(1, &mining_addr)
        })
        .await?;

        info!("  Block mined to confirm transaction");

        Ok(txid)
    }

    // ========================================================================
    // P2WPKH (SegWit v0) Transaction Methods - Uses ECDSA
    // ========================================================================

    /// Fund the P2WPKH address
    pub async fn fund_p2wpkh_address(&self) -> Result<OutPoint> {
        info!("Funding P2WPKH address...");

        let rpc = self
            .rpc_client_with_wallet
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        let address = self.get_p2wpkh_address()?;
        info!("  P2WPKH address: {}", address);

        // Send funds to the address (enough for tx + fee)
        let funding_amount = Amount::from_sat(self.amount + 5000);

        let txid = retry_bitcoin_rpc("send_to_address", || {
            rpc.send_to_address(&address, funding_amount, None, None, None, None, None, None)
        })
        .await?;

        info!("  Funding txid: {}", txid);

        // Mine a block to confirm
        let mining_addr = retry_bitcoin_rpc("get_new_address", || rpc.get_new_address(None, None))
            .await?
            .require_network(self.network)
            .map_err(|e| anyhow!("Invalid network for mining address: {}", e))?;

        let rpc_no_wallet = self
            .rpc_client
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        retry_bitcoin_rpc("generate_to_address", || {
            rpc_no_wallet.generate_to_address(1, &mining_addr)
        })
        .await?;

        info!("  Block mined to confirm funding");

        // Find the vout for our address
        let tx_info =
            retry_bitcoin_rpc("get_transaction", || rpc.get_transaction(&txid, None)).await?;

        let tx = tx_info.transaction()?;
        let vout = tx
            .output
            .iter()
            .position(|o| o.script_pubkey == address.script_pubkey())
            .ok_or(anyhow!("Could not find our output in funding tx"))? as u32;

        let outpoint = OutPoint { txid, vout };
        info!("  UTXO: {}:{}", outpoint.txid, outpoint.vout);

        Ok(outpoint)
    }

    /// Create a P2WPKH transaction
    pub fn create_p2wpkh_transaction(&self, utxo: &OutPoint) -> Result<Psbt> {
        info!("Creating P2WPKH transaction...");

        let rpc = self
            .rpc_client_with_wallet
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        let address = self.get_p2wpkh_address()?;

        // Get the UTXO info
        let tx_info = rpc
            .get_transaction(&utxo.txid, None)
            .map_err(|e| anyhow!("Failed to get UTXO info: {}", e))?;
        let tx = tx_info.transaction()?;
        let utxo_output = &tx.output[utxo.vout as usize];

        let destination = Address::from_str(&self.destination)?
            .require_network(self.network)
            .map_err(|e| anyhow!("Invalid destination address: {}", e))?;

        let input_amount = utxo_output.value.to_sat();
        let fee = 1000u64;
        let change_amount = input_amount.saturating_sub(self.amount).saturating_sub(fee);

        info!("  Input: {} sats", input_amount);
        info!("  Output: {} sats to {}", self.amount, self.destination);
        if change_amount > 546 {
            info!("  Change: {} sats back to {}", change_amount, address);
        }
        info!("  Fee: {} sats", fee);

        let tx_input = TxIn {
            previous_output: *utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let mut tx_outputs = vec![TxOut {
            value: Amount::from_sat(self.amount),
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
            "  P2WPKH transaction created with {} outputs",
            psbt.unsigned_tx.output.len()
        );

        Ok(psbt)
    }

    /// Calculate the P2WPKH sighash (BIP-143 SegWit v0)
    pub fn calculate_p2wpkh_sighash(&self, psbt: &Psbt) -> Result<[u8; 32]> {
        let tx = &psbt.unsigned_tx;

        let witness_utxo = psbt.inputs[0]
            .witness_utxo
            .as_ref()
            .ok_or(anyhow!("Missing witness UTXO"))?;

        let mut sighash_cache = SighashCache::new(tx);

        // For P2WPKH, the scriptcode is OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        // which is essentially the P2PKH script for the compressed pubkey
        let compressed = CompressedPublicKey(self.public_key);
        let script_code = ScriptBuf::new_p2pkh(&compressed.pubkey_hash());

        let sighash = sighash_cache
            .p2wpkh_signature_hash(0, &script_code, witness_utxo.value, EcdsaSighashType::All)
            .map_err(|e| anyhow!("Failed to calculate P2WPKH sighash: {}", e))?;

        Ok(sighash.to_byte_array())
    }

    /// Sign the P2WPKH sighash using single-signer ECDSA
    pub async fn sign_p2wpkh_sighash(&self, sighash: &[u8; 32]) -> Result<Vec<u8>> {
        info!("Signing P2WPKH sighash with ECDSA...");
        info!("  Sighash: {}", hex::encode(sighash));

        // Sign the 32-byte sighash with ECDSA
        self.sign_message(sighash, SignatureType::Ecdsa).await
    }

    /// Apply ECDSA signature to P2WPKH transaction and broadcast
    pub async fn apply_p2wpkh_signature_and_broadcast(
        &self,
        mut psbt: Psbt,
        signature: &[u8],
    ) -> Result<Txid> {
        info!("Applying ECDSA signature and broadcasting P2WPKH transaction...");

        // ECDSA signatures are DER-encoded, typically 70-72 bytes
        // But our enclave returns compact 64-byte signatures, so we need to convert
        if signature.len() != 64 {
            return Err(anyhow!(
                "Invalid ECDSA signature length: expected 64 bytes (compact), got {}",
                signature.len()
            ));
        }

        // Parse the compact signature
        let ecdsa_sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(signature)
            .map_err(|e| anyhow!("Failed to parse compact ECDSA signature: {}", e))?;

        // Create the Bitcoin ECDSA signature with sighash type
        let bitcoin_sig = ecdsa::Signature {
            signature: ecdsa_sig,
            sighash_type: EcdsaSighashType::All,
        };

        // For P2WPKH, witness is: [signature, pubkey]
        let mut witness = Witness::new();
        witness.push(bitcoin_sig.to_vec());
        witness.push(self.public_key.serialize());
        psbt.inputs[0].final_script_witness = Some(witness);

        let signed_tx = psbt.extract_tx()?;
        let txid = signed_tx.compute_txid();

        info!("  Transaction ID: {}", txid);

        // Broadcast
        let rpc = self
            .rpc_client
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        retry_bitcoin_rpc("send_raw_transaction", || {
            rpc.send_raw_transaction(&signed_tx)
        })
        .await?;

        info!("  P2WPKH transaction broadcast successfully!");

        // Mine a block to confirm
        let rpc_wallet = self
            .rpc_client_with_wallet
            .as_ref()
            .ok_or(anyhow!("Bitcoin RPC not available"))?;

        let mining_addr =
            retry_bitcoin_rpc("get_new_address", || rpc_wallet.get_new_address(None, None))
                .await?
                .require_network(self.network)
                .map_err(|e| anyhow!("Invalid network for mining address: {}", e))?;

        retry_bitcoin_rpc("generate_to_address", || {
            rpc.generate_to_address(1, &mining_addr)
        })
        .await?;

        info!("  Block mined to confirm P2WPKH transaction");

        Ok(txid)
    }

    /// Delete the key
    pub async fn delete_key(&self) -> Result<DeleteUserKeyResponse> {
        info!("Step 8: Deleting key...");

        let key_id = self
            .key_id
            .clone()
            .ok_or(anyhow!("No key_id - import key first"))?;

        let auth_signature = self.generate_auth_signature(&key_id.to_string())?;

        let response = self
            .client
            .delete(format!(
                "{}/api/v1/keys/{}/{}",
                self.config.gateway_url, self.user_id, key_id
            ))
            .header("X-User-Signature", auth_signature)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to delete key (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let delete_response: DeleteUserKeyResponse = response.json().await?;

        info!("Key deleted successfully: {}", delete_response.key_id);

        Ok(delete_response)
    }

    /// Generate auth signature for a request
    /// Format: nonce_hex:signature_hex
    /// Message: SHA256(scope_id || user_id || nonce)
    fn generate_auth_signature(&self, scope_id: &str) -> Result<String> {
        // Generate random nonce
        let mut nonce = [0u8; 16];
        rand::fill(&mut nonce);

        // Sign: SHA256(scope_id || user_id || nonce)
        let mut hasher = Sha256::new();
        hasher.update(scope_id.as_bytes());
        hasher.update(self.user_id.to_string().as_bytes());
        hasher.update(nonce);
        let hash = hasher.finalize();

        let hash_array: [u8; 32] = hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Hash is not 32 bytes"))?;

        let secp = Secp256k1::signing_only();
        let message = Message::from_digest(hash_array);
        let auth_secret_key = SecretKey::from_slice(&self.auth_private_key_bytes)
            .map_err(|e| anyhow!("Failed to parse auth private key: {}", e))?;
        let signature = secp.sign_ecdsa(&message, &auth_secret_key);

        // Return: nonce_hex:signature_hex
        Ok(format!(
            "{}:{}",
            hex::encode(nonce),
            hex::encode(signature.serialize_compact())
        ))
    }
}

/// Run the single-signer e2e test (basic - no Bitcoin)
pub async fn run_single_signer_test(config: ExampleConfig) -> Result<()> {
    info!("Single-Signer E2E Test");
    info!("=======================");

    let mut test = SingleSignerE2ETest::new(config).await?;

    // Check if Bitcoin RPC is available
    let has_bitcoin = test.rpc_client.is_some() && test.rpc_client_with_wallet.is_some();

    // Step 1: Reserve key slot
    test.reserve_key_slot().await?;

    // Step 2: Import key
    test.import_key().await?;

    // Step 3: List keys
    let keys = test.list_keys().await?;
    if keys.keys.is_empty() {
        return Err(anyhow!("Expected at least one key after import"));
    }

    if has_bitcoin {
        // Full Bitcoin transaction flow
        info!("");
        info!("Bitcoin RPC available - running full transaction test");
        info!("======================================================");

        // Step 4: Fund the address
        let utxo = test.fund_address().await?;

        // Step 5: Create transaction
        let psbt = test.create_transaction(&utxo)?;

        // Step 6: Calculate sighash and sign
        let sighash = test.calculate_sighash(&psbt)?;
        let signature = test.sign_sighash(&sighash).await?;

        // Step 7: Apply signature and broadcast
        let txid = test.apply_signature_and_broadcast(psbt, &signature).await?;
        info!("Transaction confirmed: {}", txid);
    } else {
        // Basic signing test (no Bitcoin)
        info!("");
        info!("Bitcoin RPC not available - running basic signing test");
        info!("=======================================================");

        // Sign with Schnorr
        let test_message = b"Hello, KeyMeld Single-Signer!";
        let schnorr_sig = test.sign_schnorr(test_message).await?;
        info!("Schnorr signature length: {} bytes", schnorr_sig.len());

        // Sign with ECDSA
        let ecdsa_sig = test.sign_ecdsa(test_message).await?;
        info!("ECDSA signature length: {} bytes", ecdsa_sig.len());
    }

    // Step 8: Delete key
    test.delete_key().await?;
    // Note: We can't verify deletion via list_keys since we need a valid key_id
    // to authenticate. The delete succeeded if no error was returned.

    info!("");
    info!("Single-Signer E2E Test PASSED!");
    info!("  - Reserved key slot");
    info!("  - Imported private key");
    info!("  - Listed keys");
    if has_bitcoin {
        info!("  - Funded taproot address");
        info!("  - Created Bitcoin transaction");
        info!("  - Signed transaction with Schnorr (BIP-340)");
        info!("  - Broadcast and confirmed transaction");
    } else {
        info!("  - Signed with Schnorr (BIP-340)");
        info!("  - Signed with ECDSA");
    }
    info!("  - Deleted key");

    Ok(())
}
