pub mod adaptor_utils;
pub mod batch_signing;
pub mod keygen_with_stored_key;
pub mod rpc_batcher;
pub mod single_signer;

use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use bdk_wallet::{
    bitcoin::{
        absolute::LockTime,
        bip32::{ChildNumber, Xpriv},
        key::TweakedPublicKey,
        psbt::Psbt,
        secp256k1::{schnorr::Signature, PublicKey, Secp256k1, SecretKey},
        transaction::Version,
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
        TxOut, Witness,
    },
    keys::bip39::Mnemonic,
    template::Bip86,
    KeychainKind, Wallet,
};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::Txid;

use keymeld_sdk::{
    CreateSigningSessionRequest, EnclaveId, EnclavePublicKeyResponse, EncryptedData,
    GetAvailableSlotsResponse, HealthCheckResponse, KeygenSessionStatusResponse, KeygenStatusKind,
    RegisterKeygenParticipantRequest, SecureCrypto, SessionId, SessionSecret,
    SigningSessionStatusResponse, SigningStatusKind, TaprootTweak, UserId,
};
use keymeld_sdk::{
    InitializeKeygenSessionRequest, InitializeKeygenSessionResponse, ReserveKeygenSessionRequest,
    ReserveKeygenSessionResponse,
};
use rand::RngCore;
use reqwest::Client;
use secp256k1::PublicKey as Secp256k1PublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

/// Configuration for Bitcoin RPC retry logic
/// For high-concurrency stress tests (1000+ parallel sessions), Bitcoin Core's
/// RPC queue can get backed up. These values allow for longer waits.
const BITCOIN_RPC_MAX_RETRIES: u32 = 20;
const BITCOIN_RPC_BASE_DELAY_MS: u64 = 100;
const BITCOIN_RPC_MAX_DELAY_MS: u64 = 30000;

/// Helper to retry Bitcoin RPC operations with exponential backoff
/// This handles 503 errors when the Bitcoin node is overloaded
async fn retry_bitcoin_rpc<T, F>(operation_name: &str, mut operation: F) -> Result<T>
where
    F: FnMut() -> std::result::Result<T, bdk_bitcoind_rpc::bitcoincore_rpc::Error>,
{
    let mut last_error = None;

    for attempt in 1..=BITCOIN_RPC_MAX_RETRIES {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                let error_str = e.to_string();
                let is_retryable = error_str.contains("503")
                    || error_str.contains("Service Unavailable")
                    || error_str.contains("transport error")
                    || error_str.contains("connection refused")
                    || error_str.contains("Connection refused");

                if is_retryable && attempt < BITCOIN_RPC_MAX_RETRIES {
                    // Exponential backoff with jitter
                    let delay = std::cmp::min(
                        BITCOIN_RPC_BASE_DELAY_MS * (1 << (attempt - 1)),
                        BITCOIN_RPC_MAX_DELAY_MS,
                    );
                    // Add some jitter (0-50% of delay)
                    let jitter = (rand::random::<u64>() % (delay / 2 + 1)) as u64;
                    let total_delay = delay + jitter;

                    warn!(
                        "⚠️  Bitcoin RPC {} failed (attempt {}/{}): {}. Retrying in {}ms...",
                        operation_name, attempt, BITCOIN_RPC_MAX_RETRIES, error_str, total_delay
                    );
                    sleep(Duration::from_millis(total_delay)).await;
                    last_error = Some(e);
                    continue;
                }

                return Err(anyhow!("{} failed: {}", operation_name, e));
            }
        }
    }

    Err(anyhow!(
        "{} failed after {} retries: {}",
        operation_name,
        BITCOIN_RPC_MAX_RETRIES,
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "Unknown error".to_string())
    ))
}

/// Session data for keygen (coordinator)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenSessionData {
    pub coordinator_pubkey: Vec<u8>,
    pub aggregate_pubkey: Option<Vec<u8>>,
}

impl KeygenSessionData {
    pub fn new(coordinator_pubkey: Vec<u8>) -> Self {
        Self {
            coordinator_pubkey,
            aggregate_pubkey: None,
        }
    }
}

/// Enclave data for keygen (coordinator)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenEnclaveData {
    pub coordinator_private_key: String,
    pub session_secret: String,
}

impl KeygenEnclaveData {
    pub fn new(coordinator_private_key: String, session_secret: String) -> Self {
        Self {
            coordinator_private_key,
            session_secret,
        }
    }
}

/// Session data for keygen participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenParticipantSessionData {
    pub participant_public_keys: BTreeMap<UserId, Vec<u8>>,
}

impl KeygenParticipantSessionData {
    pub fn new_with_public_key(user_id: UserId, participant_public_key: Vec<u8>) -> Self {
        let mut participant_public_keys = BTreeMap::new();
        participant_public_keys.insert(user_id, participant_public_key);
        Self {
            participant_public_keys,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleConfig {
    #[serde(with = "network_serde")]
    pub network: Network,
    pub num_signers: u32,
    pub gateway_url: String,
    pub bitcoin_rpc_url: String,
    pub bitcoin_rpc_auth: BitcoinRpcAuth,
    pub key_files_dir: String,
    /// Use RPC batcher for high-concurrency stress tests (100+ instances)
    /// When enabled, funding and broadcast requests are queued to files
    /// and processed by a background batcher script
    #[serde(default)]
    pub use_rpc_batcher: bool,
    /// Directory for RPC batcher queue files (default: /tmp/keymeld-rpc-queue)
    #[serde(default = "default_rpc_queue_dir")]
    pub rpc_queue_dir: String,
}

fn default_rpc_queue_dir() -> String {
    "/tmp/keymeld-rpc-queue".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinRpcAuth {
    pub username: String,
    pub password: String,
}

pub mod network_serde {
    use super::*;

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let network_str = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
        };
        serializer.serialize_str(network_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        let network_str = String::deserialize(deserializer)?;
        match network_str.as_str() {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "testnet4" => Ok(Network::Testnet4),
            "regtest" => Ok(Network::Regtest),
            "signet" => Ok(Network::Signet),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown network: {network_str}"
            ))),
        }
    }
}

#[derive(Debug)]
pub struct Participant {
    pub wallet: Wallet,
    pub derived_private_key: SecretKey,
    pub public_key: PublicKey,
}

impl Participant {
    pub fn new(mnemonic: Mnemonic, network: Network, derivation_index: u32) -> Result<Self> {
        let seed = mnemonic.to_seed("");
        let master_xpriv = Xpriv::new_master(network, &seed)?;

        let secp = Secp256k1::new();
        let derivation_path = vec![
            ChildNumber::from_hardened_idx(86)?,
            ChildNumber::from_hardened_idx(match network {
                Network::Bitcoin => 0,
                _ => 1,
            })?,
            ChildNumber::from_hardened_idx(0)?,
            ChildNumber::from_normal_idx(0)?,
            ChildNumber::from_normal_idx(derivation_index)?,
        ];

        let derived_xpriv = master_xpriv.derive_priv(&secp, &derivation_path)?;
        let derived_private_key = derived_xpriv.private_key;

        let external_descriptor = Bip86(derived_xpriv, KeychainKind::External);
        let internal_descriptor = Bip86(derived_xpriv, KeychainKind::Internal);
        let wallet = Wallet::create(external_descriptor, internal_descriptor)
            .network(network)
            .create_wallet_no_persist()?;
        Ok(Self {
            wallet,
            derived_private_key,
            public_key: PublicKey::from_secret_key(&secp, &derived_private_key),
        })
    }

    pub fn get_receive_address(&self) -> Result<Address> {
        Ok(self.wallet.peek_address(KeychainKind::External, 0).address)
    }

    pub fn fingerprint(&self) -> String {
        let pubkey_bytes = self.public_key.serialize();
        let hash = sha256::Hash::hash(&pubkey_bytes);
        hex::encode(&hash[..4])
    }
}

pub struct KeyMeldE2ETest {
    pub config: ExampleConfig,
    pub client: Client,
    pub participants: Vec<Participant>,
    pub coordinator_wallet: Wallet,
    pub coordinator_derived_private_key: SecretKey,
    pub coordinator_public_key: PublicKey,
    pub coordinator_user_id: UserId,
    pub participant_user_ids: Vec<UserId>,
    pub rpc_client: RpcClient,
    pub rpc_client_with_wallet: RpcClient, // Wallet-specific RPC client for get_transaction calls
    pub amount: u64,
    pub destination: String,
    pub session_secrets: HashMap<SessionId, String>,
    pub session_private_keys: HashMap<SessionId, secp256k1::SecretKey>,
    pub coordinator_enclave_ids: HashMap<SessionId, EnclaveId>,
    pub participants_requiring_approval: Vec<usize>, // Indices of participants requiring approval (0 = first participant, not coordinator)
    pub rpc_batcher: Option<rpc_batcher::RpcBatcher>, // Queue-based RPC for high concurrency
}

impl KeyMeldE2ETest {
    pub async fn new(
        config: ExampleConfig,
        amount: u64,
        destination: Option<String>,
    ) -> Result<Self> {
        info!("🔧 Initializing KeyMeld E2E Test");
        info!("Network: {}", config.network);
        info!("Participants: {}", config.num_signers);
        info!("Amount: {} sats", amount);

        let client = Client::new();

        let auth = Auth::UserPass(
            config.bitcoin_rpc_auth.username.clone(),
            config.bitcoin_rpc_auth.password.clone(),
        );

        let rpc_client = RpcClient::new(&config.bitcoin_rpc_url, auth.clone())
            .map_err(|e| anyhow!("Failed to create RPC client: {e}"))?;

        // Create wallet-specific RPC client for get_transaction calls
        // This is needed when multiple wallets are loaded (high-concurrency stress tests)
        let wallet_rpc_url = format!("{}/wallet/keymeld_coordinator", config.bitcoin_rpc_url);
        let rpc_client_with_wallet = RpcClient::new(&wallet_rpc_url, auth)
            .map_err(|e| anyhow!("Failed to create wallet RPC client: {e}"))?;

        let coordinator_mnemonic = Self::load_or_create_coordinator_private_key(&config)?;
        let coordinator_user_id = Uuid::now_v7().into();
        info!("👤 Coordinator user ID: {}", coordinator_user_id);

        let coordinator = Participant::new(coordinator_mnemonic, config.network, 0)?;

        // Generate destination address from coordinator wallet if not provided
        let destination = match destination {
            Some(addr) => addr,
            None => {
                let dest_addr = coordinator
                    .wallet
                    .peek_address(KeychainKind::External, 1)
                    .address;
                info!(
                    "📍 Generated destination address from coordinator wallet: {}",
                    dest_addr
                );
                dest_addr.to_string()
            }
        };

        let participant_user_ids: Vec<UserId> = Vec::new();

        // Initialize RPC batcher if enabled for high-concurrency tests
        let rpc_batcher = if config.use_rpc_batcher {
            info!("📦 RPC batcher enabled - using queue-based Bitcoin RPC");
            Some(rpc_batcher::RpcBatcher::new(&config.rpc_queue_dir))
        } else {
            None
        };

        Ok(Self {
            config,
            client,
            participants: Vec::new(),
            coordinator_wallet: coordinator.wallet,
            coordinator_derived_private_key: coordinator.derived_private_key,
            coordinator_public_key: coordinator.public_key,
            coordinator_user_id,
            participant_user_ids,
            rpc_client,
            rpc_client_with_wallet,
            amount,
            destination,
            session_secrets: HashMap::new(),
            session_private_keys: HashMap::new(),
            coordinator_enclave_ids: HashMap::new(),
            participants_requiring_approval: vec![0], // By default, only first participant (index 0) requires approval
            rpc_batcher,
        })
    }

    fn load_or_create_coordinator_private_key(config: &ExampleConfig) -> Result<Mnemonic> {
        let key_file = format!("{}/coordinator.key", config.key_files_dir);

        if Path::new(&key_file).exists() {
            info!(
                "📁 Loading existing coordinator private key from {}",
                key_file
            );
            let key_content = read_to_string(&key_file)
                .map_err(|e| anyhow!("Failed to read key file {key_file}: {e}"))?;

            let mnemonic_str = key_content.trim();
            let mnemonic = Mnemonic::from_str(mnemonic_str)
                .map_err(|e| anyhow!("Invalid mnemonic in key file: {e}"))?;

            Ok(mnemonic)
        } else {
            info!("🔑 Generating new coordinator private key");

            if let Some(parent) = Path::new(&key_file).parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| anyhow!("Failed to create key directory: {e}"))?;
            }

            let mut entropy = [0u8; 32];
            rand::rng().fill_bytes(&mut entropy);

            let mnemonic = Mnemonic::from_entropy(&entropy)
                .map_err(|e| anyhow!("Failed to create mnemonic: {e}"))?;

            fs::write(&key_file, mnemonic.to_string())
                .map_err(|e| anyhow!("Failed to write key file: {e}"))?;

            info!("💾 Coordinator private key saved to {}", key_file);
            Ok(mnemonic)
        }
    }

    pub async fn load_participants(&mut self) -> Result<()> {
        info!("👥 Loading participant keys...");
        self.participants.clear();
        self.participant_user_ids.clear();

        for i in 1..self.config.num_signers as usize {
            let key_file = format!("{}/participant_{}.key", self.config.key_files_dir, i);
            let mnemonic = if Path::new(&key_file).exists() {
                info!("📁 Loading participant {} key from {}", i, key_file);
                let key_content = read_to_string(&key_file)
                    .map_err(|e| anyhow!("Failed to read key file {key_file}: {e}"))?;
                Mnemonic::from_str(key_content.trim())
                    .map_err(|e| anyhow!("Invalid mnemonic in key file: {e}"))?
            } else {
                info!("🔑 Generating new participant {} key", i);
                if let Some(parent) = Path::new(&key_file).parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| anyhow!("Failed to create key directory: {e}"))?;
                }

                let mut entropy = [0u8; 32];
                rand::rng().fill_bytes(&mut entropy);
                let mnemonic = Mnemonic::from_entropy(&entropy)
                    .map_err(|e| anyhow!("Failed to create mnemonic: {e}"))?;

                fs::write(&key_file, mnemonic.to_string())
                    .map_err(|e| anyhow!("Failed to write key file: {e}"))?;

                info!("💾 Participant {} key saved to {}", i, key_file);
                mnemonic
            };
            let participant = Participant::new(mnemonic, self.config.network, i as u32)?;

            self.participants.push(participant);
            self.participant_user_ids.push(UserId::new_v7());
        }

        info!("✅ Loaded {} participants", self.participants.len());
        Ok(())
    }

    pub async fn fund_coordinator_from_master(&mut self) -> Result<()> {
        info!("💰 Funding coordinator from master wallet...");

        let coordinator_address = self
            .coordinator_wallet
            .peek_address(KeychainKind::External, 0)
            .address;
        info!("📍 Coordinator address: {}", coordinator_address);

        let current_balance = self.coordinator_wallet.balance().total();
        let required_amount = self.amount + 10_000;

        if current_balance.to_sat() >= required_amount {
            info!(
                "✅ Coordinator already has sufficient funds: {} sats",
                current_balance.to_sat()
            );
            return Ok(());
        }

        let funding_amount = required_amount - current_balance.to_sat() + 50_000; // Extra buffer
        info!("💸 Sending {} sats to coordinator", funding_amount);

        let funding_txid = if let Some(ref batcher) = self.rpc_batcher {
            // Use batcher for high concurrency - avoids overwhelming bitcoind
            let txid_str = batcher
                .send_to_address(
                    &coordinator_address.to_string(),
                    funding_amount as f64 / 100_000_000.0,
                )
                .await?;
            txid_str.parse::<Txid>()?
        } else {
            // Direct RPC for low concurrency - use wallet-specific client
            retry_bitcoin_rpc("send_to_address (coordinator)", || {
                self.rpc_client_with_wallet.send_to_address(
                    &coordinator_address,
                    Amount::from_sat(funding_amount),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .await?
        };

        info!("📡 Funding transaction: {}", funding_txid);

        // Wait for confirmation
        if let Some(ref batcher) = self.rpc_batcher {
            // High concurrency mode: use batcher for confirmation polling
            // Background miner handles block generation
            info!("⏳ Waiting for background miner to confirm transaction...");
            let confirmations = batcher
                .wait_for_confirmation(&funding_txid.to_string(), 1)
                .await?;
            info!("✅ Funding confirmed with {} confirmations", confirmations);
        } else {
            // Low concurrency mode: generate blocks ourselves
            info!("⛏️ Mining block to confirm transaction...");
            let addr = self
                .coordinator_wallet
                .peek_address(KeychainKind::External, 1)
                .address;
            retry_bitcoin_rpc("generatetoaddress", || {
                self.rpc_client.generate_to_address(1, &addr)
            })
            .await?;
            info!("✅ Funding confirmed");
        }

        Ok(())
    }

    pub async fn fund_aggregate_key_address(
        &mut self,
        encrypted_aggregate_key: &str,
        keygen_session_id: &SessionId,
    ) -> Result<OutPoint> {
        info!("💰 Funding aggregate key address...");

        // Get the session secret for decryption
        let session_secret_hex = self.session_secrets.get(keygen_session_id).ok_or_else(|| {
            anyhow!(
                "Session secret not found for keygen session: {}",
                keygen_session_id
            )
        })?;
        let session_secret = SessionSecret::from_hex(session_secret_hex)?;

        // Decrypt the aggregate public key
        let encrypted_data = EncryptedData::from_hex(encrypted_aggregate_key)
            .map_err(|e| anyhow!("Failed to decode encrypted aggregate key: {}", e))?;
        let key_bytes = session_secret
            .decrypt(&encrypted_data, "aggregate_public_key")
            .map_err(|e| anyhow!("Failed to decrypt aggregate key: {}", e))?;
        let pubkey =
            PublicKey::from_slice(&key_bytes).map_err(|e| anyhow!("Invalid public key: {}", e))?;
        let (x_only, _) = pubkey.x_only_public_key();
        let aggregate_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only);

        let aggregate_address = Address::p2tr_tweaked(aggregate_pubkey, self.config.network);
        info!("📍 Aggregate key address: {}", aggregate_address);

        let coordinator_address = self
            .coordinator_wallet
            .peek_address(KeychainKind::External, 0)
            .address;

        let required_amount = self.amount + 5_000;
        let required_btc = required_amount as f64 / 100_000_000.0;

        // Use batcher if enabled, otherwise direct RPC
        let funding_txid = if let Some(ref batcher) = self.rpc_batcher {
            let txid_str = batcher
                .send_to_address(&aggregate_address.to_string(), required_btc)
                .await?;
            bitcoin::Txid::from_str(&txid_str)
                .map_err(|e| anyhow!("Invalid txid from batcher: {}", e))?
        } else {
            // Use wallet-specific client for send_to_address
            retry_bitcoin_rpc("send_to_address (aggregate)", || {
                self.rpc_client_with_wallet.send_to_address(
                    &aggregate_address,
                    Amount::from_sat(required_amount),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .await?
        };

        info!("📡 Funding transaction: {}", funding_txid);

        // Skip generate_to_address when using batcher - background miner handles it
        if self.rpc_batcher.is_none() {
            let _ = retry_bitcoin_rpc("generate_to_address", || {
                self.rpc_client.generate_to_address(1, &coordinator_address)
            })
            .await?;
        }

        // Wait for confirmation - use batcher if enabled
        if let Some(ref batcher) = self.rpc_batcher {
            batcher
                .wait_for_confirmation(&funding_txid.to_string(), 1)
                .await?;
            info!("✅ Aggregate funding confirmed");
        } else {
            loop {
                sleep(Duration::from_secs(1)).await;

                if let Ok(info) = retry_bitcoin_rpc("get_transaction", || {
                    self.rpc_client_with_wallet
                        .get_transaction(&funding_txid, None)
                })
                .await
                {
                    if info.info.confirmations >= 1 {
                        info!("✅ Aggregate funding confirmed");
                        break;
                    }
                }
            }
        }

        // Find the correct output index for our aggregate address
        // Use wallet-specific client to handle multiple wallets during stress tests
        let funding_tx_info = retry_bitcoin_rpc("get_transaction", || {
            self.rpc_client_with_wallet
                .get_transaction(&funding_txid, None)
        })
        .await?;

        let funding_tx = funding_tx_info.transaction()?;
        let aggregate_script_pubkey = aggregate_address.script_pubkey();

        let mut found_vout = None;
        for (vout, output) in funding_tx.output.iter().enumerate() {
            if output.script_pubkey == aggregate_script_pubkey {
                found_vout = Some(vout as u32);
                info!("✅ Found aggregate key output at index {}", vout);
                break;
            }
        }

        let vout = found_vout.ok_or_else(|| {
            anyhow!(
                "Aggregate key address {} not found in funding transaction outputs",
                aggregate_address
            )
        })?;

        let outpoint = OutPoint::new(funding_txid, vout);
        Ok(outpoint)
    }

    pub async fn create_musig2_transaction(
        &mut self,
        encrypted_aggregate_key: &str,
        keygen_session_id: &SessionId,
        aggregate_utxo: &OutPoint,
    ) -> Result<Psbt> {
        info!("📝 Creating MuSig2 transaction...");

        // Get the session secret for decryption
        let session_secret_hex = self.session_secrets.get(keygen_session_id).ok_or_else(|| {
            anyhow!(
                "Session secret not found for keygen session: {}",
                keygen_session_id
            )
        })?;
        let session_secret = SessionSecret::from_hex(session_secret_hex)?;

        // Decrypt the aggregate public key
        let encrypted_data = EncryptedData::from_hex(encrypted_aggregate_key)
            .map_err(|e| anyhow!("Failed to decode encrypted aggregate key: {}", e))?;
        let key_bytes = session_secret
            .decrypt(&encrypted_data, "aggregate_public_key")
            .map_err(|e| anyhow!("Failed to decrypt aggregate key: {}", e))?;
        let pubkey =
            PublicKey::from_slice(&key_bytes).map_err(|e| anyhow!("Invalid public key: {}", e))?;
        let (x_only_key, parity) = pubkey.x_only_public_key();

        // KeyMeld's KeyAggContext already applied the unspendable taproot tweak
        // The aggregate_key we received is already the tweaked output key
        // So we use it directly without applying another tweak
        let aggregate_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only_key);

        info!("🔍 Key details for transaction:");
        info!("  - Original aggregate key: {}", encrypted_aggregate_key);
        info!(
            "  - Aggregate key (compressed): {}",
            hex::encode(&key_bytes)
        );
        info!(
            "  - Aggregate key (x-only): {}",
            hex::encode(x_only_key.serialize())
        );
        info!("  - Parity: {:?}", parity);

        let aggregate_address = Address::p2tr_tweaked(aggregate_pubkey, self.config.network);

        let destination_address = Address::from_str(&self.destination)
            .map_err(|e| anyhow!("Invalid destination address: {e}"))?
            .require_network(self.config.network)
            .map_err(|e| anyhow!("Destination address invalid for network: {e}"))?;

        let utxo_info = self
            .rpc_client_with_wallet
            .get_transaction(&aggregate_utxo.txid, None)
            .map_err(|e| anyhow!("Failed to get UTXO info: {e}"))?;

        let utxo_output = &utxo_info.transaction()?.output[aggregate_utxo.vout as usize];
        let input_amount = utxo_output.value;

        // Verify that the UTXO scriptPubKey matches our aggregate key
        let expected_script_pubkey = aggregate_address.script_pubkey();
        if utxo_output.script_pubkey != expected_script_pubkey {
            return Err(anyhow!(
                "UTXO scriptPubKey mismatch! Expected: {}, Found: {}. This indicates we're trying to spend a UTXO from a different aggregate key.",
                hex::encode(expected_script_pubkey.as_bytes()),
                hex::encode(utxo_output.script_pubkey.as_bytes())
            ));
        }

        info!("✅ UTXO scriptPubKey verification passed - matches current aggregate key");

        if input_amount.to_sat() < self.amount {
            return Err(anyhow!(
                "Insufficient funds: need {} sats, have {} sats",
                self.amount,
                input_amount.to_sat()
            ));
        }

        let fee = 1000u64;
        let change_amount = input_amount.to_sat() - self.amount - fee;

        let tx_input = TxIn {
            previous_output: *aggregate_utxo,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let mut tx_outputs = vec![TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: destination_address.script_pubkey(),
        }];

        if change_amount > 546 {
            tx_outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: aggregate_address.script_pubkey(),
            });
        }

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx_input],
            output: tx_outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(tx)?;
        psbt.inputs[0].witness_utxo = Some(utxo_output.clone());

        // For unspendable taproot tweak, we don't set tap_internal_key
        // The aggregate key from KeyMeld is already the tweaked output key
        // psbt.inputs[0].tap_internal_key = Some(x_only_key);

        info!(
            "✅ Transaction created with {} inputs and {} outputs",
            psbt.unsigned_tx.input.len(),
            psbt.unsigned_tx.output.len()
        );

        if psbt.unsigned_tx.input.len() != 1 {
            return Err(anyhow!(
                "Expected single-input transaction, got {} inputs",
                psbt.unsigned_tx.input.len()
            ));
        }

        Ok(psbt)
    }

    pub async fn create_keygen_session(&mut self) -> Result<SessionId> {
        info!("🔑 Creating keygen session using two-phase approach...");

        let keygen_session_id: SessionId = Uuid::now_v7().into();

        let seed = SecureCrypto::generate_session_seed()
            .map_err(|e| anyhow!("Failed to generate session seed: {e}"))?;

        let session_private_key = SecureCrypto::derive_private_key_from_seed(&seed)
            .map_err(|e| anyhow!("Failed to derive private key from seed: {e}"))?;
        let session_public_key = SecureCrypto::derive_public_key_from_seed(&seed)
            .map_err(|e| anyhow!("Failed to derive public key from seed: {e}"))?;

        let session_secret = hex::encode(&seed);

        self.session_secrets
            .insert(keygen_session_id.clone(), session_secret.clone());
        self.session_private_keys
            .insert(keygen_session_id.clone(), session_private_key);

        let coordinator_private_key_bytes = self.coordinator_derived_private_key.secret_bytes();

        let mut expected_participants = vec![self.coordinator_user_id.clone()];
        for user_id in &self.participant_user_ids {
            expected_participants.push(user_id.clone());
        }
        // Sort in descending order to match the ordering in session.rs (newest UUIDv7 first)
        expected_participants.sort_by(|a, b| b.cmp(a));

        // Encrypt the TaprootTweak with session secret
        let taproot_tweak = TaprootTweak::UnspendableTaproot;
        let encrypted_taproot_tweak =
            keymeld_sdk::validation::encrypt_structured_data_with_session_key(
                &taproot_tweak,
                &session_secret,
                "taproot_tweak",
            )
            .map_err(|e| anyhow!("Failed to encrypt taproot tweak: {e}"))?;

        // Phase 1: Reserve the keygen session
        info!("📋 Phase 1: Reserving keygen session slot...");
        let reserve_request = ReserveKeygenSessionRequest {
            keygen_session_id: keygen_session_id.clone(),
            coordinator_user_id: self.coordinator_user_id.clone(),
            expected_participants: expected_participants.clone(),
            timeout_secs: 3600,
            max_signing_sessions: Some(10),
            encrypted_taproot_tweak,
        };

        let reserve_response = self
            .client
            .post(format!("{}/api/v1/keygen/reserve", self.config.gateway_url))
            .json(&reserve_request)
            .send()
            .await?;

        if !reserve_response.status().is_success() {
            return Err(anyhow!(
                "Failed to reserve keygen session: {}",
                reserve_response.text().await?
            ));
        }

        let reserve_data: ReserveKeygenSessionResponse = reserve_response.json().await?;

        info!(
            "✅ Phase 1 complete: Session {} reserved with coordinator enclave {}",
            reserve_data.keygen_session_id,
            reserve_data.coordinator_enclave_id.as_u32()
        );

        // Phase 2: Initialize the session with encrypted data
        info!(
            "🔐 Phase 2: Encrypting data for coordinator enclave {} and initializing session...",
            reserve_data.coordinator_enclave_id.as_u32()
        );

        // Now we know which enclave to encrypt for - use the coordinator's public key
        let enclave_public_key_bytes =
            hex::decode(&reserve_data.coordinator_public_key).map_err(|e| {
                anyhow!(
                    "Failed to decode coordinator enclave public key '{}': {}",
                    reserve_data.coordinator_public_key,
                    e
                )
            })?;
        let enclave_public_key = Secp256k1PublicKey::from_slice(&enclave_public_key_bytes)
            .map_err(|e| anyhow!("Invalid coordinator enclave public key: {e}"))?;

        tracing::debug!(
            "Client encrypting session secret with coordinator enclave {} public key: {}",
            reserve_data.coordinator_enclave_id.as_u32(),
            reserve_data.coordinator_public_key
        );

        // Encrypt the seed (not the hex-encoded session_secret) for the enclaves
        let encrypted_session_secret_bytes =
            SecureCrypto::ecies_encrypt(&enclave_public_key, &seed)
                .map_err(|e| anyhow!("Failed to encrypt session seed: {e}"))?;
        let encrypted_session_secret = hex::encode(&encrypted_session_secret_bytes);

        // Encrypt the coordinator private key with the coordinator enclave public key
        let encrypted_coordinator_key_bytes =
            SecureCrypto::ecies_encrypt(&enclave_public_key, &coordinator_private_key_bytes)
                .map_err(|e| anyhow!("Failed to encrypt coordinator private key: {e}"))?;
        let encrypted_key = hex::encode(&encrypted_coordinator_key_bytes);

        // Create and encrypt session data using typed struct
        let session_data = KeygenSessionData::new(self.coordinator_public_key.serialize().to_vec());
        let encrypted_session_data =
            keymeld_sdk::validation::encrypt_structured_data_with_session_key(
                &session_data,
                &session_secret,
                "keygen_session",
            )
            .map_err(|e| anyhow!("Failed to encrypt session data: {e}"))?;

        // Create and encrypt enclave data using typed struct
        let enclave_data = KeygenEnclaveData::new(encrypted_key.clone(), session_secret.clone());
        let encrypted_enclave_data =
            keymeld_sdk::validation::encrypt_structured_data_with_enclave_key(
                &enclave_data,
                &reserve_data.coordinator_public_key,
            )
            .map_err(|e| anyhow!("Failed to encrypt enclave data: {e}"))?;

        let initialize_request = InitializeKeygenSessionRequest {
            coordinator_pubkey: self.coordinator_public_key.serialize().to_vec(),
            coordinator_encrypted_private_key: encrypted_key,
            session_public_key: session_public_key.serialize().to_vec(),
            encrypted_session_secret,
            encrypted_session_data,
            encrypted_enclave_data,
            enclave_key_epoch: reserve_data.coordinator_key_epoch,
        };

        let initialize_response = self
            .client
            .post(format!(
                "{}/api/v1/keygen/{}/initialize",
                self.config.gateway_url, keygen_session_id
            ))
            .json(&initialize_request)
            .send()
            .await?;

        if !initialize_response.status().is_success() {
            return Err(anyhow!(
                "Failed to initialize keygen session: {}",
                initialize_response.text().await?
            ));
        }

        let initialize_data: InitializeKeygenSessionResponse = initialize_response.json().await?;

        info!(
            "✅ Phase 2 complete: Session {} initialized and moved to CollectingParticipants",
            initialize_data.keygen_session_id
        );

        // Store the coordinator enclave ID for later use during participant registration
        self.coordinator_enclave_ids.insert(
            keygen_session_id.clone(),
            reserve_data.coordinator_enclave_id,
        );

        // Poll for session status to ensure initialization is complete
        info!("⏳ Waiting for session initialization to complete...");
        self.wait_for_session_initialization(&keygen_session_id)
            .await?;
        info!("✅ Session initialization complete, proceeding with participant registration");

        Ok(keygen_session_id)
    }

    /// Poll keygen session status until it's properly initialized (moved to CollectingParticipants)
    async fn wait_for_session_initialization(&self, keygen_session_id: &SessionId) -> Result<()> {
        const MAX_RETRIES: u32 = 20;
        const RETRY_DELAY_MS: u64 = 250;

        for attempt in 1..=MAX_RETRIES {
            let session_signature = self.generate_session_signature(keygen_session_id)?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/keygen/{}/status",
                    self.config.gateway_url, keygen_session_id
                ))
                .header("X-Session-Signature", session_signature)
                .send()
                .await?;

            let status_code = response.status();
            if !status_code.is_success() {
                if attempt < MAX_RETRIES {
                    info!(
                        "Session status check failed (attempt {}/{}), retrying in {}ms...",
                        attempt, MAX_RETRIES, RETRY_DELAY_MS
                    );
                    tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                } else {
                    let error_text = response.text().await?;
                    return Err(anyhow!(
                        "Failed to get keygen status after {} attempts: HTTP {} - {}",
                        MAX_RETRIES,
                        status_code,
                        error_text
                    ));
                }
            }

            let status: KeygenSessionStatusResponse = response.json().await?;

            match status.status {
                KeygenStatusKind::CollectingParticipants => {
                    info!(
                        "✅ Session {} is now accepting participants (attempt {})",
                        keygen_session_id, attempt
                    );
                    return Ok(());
                }
                KeygenStatusKind::Reserved => {
                    if attempt < MAX_RETRIES {
                        info!(
                            "Session {} still reserved, waiting for initialization (attempt {}/{})",
                            keygen_session_id, attempt, MAX_RETRIES
                        );
                        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    } else {
                        return Err(anyhow!(
                            "Session {} stuck in reserved state after {} attempts",
                            keygen_session_id,
                            MAX_RETRIES
                        ));
                    }
                }
                other_status => {
                    return Err(anyhow!(
                        "Session {} in unexpected state: {:?}",
                        keygen_session_id,
                        other_status
                    ));
                }
            }
        }

        Err(anyhow!(
            "Timeout waiting for session {} initialization",
            keygen_session_id
        ))
    }

    /// Share session secret out of band between coordinator and other participants
    fn share_session_secret_out_of_band(&self, session_secret: &str) {
        info!("🔐 Session secret shared out-of-band with participants");
        info!("🔗 Secret: {}", &session_secret[..8]);
    }

    pub async fn register_keygen_participants(
        &mut self,
        keygen_session_id: &SessionId,
    ) -> Result<()> {
        info!("📝 Registering keygen participants...");

        // Wait for all enclaves to be healthy before proceeding
        self.wait_for_all_enclaves_healthy().await?;

        // Get available slots to determine enclave assignments (with retry for race conditions)
        const MAX_SLOTS_RETRIES: u32 = 5;
        const SLOTS_RETRY_DELAY_MS: u64 = 200;

        let slots_response = {
            let mut last_error = None;
            let mut slots = None;

            for attempt in 1..=MAX_SLOTS_RETRIES {
                let response = self
                    .client
                    .get(format!(
                        "{}/api/v1/keygen/{}/slots",
                        self.config.gateway_url, keygen_session_id
                    ))
                    .send()
                    .await?;

                let status_code = response.status();
                if status_code.is_success() {
                    slots = Some(response.json::<GetAvailableSlotsResponse>().await?);
                    break;
                }

                let error_text = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "Unknown error".to_string());

                // Retry on race condition errors (session not yet initialized)
                if Self::is_race_condition_error(&error_text) && attempt < MAX_SLOTS_RETRIES {
                    warn!(
                        "⚠️  Slots request race condition (attempt {}/{}): {}. Retrying in {}ms...",
                        attempt, MAX_SLOTS_RETRIES, error_text, SLOTS_RETRY_DELAY_MS
                    );
                    tokio::time::sleep(Duration::from_millis(SLOTS_RETRY_DELAY_MS)).await;
                    continue;
                }

                last_error = Some(format!("HTTP {} - {}", status_code, error_text));
                break;
            }

            match slots {
                Some(s) => s,
                None => {
                    return Err(anyhow::anyhow!(
                        "Failed to get available slots after {} attempts: {}",
                        MAX_SLOTS_RETRIES,
                        last_error.unwrap_or_else(|| "Unknown error".to_string())
                    ));
                }
            }
        };

        info!(
            "Found {} available slots for keygen session",
            slots_response.available_slots.len()
        );

        // Try participant registration - individual methods now handle race condition retries
        info!("🚀 Starting participant registration with race condition protection...");
        match self
            .try_register_all_participants(keygen_session_id, &slots_response)
            .await
        {
            Ok(_) => {
                info!("✅ Successfully registered all participants (race condition fix working)");
            }
            Err(e) => {
                error!(
                    "❌ Failed to register participants despite race condition fixes: {}",
                    e
                );
                return Err(e);
            }
        }

        Ok(())
    }

    async fn wait_for_all_enclaves_healthy(&self) -> Result<()> {
        info!("🏥 Waiting for all enclaves to be healthy...");

        let mut retry_count = 0;
        const MAX_HEALTH_RETRIES: u32 = 30;
        const HEALTH_CHECK_DELAY_MS: u64 = 1000;

        loop {
            match self
                .client
                .get(format!("{}/api/v1/health/detail", self.config.gateway_url))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => {
                    match response.json::<HealthCheckResponse>().await {
                        Ok(health_data) => {
                            let healthy_enclaves = health_data.healthy_enclaves as u64;
                            let total_enclaves = health_data.total_enclaves as u64;

                            info!(
                                "🏥 Health check: {}/{} enclaves healthy",
                                healthy_enclaves, total_enclaves
                            );

                            if total_enclaves > 0 && healthy_enclaves == total_enclaves {
                                info!(
                                    "✅ All {} enclaves are healthy, proceeding with registration",
                                    total_enclaves
                                );
                                return Ok(());
                            }

                            if retry_count >= MAX_HEALTH_RETRIES {
                                return Err(anyhow!(
                                    "Not all enclaves are healthy after {} attempts. {}/{} enclaves healthy. Please ensure all enclave services are running.",
                                    MAX_HEALTH_RETRIES, healthy_enclaves, total_enclaves
                                ));
                            }
                        }
                        Err(e) => {
                            warn!("Failed to parse health response: {}", e);
                        }
                    }
                }
                Ok(response) => {
                    warn!(
                        "Health check returned non-success status: {}",
                        response.status()
                    );
                }
                Err(e) => {
                    warn!("Health check request failed: {}", e);
                }
            }

            retry_count += 1;
            tokio::time::sleep(tokio::time::Duration::from_millis(HEALTH_CHECK_DELAY_MS)).await;
        }
    }

    async fn try_register_all_participants(
        &mut self,
        keygen_session_id: &SessionId,
        slots_response: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        self.register_keygen_coordinator_with_retry(keygen_session_id, slots_response)
            .await?;

        let participants_len = self.participants.len();
        for i in 0..participants_len {
            self.register_keygen_participant_with_retry(keygen_session_id, i, slots_response)
                .await?;
        }

        self.verify_keygen_participants_registered(keygen_session_id)
            .await?;

        Ok(())
    }

    /// Check if an error indicates a session state race condition
    fn is_race_condition_error(error_msg: &str) -> bool {
        error_msg.contains("reserved but not yet initialized")
            || error_msg.contains("session is reserved")
            || error_msg.contains("not yet ready")
            || error_msg.contains("still initializing")
    }

    async fn register_keygen_coordinator_with_retry(
        &mut self,
        keygen_session_id: &SessionId,
        slots: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 200;

        for attempt in 1..=MAX_RETRIES {
            match self
                .register_keygen_coordinator(keygen_session_id, slots)
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let error_msg = e.to_string();
                    if Self::is_race_condition_error(&error_msg) && attempt < MAX_RETRIES {
                        warn!(
                                "Race condition detected for coordinator: {}. Retrying in {}ms (attempt {}/{})",
                                error_msg, RETRY_DELAY_MS, attempt, MAX_RETRIES
                            );
                        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    }
                    return Err(anyhow!(
                        "Failed to register coordinator after {} retries: {}",
                        MAX_RETRIES,
                        e
                    ));
                }
            }
        }
        Ok(())
    }

    async fn register_keygen_coordinator(
        &mut self,
        keygen_session_id: &SessionId,
        slots: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        info!("👤 Registering coordinator...");

        // Find the slot for the coordinator by matching user_id
        let coordinator_slot = slots
            .available_slots
            .iter()
            .find(|slot| slot.user_id == self.coordinator_user_id)
            .ok_or(anyhow!(
                "No available slot for coordinator {}",
                self.coordinator_user_id
            ))?;

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or(anyhow!(
                "Session secret not found for keygen session: {keygen_session_id}"
            ))?
            .clone();

        self.share_session_secret_out_of_band(&session_secret);

        // Get the coordinator's assigned enclave public key
        let enclave_public_key_response: EnclavePublicKeyResponse = self
            .client
            .get(format!(
                "{}/api/v1/enclaves/{}/public-key",
                self.config.gateway_url,
                coordinator_slot.enclave_id.as_u32()
            ))
            .send()
            .await?
            .json()
            .await?;

        // Encrypt the coordinator private key with ECIES using assigned enclave public key
        let encrypted_private_key = {
            let private_key_bytes = &self.coordinator_derived_private_key.as_ref()[..32];

            let encrypted_data = SecureCrypto::ecies_encrypt_from_hex(
                &enclave_public_key_response.public_key,
                private_key_bytes,
            )?;
            hex::encode(encrypted_data)
        };

        // Create session data with public key and encrypt it using typed struct
        let session_data = KeygenParticipantSessionData::new_with_public_key(
            self.coordinator_user_id.clone(),
            self.coordinator_public_key.serialize().to_vec(),
        );
        let encrypted_session_data =
            keymeld_sdk::validation::encrypt_structured_data_with_session_key(
                &session_data,
                &session_secret,
                "keygen_participant_session",
            )
            .map_err(|e| anyhow!("Failed to encrypt session data: {e}"))?;

        // Derive session-specific auth pubkey for authorization
        let coordinator_private_key_bytes = self.coordinator_derived_private_key.secret_bytes();
        let (_, auth_pubkey) = SecureCrypto::derive_session_auth_keypair(
            &coordinator_private_key_bytes,
            &keygen_session_id.to_string(),
        )
        .map_err(|e| anyhow!("Failed to derive session auth keypair: {e}"))?;

        let request = RegisterKeygenParticipantRequest {
            keygen_session_id: keygen_session_id.clone(),
            user_id: self.coordinator_user_id.clone(),
            encrypted_private_key,
            public_key: self.coordinator_public_key.serialize().to_vec(),
            encrypted_session_data,
            enclave_public_key: enclave_public_key_response.public_key.clone(),
            enclave_key_epoch: enclave_public_key_response.key_epoch,
            require_signing_approval: true,
            auth_pubkey: auth_pubkey.serialize().to_vec(),
        };

        let session_signature = self.generate_session_signature(keygen_session_id)?;

        let response = self
            .client
            .post(format!(
                "{}/api/v1/keygen/{}/participants",
                self.config.gateway_url, keygen_session_id
            ))
            .header("X-Session-Signature", session_signature)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(anyhow!(
                "Failed to register coordinator (HTTP {}): {}",
                status,
                error_text
            ));
        }

        info!("✅ Coordinator registered successfully");
        Ok(())
    }

    async fn register_keygen_participant_with_retry(
        &mut self,
        keygen_session_id: &SessionId,
        participant_index: usize,
        slots: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 200;

        for attempt in 1..=MAX_RETRIES {
            match self
                .register_keygen_participant(keygen_session_id, participant_index, slots)
                .await
            {
                Ok(_) => return Ok(()),
                Err(e) => {
                    let error_msg = e.to_string();
                    if Self::is_race_condition_error(&error_msg) && attempt < MAX_RETRIES {
                        warn!(
                                "Race condition detected for participant {}: {}. Retrying in {}ms (attempt {}/{})",
                                self.participant_user_ids[participant_index], error_msg, RETRY_DELAY_MS, attempt, MAX_RETRIES
                            );
                        tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                        continue;
                    }
                    return Err(anyhow!(
                        "Failed to register participant {} after {} retries: {}",
                        self.participant_user_ids[participant_index],
                        MAX_RETRIES,
                        e
                    ));
                }
            }
        }
        Ok(())
    }

    async fn register_keygen_participant(
        &mut self,
        keygen_session_id: &SessionId,
        participant_index: usize,
        slots: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        let participant = &self.participants[participant_index];

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or(anyhow!(
                "Session secret not found for keygen session: {keygen_session_id}"
            ))?
            .clone();

        // Get participant's assigned slot by matching user_id
        let participant_user_id = &self.participant_user_ids[participant_index];
        let participant_slot = slots
            .available_slots
            .iter()
            .find(|slot| &slot.user_id == participant_user_id)
            .ok_or(anyhow!(
                "No available slot for participant {participant_user_id}"
            ))?;

        // Get the assigned enclave's public key
        let enclave_public_key_response: EnclavePublicKeyResponse = self
            .client
            .get(format!(
                "{}/api/v1/enclaves/{}/public-key",
                self.config.gateway_url,
                participant_slot.enclave_id.as_u32()
            ))
            .send()
            .await?
            .json()
            .await?;

        // Encrypt the participant private key with ECIES using assigned enclave public key
        let encrypted_private_key = {
            let private_key_bytes = &participant.derived_private_key.as_ref()[..32];

            let encrypted_data = SecureCrypto::ecies_encrypt_from_hex(
                &enclave_public_key_response.public_key,
                private_key_bytes,
            )?;
            hex::encode(encrypted_data)
        };

        // Create session data with public key and encrypt it using typed struct
        let session_data = KeygenParticipantSessionData::new_with_public_key(
            self.participant_user_ids[participant_index].clone(),
            participant.public_key.serialize().to_vec(),
        );
        let encrypted_session_data =
            keymeld_sdk::validation::encrypt_structured_data_with_session_key(
                &session_data,
                &session_secret,
                "keygen_participant_session",
            )
            .map_err(|e| anyhow!("Failed to encrypt session data: {e}"))?;

        // Derive session-specific auth pubkey for authorization
        let participant_private_key_bytes = participant.derived_private_key.secret_bytes();
        let (_, auth_pubkey) = SecureCrypto::derive_session_auth_keypair(
            &participant_private_key_bytes,
            &keygen_session_id.to_string(),
        )
        .map_err(|e| anyhow!("Failed to derive session auth keypair: {e}"))?;

        // Check if this participant requires approval
        let require_signing_approval = self
            .participants_requiring_approval
            .contains(&participant_index);

        let request = RegisterKeygenParticipantRequest {
            keygen_session_id: keygen_session_id.clone(),
            user_id: participant_user_id.clone(),
            encrypted_private_key,
            public_key: participant.public_key.serialize().to_vec(),
            encrypted_session_data,
            enclave_public_key: enclave_public_key_response.public_key.clone(),
            enclave_key_epoch: enclave_public_key_response.key_epoch,
            require_signing_approval,
            auth_pubkey: auth_pubkey.serialize().to_vec(),
        };

        let session_signature = self.generate_session_signature(keygen_session_id)?;

        let response = self
            .client
            .post(format!(
                "{}/api/v1/keygen/{}/participants",
                self.config.gateway_url, keygen_session_id
            ))
            .header("X-Session-Signature", session_signature)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error response".to_string());
            return Err(anyhow!(
                "Failed to register participant {} (HTTP {}): {}",
                self.participant_user_ids[participant_index],
                status,
                error_text
            ));
        }

        info!(
            "✅ Participant {} registered",
            self.participant_user_ids[participant_index]
        );
        Ok(())
    }

    async fn verify_keygen_participants_registered(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<()> {
        loop {
            let session_signature = self.generate_session_signature(keygen_session_id)?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/keygen/{}/status",
                    self.config.gateway_url, keygen_session_id
                ))
                .header("X-Session-Signature", session_signature)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow!(
                    "Failed to get keygen status: {}",
                    response.text().await?
                ));
            }

            let status: KeygenSessionStatusResponse = response.json().await?;

            if status.registered_participants >= self.config.num_signers as usize {
                info!(
                    "✅ All {} participants registered",
                    status.registered_participants
                );
                break;
            }

            info!(
                "⏳ Waiting for participants: {}/{}",
                status.registered_participants, self.config.num_signers
            );
            sleep(Duration::from_secs(1)).await;
        }

        Ok(())
    }

    pub async fn wait_for_keygen_completion(
        &mut self,
        keygen_session_id: &SessionId,
    ) -> Result<String> {
        info!("⏳ Waiting for keygen completion...");

        loop {
            let session_signature = self.generate_session_signature(keygen_session_id)?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/keygen/{}/status",
                    self.config.gateway_url, keygen_session_id
                ))
                .header("X-Session-Signature", session_signature)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(anyhow!(
                    "Failed to get keygen status: {}",
                    response.text().await?
                ));
            }

            let status: KeygenSessionStatusResponse = response.json().await?;

            match status.status {
                KeygenStatusKind::Completed => {
                    if let Some(aggregate_key) = status.aggregate_public_key {
                        return Ok(aggregate_key);
                    } else {
                        return Err(anyhow!("Keygen completed but no aggregate key found"));
                    }
                }
                KeygenStatusKind::Failed => {
                    return Err(anyhow!("Keygen session failed"));
                }
                KeygenStatusKind::Reserved => {
                    info!("Keygen session is reserved but not yet initialized...");
                }
                KeygenStatusKind::CollectingParticipants => {
                    info!("Keygen still collecting participants...");
                }
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    pub async fn create_signing_session(
        &mut self,
        keygen_session_id: &SessionId,
        psbt: &Psbt,
    ) -> Result<SessionId> {
        let signing_session_id: SessionId = Uuid::now_v7().into();
        let sighash = self.calculate_taproot_sighash(psbt)?;

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or(anyhow!(
                "Session secret not found for keygen session: {keygen_session_id}"
            ))?
            .clone();

        self.session_secrets
            .insert(signing_session_id.clone(), session_secret.clone());

        let encrypted_adaptor_configs = String::new();

        let encrypted_message = keymeld_sdk::validation::encrypt_session_data(
            &hex::encode(&sighash[..]),
            &session_secret,
        )?;

        // Create a batch item for the single message
        let batch_item = keymeld_sdk::SigningBatchItem {
            batch_item_id: uuid::Uuid::now_v7(),
            message_hash: sighash.to_vec(),
            encrypted_message: Some(encrypted_message),
            encrypted_adaptor_configs: if encrypted_adaptor_configs.is_empty() {
                None
            } else {
                Some(encrypted_adaptor_configs)
            },
        };

        let request = CreateSigningSessionRequest {
            signing_session_id: signing_session_id.clone(),
            keygen_session_id: keygen_session_id.clone(),
            timeout_secs: 1800,
            batch_items: vec![batch_item],
        };

        let session_signature = self.generate_session_signature(keygen_session_id)?;

        let response = self
            .client
            .post(format!("{}/api/v1/signing", self.config.gateway_url))
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

        info!("✅ Signing session {} created", signing_session_id);
        Ok(signing_session_id)
    }

    pub async fn wait_for_signing_completion(
        &mut self,
        signing_session_id: &SessionId,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<u8>> {
        info!("⏳ Waiting for signing completion...");

        loop {
            let user_signature = self.generate_user_signature(
                signing_session_id,
                &self.coordinator_user_id,
                &self.coordinator_derived_private_key,
                keygen_session_id,
            )?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/signing/{}/status/{}",
                    self.config.gateway_url, signing_session_id, self.coordinator_user_id
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
                    if let Some(first_result) = status.batch_results.first() {
                        if let Some(ref encrypted_sig) = first_result.signature {
                            let session_secret =
                                self.session_secrets.get(keygen_session_id).ok_or(anyhow!(
                                "Session secret not found for keygen session: {keygen_session_id}"
                            ))?;

                            let signature_bytes =
                                keymeld_sdk::validation::decrypt_signature_with_secret(
                                    encrypted_sig,
                                    session_secret,
                                )?;

                            return Ok(signature_bytes);
                        } else if let Some(ref error) = first_result.error {
                            return Err(anyhow!("Signing failed: {}", error));
                        } else {
                            return Err(anyhow!("Signing completed but no signature found"));
                        }
                    } else {
                        return Err(anyhow!("Signing completed but no batch results found"));
                    }
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
                    info!("✍️  Finalizing signature...");
                }
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    pub async fn apply_signature_and_broadcast(
        &self,
        mut psbt: Psbt,
        signature: &[u8],
    ) -> Result<Transaction> {
        info!("📝 Applying signature to transaction...");

        if signature.len() != 64 {
            return Err(anyhow!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature.len()
            ));
        }

        let signature = Signature::from_slice(signature)
            .map_err(|e| anyhow!("Failed to parse signature: {e}"))?;

        if psbt.inputs.is_empty() {
            return Err(anyhow!("PSBT has no inputs"));
        }

        // For taproot key-path spending, witness should contain just the signature
        // Following musig2 reference: only set witness, not tap_key_sig
        let mut witness = Witness::new();
        witness.push(signature.as_ref());
        psbt.inputs[0].final_script_witness = Some(witness);

        let signed_tx = psbt.extract_tx()?;

        info!("🔍 Transaction being broadcast:");
        info!("  - Transaction ID: {}", signed_tx.compute_txid());
        info!("✅ Transaction signed successfully");

        // Use batcher if enabled, otherwise direct RPC
        let txid = if let Some(ref batcher) = self.rpc_batcher {
            let raw_tx_hex = bitcoin::consensus::encode::serialize_hex(&signed_tx);
            let txid_str = batcher.send_raw_transaction(&raw_tx_hex).await?;
            Txid::from_str(&txid_str).map_err(|e| anyhow!("Invalid txid from batcher: {}", e))?
        } else {
            retry_bitcoin_rpc("send_raw_transaction", || {
                self.rpc_client.send_raw_transaction(&signed_tx)
            })
            .await?
        };

        info!("📡 Transaction broadcast successfully: {}", txid);

        Ok(signed_tx)
    }

    pub fn calculate_taproot_sighash(&self, psbt: &Psbt) -> Result<[u8; 32]> {
        let tx = &psbt.unsigned_tx;

        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .clone()
                    .ok_or(anyhow!("Missing witness UTXO for input"))
            })
            .collect::<Result<Vec<_>>>()?;

        if !prevouts.is_empty() {
            info!("  - Input 0 value: {} sats", prevouts[0].value.to_sat());
            info!(
                "  - Input 0 scriptPubKey: {}",
                hex::encode(prevouts[0].script_pubkey.as_bytes())
            );
        }

        let prevouts = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .map_err(|e| anyhow!("Failed to calculate taproot sighash: {e}"))?;

        Ok(sighash.to_byte_array())
    }

    pub fn generate_session_signature(&self, session_id: &SessionId) -> Result<String> {
        // Get the stored private key for this session
        let private_key = self.session_private_keys.get(session_id).ok_or(anyhow!(
            "Session private key not found for session: {session_id}"
        ))?;

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Create the message to sign: session_id:nonce
        let message = format!("{session_id}:{nonce}");
        let message_hash = sha256::Hash::hash(message.as_bytes());
        let message_secp = Message::from_digest(message_hash.to_byte_array());

        // Convert secp256k1::SecretKey to bitcoin::secp256k1::SecretKey using raw bytes
        let private_key_bytes = &private_key.as_ref()[..32];
        let bitcoin_private_key = bitcoin::secp256k1::SecretKey::from_slice(private_key_bytes)
            .map_err(|e| anyhow!("Failed to convert private key: {e}"))?;

        // Sign the message with the session private key
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&message_secp, &bitcoin_private_key);
        let signature_hex = hex::encode(signature.serialize_compact());

        // Return in format "nonce:signature"
        Ok(format!("{nonce}:{signature_hex}"))
    }

    pub async fn approve_signing_session(
        &self,
        signing_session_id: &SessionId,
        user_id: &UserId,
        private_key: &SecretKey,
        keygen_session_id: &SessionId,
    ) -> Result<()> {
        info!(
            "📝 Starting approval process for signing session {} and user: {}",
            signing_session_id, user_id
        );

        const MAX_RETRIES: u32 = 10;
        const INITIAL_DELAY_MS: u64 = 500;

        let user_signature = self.generate_user_signature(
            signing_session_id,
            user_id,
            private_key,
            keygen_session_id,
        )?;

        let mut retry_count = 0;
        loop {
            let response = self
                .client
                .post(format!(
                    "{}/api/v1/signing/{}/approve/{}",
                    self.config.gateway_url, signing_session_id, user_id
                ))
                .header("X-User-Signature", user_signature.clone())
                .send()
                .await?;

            if response.status().is_success() {
                info!(
                    "✅ Signing session {} successfully approved for user: {}",
                    signing_session_id, user_id
                );
                return Ok(());
            }

            // Handle 404 - signing session not ready yet
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                if retry_count >= MAX_RETRIES {
                    return Err(anyhow!(
                        "Signing session {} still not ready after {} retries",
                        signing_session_id,
                        MAX_RETRIES
                    ));
                }

                let delay_ms = INITIAL_DELAY_MS * (2_u64.pow((retry_count).min(4))); // Cap at 2^4 = 16x multiplier
                info!(
                    "⏳ Signing session {} not ready for approval - session initialization still in progress (attempt {}/{}), retrying in {}ms",
                    signing_session_id,
                    retry_count + 1,
                    MAX_RETRIES,
                    delay_ms
                );

                retry_count += 1;
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                continue;
            }

            // Other errors - fail immediately
            return Err(anyhow!(
                "Failed to approve signing session for {}: {}",
                user_id,
                response.text().await?
            ));
        }
    }

    /// Derive a shared private key from the session secret for authentication
    fn derive_session_auth_key(&self, session_secret: &str) -> Result<SecretKey> {
        let key_material = sha256::Hash::hash(session_secret.as_bytes());
        SecretKey::from_slice(key_material.as_ref())
            .map_err(|e| anyhow!("Failed to derive auth key from session secret: {e}"))
    }

    /// Get the public key for session authentication (for gateway validation)
    pub fn get_session_auth_public_key(&self, session_secret: &str) -> Result<PublicKey> {
        let private_key = self.derive_session_auth_key(session_secret)?;
        let secp = Secp256k1::new();
        Ok(PublicKey::from_secret_key(&secp, &private_key))
    }

    /// Helper method to decrypt and convert aggregate key to hex for display
    pub fn decrypt_aggregate_key_for_display(
        &self,
        encrypted_aggregate_key: &str,
        keygen_session_id: &SessionId,
    ) -> Result<String> {
        // Get the session secret for decryption
        let session_secret_hex = self.session_secrets.get(keygen_session_id).ok_or_else(|| {
            anyhow!(
                "Session secret not found for keygen session: {}",
                keygen_session_id
            )
        })?;
        let session_secret = SessionSecret::from_hex(session_secret_hex)?;

        // Decrypt the aggregate public key
        let encrypted_data = EncryptedData::from_hex(encrypted_aggregate_key)
            .map_err(|e| anyhow!("Failed to decode encrypted aggregate key: {}", e))?;
        let key_bytes = session_secret
            .decrypt(&encrypted_data, "aggregate_public_key")
            .map_err(|e| anyhow!("Failed to decrypt aggregate key: {}", e))?;

        Ok(hex::encode(key_bytes))
    }

    /// Generate ECDSA signature for user approval using session-specific auth key
    pub fn generate_user_signature(
        &self,
        signing_session_id: &SessionId,
        user_id: &UserId,
        private_key: &SecretKey,
        keygen_session_id: &SessionId,
    ) -> Result<String> {
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);

        // Use session auth key for signing
        let private_key_bytes = private_key.secret_bytes();
        let signature = SecureCrypto::sign_auth_message_with_session_key(
            &private_key_bytes,
            &keygen_session_id.to_string(),
            &signing_session_id.to_string(),
            &user_id.to_string(),
            &nonce_bytes,
        )
        .map_err(|e| anyhow!("Failed to sign auth message: {e}"))?;

        // Return in format "nonce:signature"
        Ok(format!(
            "{}:{}",
            hex::encode(nonce_bytes),
            hex::encode(signature)
        ))
    }
}
