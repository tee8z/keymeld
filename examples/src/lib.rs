pub mod adaptor_utils;

use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use bdk_wallet::{
    bitcoin::{
        absolute::LockTime,
        bip32::{ChildNumber, Xpriv},
        key::TweakedPublicKey,
        psbt::Psbt,
        secp256k1::{PublicKey, Secp256k1, SecretKey},
        transaction::Version,
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
        TxOut, Witness,
    },
    keys::bip39::Mnemonic,
    template::Bip86,
    KeychainKind, Wallet,
};
use bitcoin::sighash::{Prevouts, SighashCache};

use keymeld_core::{
    api::{
        CreateKeygenSessionRequest, CreateKeygenSessionResponse, CreateSigningSessionRequest,
        KeygenSessionStatusResponse, RegisterKeygenParticipantRequest,
        SigningSessionStatusResponse, TaprootTweak,
    },
    session::{KeygenStatusKind, SigningStatusKind},
};
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use bitcoin::hashes::{sha256, Hash};

use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;
use tokio::time::{sleep, Duration};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleConfig {
    #[serde(with = "network_serde")]
    pub network: Network,
    pub num_signers: u32,
    pub gateway_url: String,
    pub bitcoin_rpc_url: String,
    pub bitcoin_rpc_auth: BitcoinRpcAuth,
    pub key_files_dir: String,
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
                "Unknown network: {}",
                network_str
            ))),
        }
    }
}

#[derive(Debug)]
pub struct Participant {
    pub user_id: String,
    pub wallet: Wallet,
    pub derived_private_key: SecretKey,
    pub public_key: PublicKey,
}

impl Participant {
    pub fn new(
        user_id: String,
        mnemonic: Mnemonic,
        network: Network,
        derivation_index: u32,
    ) -> Result<Self> {
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
        let public_key = derived_private_key.public_key(&secp);

        let external_descriptor = Bip86(derived_xpriv, KeychainKind::External);
        let internal_descriptor = Bip86(derived_xpriv, KeychainKind::Internal);
        let wallet = Wallet::create(external_descriptor, internal_descriptor)
            .network(network)
            .create_wallet_no_persist()?;

        Ok(Self {
            user_id,
            wallet,
            derived_private_key,
            public_key,
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
    pub coordinator_user_id: String,
    pub participant_user_ids: Vec<String>,
    pub rpc_client: RpcClient,
    pub amount: u64,
    pub destination: String,
    pub session_secrets: HashMap<String, String>,
}

impl KeyMeldE2ETest {
    pub async fn new(config: ExampleConfig, amount: u64, destination: String) -> Result<Self> {
        info!("🔧 Initializing KeyMeld E2E Test");
        info!("Network: {}", config.network);
        info!("Participants: {}", config.num_signers);
        info!("Amount: {} sats", amount);

        let client = Client::new();

        let auth = Auth::UserPass(
            config.bitcoin_rpc_auth.username.clone(),
            config.bitcoin_rpc_auth.password.clone(),
        );

        let rpc_client = RpcClient::new(&config.bitcoin_rpc_url, auth)
            .map_err(|e| anyhow!("Failed to create RPC client: {e}"))?;

        let coordinator_mnemonic = Self::load_or_create_coordinator_private_key(&config)?;
        let coordinator = Participant::new(
            "coordinator".to_string(),
            coordinator_mnemonic,
            config.network,
            0,
        )?;

        let coordinator_user_id = uuid::Uuid::now_v7().to_string();
        info!("👤 Coordinator user ID: {}", coordinator_user_id);

        let mut participant_user_ids = vec![coordinator_user_id.clone()];
        for _ in 1..config.num_signers {
            let user_id = uuid::Uuid::now_v7().to_string();
            participant_user_ids.push(user_id);
        }

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
            amount,
            destination,
            session_secrets: HashMap::new(),
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

        for i in 1..self.config.num_signers {
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

            let participant = Participant::new(
                format!("participant_{}", i),
                mnemonic,
                self.config.network,
                i,
            )?;

            self.participants.push(participant);
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

        let funding_txid = self
            .rpc_client
            .send_to_address(
                &coordinator_address,
                Amount::from_sat(funding_amount),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| anyhow!("Failed to fund coordinator: {e}"))?;

        info!("📡 Funding transaction: {}", funding_txid);

        // Generate a block to confirm
        let _ = self
            .rpc_client
            .generate_to_address(1, &coordinator_address)
            .map_err(|e| anyhow!("Failed to generate block: {e}"))?;

        // Wait for confirmation
        loop {
            sleep(Duration::from_secs(1)).await;

            let tx_info = self.rpc_client.get_transaction(&funding_txid, None);
            if let Ok(info) = tx_info {
                if info.info.confirmations >= 1 {
                    info!(
                        "✅ Funding confirmed with {} confirmations",
                        info.info.confirmations
                    );
                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn fund_aggregate_key_address(&mut self, aggregate_key: &str) -> Result<OutPoint> {
        info!("💰 Funding aggregate key address...");

        let key_bytes =
            hex::decode(aggregate_key).map_err(|e| anyhow!("Invalid hex in aggregate key: {e}"))?;
        let pubkey =
            PublicKey::from_slice(&key_bytes).map_err(|e| anyhow!("Invalid public key: {e}"))?;
        let (x_only, _) = pubkey.x_only_public_key();
        let aggregate_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only);

        let aggregate_address = Address::p2tr_tweaked(aggregate_pubkey, self.config.network);
        info!("📍 Aggregate key address: {}", aggregate_address);

        let coordinator_address = self
            .coordinator_wallet
            .peek_address(KeychainKind::External, 0)
            .address;

        let required_amount = self.amount + 5_000;
        let funding_txid = self
            .rpc_client
            .send_to_address(
                &aggregate_address,
                Amount::from_sat(required_amount),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .map_err(|e| anyhow!("Failed to fund aggregate address: {e}"))?;

        info!("📡 Funding transaction: {}", funding_txid);

        let _ = self
            .rpc_client
            .generate_to_address(1, &coordinator_address)
            .map_err(|e| anyhow!("Failed to generate block: {e}"))?;

        loop {
            sleep(Duration::from_secs(1)).await;

            let tx_info = self.rpc_client.get_transaction(&funding_txid, None);
            if let Ok(info) = tx_info {
                if info.info.confirmations >= 1 {
                    info!("✅ Aggregate funding confirmed");
                    break;
                }
            }
        }

        Ok(OutPoint::new(funding_txid, 0))
    }

    pub async fn create_musig2_transaction(
        &self,
        aggregate_key: &str,
        aggregate_utxo: &OutPoint,
    ) -> Result<Psbt> {
        info!("📝 Creating MuSig2 transaction...");

        let key_bytes =
            hex::decode(aggregate_key).map_err(|e| anyhow!("Invalid hex in aggregate key: {e}"))?;
        let pubkey =
            PublicKey::from_slice(&key_bytes).map_err(|e| anyhow!("Invalid public key: {e}"))?;
        let (x_only, _) = pubkey.x_only_public_key();
        let aggregate_pubkey = TweakedPublicKey::dangerous_assume_tweaked(x_only);

        let aggregate_address = Address::p2tr_tweaked(aggregate_pubkey, self.config.network);

        let destination_address = Address::from_str(&self.destination)
            .map_err(|e| anyhow!("Invalid destination address: {e}"))?
            .require_network(self.config.network)
            .map_err(|e| anyhow!("Destination address invalid for network: {e}"))?;

        let utxo_info = self
            .rpc_client
            .get_transaction(&aggregate_utxo.txid, None)
            .map_err(|e| anyhow!("Failed to get UTXO info: {e}"))?;

        let utxo_output = &utxo_info.transaction()?.output[aggregate_utxo.vout as usize];
        let input_amount = utxo_output.value;

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
        psbt.inputs[0].tap_internal_key = Some(aggregate_pubkey.to_x_only_public_key());

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

    pub async fn create_keygen_session(&mut self) -> Result<String> {
        info!("🔑 Creating keygen session...");

        let keygen_session_id = Uuid::now_v7().to_string();
        let session_secret = keymeld_core::api::validation::generate_session_secret()?;

        self.session_secrets
            .insert(keygen_session_id.clone(), session_secret.clone());

        let session_secret_obj = keymeld_core::crypto::SessionSecret::from_hex(&session_secret)?;
        let encrypted_key = session_secret_obj.encrypt(
            &self.coordinator_derived_private_key.secret_bytes(),
            "private_key",
        )?;

        let mut expected_participants = vec![self.coordinator_user_id.clone().try_into().unwrap()];
        for participant in &self.participants {
            expected_participants.push(participant.user_id.clone().try_into().unwrap());
        }

        let request = CreateKeygenSessionRequest {
            keygen_session_id: keygen_session_id.clone().try_into().unwrap(),
            coordinator_pubkey: self.coordinator_public_key.serialize().to_vec(),
            coordinator_encrypted_private_key: encrypted_key.to_hex_json()?,
            coordinator_enclave_id: 1u32.into(),
            expected_participants,
            timeout_secs: 1800,
            encrypted_session_secret: session_secret.clone(),
            max_signing_sessions: None,
            taproot_tweak_config: TaprootTweak::None,
        };

        let session_hmac = self.generate_session_hmac(
            &keygen_session_id,
            &self.coordinator_user_id,
            &session_secret,
        )?;

        let response = self
            .client
            .post(format!("{}/api/v1/keygen", self.config.gateway_url))
            .header("X-Session-HMAC", session_hmac)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to create keygen session: {}",
                response.text().await?
            ));
        }

        let response_data: CreateKeygenSessionResponse = response.json().await?;
        info!(
            "✅ Keygen session {} created",
            response_data.keygen_session_id
        );

        Ok(keygen_session_id)
    }

    fn share_session_secret_out_of_band(&self, session_secret: &str) {
        info!("🔐 Session secret shared out-of-band with participants");
        info!("🔗 Secret: {}", &session_secret[..8]);
    }

    pub async fn register_keygen_participants(&mut self, keygen_session_id: &str) -> Result<()> {
        info!("📝 Registering keygen participants...");

        let keygen_session_id_clone = keygen_session_id.to_string();
        self.register_keygen_coordinator(&keygen_session_id_clone)
            .await?;

        let participants_len = self.participants.len();
        for i in 0..participants_len {
            self.register_keygen_participant(&keygen_session_id_clone, i)
                .await?;
        }

        self.verify_keygen_participants_registered(&keygen_session_id_clone)
            .await?;

        Ok(())
    }

    async fn register_keygen_coordinator(&mut self, keygen_session_id: &str) -> Result<()> {
        info!("👤 Registering coordinator...");

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session: {}",
                    keygen_session_id
                )
            })?
            .clone();

        self.share_session_secret_out_of_band(&session_secret);

        let session_secret_obj = keymeld_core::crypto::SessionSecret::from_hex(&session_secret)?;
        let encrypted_key = session_secret_obj.encrypt(
            &self.coordinator_derived_private_key.secret_bytes(),
            "private_key",
        )?;

        let request = RegisterKeygenParticipantRequest {
            keygen_session_id: keygen_session_id.try_into().unwrap(),
            user_id: self.coordinator_user_id.clone().try_into().unwrap(),
            encrypted_private_key: encrypted_key.to_hex_json()?,
            public_key: self.coordinator_public_key.serialize().to_vec(),
            require_signing_approval: true,
        };

        let session_hmac = self.generate_session_hmac(
            keygen_session_id,
            &self.coordinator_user_id,
            &session_secret,
        )?;

        let response = self
            .client
            .post(format!(
                "{}/api/v1/keygen/{}/participants",
                self.config.gateway_url, keygen_session_id
            ))
            .header("X-Session-HMAC", session_hmac)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to register coordinator: {}",
                response.text().await?
            ));
        }

        info!("✅ Coordinator registered successfully");
        Ok(())
    }

    async fn register_keygen_participant(
        &mut self,
        keygen_session_id: &str,
        participant_index: usize,
    ) -> Result<()> {
        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session: {}",
                    keygen_session_id
                )
            })?
            .clone();

        let participant = &self.participants[participant_index];
        let session_secret_obj = keymeld_core::crypto::SessionSecret::from_hex(&session_secret)?;
        let encrypted_key = session_secret_obj.encrypt(
            &participant.derived_private_key.secret_bytes(),
            "private_key",
        )?;

        let requires_approval = participant_index == 0;

        let request = RegisterKeygenParticipantRequest {
            keygen_session_id: keygen_session_id.try_into().unwrap(),
            user_id: participant.user_id.clone().try_into().unwrap(),
            encrypted_private_key: encrypted_key.to_hex_json()?,
            public_key: participant.public_key.serialize().to_vec(),
            require_signing_approval: requires_approval,
        };

        let session_hmac =
            self.generate_session_hmac(keygen_session_id, &participant.user_id, &session_secret)?;

        let response = self
            .client
            .post(format!(
                "{}/api/v1/keygen/{}/participants",
                self.config.gateway_url, keygen_session_id
            ))
            .header("X-Session-HMAC", session_hmac)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to register participant {}: {}",
                participant.user_id,
                response.text().await?
            ));
        }

        info!("✅ Participant {} registered", participant.user_id);
        Ok(())
    }

    async fn verify_keygen_participants_registered(&self, keygen_session_id: &str) -> Result<()> {
        info!("🔍 Verifying all participants are registered...");

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session: {}",
                    keygen_session_id
                )
            })?
            .clone();

        loop {
            let session_hmac = self.generate_session_hmac(
                keygen_session_id,
                &self.coordinator_user_id,
                &session_secret,
            )?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/keygen/{}/status",
                    self.config.gateway_url, keygen_session_id
                ))
                .header("X-Session-HMAC", session_hmac)
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

    pub async fn wait_for_keygen_completion(&mut self, keygen_session_id: &str) -> Result<String> {
        info!("⏳ Waiting for keygen completion...");

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session: {}",
                    keygen_session_id
                )
            })?
            .clone();

        loop {
            let session_hmac = self.generate_session_hmac(
                keygen_session_id,
                &self.coordinator_user_id,
                &session_secret,
            )?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/keygen/{}/status",
                    self.config.gateway_url, keygen_session_id
                ))
                .header("X-Session-HMAC", session_hmac)
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
                        return Ok(hex::encode(aggregate_key));
                    } else {
                        return Err(anyhow!("Keygen completed but no aggregate key found"));
                    }
                }
                KeygenStatusKind::Failed => {
                    return Err(anyhow!("Keygen session failed"));
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
        keygen_session_id: &str,
        psbt: &Psbt,
    ) -> Result<String> {
        let signing_session_id = Uuid::now_v7().to_string();
        let sighash = self.calculate_taproot_sighash(psbt)?;

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session: {}",
                    keygen_session_id
                )
            })?
            .clone();

        self.session_secrets
            .insert(signing_session_id.clone(), session_secret.clone());

        let encrypted_adaptor_configs = String::new();

        let request = CreateSigningSessionRequest {
            signing_session_id: signing_session_id.clone().try_into().unwrap(),
            keygen_session_id: keygen_session_id.try_into().unwrap(),
            message_hash: sighash.to_vec(),
            encrypted_message: Some(hex::encode(&sighash[..])),
            timeout_secs: 1800,
            encrypted_adaptor_configs,
        };

        let session_hmac = self.generate_session_hmac(
            keygen_session_id,
            self.coordinator_user_id.as_str(),
            &session_secret,
        )?;

        let response = self
            .client
            .post(format!("{}/api/v1/signing", self.config.gateway_url))
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

        info!("✅ Signing session {} created", signing_session_id);
        Ok(signing_session_id)
    }

    pub async fn wait_for_signing_completion(
        &mut self,
        signing_session_id: &str,
        keygen_session_id: &str,
    ) -> Result<Vec<u8>> {
        info!("⏳ Waiting for signing completion...");

        loop {
            let user_hmac = self.generate_user_hmac(
                self.coordinator_user_id.as_str(),
                &self.coordinator_derived_private_key,
            )?;

            let response = self
                .client
                .get(format!(
                    "{}/api/v1/signing/{}/status",
                    self.config.gateway_url, signing_session_id
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
                    if let Some(encrypted_sig) = status.final_signature {
                        let session_secret =
                            self.session_secrets.get(keygen_session_id).ok_or_else(|| {
                                anyhow!(
                                    "Session secret not found for keygen session: {}",
                                    keygen_session_id
                                )
                            })?;

                        let signature_bytes =
                            keymeld_core::api::validation::decrypt_signature_with_secret(
                                &encrypted_sig,
                                session_secret,
                            )?;
                        return Ok(signature_bytes);
                    } else {
                        return Err(anyhow!("Signing completed but no signature found"));
                    }
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
                    info!("Finalizing signature...");
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

        let signature_bytes = signature.to_vec();
        psbt.inputs[0].final_script_witness = Some(Witness::from_slice(&[signature_bytes]));

        let signed_tx = psbt.extract_tx()?;
        info!("✅ Transaction signed successfully");

        let txid = self
            .rpc_client
            .send_raw_transaction(&signed_tx)
            .map_err(|e| anyhow!("Failed to broadcast transaction: {e}"))?;

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
                    .ok_or_else(|| anyhow!("Missing witness UTXO for input"))
            })
            .collect::<Result<Vec<_>>>()?;

        let prevouts = Prevouts::All(&prevouts);
        let mut sighash_cache = SighashCache::new(tx);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .map_err(|e| anyhow!("Failed to calculate taproot sighash: {e}"))?;

        Ok(sighash.to_byte_array())
    }

    pub fn generate_session_hmac(
        &self,
        session_id: &str,
        user_id: &str,
        session_secret: &str,
    ) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(session_secret.as_bytes())
            .map_err(|e| anyhow!("HMAC key error: {e}"))?;

        mac.update(session_id.as_bytes());
        mac.update(user_id.as_bytes());

        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    pub fn generate_user_hmac(&self, user_id: &str, private_key: &SecretKey) -> Result<String> {
        use rand::RngCore;

        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let message = format!("{}:{}", user_id, nonce);
        let message_hash = sha256::Hash::hash(message.as_bytes());

        let secp = Secp256k1::new();
        let message = bitcoin::secp256k1::Message::from_digest_slice(message_hash.as_ref())
            .map_err(|e| anyhow!("Failed to create message from hash: {}", e))?;
        let signature = secp.sign_ecdsa(&message, private_key);
        let signature_bytes = signature.serialize_compact();

        Ok(format!(
            "{}:{}:{}",
            user_id,
            nonce,
            hex::encode(signature_bytes)
        ))
    }

    pub async fn approve_signing_session(
        &self,
        signing_session_id: &str,
        user_id: &str,
        private_key: &SecretKey,
    ) -> Result<()> {
        info!("✅ Approving signing session for user: {}", user_id);

        let user_hmac = self.generate_user_hmac(user_id, private_key)?;

        let response = self
            .client
            .post(format!(
                "{}/api/v1/signing/{}",
                self.config.gateway_url, signing_session_id
            ))
            .header("X-Signing-HMAC", user_hmac)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to approve signing session for {}: {}",
                user_id,
                response.text().await?
            ));
        }

        info!("✅ Signing session approved for user: {}", user_id);
        Ok(())
    }
}
