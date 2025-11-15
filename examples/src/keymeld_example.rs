use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::{self, Auth, Client as RpcClient, RpcApi};
use bdk_wallet::{
    bitcoin::{
        absolute::LockTime,
        bip32::{ChildNumber, Xpriv},
        key::TweakedPublicKey,
        psbt::Psbt,
        secp256k1::{schnorr::Signature, PublicKey, Secp256k1, SecretKey},
        taproot::Signature as TaprootSignature,
        transaction::Version,
        Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, TapSighashType,
        Transaction, TxIn, TxOut, Txid, Witness,
    },
    keys::{
        bip39::{Language, Mnemonic, WordCount},
        DerivableKey, ExtendedKey, GeneratableKey, GeneratedKey,
    },
    miniscript::BareCtx,
    template::Bip86,
    KeychainKind, SignOptions, Wallet,
};
use bitcoin::sighash::{Prevouts, SighashCache};
use clap::{Arg, Command};

use keymeld_core::{
    api::{
        validation, CreateKeygenSessionRequest, CreateKeygenSessionResponse,
        CreateSigningSessionRequest, GetAvailableSlotsResponse, KeygenSessionStatusResponse,
        RegisterKeygenParticipantRequest, SigningSessionStatusResponse, *,
    },
    crypto::SecureCrypto,
    identifiers::UserId,
    session::{KeygenStatusKind, SigningStatusKind},
};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Message;
use std::collections::HashMap;
use std::fs;
use std::fs::read_to_string;
use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use tracing_subscriber::fmt::init;
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let (config, amount, destination) = load_config()?;
    info!("Loaded configuration");
    let mut test = KeyMeldE2ETest::new(config, amount, destination).await?;

    tokio::select! {
        result = run(&mut test) => {
            match result {
                Ok(()) => {
                    println!("\n✅ KeyMeld end-to-end test completed successfully!");
                }
                Err(e) => {
                    error!("End-to-end test failed: {e}");
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

async fn run(test: &mut KeyMeldE2ETest) -> Result<()> {
    info!("🧪 KeyMeld End-to-End Test - Two-Phase Flow");
    info!("============================================");
    info!("Network: {}", test.config.network);
    info!("Gateway: {}", test.config.gateway_url);
    info!("Participants: {}", test.config.num_signers);

    test.load_participants().await?;

    test.fund_coordinator_from_master().await?;

    info!("🔑 Starting Phase 1: Keygen Session");
    let keygen_session_id = test.create_keygen_session().await?;

    info!("📋 Approval Configuration:");
    info!("   - Coordinator requires signing approval: YES");
    info!("   - Participant 0 requires signing approval: YES");
    if test.participants.len() > 1 {
        info!("   - Other participants require signing approval: NO");
    }

    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;
    info!("✅ Keygen complete: {}", aggregate_key);

    let aggregate_utxo = test.fund_aggregate_key_address(&aggregate_key).await?;

    let psbt = test
        .create_musig2_transaction(&aggregate_key, &aggregate_utxo)
        .await?;

    info!("✍️ Starting Phase 2: Signing Session");
    let signing_session_id = test
        .create_signing_session(&keygen_session_id, &psbt)
        .await?;

    info!("📋 Starting Phase 2a: Signing Approvals");
    info!("⚠️  Participants requiring approval before signing can proceed:");
    info!("   - Coordinator: {}", test.coordinator_user_id.as_str());
    info!(
        "   - Participant 0: {}",
        test.participant_user_ids[0].as_str()
    );

    // Approve for coordinator (requires approval)
    test.approve_signing_session(
        &signing_session_id,
        &test.coordinator_user_id.as_str(),
        &test.coordinator_derived_private_key,
    )
    .await?;

    // Approve for first participant (requires approval)
    test.approve_signing_session(
        &signing_session_id,
        &test.participant_user_ids[0].as_str(),
        &test.participants[0].derived_private_key,
    )
    .await?;
    info!("✅ All required approvals completed - signing can now proceed");

    let signature = test
        .wait_for_signing_completion(&signing_session_id, &keygen_session_id)
        .await?;

    let signed_tx = test.apply_signature_and_broadcast(psbt, &signature).await?;

    println!("\n🎉 Three-Phase KeyMeld Test Completed Successfully!");
    println!("✅ Phase 1: Keygen session completed");
    println!("✅ Phase 2a: Signing approvals completed (with HMAC authentication)");
    println!("✅ Phase 2b: Signing session completed (participants inherited from keygen)");
    println!("✅ Aggregate key: {}", aggregate_key);
    println!("✅ Transaction broadcast: {}", signed_tx.compute_txid());
    println!("📋 Keygen Session ID: {}", keygen_session_id);
    println!("📋 Signing Session ID: {}", signing_session_id);

    Ok(())
}

fn load_config() -> Result<(ExampleConfig, u64, String)> {
    let matches = Command::new("KeyMeld End-to-End Test")
        .version("1.0")
        .about("End-to-end test of KeyMeld distributed MuSig2 signing")
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
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let amount_str = matches.get_one::<String>("amount").unwrap();
    let destination = matches.get_one::<String>("destination").unwrap().clone();

    let amount = amount_str
        .parse::<u64>()
        .map_err(|e| anyhow!("Invalid amount '{amount_str}': {e}"))?;

    if !Path::new(config_path).exists() {
        return Err(anyhow!(
            "Configuration file '{config_path}' not found. Please create it with all required settings.",
        ));
    }

    let config_content = read_to_string(config_path)
        .map_err(|e| anyhow!("Failed to read config file {config_path}: {e}",))?;

    let config = serde_yaml::from_str::<ExampleConfig>(&config_content)
        .map_err(|e| anyhow!("Failed to parse config file: {e}"))?;

    Ok((config, amount, destination))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExampleConfig {
    #[serde(with = "network_serde")]
    network: Network,
    num_signers: usize,
    gateway_url: String,
    bitcoin_rpc_url: String,
    bitcoin_rpc_auth: BitcoinRpcAuth,
    key_files_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BitcoinRpcAuth {
    username: String,
    password: String,
}

mod network_serde {
    use super::*;

    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match network {
            Network::Bitcoin => "mainnet",
            Network::Testnet => "testnet",
            Network::Testnet4 => "testnet4",
            Network::Signet => "signet",
            Network::Regtest => "regtest",
        };
        serializer.serialize_str(s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "mainnet" => Ok(Network::Bitcoin),
            "testnet" => Ok(Network::Testnet),
            "testnet4" => Ok(Network::Testnet4),
            "signet" => Ok(Network::Signet),
            "regtest" => Ok(Network::Regtest),
            _ => Err(serde::de::Error::custom(format!("Unknown network: {s}"))),
        }
    }
}

#[derive(Debug)]
struct Participant {
    user_id: String,
    wallet: bdk_wallet::Wallet,
    derived_private_key: SecretKey,
    public_key: PublicKey,
}

impl Participant {
    fn new(user_id: String, network: Network) -> Result<Self> {
        let mnemonic: GeneratedKey<_, _> =
            Mnemonic::generate((WordCount::Words12, Language::English))
                .map_err(|e| anyhow!("Failed to generate mnemonic: {:?}", e))?;

        let xkey: ExtendedKey = mnemonic
            .into_extended_key()
            .map_err(|e| anyhow!("Failed to create extended key: {}", e))?;

        let xprv = xkey.into_xprv(network).unwrap();

        let wallet = Wallet::create(
            Bip86(xprv, KeychainKind::External),
            Bip86(xprv, KeychainKind::Internal),
        )
        .network(network)
        .create_wallet_no_persist()
        .map_err(|e| anyhow!("Failed to create participant wallet: {}", e))?;

        let secp = Secp256k1::new();
        let derived_key = xprv
            .derive_priv(
                &secp,
                &[
                    ChildNumber::from_normal_idx(0).unwrap(),
                    ChildNumber::from_normal_idx(0).unwrap(),
                ],
            )
            .map_err(|e| anyhow!("Failed to derive key: {}", e))?;

        let derived_private_key = derived_key.private_key;
        let public_key = PublicKey::from_secret_key(&secp, &derived_private_key);

        Ok(Self {
            user_id,
            wallet,
            derived_private_key,
            public_key,
        })
    }

    fn get_receive_address(&mut self) -> String {
        let address = self.wallet.reveal_next_address(KeychainKind::External);
        address.to_string()
    }

    fn fingerprint(&self) -> String {
        format!(
            "{:x}",
            self.public_key.x_only_public_key().0.serialize()[0..4]
                .iter()
                .fold(0u32, |acc, &x| (acc << 8) | x as u32)
        )
    }
}

struct KeyMeldE2ETest {
    config: ExampleConfig,
    client: Client,
    participants: Vec<Participant>,
    coordinator_wallet: Wallet,
    coordinator_derived_private_key: SecretKey,
    coordinator_public_key: PublicKey,
    coordinator_user_id: UserId,
    participant_user_ids: Vec<UserId>,
    rpc_client: RpcClient,
    amount: u64,
    destination: String,
    session_secrets: HashMap<String, String>,
}

impl KeyMeldE2ETest {
    pub async fn new(config: ExampleConfig, amount: u64, destination: String) -> Result<Self> {
        let wallet_url = format!("{}/wallet/keymeld_coordinator", config.bitcoin_rpc_url);
        let rpc_client = RpcClient::new(
            &wallet_url,
            Auth::UserPass(
                config.bitcoin_rpc_auth.username.clone(),
                config.bitcoin_rpc_auth.password.clone(),
            ),
        )
        .map_err(|e| {
            anyhow!(
                "Failed to create RPC client for keymeld_coordinator wallet: {}",
                e
            )
        })?;

        info!("Setting up Bitcoin Core wallet for funding...");

        info!("✅ Connected to Bitcoin Core keymeld_coordinator wallet");

        match rpc_client.call::<bitcoincore_rpc::json::GetBalancesResult>("getbalances", &[]) {
            Ok(balances) => {
                info!(
                    "✅ Bitcoin Core keymeld_coordinator wallet balance: {} BTC",
                    balances.mine.trusted
                );
                if balances.mine.trusted.to_sat() == 0 {
                    return Err(anyhow!("ERROR: keymeld_coordinator wallet has 0 balance! Run 'just fund-coordinator' first."));
                }
            }
            Err(e) => {
                return Err(anyhow!("ERROR: Cannot access keymeld_coordinator wallet: {}. Make sure it exists and is funded.", e));
            }
        }

        let (coordinator_derived_private_key, coordinator_wallet) =
            Self::load_or_create_coordinator_private_key(&config.key_files_dir, config.network)?;

        let secp = Secp256k1::new();
        let coordinator_public_key =
            PublicKey::from_secret_key(&secp, &coordinator_derived_private_key);

        let coordinator_address =
            coordinator_wallet.peek_address(bdk_wallet::KeychainKind::External, 0);
        info!(
            "🔑 Persistent Coordinator Address: {}",
            coordinator_address.address
        );
        info!("💰 To fund coordinator manually: bitcoin-cli -regtest -rpcuser=keymeld -rpcpassword=keymeldpass123 generatetoaddress 101 {}", coordinator_address.address);

        Ok(Self {
            config,
            client: Client::new(),
            participants: Vec::new(),
            coordinator_wallet,
            coordinator_derived_private_key,
            coordinator_public_key,
            coordinator_user_id: UserId::new_v7(),
            participant_user_ids: Vec::new(),
            rpc_client,
            amount,
            destination,
            session_secrets: HashMap::new(),
        })
    }

    fn load_or_create_coordinator_private_key(
        key_files_dir: &str,
        network: Network,
    ) -> Result<(SecretKey, Wallet)> {
        fs::create_dir_all(key_files_dir)
            .map_err(|e| anyhow!("Failed to create key directory {}: {}", key_files_dir, e))?;

        let key_file_path = Path::new(key_files_dir).join("coordinator_master.key");

        if key_file_path.exists() {
            info!(
                "Loading coordinator private key from: {}",
                key_file_path.display()
            );
            let key_content = fs::read_to_string(&key_file_path)
                .map_err(|e| anyhow!("Failed to read coordinator key file: {}", e))?;

            let trimmed_content = key_content.trim();

            if trimmed_content.starts_with("tprv") || trimmed_content.starts_with("xprv") {
                info!("Found extended private key (xprv) format from Bitcoin Core");

                let master_xprv = Xpriv::from_str(trimmed_content)
                    .map_err(|e| anyhow!("Failed to parse extended private key: {}", e))?;

                let secp = Secp256k1::new();
                let account_xprv = master_xprv
                    .derive_priv(
                        &secp,
                        &[
                            ChildNumber::from_hardened_idx(86).unwrap(),
                            ChildNumber::from_hardened_idx(1).unwrap(),
                            ChildNumber::from_hardened_idx(0).unwrap(),
                        ],
                    )
                    .map_err(|e| anyhow!("Failed to derive BIP86 account key: {}", e))?;

                let wallet = Wallet::create(
                    Bip86(account_xprv, KeychainKind::External),
                    Bip86(account_xprv, KeychainKind::Internal),
                )
                .network(network)
                .create_wallet_no_persist()
                .map_err(|e| anyhow!("Failed to create coordinator wallet: {}", e))?;

                let signing_key = account_xprv
                    .derive_priv(
                        &secp,
                        &[
                            ChildNumber::from_normal_idx(0).unwrap(),
                            ChildNumber::from_normal_idx(0).unwrap(),
                        ],
                    )
                    .map_err(|e| anyhow!("Failed to derive signing key: {}", e))?;

                info!("✅ Using extended private key from Bitcoin Core with BIP86 derivation");
                return Ok((signing_key.private_key, wallet));
            }

            if trimmed_content.len() > 50
                && (trimmed_content.starts_with('K')
                    || trimmed_content.starts_with('L')
                    || trimmed_content.starts_with('5'))
            {
                info!("Found raw private key in WIF format from Bitcoin Core");

                let private_key = bitcoin::PrivateKey::from_wif(trimmed_content)
                    .map_err(|e| anyhow!("Failed to parse WIF private key: {}", e))?;

                let secret_key = private_key.inner;

                let generated_key: GeneratedKey<Mnemonic, BareCtx> =
                    Mnemonic::generate((WordCount::Words12, Language::English))
                        .map_err(|e| anyhow!("Failed to generate temporary mnemonic: {:?}", e))?;
                let mnemonic = generated_key.into_key();

                let xkey: ExtendedKey = mnemonic
                    .into_extended_key()
                    .map_err(|e| anyhow!("Failed to create extended key: {}", e))?;
                let xprv = xkey.into_xprv(network).unwrap();

                let wallet = Wallet::create(
                    Bip86(xprv, KeychainKind::External),
                    Bip86(xprv, KeychainKind::Internal),
                )
                .network(network)
                .create_wallet_no_persist()
                .map_err(|e| anyhow!("Failed to create coordinator wallet: {}", e))?;

                info!("✅ Using raw private key from Bitcoin Core");
                return Ok((secret_key, wallet));
            }

            let mnemonic = Mnemonic::from_str(trimmed_content)
                .map_err(|e| anyhow!("Failed to parse coordinator key from file: {:?}", e))?;

            let xkey: ExtendedKey = mnemonic
                .into_extended_key()
                .map_err(|e| anyhow!("Failed to create extended key: {}", e))?;
            let xprv = xkey.into_xprv(network).unwrap();

            let wallet = Wallet::create(
                Bip86(xprv, KeychainKind::External),
                Bip86(xprv, KeychainKind::Internal),
            )
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| anyhow!("Failed to create coordinator wallet: {}", e))?;

            let secp = Secp256k1::new();
            let derived_key = xprv
                .derive_priv(
                    &secp,
                    &[
                        ChildNumber::from_normal_idx(0).unwrap(),
                        ChildNumber::from_normal_idx(0).unwrap(),
                    ],
                )
                .map_err(|e| anyhow!("Failed to derive coordinator key: {}", e))?;

            Ok((derived_key.private_key, wallet))
        } else {
            info!(
                "Creating new coordinator private key at: {}",
                key_file_path.display()
            );
            let generated_key: GeneratedKey<Mnemonic, BareCtx> =
                Mnemonic::generate((WordCount::Words12, Language::English))
                    .map_err(|e| anyhow!("Failed to generate coordinator mnemonic: {:?}", e))?;
            let mnemonic = generated_key.into_key();

            fs::write(&key_file_path, mnemonic.to_string())
                .map_err(|e| anyhow!("Failed to write coordinator key file: {}", e))?;

            let xkey: ExtendedKey = mnemonic
                .into_extended_key()
                .map_err(|e| anyhow!("Failed to create extended key: {}", e))?;
            let xprv = xkey.into_xprv(network).unwrap();

            let wallet = Wallet::create(
                Bip86(xprv, KeychainKind::External),
                Bip86(xprv, KeychainKind::Internal),
            )
            .network(network)
            .create_wallet_no_persist()
            .map_err(|e| anyhow!("Failed to create coordinator wallet: {}", e))?;

            let secp = Secp256k1::new();
            let derived_key = xprv
                .derive_priv(
                    &secp,
                    &[
                        ChildNumber::from_normal_idx(0).unwrap(),
                        ChildNumber::from_normal_idx(0).unwrap(),
                    ],
                )
                .map_err(|e| anyhow!("Failed to derive coordinator key: {}", e))?;

            info!(
                "✅ Coordinator private key saved to: {}",
                key_file_path.display()
            );
            Ok((derived_key.private_key, wallet))
        }
    }

    async fn load_participants(&mut self) -> Result<()> {
        info!(
            "Creating {} participant wallets...",
            self.config.num_signers
        );

        for _ in 0..self.config.num_signers {
            let user_id = Uuid::now_v7().to_string();
            let mut participant = Participant::new(user_id.clone(), self.config.network)?;

            let address = participant.get_receive_address();
            info!(
                "Created participant ({}): {} ({}) - Address: {}",
                participant.user_id,
                participant.public_key,
                participant.fingerprint(),
                address
            );

            self.participants.push(participant);
        }

        Ok(())
    }

    async fn fund_coordinator_from_master(&mut self) -> Result<()> {
        info!("📤 Step 1: Funding coordinator's derived address from master wallet...");

        let coord_address = self
            .coordinator_wallet
            .peek_address(bdk_wallet::KeychainKind::External, 0)
            .address;
        info!("🔑 Coordinator derived address: {}", coord_address);

        //TODO(@tee8z): make configurable
        let needed_amount = self.amount + 10000;
        let balance = self.coordinator_wallet.balance();

        if balance.trusted_spendable().to_sat() >= needed_amount {
            info!("✅ Coordinator already has sufficient funds");
            return Ok(());
        }

        if self.config.network == Network::Regtest {
            //TODO(@tee8z): make configurable
            let send_amount = Amount::from_sat(needed_amount + 50000);
            info!(
                "💰 Sending {} BTC from master wallet to coordinator: {}",
                send_amount.to_btc(),
                coord_address
            );

            let txid = self.rpc_client.send_to_address(
                &coord_address,
                send_amount,
                None,
                None,
                None,
                None,
                None,
                None,
            )?;
            info!("✅ Funding transaction sent: {}", txid);

            let btc_address: String = self
                .rpc_client
                .call("getnewaddress", &[serde_json::json!("")])
                .map_err(|e| anyhow!("Failed to get address from Bitcoin Core: {}", e))?;
            let bloc_nums = 6;
            self.rpc_client.generate_to_address(
                bloc_nums,
                &Address::from_str(&btc_address)?.assume_checked(),
            )?;
            info!("⛏️ Mined {} blocks to confirm funding", bloc_nums);

            info!("🔄 Refreshing coordinator wallet state...");

            let tx_info = self.rpc_client.get_transaction(&txid, None)?;
            let funding_tx: Transaction = bitcoin::consensus::deserialize(&tx_info.hex)?;

            for (vout, output) in funding_tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(funding_tx.compute_txid(), vout as u32);
                if self
                    .coordinator_wallet
                    .is_mine(output.script_pubkey.clone())
                {
                    self.coordinator_wallet
                        .insert_txout(outpoint, output.clone());
                }
            }

            let block_height = self.rpc_client.get_block_count()?;
            let _block_hash = self.rpc_client.get_block_hash(block_height)?;
            let block_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            self.coordinator_wallet
                .apply_unconfirmed_txs([(funding_tx, block_time)]);

            let balance = self.coordinator_wallet.balance();
            info!(
                "✅ Wallet state refreshed! Balance: {} sats",
                balance.total()
            );
            info!("   - Confirmed: {} sats", balance.confirmed);
            info!("   - Trusted pending: {} sats", balance.trusted_pending);
            info!("   - Untrusted pending: {} sats", balance.untrusted_pending);
            info!("   - Immature: {} sats", balance.immature);
        } else {
            return Err(anyhow!(
                "For non-regtest networks, please fund coordinator manually: {}",
                coord_address
            ));
        }

        Ok(())
    }
}

impl KeyMeldE2ETest {
    async fn fund_aggregate_key_address(
        &mut self,
        aggregate_key: &str,
    ) -> Result<(String, u32, u64)> {
        info!("💰 Step 2A: Funding aggregate key address (consolidation transaction)...");

        let key_bytes = hex::decode(aggregate_key)?;
        let compressed_key = bitcoin::secp256k1::PublicKey::from_slice(&key_bytes)?;
        let (tweaked_key, _parity) = compressed_key.x_only_public_key();
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(tweaked_key);
        let taproot_address = Address::p2tr_tweaked(tweaked_pubkey, self.config.network);

        info!("🏦 Aggregate key taproot address: {}", taproot_address);

        //TODO(@tee8z): make configurable
        let amount = Amount::from_sat(self.amount + 10000);

        let mut tx_builder = self.coordinator_wallet.build_tx();
        tx_builder
            .add_recipient(taproot_address.script_pubkey(), amount)
            .fee_rate(FeeRate::from_sat_per_vb(1).unwrap());

        let mut consolidation_psbt = tx_builder.finish()?;

        let finalized = self
            .coordinator_wallet
            .sign(&mut consolidation_psbt, SignOptions::default())?;

        if !finalized {
            return Err(anyhow!("Failed to finalize consolidation PSBT"));
        }

        let consolidation_tx = consolidation_psbt.extract_tx()?;

        let auth = Auth::UserPass(
            self.config.bitcoin_rpc_auth.username.clone(),
            self.config.bitcoin_rpc_auth.password.clone(),
        );

        let rpc_client = RpcClient::new(&self.config.bitcoin_rpc_url, auth)?;
        let txid = rpc_client.send_raw_transaction(&consolidation_tx)?;

        info!("✅ Consolidation transaction sent: {}", txid);

        rpc_client.generate_to_address(6, &taproot_address)?;
        info!("⛏️ Mined 6 blocks to confirm consolidation");

        let output_index = consolidation_tx
            .output
            .iter()
            .position(|output| output.script_pubkey == taproot_address.script_pubkey())
            .ok_or_else(|| anyhow!("Could not find aggregate key output in consolidation tx"))?;

        Ok((
            txid.to_string(),
            output_index as u32,
            consolidation_tx.output[output_index].value.to_sat(),
        ))
    }

    async fn create_musig2_transaction(
        &mut self,
        aggregate_key: &str,
        utxo: &(String, u32, u64),
    ) -> Result<Psbt> {
        info!("📝 Step 2B: Creating transaction spending from aggregate key...");

        let destination =
            Address::from_str(&self.destination)?.require_network(self.config.network)?;
        let amount = Amount::from_sat(self.amount);
        let (prev_txid, prev_vout, prev_value) = utxo;

        info!(
            "Creating MuSig2 transaction: {} sats to {}",
            amount.to_sat(),
            destination
        );
        info!(
            "Spending UTXO: {}:{} ({} sats)",
            prev_txid, prev_vout, prev_value
        );

        let key_bytes = hex::decode(aggregate_key)?;
        let compressed_key = bitcoin::secp256k1::PublicKey::from_slice(&key_bytes)?;
        let (already_tweaked_key, _parity) = compressed_key.x_only_public_key();

        // KeyMeld returns the already-tweaked aggregate key, so use it directly
        let tweaked_pubkey = TweakedPublicKey::dangerous_assume_tweaked(already_tweaked_key);
        let taproot_address = Address::p2tr_tweaked(tweaked_pubkey, self.config.network);

        info!("✅ Using KeyMeld's pre-tweaked MuSig2 aggregate key for Bitcoin compatibility");

        let prev_txid = Txid::from_str(prev_txid)?;
        let input = TxIn {
            previous_output: OutPoint::new(prev_txid, *prev_vout),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let estimated_tx_size = 193;
        let fee = estimated_tx_size;
        let output_amount = prev_value - fee;

        if output_amount < amount.to_sat() {
            return Err(anyhow!(
                "Insufficient funds: need {} sats, have {} sats (after {} sat fee)",
                amount.to_sat(),
                output_amount,
                fee
            ));
        }

        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount.to_sat()),
            script_pubkey: destination.script_pubkey(),
        }];

        let change_amount = output_amount - amount.to_sat();
        if change_amount > 546 {
            outputs.push(TxOut {
                value: Amount::from_sat(change_amount),
                script_pubkey: taproot_address.script_pubkey(),
            });
        }

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![input],
            output: outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(transaction)?;

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(*prev_value),
            script_pubkey: taproot_address.script_pubkey(),
        });

        info!(
            "✅ Created MuSig2 transaction with {} inputs and {} outputs",
            psbt.unsigned_tx.input.len(),
            psbt.unsigned_tx.output.len()
        );
        info!("🔐 This transaction will be signed using KeyMeld MuSig2");

        Ok(psbt)
    }

    async fn create_keygen_session(&mut self) -> Result<String> {
        info!("🔑 Creating KeyMeld keygen session...");

        let coordinator_pubkey = self.coordinator_public_key;

        let enclaves_response = self
            .client
            .get(format!("{}/api/v1/enclaves", self.config.gateway_url))
            .send()
            .await?;

        if !enclaves_response.status().is_success() {
            return Err(anyhow!(
                "Failed to get enclaves: {}",
                enclaves_response.text().await?
            ));
        }

        let enclaves: ListEnclavesResponse = enclaves_response.json().await?;
        if enclaves.enclaves.is_empty() {
            return Err(anyhow!("No enclaves available"));
        }

        let selected_enclave = enclaves
            .enclaves
            .iter()
            .find(|e| e.healthy)
            .ok_or_else(|| anyhow!("No healthy enclaves available"))?;

        info!(
            "Selected enclave {} with key epoch {}",
            selected_enclave.enclave_id, selected_enclave.key_epoch
        );

        let keygen_session_id = Uuid::now_v7().to_string();

        let coordinator_encrypted_private_key = {
            let encrypted_data = SecureCrypto::ecies_encrypt_from_hex(
                &selected_enclave.public_key,
                self.coordinator_derived_private_key.secret_bytes().as_ref(),
            )
            .map_err(|e| anyhow!("Failed to encrypt coordinator private key: {}", e))?;
            hex::encode(encrypted_data)
        };

        let coordinator_user_id = UserId::new_v7();
        let mut expected_participants = vec![coordinator_user_id.clone()];

        let mut participant_user_ids = Vec::new();
        for _participant in &self.participants {
            let user_id = UserId::new_v7();
            participant_user_ids.push(user_id.clone());
            expected_participants.push(user_id);
        }

        self.coordinator_user_id = coordinator_user_id.clone();
        self.participant_user_ids = participant_user_ids;

        let session_secret = {
            let mut rng = rand::rng();
            let mut secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut secret_bytes);
            hex::encode(secret_bytes)
        };

        let encrypted_session_secret = {
            let encrypted_bytes = SecureCrypto::ecies_encrypt_from_hex(
                &selected_enclave.public_key,
                session_secret.as_bytes(),
            )
            .map_err(|e| anyhow!("Failed to encrypt session secret with ECIES: {}", e))?;
            hex::encode(encrypted_bytes)
        };

        let request = CreateKeygenSessionRequest {
            keygen_session_id: keygen_session_id.clone().try_into().unwrap(),
            coordinator_pubkey: coordinator_pubkey.serialize().to_vec(),
            coordinator_encrypted_private_key,
            coordinator_enclave_id: selected_enclave.enclave_id,
            expected_participants,
            timeout_secs: 1800,
            encrypted_session_secret,
            max_signing_sessions: None,
            taproot_tweak_config: TaprootTweak::UnspendableTaproot,
        };

        let response = self
            .client
            .post(format!("{}/api/v1/keygen", self.config.gateway_url))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Failed to create keygen session: {}",
                response.text().await?
            ));
        }

        let _response: CreateKeygenSessionResponse = response.json().await?;

        self.share_session_secret_out_of_band(&keygen_session_id, &session_secret);

        info!("✅ Keygen session {} created", keygen_session_id);

        Ok(keygen_session_id)
    }

    fn share_session_secret_out_of_band(&mut self, keygen_session_id: &str, session_secret: &str) {
        info!("🔐 Simulating out-of-band session secret sharing...");
        info!("   📋 Session ID: {}", keygen_session_id);
        info!(
            "   🔑 Session Secret (first 10 chars): {}...",
            &session_secret[..10]
        );
        info!(
            "   ⚠️  In production, coordinator would securely share this secret with participants"
        );
        info!("      through encrypted channels (Signal, PGP, secure email, in-person, etc.)");
        info!("   ⚠️  This secret enables participants to prove authorization for keygen participation");

        self.session_secrets
            .insert(keygen_session_id.to_string(), session_secret.to_string());

        for (i, participant) in self.participants.iter().enumerate() {
            info!(
                "   📤 [OUT-OF-BAND] Coordinator securely shares session secret with participant {} ({})",
                i + 1,
                participant.fingerprint()
            );
            info!(
                "      📱 Participant {} receives and stores session secret securely",
                i + 1
            );
        }

        info!("✅ Out-of-band session secret sharing simulation completed");
        info!("   🔒 All participants now have the shared secret for HMAC generation");
    }

    async fn register_keygen_participants(&mut self, keygen_session_id: &str) -> Result<()> {
        info!("👥 Registering participants for keygen session...");

        let slots_response = self
            .client
            .get(format!(
                "{}/api/v1/keygen/{}/slots",
                self.config.gateway_url, keygen_session_id
            ))
            .send()
            .await?;

        if !slots_response.status().is_success() {
            return Err(anyhow!(
                "Failed to get available slots for keygen session {}: {}",
                keygen_session_id,
                slots_response.text().await?
            ));
        }

        let slots: GetAvailableSlotsResponse = slots_response.json().await?;
        info!(
            "Keygen session {} has {} available slots",
            keygen_session_id,
            slots.available_slots.len()
        );

        let total_needed = 1 + self.participants.len();
        if slots.available_slots.len() < total_needed {
            return Err(anyhow!(
                "Not enough available slots for keygen: need {}, got {}",
                total_needed,
                slots.available_slots.len()
            ));
        }

        // Register coordinator first
        info!("📝 Registering coordinator...");
        self.register_keygen_coordinator(keygen_session_id, &slots)
            .await?;

        // Register all participants
        for i in 0..self.participants.len() {
            info!("📝 Registering participant {}...", i);
            self.register_keygen_participant(keygen_session_id, i, &slots)
                .await?;
        }

        info!("✅ All {} participants registered for keygen", total_needed);

        // Add a small delay to allow for processing
        sleep(Duration::from_secs(1)).await;

        // Verify all participants are registered by checking status
        self.verify_keygen_participants_registered(keygen_session_id)
            .await?;

        Ok(())
    }

    async fn register_keygen_coordinator(
        &mut self,
        keygen_session_id: &str,
        slots: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        let coordinator_slot = slots
            .available_slots
            .first()
            .ok_or_else(|| anyhow!("No available slots for coordinator"))?;

        let enclave_key_response = self
            .client
            .get(format!(
                "{}/api/v1/enclaves/{}/public-key",
                self.config.gateway_url,
                coordinator_slot.enclave_id.as_u32()
            ))
            .send()
            .await?;

        let enclave_key: EnclavePublicKeyResponse = enclave_key_response.json().await?;

        let encrypted_private_key = {
            let encrypted_data = SecureCrypto::ecies_encrypt_from_hex(
                &enclave_key.public_key,
                self.coordinator_derived_private_key.secret_bytes().as_ref(),
            )?;
            hex::encode(encrypted_data)
        };

        let request = RegisterKeygenParticipantRequest {
            keygen_session_id: keygen_session_id.try_into().unwrap(),
            user_id: self.coordinator_user_id.clone(),
            encrypted_private_key,
            public_key: self.coordinator_public_key.serialize().to_vec(),

            // Coordinator also requires approval for demonstration
            require_signing_approval: true,
        };

        // Generate session HMAC for header
        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| anyhow!("Session secret not found for keygen session"))?;
        let session_hmac = self.generate_session_hmac(
            keygen_session_id,
            &self.coordinator_user_id.as_str(),
            session_secret,
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
                "Failed to register coordinator for keygen: {}",
                response.text().await?
            ));
        }

        info!("✅ Coordinator registered for keygen");
        Ok(())
    }

    async fn register_keygen_participant(
        &mut self,
        keygen_session_id: &str,
        participant_index: usize,
        slots: &GetAvailableSlotsResponse,
    ) -> Result<()> {
        let participant_slot = slots
            .available_slots
            .get(participant_index + 1)
            .ok_or_else(|| anyhow!("No available slot for participant {}", participant_index))?;

        let enclave_key_response = self
            .client
            .get(format!(
                "{}/api/v1/enclaves/{}/public-key",
                self.config.gateway_url,
                participant_slot.enclave_id.as_u32()
            ))
            .send()
            .await?;

        let enclave_key: EnclavePublicKeyResponse = enclave_key_response.json().await?;

        let participant = &self.participants[participant_index];
        let encrypted_private_key = {
            let encrypted_data = SecureCrypto::ecies_encrypt_from_hex(
                &enclave_key.public_key,
                participant.derived_private_key.secret_bytes().as_ref(),
            )?;
            hex::encode(encrypted_data)
        };

        let request = RegisterKeygenParticipantRequest {
            keygen_session_id: keygen_session_id.try_into().unwrap(),
            user_id: self.participant_user_ids[participant_index].clone(),
            encrypted_private_key,
            public_key: participant.public_key.serialize().to_vec(),
            // Make the first participant require approval for demonstration
            require_signing_approval: participant_index == 0,
        };

        // Generate session HMAC for header
        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| anyhow!("Session secret not found for keygen session"))?;
        let session_hmac = self.generate_session_hmac(
            keygen_session_id,
            &self.participant_user_ids[participant_index].as_str(),
            session_secret,
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
                "Failed to register participant {} for keygen: {}",
                participant_index,
                response.text().await?
            ));
        }

        let response_text = response.text().await?;
        info!(
            "✅ Participant {} registered for keygen: {}",
            participant_index, response_text
        );
        Ok(())
    }

    async fn verify_keygen_participants_registered(
        &mut self,
        keygen_session_id: &str,
    ) -> Result<()> {
        info!("🔍 Verifying all participants are properly registered...");

        // Generate session HMAC for status check
        let session_secret = self.session_secrets.get(keygen_session_id).ok_or_else(|| {
            anyhow!(
                "Session secret not found for keygen session {}",
                keygen_session_id
            )
        })?;

        let session_hmac = self.generate_session_hmac(
            keygen_session_id,
            &self.coordinator_user_id.as_str(),
            session_secret,
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
                "Failed to get keygen status for verification: {}",
                response.text().await?
            ));
        }

        let status: KeygenSessionStatusResponse = response.json().await?;

        info!("📊 Keygen session status: {:?}", status.status);
        info!(
            "📊 Registered participants: {}",
            status.registered_participants
        );
        info!("📊 Expected participants: {}", status.expected_participants);

        let total_expected = 1 + self.participants.len();
        if status.registered_participants != total_expected {
            warn!(
                "⚠️  Participant count mismatch: expected {}, got {}",
                total_expected, status.registered_participants
            );
        } else {
            info!("✅ All {} participants properly registered", total_expected);
        }

        Ok(())
    }

    async fn wait_for_keygen_completion(&mut self, keygen_session_id: &str) -> Result<String> {
        info!("⏳ Waiting for keygen completion...");

        let mut attempts = 0;
        let max_attempts = 60; // Wait up to 2 minutes

        loop {
            attempts += 1;

            // Generate session HMAC for keygen status check
            let session_secret = self.session_secrets.get(keygen_session_id).ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session {}",
                    keygen_session_id
                )
            })?;

            let session_hmac = self.generate_session_hmac(
                keygen_session_id,
                &self.coordinator_user_id.as_str(),
                session_secret,
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

            info!(
                "⏳ Keygen attempt {}/{} - Status: {:?}, Registered: {}/{}",
                attempts,
                max_attempts,
                status.status,
                status.registered_participants,
                status.expected_participants
            );

            match status.status {
                KeygenStatusKind::Completed => {
                    if let Some(agg_key) = status.aggregate_public_key {
                        let key_hex = hex::encode(agg_key);
                        info!(
                            "🎉 Keygen completed successfully after {} attempts",
                            attempts
                        );
                        return Ok(key_hex);
                    } else {
                        return Err(anyhow!("Keygen completed but no aggregate key found"));
                    }
                }
                KeygenStatusKind::Failed => {
                    return Err(anyhow!("Keygen session failed after {} attempts", attempts));
                }
                KeygenStatusKind::CollectingParticipants => {
                    if attempts % 5 == 0 {
                        info!(
                            "🔄 Still collecting participants... ({}/{} registered)",
                            status.registered_participants, status.expected_participants
                        );
                    }
                }
            }

            if attempts >= max_attempts {
                return Err(anyhow!(
                    "Keygen session timed out after {} attempts. Current status: {:?}",
                    max_attempts,
                    status.status
                ));
            }

            sleep(Duration::from_secs(2)).await;
        }
    }

    async fn create_signing_session(
        &mut self,
        keygen_session_id: &str,
        psbt: &Psbt,
    ) -> Result<String> {
        info!("✍️ Creating signing session...");

        let signing_session_id = Uuid::now_v7().to_string();

        let sighash = self.calculate_taproot_sighash(psbt, 0)?;

        let session_secret = self
            .session_secrets
            .get(keygen_session_id)
            .ok_or_else(|| {
                anyhow!(
                    "Session secret not found for keygen session {}",
                    keygen_session_id
                )
            })?
            .clone();

        self.session_secrets
            .insert(signing_session_id.clone(), session_secret.clone());

        let request = CreateSigningSessionRequest {
            signing_session_id: signing_session_id.clone().try_into().unwrap(),
            keygen_session_id: keygen_session_id.try_into().unwrap(),
            message_hash: sighash.to_vec(),
            encrypted_message: Some(hex::encode(&sighash[..])),
            timeout_secs: 1800,
        };

        // Generate session HMAC for authorization (use keygen session ID, not signing session ID)
        let session_hmac = self.generate_session_hmac(
            keygen_session_id,
            &self.coordinator_user_id.as_str(),
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

    async fn wait_for_signing_completion(
        &mut self,
        signing_session_id: &str,
        keygen_session_id: &str,
    ) -> Result<Vec<u8>> {
        info!("⏳ Waiting for signing completion...");

        loop {
            // Generate user HMAC for signing status check (use coordinator credentials)
            let user_hmac = self.generate_user_hmac(
                &self.coordinator_user_id.as_str(),
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
                        // Get the session secret for decryption
                        let session_secret =
                            self.session_secrets.get(keygen_session_id).ok_or_else(|| {
                                anyhow!(
                                    "Session secret not found for keygen session: {}",
                                    keygen_session_id
                                )
                            })?;

                        // Decrypt the hex-encoded signature using the hex-based function
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

    async fn apply_signature_and_broadcast(
        &self,
        mut psbt: Psbt,
        signature_bytes: &[u8],
    ) -> Result<Transaction> {
        info!("🔏 Applying MuSig2 signature to transaction...");

        if signature_bytes.len() != 64 {
            return Err(anyhow!(
                "Invalid signature length: expected 64 bytes, got {}",
                signature_bytes.len()
            ));
        }

        let signature = Signature::from_slice(signature_bytes)
            .map_err(|e| anyhow!("Failed to parse signature: {}", e))?;

        if psbt.inputs.is_empty() {
            return Err(anyhow!("PSBT has no inputs"));
        }

        let taproot_sig = TaprootSignature {
            signature,
            sighash_type: TapSighashType::Default,
        };

        psbt.inputs[0].tap_key_sig = Some(taproot_sig);

        // For taproot key-path spending, witness should contain just the signature
        // Create witness with a single stack item containing the 64-byte signature
        let mut witness = Witness::new();
        witness.push(signature_bytes);
        psbt.inputs[0].final_script_witness = Some(witness);

        let signed_tx = psbt
            .extract_tx()
            .map_err(|e| anyhow!("Failed to extract transaction from PSBT: {}", e))?;

        info!("📡 Broadcasting transaction: {}", signed_tx.compute_txid());

        let rpc_client = RpcClient::new(
            &self.config.bitcoin_rpc_url,
            Auth::UserPass(
                self.config.bitcoin_rpc_auth.username.clone(),
                self.config.bitcoin_rpc_auth.password.clone(),
            ),
        )
        .map_err(|e| anyhow!("Failed to create RPC client: {}", e))?;

        let _txid = rpc_client
            .send_raw_transaction(&signed_tx)
            .map_err(|e| anyhow!("Failed to broadcast transaction: {}", e))?;

        info!(
            "✅ Transaction broadcast successfully: {}",
            signed_tx.compute_txid()
        );

        Ok(signed_tx)
    }

    fn calculate_taproot_sighash(&self, psbt: &Psbt, input_index: usize) -> Result<[u8; 32]> {
        let tx = &psbt.unsigned_tx;

        let mut sighash_cache = SighashCache::new(tx);
        if input_index >= psbt.inputs.len() {
            return Err(anyhow!(
                "Input index {} out of range (max: {})",
                input_index,
                psbt.inputs.len() - 1
            ));
        }

        let all_prevouts: Vec<_> = psbt
            .inputs
            .iter()
            .map(|input| input.witness_utxo.as_ref().unwrap())
            .collect();
        let prevouts = Prevouts::All(&all_prevouts);

        let sighash = sighash_cache
            .taproot_key_spend_signature_hash(input_index, &prevouts, TapSighashType::Default)
            .map_err(|e| {
                anyhow!(
                    "Failed to calculate taproot sighash for input {}: {}",
                    input_index,
                    e
                )
            })?;

        Ok(*sighash.as_ref())
    }

    /// Generate session HMAC for keygen operations (format: user_id:nonce:hmac)
    fn generate_session_hmac(
        &self,
        session_id: &str,
        user_id: &str,
        session_secret: &str,
    ) -> Result<String> {
        use rand::RngCore;

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Create message: session_id:user_id:nonce
        let message = format!("{}:{}:{}", session_id, user_id, nonce);

        // Generate HMAC
        let hmac = validation::generate_registration_hmac(&message, session_secret)
            .map_err(|e| anyhow!("Failed to generate session HMAC: {}", e))?;

        // Return format: nonce:hmac
        Ok(format!("{}:{}", nonce, hmac))
    }

    /// Generate user HMAC signature for signing operations (format: user_id:nonce:signature)
    fn generate_user_hmac(&self, user_id: &str, private_key: &SecretKey) -> Result<String> {
        use rand::RngCore;

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        // Create message to sign: user_id:nonce
        let message = format!("{}:{}", user_id, nonce);
        let message_hash = sha256::Hash::hash(message.as_bytes());
        let message_secp = Message::from_digest_slice(message_hash.as_ref())
            .map_err(|e| anyhow!("Failed to create message from hash: {}", e))?;

        // Sign with private key
        let secp = Secp256k1::new();
        let signature = secp.sign_ecdsa(&message_secp, private_key);
        let signature_bytes = signature.serialize_compact();

        // Return format: user_id:nonce:signature
        Ok(format!(
            "{}:{}:{}",
            user_id,
            nonce,
            hex::encode(signature_bytes)
        ))
    }

    /// Approve a signing session for participants who require approval
    async fn approve_signing_session(
        &self,
        signing_session_id: &str,
        user_id: &str,
        private_key: &SecretKey,
    ) -> Result<()> {
        info!(
            "✅ Approving signing session {} for user {}",
            signing_session_id, user_id
        );

        // Generate user HMAC signature for authorization
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
                "Failed to approve signing session: {}",
                response.text().await?
            ));
        }

        info!(
            "✅ Signing session {} approved by user {}",
            signing_session_id, user_id
        );
        Ok(())
    }
}
