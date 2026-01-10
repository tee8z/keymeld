//! DLC Batch Signing Example
//!
//! Demonstrates using keymeld's batch signing API with dlctix for Ticketed DLCs.
//!
//! Key features:
//! - Outcome transactions: n-of-n aggregate key with adaptor signatures
//! - Split transactions: subset aggregate keys (winner + market_maker per outcome)
//! - Weighted payouts: multiple winners per outcome

use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bdk_wallet::KeychainKind;
use keymeld_examples::{retry_bitcoin_rpc, ExampleConfig, KeyMeldE2ETest};
use keymeld_sdk::dlctix::{
    dlctix::{
        attestation_locking_point, attestation_secret,
        bitcoin::consensus,
        bitcoin::{Amount, FeeRate, Transaction},
        secp::{MaybePoint, MaybeScalar, Point, Scalar},
        ContractParameters, ContractSignatures, EventLockingConditions, MarketMaker, Outcome,
        OutcomeIndex, PayoutWeights, Player, SignedContract, TicketedDLC, WinCondition,
    },
    DlcBatchBuilder, DlcSubsetBuilder,
};
use keymeld_sdk::prelude::{SessionCredentials, SigningOptions};
use std::collections::BTreeMap;
use std::fs::read_to_string;
use tracing::info;

const NUM_PLAYERS: usize = 3;
const NUM_OUTCOMES: usize = 3;
const FUNDING_AMOUNT_SATS: u64 = 300_000;

pub async fn run_with_args(config_path: String) -> Result<()> {
    let config_content = read_to_string(&config_path)?;
    let config: ExampleConfig = serde_yaml::from_str(&config_content)?;
    run_dlctix_batch_test(config).await
}

pub async fn run_dlctix_batch_test(config: ExampleConfig) -> Result<()> {
    info!("DLC Batch Signing Example");
    info!("==========================");
    info!("Network: {}", config.network);
    info!("Gateway: {}", config.gateway_url);
    info!("Players: {}", NUM_PLAYERS);
    info!("Outcomes: {}", NUM_OUTCOMES);

    // Phase 1: Setup
    info!("\n=== Phase 1: Setup ===");

    let mut rng = rand::rng();
    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_pubkey = oracle_seckey.base_point_mul();
    let oracle_secnonce = Scalar::random(&mut rng);
    let nonce_point = oracle_secnonce.base_point_mul();

    info!("Created fake oracle");
    info!(
        "  Oracle pubkey: {}",
        hex::encode(oracle_pubkey.serialize())
    );

    let outcome_messages: Vec<Vec<u8>> = (0..NUM_OUTCOMES)
        .map(|i| format!("outcome_{}", i).into_bytes())
        .collect();

    let locking_points: Vec<MaybePoint> = outcome_messages
        .iter()
        .map(|msg| attestation_locking_point(oracle_pubkey, nonce_point, msg))
        .collect();

    info!("Created {} outcome locking points", locking_points.len());

    // Phase 2: KeyMeld Setup
    info!("\n=== Phase 2: KeyMeld Setup ===");

    let mut test_config = config.clone();
    test_config.num_signers = (NUM_PLAYERS + 1) as u32;

    let mut test = KeyMeldE2ETest::new(test_config, FUNDING_AMOUNT_SATS + 50_000, None).await?;
    test.load_participants().await?;
    test.fund_coordinator_from_master().await?;

    info!(
        "Creating keygen session with {} participants",
        NUM_PLAYERS + 1
    );

    // Phase 3: Create DLC Contract (before keygen, so we can use DlcSubsetBuilder)
    info!("\n=== Phase 3: Create DLC Contract ===");

    let market_maker = MarketMaker {
        pubkey: Point::from_slice(&test.coordinator_public_key.serialize())
            .map_err(|e| anyhow!("Invalid coordinator pubkey: {}", e))?,
    };

    let mut players = Vec::new();
    let mut ticket_preimages: Vec<[u8; 32]> = Vec::new();

    for (i, participant) in test.participants.iter().enumerate() {
        let ticket_preimage = dlctix::hashlock::preimage_random(&mut rng);
        let ticket_hash = dlctix::hashlock::sha256(&ticket_preimage);
        ticket_preimages.push(ticket_preimage);

        let payout_preimage = dlctix::hashlock::preimage_random(&mut rng);
        let payout_hash = dlctix::hashlock::sha256(&payout_preimage);

        let player = Player {
            pubkey: Point::from_slice(&participant.public_key.serialize())
                .map_err(|e| anyhow!("Invalid player {} pubkey: {}", i, e))?,
            ticket_hash,
            payout_hash,
        };
        players.push(player);
    }

    info!("Created {} players", players.len());

    // Create outcome payouts with MULTIPLE winners per outcome using weighted payouts
    // This demonstrates the most complex case: each outcome has 2+ winners splitting the pot
    let mut outcome_payouts = BTreeMap::new();

    // Outcome 0: Player 0 gets 60%, Player 1 gets 40%
    outcome_payouts.insert(
        Outcome::Attestation(0),
        PayoutWeights::from([(0usize, 3u64), (1usize, 2u64)]), // 3:2 ratio = 60:40
    );
    info!("  Outcome 0: Player 0 (60%) + Player 1 (40%)");

    // Outcome 1: Player 1 gets 50%, Player 2 gets 50%
    outcome_payouts.insert(
        Outcome::Attestation(1),
        PayoutWeights::from([(1usize, 1u64), (2usize, 1u64)]), // 1:1 ratio = 50:50
    );
    info!("  Outcome 1: Player 1 (50%) + Player 2 (50%)");

    // Outcome 2: All three players win - Player 0 (50%), Player 1 (30%), Player 2 (20%)
    outcome_payouts.insert(
        Outcome::Attestation(2),
        PayoutWeights::from([(0usize, 5u64), (1usize, 3u64), (2usize, 2u64)]), // 5:3:2 ratio
    );
    info!("  Outcome 2: Player 0 (50%) + Player 1 (30%) + Player 2 (20%)");

    let contract_params = ContractParameters {
        market_maker,
        players,
        event: EventLockingConditions {
            locking_points,
            expiry: None,
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(50),
        funding_value: Amount::from_sat(FUNDING_AMOUNT_SATS),
        relative_locktime_block_delta: 1,
    };

    contract_params
        .validate()
        .map_err(|e| anyhow!("Invalid contract params: {:?}", e))?;
    info!("Contract parameters validated");

    // Phase 4: Create Keygen Session with Subset Definitions
    info!("\n=== Phase 4: Keygen with Subset Definitions ===");

    // Use SDK's DlcSubsetBuilder to create subset definitions from contract parameters
    // This extracts winners from each outcome's payout weights automatically
    let player_ids: Vec<_> = test.participant_user_ids.clone();
    let dlc_subsets = DlcSubsetBuilder::new(
        &contract_params,
        test.coordinator_user_id.clone(),
        player_ids,
    )
    .build()
    .map_err(|e| anyhow!("Failed to build DLC subsets: {}", e))?;

    info!(
        "Created {} subset definitions for split transactions (one per outcome)",
        dlc_subsets.definitions.len()
    );
    for (outcome_idx, subset_id) in &dlc_subsets.outcome_subset_ids {
        info!("  Outcome {} -> Subset {}", outcome_idx, subset_id);
    }

    let keygen_session_id = test
        .create_keygen_session_with_subsets(dlc_subsets.definitions)
        .await?;
    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let encrypted_aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;

    info!("Keygen complete!");
    let aggregate_key_hex =
        test.decrypt_aggregate_key_for_display(&encrypted_aggregate_key, &keygen_session_id)?;
    info!("  Aggregate key: {}...", &aggregate_key_hex[..16]);

    // Phase 5: Fund the DLC
    info!("\n=== Phase 5: Fund the DLC ===");

    // Get the funding output from dlctix - this uses dlctix's internally computed aggregate key
    let funding_output = contract_params
        .funding_output()
        .map_err(|e| anyhow!("Failed to get funding output: {:?}", e))?;

    info!("Funding output script: {}", funding_output.script_pubkey);
    info!("Funding amount: {} sats", funding_output.value.to_sat());

    // Fund the dlctix funding address (not the keymeld aggregate address)
    let funding_utxo = test.fund_dlctix_output(&funding_output).await?;
    info!(
        "Funded DLC at outpoint: {}:{}",
        funding_utxo.txid, funding_utxo.vout
    );

    let ticketed_dlc = TicketedDLC::new(contract_params.clone(), funding_utxo)
        .map_err(|e| anyhow!("Failed to create DLC: {:?}", e))?;
    info!("Created TicketedDLC");

    // Phase 6: Extract Signing Data
    info!("\n=== Phase 6: Extract Signing Data ===");

    let signing_data = ticketed_dlc
        .signing_data()
        .map_err(|e| anyhow!("Failed to get signing data: {:?}", e))?;

    info!("Extracted signing data:");
    info!(
        "  Outcome sighashes: {}",
        signing_data.outcome_sighashes.len()
    );
    info!("  Adaptor points: {}", signing_data.adaptor_points.len());
    info!("  Split sighashes: {}", signing_data.split_sighashes.len());

    // Compare keymeld aggregate key with dlctix aggregate key
    let dlctix_agg_key_hex = hex::encode(signing_data.funding_agg_pubkey.serialize());
    info!("  dlctix funding_agg_pubkey: {}", dlctix_agg_key_hex);
    info!("  keymeld aggregate key:     {}", aggregate_key_hex);
    if dlctix_agg_key_hex != aggregate_key_hex {
        info!("  WARNING: Aggregate keys do NOT match!");
        info!("  This means keymeld participants don't match dlctix participants");
    } else {
        info!("  Aggregate keys match!");
    }
    info!(
        "  Total signatures needed: {}",
        signing_data.total_signature_count()
    );

    // Phase 7: Batch Signing with KeyMeld SDK
    info!("\n=== Phase 7: Batch Signing with KeyMeld SDK ===");

    // Use SDK's DlcBatchBuilder to create batch items from signing data
    let dlc_batch = DlcBatchBuilder::new(&signing_data)
        .with_outcome_subsets(&dlc_subsets.outcome_subset_ids)
        .build()
        .map_err(|e| anyhow!("Failed to build DLC batch: {}", e))?;

    info!(
        "  Total: {} outcome txs + {} split txs = {} batch items",
        dlc_batch.outcome_batch_ids.len(),
        dlc_batch.split_batch_ids.len(),
        dlc_batch.items.len()
    );

    // Restore keygen session credentials from stored seed
    let session_secret_hex = test
        .session_secrets
        .get(&keygen_session_id)
        .ok_or(anyhow!("Session secret not found"))?;
    let seed_bytes = hex::decode(session_secret_hex)?;
    let seed: [u8; 32] = seed_bytes
        .try_into()
        .map_err(|_| anyhow!("Invalid session seed length"))?;

    // Get SDK coordinator client
    let coordinator_client = test
        .sdk_coordinator_client
        .as_ref()
        .ok_or_else(|| anyhow!("SDK coordinator client not initialized"))?;

    // Restore keygen session using SDK
    let keygen_credentials = SessionCredentials::from_session_secret(&seed)
        .map_err(|e| anyhow!("Failed to restore session credentials: {e}"))?;
    let keygen_session = coordinator_client
        .keygen()
        .restore_session(keygen_session_id.clone(), keygen_credentials)
        .await
        .map_err(|e| anyhow!("Failed to restore keygen session: {e}"))?;

    // Create batch signing session using SDK's SigningManager
    info!("Creating batch signing session via SDK...");
    let mut signing_session = coordinator_client
        .signer()
        .sign_batch(
            &keygen_session,
            dlc_batch.items.clone(),
            SigningOptions::default().timeout(1800),
        )
        .await
        .map_err(|e| anyhow!("Failed to create signing session: {e}"))?;

    let signing_session_id = signing_session.session_id().clone();
    info!("  Signing session created: {}", signing_session_id);

    // Validate: Before approving, verify the messages match what we expect to sign
    // In production, each participant should independently verify the transaction sighashes
    info!("Validating messages before approval...");
    info!(
        "  Outcome sighashes: {} items",
        signing_data.outcome_sighashes.len()
    );
    info!(
        "  Split sighashes: {} items",
        signing_data.split_sighashes.len()
    );

    // Coordinator approves using SDK
    info!("Submitting signing approvals via SDK...");
    signing_session
        .approve()
        .await
        .map_err(|e| anyhow!("Coordinator approval failed: {e}"))?;
    info!("  Coordinator approved");

    // Participants requiring approval use SDK
    for idx in test.participants_requiring_approval.clone() {
        if idx < test.sdk_participant_clients.len() {
            info!("  Participant {} approving...", idx);

            let participant_client = &test.sdk_participant_clients[idx];

            // Restore keygen session for this participant
            let participant_keygen_credentials = SessionCredentials::from_session_secret(&seed)
                .map_err(|e| anyhow!("Failed to restore session credentials: {e}"))?;
            let participant_keygen = participant_client
                .keygen()
                .restore_session(keygen_session_id.clone(), participant_keygen_credentials)
                .await
                .map_err(|e| {
                    anyhow!(
                        "Failed to restore keygen session for participant {}: {e}",
                        idx
                    )
                })?;

            // Restore signing session and approve
            let mut participant_signing = participant_client
                .signer()
                .restore_session(signing_session_id.clone(), &participant_keygen)
                .await
                .map_err(|e| {
                    anyhow!(
                        "Failed to restore signing session for participant {}: {e}",
                        idx
                    )
                })?;

            participant_signing
                .approve()
                .await
                .map_err(|e| anyhow!("Participant {} approval failed: {e}", idx))?;

            info!("  Participant {} approved", idx);
        }
    }
    info!("All approvals submitted");

    // Wait for batch signing completion using SDK
    info!("Waiting for batch signing completion...");
    let signature_results = signing_session
        .wait_for_completion()
        .await
        .map_err(|e| anyhow!("Signing failed: {e}"))?;
    info!(
        "Batch signing complete! Results received: {}",
        signature_results.len()
    );

    // Phase 8: Parse Results into ContractSignatures
    info!("\n=== Phase 8: Parse Results into ContractSignatures ===");

    // Use SDK's parse_results helper to convert keymeld results to dlctix types
    let dlc_sigs = dlc_batch
        .parse_results(&signature_results)
        .map_err(|e| anyhow!("Failed to parse DLC signatures: {}", e))?;

    info!(
        "  Parsed {} outcome + {} split signatures",
        dlc_sigs.outcome_signatures.len(),
        dlc_sigs.split_signatures.len()
    );

    let contract_signatures = ContractSignatures {
        expiry_tx_signature: None,
        outcome_tx_signatures: dlc_sigs.outcome_signatures,
        split_tx_signatures: dlc_sigs.split_signatures,
    };

    let signed_contract: SignedContract = ticketed_dlc.into_signed_contract(contract_signatures);
    info!(
        "Created SignedContract with {} outcome + {} split signatures",
        dlc_batch.outcome_batch_ids.len(),
        dlc_batch.split_batch_ids.len()
    );

    // Phase 9: Oracle Attestation
    info!("\n=== Phase 9: Oracle Attestation ===");

    let attested_outcome_idx: OutcomeIndex = 0;
    let attested_message = &outcome_messages[attested_outcome_idx];
    let oracle_attestation: MaybeScalar =
        attestation_secret(oracle_seckey, oracle_secnonce, attested_message);

    info!(
        "Oracle attested to outcome {}: {:?}",
        attested_outcome_idx,
        String::from_utf8_lossy(attested_message)
    );

    // Phase 10: Broadcast Outcome Transaction
    info!("\n=== Phase 10: Broadcast Outcome Transaction ===");

    let outcome_tx = signed_contract
        .signed_outcome_tx(attested_outcome_idx, oracle_attestation)
        .map_err(|e| anyhow!("Failed to create signed outcome tx: {:?}", e))?;

    info!("Created signed outcome transaction");
    info!("  Txid: {}", outcome_tx.compute_txid());

    // Validate: Before broadcasting, verify the transaction matches our expectations
    // In production, verify the outcome tx spends the correct funding UTXO
    if outcome_tx.input[0].previous_output != funding_utxo {
        return Err(anyhow!(
            "Outcome tx input mismatch! Expected {} but got {}",
            funding_utxo,
            outcome_tx.input[0].previous_output
        ));
    }
    info!("  Outcome tx input verified");

    let outcome_txid = broadcast_transaction(&test, &outcome_tx).await?;
    info!("Broadcast outcome transaction: {}", outcome_txid);

    mine_blocks(&test, 1).await?;
    info!("Mined 1 block to confirm outcome tx");

    // Phase 11: Broadcast Split Transactions for ALL Winners (Weighted Payout)
    info!("\n=== Phase 11: Broadcast Split Transactions ===");

    // Get the payout weights for the attested outcome from the contract
    let attested_outcome = Outcome::Attestation(attested_outcome_idx);
    let payout_weights = contract_params
        .outcome_payouts
        .get(&attested_outcome)
        .ok_or_else(|| anyhow!("No payout weights for outcome {}", attested_outcome_idx))?;

    // Calculate total weight for percentage display
    let total_weight: u64 = payout_weights.values().sum();

    info!(
        "Outcome {} has {} winners with weighted payouts:",
        attested_outcome_idx,
        payout_weights.len()
    );

    let mut split_txids = Vec::new();
    for (player_idx, weight) in payout_weights {
        let payout_pct = (*weight as f64 / total_weight as f64) * 100.0;

        let win_condition = WinCondition {
            outcome: attested_outcome,
            player_index: *player_idx,
        };

        info!(
            "  Player {} claims {:.0}% of the pot (weight {}/{})",
            player_idx, payout_pct, weight, total_weight
        );

        let ticket_preimage = ticket_preimages[*player_idx];
        let split_tx = signed_contract
            .signed_split_tx(&win_condition, ticket_preimage)
            .map_err(|e| {
                anyhow!(
                    "Failed to create signed split tx for player {}: {:?}",
                    player_idx,
                    e
                )
            })?;

        info!(
            "    Split TX for player {}: {}",
            player_idx,
            split_tx.compute_txid()
        );

        let split_txid = broadcast_transaction(&test, &split_tx).await?;
        split_txids.push((*player_idx, split_txid));
        info!("    Broadcast split transaction: {}", split_txid);
    }

    mine_blocks(&test, 1).await?;
    info!("Mined 1 block to confirm all split txs");

    // Phase 12: Summary
    info!("\n=== DLC Batch Signing Example Complete ===");
    info!("Transaction chain:");
    info!("  1. Funding: {}:{}", funding_utxo.txid, funding_utxo.vout);
    info!("  2. Outcome: {}", outcome_txid);
    for (player_idx, txid) in &split_txids {
        info!("  3. Split (Player {}): {}", player_idx, txid);
    }
    info!("");
    info!("Summary:");
    info!("  - {} players, {} outcomes", NUM_PLAYERS, NUM_OUTCOMES);
    info!(
        "  - Batch signed {} outcome txs (n-of-n adaptor) + {} split txs (2-of-2 subset)",
        dlc_batch.outcome_batch_ids.len(),
        dlc_batch.split_batch_ids.len()
    );
    info!("  - Oracle attested to outcome {}", attested_outcome_idx);
    info!(
        "  - {} winners claimed weighted payouts via separate split txs",
        split_txids.len()
    );
    info!("");
    info!("Key features demonstrated:");
    info!("  - Subset definitions per OUTCOME: market_maker + ALL winners for that outcome");
    info!("  - Per-batch-item subset_id for signing with outcome's aggregate key");
    info!("  - WEIGHTED PAYOUTS: Multiple winners per outcome with proportional splits");
    info!(
        "  - Full DLC flow: fund -> outcome tx (n-of-n adaptor) -> split txs (k-of-k per outcome)"
    );

    Ok(())
}

async fn broadcast_transaction(
    test: &KeyMeldE2ETest,
    tx: &Transaction,
) -> Result<dlctix::bitcoin::Txid> {
    let tx_hex = consensus::encode::serialize_hex(tx);

    if let Some(ref batcher) = test.rpc_batcher {
        let txid_str = batcher.send_raw_transaction(&tx_hex).await?;
        txid_str
            .parse()
            .map_err(|e| anyhow!("Failed to parse txid: {}", e))
    } else {
        let txid = retry_bitcoin_rpc("sendrawtransaction", || {
            test.rpc_client.send_raw_transaction(tx)
        })
        .await?;
        txid.to_string()
            .parse()
            .map_err(|e| anyhow!("Failed to parse txid: {}", e))
    }
}

async fn mine_blocks(test: &KeyMeldE2ETest, num_blocks: u64) -> Result<()> {
    let coordinator_address = test
        .coordinator_wallet
        .peek_address(KeychainKind::External, 0)
        .address;

    if let Some(ref batcher) = test.rpc_batcher {
        batcher
            .generate_to_address(num_blocks, &coordinator_address.to_string())
            .await?;
    } else {
        retry_bitcoin_rpc("generatetoaddress", || {
            test.rpc_client
                .generate_to_address(num_blocks, &coordinator_address)
        })
        .await?;
    }

    Ok(())
}
