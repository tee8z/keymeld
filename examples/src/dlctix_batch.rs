//! DLC Batch Signing Example
//!
//! Demonstrates using keymeld's batch signing API to sign both outcome transactions
//! and split transactions for a Ticketed DLC.
//!
//! Key features demonstrated:
//! - Outcome transactions: Use full n-of-n aggregate key with adaptor signatures
//! - Split transactions: Use 2-of-2 subset aggregate keys (winner + market_maker)
//! - Subset definitions: Define player+market_maker pairs at keygen time
//! - Weighted payouts: Multiple winners per outcome with proportional payouts
//! - Happy path: Oracle attests, outcome tx broadcast, then split txs for each winner

use crate::{retry_bitcoin_rpc, ExampleConfig, KeyMeldE2ETest};
use anyhow::{anyhow, Result};
use bdk_bitcoind_rpc::bitcoincore_rpc::RpcApi;
use bdk_wallet::KeychainKind;
use dlctix::bitcoin::consensus;
use dlctix::bitcoin::{Amount, FeeRate, Transaction};
use dlctix::musig2::{AdaptorSignature, CompactSignature};
use dlctix::secp::{MaybePoint, MaybeScalar, Point, Scalar};
use dlctix::{
    attestation_locking_point, attestation_secret, ContractParameters, ContractSignatures,
    EventLockingConditions, MarketMaker, Outcome, OutcomeIndex, PayoutWeights, Player,
    SignedContract, TicketedDLC, WinCondition,
};
use keymeld_sdk::{
    validation::{
        decrypt_adaptor_signatures_with_secret, decrypt_signature_with_secret,
        encrypt_adaptor_configs_for_client, encrypt_session_data,
    },
    AdaptorConfig, AdaptorType, CreateSigningSessionRequest, SigningBatchItem, SigningMode,
    SigningSessionStatusResponse, SigningStatusKind, SubsetDefinition, TaprootTweak,
};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::info;
use uuid::Uuid;

const NUM_PLAYERS: usize = 3;
const NUM_OUTCOMES: usize = 3;
const FUNDING_AMOUNT_SATS: u64 = 300_000; // Increased to support multiple winners per outcome

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

    // Create subset definitions for each OUTCOME (not per player!)
    // Each outcome's split tx uses an aggregate key of: market_maker + ALL winners for that outcome
    // This is critical: dlctix computes the split key from market_maker + winner pubkeys for the outcome
    let mut subset_definitions = Vec::new();
    let mut outcome_subset_ids: BTreeMap<OutcomeIndex, Uuid> = BTreeMap::new();

    // Define the winners for each outcome (must match outcome_payouts defined later)
    let outcome_winners: Vec<(OutcomeIndex, Vec<usize>)> = vec![
        (0, vec![0, 1]),    // Outcome 0: Player 0 + Player 1 win
        (1, vec![1, 2]),    // Outcome 1: Player 1 + Player 2 win
        (2, vec![0, 1, 2]), // Outcome 2: All players win
    ];

    for (outcome_idx, winner_indices) in &outcome_winners {
        let subset_id = Uuid::now_v7();
        outcome_subset_ids.insert(*outcome_idx, subset_id);

        // Subset includes: market_maker (coordinator) + ALL winning players for this outcome
        let mut participants = vec![test.coordinator_user_id.clone()]; // market_maker
        for player_idx in winner_indices {
            participants.push(test.participant_user_ids[*player_idx].clone());
        }

        let subset_def = SubsetDefinition {
            subset_id,
            participants,
        };
        subset_definitions.push(subset_def);
        info!(
            "  Subset {} for outcome {}: market_maker + players {:?}",
            subset_id, outcome_idx, winner_indices
        );
    }

    info!(
        "Created {} subset definitions for split transactions (one per outcome)",
        subset_definitions.len()
    );

    let keygen_session_id = test
        .create_keygen_session_with_subsets(subset_definitions)
        .await?;
    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let encrypted_aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;

    info!("Keygen complete!");
    let aggregate_key_hex =
        test.decrypt_aggregate_key_for_display(&encrypted_aggregate_key, &keygen_session_id)?;
    info!("  Aggregate key: {}...", &aggregate_key_hex[..16]);

    // Phase 3: Create DLC Contract
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

    // Phase 4: Fund the DLC
    info!("\n=== Phase 4: Fund the DLC ===");

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

    // Phase 5: Extract Signing Data
    info!("\n=== Phase 5: Extract Signing Data ===");

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

    // Phase 6: Batch Signing with KeyMeld
    info!("\n=== Phase 6: Batch Signing with KeyMeld ===");

    let session_secret = test
        .session_secrets
        .get(&keygen_session_id)
        .ok_or(anyhow!("Session secret not found"))?;

    let mut outcome_batch_ids: BTreeMap<OutcomeIndex, Uuid> = BTreeMap::new();
    let mut batch_items = Vec::new();

    for (outcome, sighash) in &signing_data.outcome_sighashes {
        let batch_item_id = Uuid::now_v7();
        let encrypted_message = encrypt_session_data(&hex::encode(sighash), session_secret)?;

        // Outcome transactions use NO tweak - dlctix uses untweaked aggregate key
        // (the key is marked as "dangerous_assume_tweaked" at the Bitcoin layer,
        // but MuSig2 signing uses the raw aggregate key)
        let encrypted_tweak =
            encrypt_session_data(&serde_json::to_string(&TaprootTweak::None)?, session_secret)?;

        let signing_mode = match outcome {
            Outcome::Attestation(idx) => {
                outcome_batch_ids.insert(*idx, batch_item_id);

                if let Some(adaptor_point) = signing_data.adaptor_points.get(idx) {
                    let point_bytes = match adaptor_point {
                        MaybePoint::Infinity => {
                            return Err(anyhow!("Adaptor point is infinity for outcome {}", idx));
                        }
                        MaybePoint::Valid(p) => p.serialize().to_vec(),
                    };

                    let adaptor_config = AdaptorConfig {
                        adaptor_id: Uuid::now_v7(),
                        adaptor_type: AdaptorType::Single,
                        adaptor_points: vec![hex::encode(point_bytes)],
                        hints: None,
                    };

                    let encrypted_adaptor_configs =
                        encrypt_adaptor_configs_for_client(&[adaptor_config], session_secret)?;
                    SigningMode::Adaptor {
                        encrypted_message,
                        encrypted_adaptor_configs,
                    }
                } else {
                    SigningMode::Regular { encrypted_message }
                }
            }
            Outcome::Expiry => SigningMode::Regular { encrypted_message },
        };

        batch_items.push(SigningBatchItem {
            batch_item_id,
            message_hash: sighash.to_vec(),
            signing_mode,
            encrypted_taproot_tweak: encrypted_tweak.clone(),
            subset_id: None, // Use full n-of-n aggregate key for outcome transactions
        });
        info!(
            "  Outcome batch item for {:?}: {} (n-of-n)",
            outcome, batch_item_id
        );
    }

    // Add split transactions using subset aggregate keys
    // Each split tx uses the outcome's subset (market_maker + ALL winners for that outcome)
    let mut split_batch_ids: BTreeMap<WinCondition, Uuid> = BTreeMap::new();
    let encrypted_tweak =
        encrypt_session_data(&serde_json::to_string(&TaprootTweak::None)?, session_secret)?;

    for (win_condition, sighash) in &signing_data.split_sighashes {
        let batch_item_id = Uuid::now_v7();
        let encrypted_message = encrypt_session_data(&hex::encode(sighash), session_secret)?;

        // Get the outcome index from the win condition
        let outcome_idx = match win_condition.outcome {
            Outcome::Attestation(idx) => idx,
            Outcome::Expiry => {
                return Err(anyhow!("Expiry outcome not supported in this example"));
            }
        };

        // Get the subset_id for this OUTCOME's split transaction
        // (not per-player - all winners for this outcome share the same aggregate key)
        let subset_id = outcome_subset_ids.get(&outcome_idx).ok_or_else(|| {
            anyhow!(
                "No subset defined for outcome {} in win condition {:?}",
                outcome_idx,
                win_condition
            )
        })?;

        split_batch_ids.insert(*win_condition, batch_item_id);

        batch_items.push(SigningBatchItem {
            batch_item_id,
            message_hash: sighash.to_vec(),
            signing_mode: SigningMode::Regular { encrypted_message }, // Split transactions use regular signatures
            encrypted_taproot_tweak: encrypted_tweak.clone(),
            subset_id: Some(*subset_id), // Use outcome's subset aggregate key
        });
        info!(
            "  Split batch item for {:?}: {} (outcome {} subset {})",
            win_condition, batch_item_id, outcome_idx, subset_id
        );
    }

    info!(
        "  Total: {} outcome txs + {} split txs = {} batch items",
        outcome_batch_ids.len(),
        split_batch_ids.len(),
        batch_items.len()
    );

    let signing_session_id = keymeld_sdk::SessionId::new_v7();
    info!("Creating signing session: {}", signing_session_id);
    info!("  Total batch items: {}", batch_items.len());

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
    info!("Signing session created");

    info!("Submitting signing approvals...");
    test.approve_signing_session(
        &signing_session_id,
        &test.coordinator_user_id.clone(),
        &test.coordinator_derived_private_key.clone(),
        &keygen_session_id,
    )
    .await?;

    for idx in test.participants_requiring_approval.clone() {
        test.approve_signing_session(
            &signing_session_id,
            &test.participant_user_ids[idx].clone(),
            &test.participants[idx].derived_private_key.clone(),
            &keygen_session_id,
        )
        .await?;
    }
    info!("All approvals submitted");

    info!("Waiting for batch signing completion...");
    let batch_results =
        wait_for_batch_completion(&test, &signing_session_id, &keygen_session_id).await?;
    info!(
        "Batch signing complete! Results received: {}",
        batch_results.len()
    );

    // Phase 7: Parse Results into ContractSignatures
    info!("\n=== Phase 7: Parse Results into ContractSignatures ===");

    let results_by_id: BTreeMap<Uuid, &keymeld_sdk::BatchItemResult> =
        batch_results.iter().map(|r| (r.batch_item_id, r)).collect();

    let mut outcome_tx_signatures: BTreeMap<OutcomeIndex, AdaptorSignature> = BTreeMap::new();
    for (outcome_idx, batch_id) in &outcome_batch_ids {
        let result = results_by_id
            .get(batch_id)
            .ok_or(anyhow!("Missing result for outcome {}", outcome_idx))?;

        let encrypted_adaptor_sigs = result
            .adaptor_signatures
            .as_ref()
            .ok_or(anyhow!("No adaptor signature for outcome {}", outcome_idx))?;

        if encrypted_adaptor_sigs.is_empty() {
            return Err(anyhow!(
                "Empty adaptor signature for outcome {}",
                outcome_idx
            ));
        }

        // Decrypt the adaptor signatures
        let decrypted_adaptor_sigs =
            decrypt_adaptor_signatures_with_secret(encrypted_adaptor_sigs, session_secret)
                .map_err(|e| anyhow!("Failed to decrypt adaptor signatures: {:?}", e))?;

        // There should be exactly one adaptor signature result per batch item
        let adaptor_result = decrypted_adaptor_sigs.values().next().ok_or(anyhow!(
            "No adaptor signature result for outcome {}",
            outcome_idx
        ))?;

        // Parse the adaptor signature - signature_scalar contains the full 65-byte serialized AdaptorSignature
        let adaptor_sig = AdaptorSignature::from_bytes(&adaptor_result.signature_scalar)
            .map_err(|e| anyhow!("Failed to parse adaptor signature: {:?}", e))?;

        outcome_tx_signatures.insert(*outcome_idx, adaptor_sig);
        info!("  Parsed adaptor signature for outcome {}", outcome_idx);
    }

    // Parse split transaction signatures (regular Schnorr signatures, not adaptors)
    let mut split_tx_signatures: BTreeMap<WinCondition, CompactSignature> = BTreeMap::new();
    for (win_condition, batch_id) in &split_batch_ids {
        let result = results_by_id
            .get(batch_id)
            .ok_or(anyhow!("Missing result for split {:?}", win_condition))?;

        // Split transactions have regular signatures, not adaptor signatures
        let encrypted_signature = result
            .signature
            .as_ref()
            .ok_or(anyhow!("No signature for split {:?}", win_condition))?;

        // Decrypt the signature
        let signature_bytes = decrypt_signature_with_secret(encrypted_signature, session_secret)
            .map_err(|e| anyhow!("Failed to decrypt split signature: {:?}", e))?;

        // Parse as CompactSignature (64 bytes)
        let compact_sig = CompactSignature::from_bytes(&signature_bytes)
            .map_err(|e| anyhow!("Failed to parse split signature: {:?}", e))?;

        split_tx_signatures.insert(*win_condition, compact_sig);
        info!("  Parsed signature for split {:?}", win_condition);
    }

    let contract_signatures = ContractSignatures {
        expiry_tx_signature: None,
        outcome_tx_signatures,
        split_tx_signatures,
    };

    let signed_contract: SignedContract = ticketed_dlc.into_signed_contract(contract_signatures);
    info!(
        "Created SignedContract with {} outcome + {} split signatures",
        outcome_batch_ids.len(),
        split_batch_ids.len()
    );

    // Phase 8: Oracle Attestation
    info!("\n=== Phase 8: Oracle Attestation ===");

    let attested_outcome_idx: OutcomeIndex = 0;
    let attested_message = &outcome_messages[attested_outcome_idx];
    let oracle_attestation: MaybeScalar =
        attestation_secret(oracle_seckey, oracle_secnonce, attested_message);

    info!(
        "Oracle attested to outcome {}: {:?}",
        attested_outcome_idx,
        String::from_utf8_lossy(attested_message)
    );

    // Phase 9: Broadcast Outcome Transaction
    info!("\n=== Phase 9: Broadcast Outcome Transaction ===");

    let outcome_tx = signed_contract
        .signed_outcome_tx(attested_outcome_idx, oracle_attestation)
        .map_err(|e| anyhow!("Failed to create signed outcome tx: {:?}", e))?;

    info!("Created signed outcome transaction");
    info!("  Txid: {}", outcome_tx.compute_txid());

    let outcome_txid = broadcast_transaction(&test, &outcome_tx).await?;
    info!("Broadcast outcome transaction: {}", outcome_txid);

    mine_blocks(&test, 1).await?;
    info!("Mined 1 block to confirm outcome tx");

    // Phase 10: Broadcast Split Transactions for ALL Winners (Weighted Payout)
    info!("\n=== Phase 10: Broadcast Split Transactions ===");

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

    // Phase 11: Summary
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
        outcome_batch_ids.len(),
        split_batch_ids.len()
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

async fn wait_for_batch_completion(
    test: &KeyMeldE2ETest,
    signing_session_id: &keymeld_sdk::SessionId,
    keygen_session_id: &keymeld_sdk::SessionId,
) -> Result<Vec<keymeld_sdk::BatchItemResult>> {
    const MAX_WAIT_SECS: u64 = 120;
    const POLL_INTERVAL_MS: u64 = 500;

    let start = Instant::now();

    loop {
        if start.elapsed().as_secs() > MAX_WAIT_SECS {
            return Err(anyhow!("Timeout waiting for batch signing completion"));
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
            SigningStatusKind::Completed => return Ok(status.batch_results),
            SigningStatusKind::Failed => return Err(anyhow!("Batch signing session failed")),
            SigningStatusKind::CollectingParticipants => info!("  Collecting participants..."),
            SigningStatusKind::InitializingSession => info!("  Initializing session..."),
            SigningStatusKind::DistributingNonces => info!("  Distributing nonces..."),
            SigningStatusKind::FinalizingSignature => info!("  Finalizing signatures..."),
        }

        sleep(Duration::from_millis(POLL_INTERVAL_MS)).await;
    }
}
