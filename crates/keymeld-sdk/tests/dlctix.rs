#![cfg(all(feature = "client", feature = "dlctix"))]

use keymeld_core::{
    BinaryEncoding, CompactSignature, FirstRound, KeyAggContext, PartialSignature, PublicKey,
    SecondRound,
};
use keymeld_sdk::dlctix::{
    dlctix::{
        bitcoin::{Amount, FeeRate, OutPoint},
        hashlock,
        secp::{MaybePoint, Point, Scalar},
        ContractParameters, ContractSignatures, EventLockingConditions, MarketMaker, Outcome,
        Player, TicketedDLC, WinCondition,
    },
    DlcBatchBuilder, DlcSubsetBuilder,
};
use keymeld_sdk::{AdaptorSignatureResult, AdaptorType, SdkError, SignatureResult, UserId};
use secp256k1::{Secp256k1, SecretKey};
use std::collections::BTreeMap;
use uuid::Uuid;

fn contract_fixture() -> (TicketedDLC, BTreeMap<[u8; 33], SecretKey>) {
    let secp = Secp256k1::new();
    let secret_keys: Vec<_> = (1..=4)
        .map(|n| SecretKey::from_byte_array([n; 32]).unwrap())
        .collect();
    let public_keys: Vec<_> = secret_keys
        .iter()
        .map(|key| PublicKey::from_secret_key(&secp, key).serialize())
        .collect();
    let keys = public_keys.iter().copied().zip(secret_keys).collect();
    let params = ContractParameters {
        market_maker: MarketMaker {
            pubkey: Point::from_slice(&public_keys[0]).unwrap(),
        },
        players: public_keys[1..]
            .iter()
            .enumerate()
            .map(|(index, pubkey)| Player {
                pubkey: Point::from_slice(pubkey).unwrap(),
                ticket_hash: hashlock::sha256(&[10 + index as u8; 32]),
                payout_hash: hashlock::sha256(&[20 + index as u8; 32]),
            })
            .collect(),
        event: EventLockingConditions {
            locking_points: [30, 31]
                .map(|n| {
                    Scalar::from_slice(&[n; 32])
                        .unwrap()
                        .base_point_mul()
                        .into()
                })
                .to_vec(),
            expiry: Some(1_000_000),
        },
        outcome_payouts: BTreeMap::from([
            (Outcome::Attestation(0), BTreeMap::from([(0, 3), (1, 2)])),
            (Outcome::Attestation(1), BTreeMap::from([(1, 1), (2, 1)])),
            // KeyMeld currently signs expiry splits with the full participant set.
            (Outcome::Expiry, BTreeMap::from([(0, 1), (1, 1), (2, 1)])),
        ]),
        fee_rate: FeeRate::from_sat_per_vb_u32(1),
        funding_value: Amount::from_sat(300_000),
        relative_locktime_block_delta: 1,
    };
    (TicketedDLC::new(params, OutPoint::null()).unwrap(), keys)
}

/// Use the same MuSig2 implementation as KeyMeld's enclave, then cross the SDK's
/// serialized-signature boundary into dlctix's independently versioned MuSig2.
fn sign_with_keymeld(
    batch_item_id: Uuid,
    signers: &[Point],
    expected_aggregate_key: Point,
    message: [u8; 32],
    adaptor: Option<MaybePoint>,
    keys: &BTreeMap<[u8; 33], SecretKey>,
) -> SignatureResult {
    let mut public_keys: Vec<_> = signers
        .iter()
        .map(|key| PublicKey::from_slice(&key.serialize()).unwrap())
        .collect();
    public_keys.sort_by_key(PublicKey::serialize);
    let key_agg_ctx = KeyAggContext::new(public_keys.iter().copied()).unwrap();
    let aggregate_key: PublicKey = key_agg_ctx.aggregated_pubkey();
    assert_eq!(
        aggregate_key.serialize(),
        expected_aggregate_key.serialize()
    );

    let mut first_rounds: Vec<_> = (0..public_keys.len())
        .map(|index| {
            FirstRound::new(
                key_agg_ctx.clone(),
                secp256k1::rand::random::<[u8; 32]>(),
                index,
                Default::default(),
            )
            .unwrap()
        })
        .collect();
    let nonces: Vec<_> = first_rounds
        .iter()
        .map(FirstRound::our_public_nonce)
        .collect();
    for round in &mut first_rounds {
        for (index, nonce) in nonces.iter().enumerate() {
            round.receive_nonce(index, nonce.clone()).unwrap();
        }
    }

    let adaptor_key = adaptor.map(|point| PublicKey::from_slice(&point.serialize()).unwrap());
    let mut second_rounds: Vec<SecondRound<[u8; 32]>> = first_rounds
        .into_iter()
        .zip(&public_keys)
        .map(|(round, pubkey)| {
            let secret_key = keys[&pubkey.serialize()];
            match adaptor_key {
                Some(point) => round.finalize_adaptor(secret_key, point, message).unwrap(),
                None => round.finalize(secret_key, message).unwrap(),
            }
        })
        .collect();
    let partial_signatures: Vec<PartialSignature> = second_rounds
        .iter()
        .map(SecondRound::our_signature)
        .collect();
    for round in &mut second_rounds {
        for (index, signature) in partial_signatures.iter().enumerate() {
            round.receive_signature(index, *signature).unwrap();
        }
    }

    let round = second_rounds.into_iter().next().unwrap();
    let mut result = SignatureResult {
        batch_item_id,
        signature: None,
        adaptor_signatures: None,
        error: None,
    };
    if let Some(point) = adaptor_key {
        let adaptor_id = Uuid::now_v7();
        let nonce_point = round.aggregated_nonce().serialize().to_vec();
        // The generic parameter in musig2 0.3's finalize_adaptor is unused.
        let signature = round.finalize_adaptor::<()>().unwrap();
        result.adaptor_signatures = Some(BTreeMap::from([(
            adaptor_id,
            AdaptorSignatureResult {
                adaptor_id,
                adaptor_type: AdaptorType::Single,
                signature_scalar: signature.to_bytes().to_vec(),
                nonce_point,
                adaptor_points: vec![point.serialize().to_vec()],
                hints: None,
                aggregate_adaptor_point: point.serialize().to_vec(),
            },
        )]));
    } else {
        let signature: CompactSignature = round.finalize().unwrap();
        result.signature = Some(signature.to_bytes().to_vec());
    }
    result
}

fn externally_signed_contract() -> (TicketedDLC, ContractSignatures) {
    let (dlc, keys) = contract_fixture();
    let subsets = DlcSubsetBuilder::new(
        dlc.params(),
        UserId::new_v7(),
        (0..dlc.params().players.len())
            .map(|_| UserId::new_v7())
            .collect(),
    )
    .build()
    .unwrap();
    let signing_data = dlc.signing_data().unwrap();
    let batch = DlcBatchBuilder::new(&signing_data)
        .with_outcome_subsets(&subsets.outcome_subset_ids)
        .build()
        .unwrap();
    let mut results = Vec::new();
    for (outcome, message) in &signing_data.outcome_sighashes {
        let batch_id = match outcome {
            Outcome::Attestation(index) => batch.outcome_batch_ids[index],
            Outcome::Expiry => batch.expiry_batch_id.unwrap(),
        };
        results.push(sign_with_keymeld(
            batch_id,
            &signing_data.funding_signers,
            signing_data.funding_agg_pubkey,
            *message,
            signing_data.adaptor_point(outcome).unwrap(),
            &keys,
        ));
    }
    for (win_condition, message) in &signing_data.split_sighashes {
        results.push(sign_with_keymeld(
            batch.split_batch_ids[win_condition],
            &signing_data.split_signers[&win_condition.outcome],
            signing_data.split_agg_pubkeys[&win_condition.outcome],
            *message,
            None,
            &keys,
        ));
    }
    assert_eq!(results.len(), signing_data.total_signature_count());
    let parsed = batch.parse_results(&results).unwrap();
    (
        dlc,
        ContractSignatures {
            expiry_tx_signature: parsed.expiry_signature,
            outcome_tx_signatures: parsed.outcome_signatures,
            split_tx_signatures: parsed.split_signatures,
        },
    )
}

#[test]
fn keymeld_signatures_verify_with_dlctix() {
    let (dlc, signatures) = externally_signed_contract();
    let market_maker = dlc.params().market_maker.pubkey;
    dlc.verify_signatures(market_maker, &signatures).unwrap();
    let signed = dlc.into_signed_contract(market_maker, signatures).unwrap();

    let oracle_secret = Scalar::from_slice(&[30; 32]).unwrap();
    let outcome_tx = signed.signed_outcome_tx(0, oracle_secret).unwrap();
    assert!(!outcome_tx.input[0].witness.is_empty());
    let split_tx = signed
        .signed_split_tx(
            &WinCondition {
                outcome: Outcome::Attestation(0),
                player_index: 0,
            },
            [10; 32],
        )
        .unwrap();
    assert!(!split_tx.input[0].witness.is_empty());
}

#[test]
fn dlctix_rejects_incomplete_or_invalid_keymeld_signatures() {
    let (dlc, signatures) = externally_signed_contract();
    let market_maker = dlc.params().market_maker.pubkey;

    let mut missing_split = signatures.clone();
    missing_split.split_tx_signatures.pop_first().unwrap();
    assert!(dlc.verify_signatures(market_maker, &missing_split).is_err());
    assert!(dlc
        .clone()
        .into_signed_contract(market_maker, missing_split)
        .is_err());

    let mut missing_expiry = signatures.clone();
    missing_expiry.expiry_tx_signature = None;
    assert!(dlc
        .verify_signatures(market_maker, &missing_expiry)
        .is_err());

    // A valid signature for another outcome still parses, but must not validate
    // for this contract's sighash and adaptor point.
    let mut wrong_outcome = signatures;
    wrong_outcome
        .outcome_tx_signatures
        .insert(0, wrong_outcome.outcome_tx_signatures[&1]);
    assert!(dlc.verify_signatures(market_maker, &wrong_outcome).is_err());
    assert!(dlc
        .into_signed_contract(market_maker, wrong_outcome)
        .is_err());
}

#[test]
fn batch_builder_rejects_missing_or_infinite_attestation_adaptors() {
    let (dlc, _) = contract_fixture();
    let signing_data = dlc.signing_data().unwrap();
    assert!(DlcBatchBuilder::new(&signing_data).build().is_ok());

    for (case, point) in [("missing", None), ("infinite", Some(MaybePoint::Infinity))] {
        let mut invalid_data = signing_data.clone();
        invalid_data.adaptor_points.remove(&0);
        if let Some(point) = point {
            invalid_data.adaptor_points.insert(0, point);
        }

        // Neither malformed input may yield a batch that could sign an
        // attestation outcome without the oracle's secret.
        assert!(
            matches!(
                DlcBatchBuilder::new(&invalid_data).build(),
                Err(SdkError::InvalidInput(_))
            ),
            "{case} attestation adaptor must be rejected"
        );
    }
}

#[test]
fn persisted_batch_preserves_exact_ids_and_rejects_duplicate_split_keys() {
    let (contract, _) = contract_fixture();
    let signing = contract.signing_data().unwrap();
    let batch = DlcBatchBuilder::new(&signing).build().unwrap();
    let encoded = serde_json::to_value(&batch).unwrap();
    let restored: keymeld_sdk::dlctix::DlcBatchItems =
        serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(restored).unwrap(), encoded);
    let mut altered = encoded;
    let splits = altered["split_batch_ids"].as_array_mut().unwrap();
    assert!(!splits.is_empty());
    splits.push(splits[0].clone());
    assert!(serde_json::from_value::<keymeld_sdk::dlctix::DlcBatchItems>(altered).is_err());
}
