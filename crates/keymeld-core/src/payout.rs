//! Payout preimage release.
//!
//! An enclave holding a participant's key can release a secret derived from
//! it, the *payout preimage*, to a claimant that proves it paid the
//! participant's registered Lightning Address what a settlement rule says is
//! owed. The exchange is generic; the settlement rule implemented here is a
//! ticketed DLC contract (dlctix), in which a winner's on-chain share can be
//! swept by the contract's market maker with the winner's payout preimage.
//!
//! Trust model: the claimant is not trusted. Everything it supplies is checked
//! against data the enclave already holds (the participant's key, registered
//! payout policy, and the batch the claimant itself authorized for signing)
//! or against the participant's own Lightning Address service (whose invoice
//! commits to the address through the LNURL-pay metadata hash, LUD-06/LUD-16)
//! and the settled payment (whose preimage opens the invoice's payment hash).

use crate::authorization::PayoutPolicy;
use dlctix::bitcoin::hashes::Hash as _;
use dlctix::{
    bitcoin::OutPoint,
    secp::{MaybePoint, Scalar},
    ContractParameters, Outcome, TicketedDLC,
};
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescriptionRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, str::FromStr};

/// Upper bound on a submitted BOLT11 invoice or LNURL metadata blob.
pub const MAX_PROOF_FIELD_LEN: usize = 8192;

/// The contract a keygen session signed, as the claimant states it.
/// It is bound to the signed batch by [`verify_contract_binding`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCommitment {
    pub contract_parameters: ContractParameters,
    pub funding_outpoint: OutPoint,
}

/// Evidence that the participant was paid.
#[derive(Debug, Clone, Copy)]
pub struct PaymentProof<'a> {
    /// The BOLT11 invoice obtained from the participant's Lightning Address.
    pub invoice: &'a str,
    /// The LNURL-pay metadata the invoice's description hash commits to.
    pub lnurl_metadata: &'a str,
    /// The preimage revealed when the invoice was paid.
    pub payment_preimage: &'a [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutError {
    /// The claimed contract does not produce the messages that were signed.
    ContractMismatch(String),
    /// The attestation matches no outcome of the contract.
    UnknownOutcome,
    /// The participant is not a player of the contract.
    NotAPlayer,
    /// The participant is not paid under the attested outcome.
    NotAWinner,
    InvalidInvoice(String),
    /// The invoice does not commit to the LNURL metadata (LUD-06 `h` tag).
    UncommittedInvoice,
    /// The metadata names no or a different Lightning Address.
    AddressMismatch,
    /// The invoice was not signed by the node registered in the policy.
    PayeeMismatch,
    /// The invoice pays less than the contract owes.
    Underpaid {
        invoice_msat: u64,
        owed_sats: u64,
    },
    /// The preimage does not open the invoice's payment hash.
    PreimageMismatch,
    /// A proof field exceeds [`MAX_PROOF_FIELD_LEN`].
    ProofTooLarge,
}

impl fmt::Display for PayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractMismatch(reason) => {
                write!(
                    f,
                    "claimed contract does not match the signed batch: {reason}"
                )
            }
            Self::UnknownOutcome => write!(f, "attestation matches no contract outcome"),
            Self::NotAPlayer => write!(f, "participant is not a player of the contract"),
            Self::NotAWinner => write!(f, "participant is not a winner of the attested outcome"),
            Self::InvalidInvoice(reason) => write!(f, "invalid invoice: {reason}"),
            Self::UncommittedInvoice => {
                write!(f, "invoice does not commit to the LNURL-pay metadata")
            }
            Self::AddressMismatch => {
                write!(
                    f,
                    "invoice metadata does not name the registered Lightning Address"
                )
            }
            Self::Underpaid {
                invoice_msat,
                owed_sats,
            } => write!(
                f,
                "invoice pays {invoice_msat} msat but {owed_sats} sats are owed"
            ),
            Self::PayeeMismatch => {
                write!(f, "invoice was not signed by the registered payee node")
            }
            Self::PreimageMismatch => write!(f, "payment preimage does not open the invoice"),
            Self::ProofTooLarge => write!(f, "payment proof field is too large"),
        }
    }
}

impl std::error::Error for PayoutError {}

/// Every sighash the contract's outcome and split transactions need.
pub fn contract_sighashes(
    commitment: &ContractCommitment,
) -> Result<BTreeSet<[u8; 32]>, PayoutError> {
    let dlc = TicketedDLC::new(
        commitment.contract_parameters.clone(),
        commitment.funding_outpoint,
    )
    .map_err(|e| PayoutError::ContractMismatch(e.to_string()))?;
    let signing_data = dlc
        .signing_data()
        .map_err(|e| PayoutError::ContractMismatch(e.to_string()))?;
    Ok(signing_data
        .outcome_sighashes
        .values()
        .chain(signing_data.split_sighashes.values())
        .copied()
        .collect())
}

/// The claimed contract is the one that was signed iff the signed messages
/// are exactly its sighashes. Any other message in the batch, or any missing
/// sighash, means the authority signed something else.
pub fn verify_contract_binding(
    commitment: &ContractCommitment,
    signed_messages: &[[u8; 32]],
) -> Result<(), PayoutError> {
    let expected = contract_sighashes(commitment)?;
    let signed: BTreeSet<[u8; 32]> = signed_messages.iter().copied().collect();
    if signed_messages.len() != signed.len() {
        return Err(PayoutError::ContractMismatch(
            "signed batch contains duplicate messages".into(),
        ));
    }
    if expected != signed {
        return Err(PayoutError::ContractMismatch(format!(
            "contract needs {} signatures, batch signed {} matching messages",
            expected.len(),
            expected.intersection(&signed).count()
        )));
    }
    Ok(())
}

/// The outcome whose locking point the oracle's attestation opens.
pub fn attested_outcome(
    params: &ContractParameters,
    attestation: &[u8; 32],
) -> Result<Outcome, PayoutError> {
    let attestation = Scalar::from_slice(attestation).map_err(|_| PayoutError::UnknownOutcome)?;
    let locking_point = MaybePoint::Valid(attestation.base_point_mul());
    params
        .event
        .locking_points
        .iter()
        .position(|point| *point == locking_point)
        .map(Outcome::Attestation)
        .ok_or(PayoutError::UnknownOutcome)
}

/// What the contract owes the player with `player_pubkey` (compressed
/// secp256k1) under `outcome`: their weight's share of the funding value.
/// Weights sum to 100.
pub fn owed_sats(
    params: &ContractParameters,
    outcome: &Outcome,
    player_pubkey: &[u8],
) -> Result<u64, PayoutError> {
    let index = params
        .players
        .iter()
        .position(|player| player.pubkey.serialize().as_slice() == player_pubkey)
        .ok_or(PayoutError::NotAPlayer)?;
    let weight = params
        .outcome_payouts
        .get(outcome)
        .and_then(|weights| weights.get(&index))
        .copied()
        .filter(|weight| *weight > 0)
        .ok_or(PayoutError::NotAWinner)?;
    Ok(params.funding_value.to_sat().saturating_mul(weight) / 100)
}

/// Accept the proof only if the invoice was issued for the registered
/// Lightning Address, pays at least what is owed, and was settled.
pub fn verify_payment_proof(
    policy: &PayoutPolicy,
    owed_sats: u64,
    proof: &PaymentProof<'_>,
) -> Result<(), PayoutError> {
    if proof.invoice.len() > MAX_PROOF_FIELD_LEN || proof.lnurl_metadata.len() > MAX_PROOF_FIELD_LEN
    {
        return Err(PayoutError::ProofTooLarge);
    }
    let invoice = Bolt11Invoice::from_str(proof.invoice.trim())
        .map_err(|e| PayoutError::InvalidInvoice(e.to_string()))?;

    let invoice_msat = invoice
        .amount_milli_satoshis()
        .ok_or_else(|| PayoutError::InvalidInvoice("invoice states no amount".into()))?;
    if owed_sats
        .checked_mul(1000)
        .is_none_or(|owed_msat| invoice_msat < owed_msat)
    {
        return Err(PayoutError::Underpaid {
            invoice_msat,
            owed_sats,
        });
    }

    let payment_hash: [u8; 32] = Sha256::digest(proof.payment_preimage).into();
    if invoice.payment_hash().to_byte_array()[..] != payment_hash[..] {
        return Err(PayoutError::PreimageMismatch);
    }

    let Bolt11InvoiceDescriptionRef::Hash(description_hash) = invoice.description() else {
        return Err(PayoutError::UncommittedInvoice);
    };
    let metadata_hash: [u8; 32] = Sha256::digest(proof.lnurl_metadata.as_bytes()).into();
    if description_hash.0.to_byte_array()[..] != metadata_hash[..] {
        return Err(PayoutError::UncommittedInvoice);
    }

    if !metadata_names_address(proof.lnurl_metadata, &policy.lightning_address) {
        return Err(PayoutError::AddressMismatch);
    }

    // Anyone with a node can sign an invoice carrying the right description
    // hash; only the pinned payee's signature proves the provider issued it.
    let payee = hex::encode(invoice.recover_payee_pub_key().serialize());
    if !payee.eq_ignore_ascii_case(policy.payee_node_id.trim()) {
        return Err(PayoutError::PayeeMismatch);
    }
    Ok(())
}

/// LUD-16: the metadata array carries `["text/identifier", "user@domain"]`
/// (or `text/email`) for the address the invoice was requested for.
fn metadata_names_address(metadata: &str, lightning_address: &str) -> bool {
    let Ok(entries) = serde_json::from_str::<Vec<Vec<serde_json::Value>>>(metadata) else {
        return false;
    };
    let wanted = lightning_address.trim();
    entries.iter().any(|entry| {
        matches!(
            (entry.first().and_then(|v| v.as_str()), entry.get(1).and_then(|v| v.as_str())),
            (Some("text/identifier") | Some("text/email"), Some(address))
                if address.trim().eq_ignore_ascii_case(wanted)
        )
    })
}

/// Run every check and, if they all pass, derive the participant's payout
/// preimage from their private key.
pub fn release_payout_preimage(
    commitment: &ContractCommitment,
    signed_messages: &[[u8; 32]],
    attestation: &[u8; 32],
    player_pubkey: &[u8],
    policy: &PayoutPolicy,
    proof: &PaymentProof<'_>,
    private_key: &[u8; 32],
) -> Result<[u8; 32], PayoutError> {
    verify_contract_binding(commitment, signed_messages)?;
    let outcome = attested_outcome(&commitment.contract_parameters, attestation)?;
    let owed = owed_sats(&commitment.contract_parameters, &outcome, player_pubkey)?;
    verify_payment_proof(policy, owed, proof)?;
    Ok(crate::crypto::derive_payout_preimage(private_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlctix::{
        attestation_locking_point,
        bitcoin::{
            hashes::{sha256, Hash},
            secp256k1::{PublicKey, Secp256k1, SecretKey},
            Amount, FeeRate, Txid,
        },
        hashlock, MarketMaker, PayoutWeights, Player,
    };
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    use std::collections::BTreeMap;

    struct Fixture {
        commitment: ContractCommitment,
        winner_key: Scalar,
        loser_key: Scalar,
        attestation: [u8; 32],
        other_attestation: [u8; 32],
    }

    fn fixture() -> Fixture {
        let mut rng = rand::rng();
        let winner_key = Scalar::random(&mut rng);
        let loser_key = Scalar::random(&mut rng);
        let player = |key: Scalar, rng: &mut rand::rngs::ThreadRng| Player {
            pubkey: key.base_point_mul(),
            ticket_hash: hashlock::sha256(&hashlock::preimage_random(rng)),
            payout_hash: hashlock::sha256(&hashlock::preimage_random(rng)),
        };
        let oracle_key = Scalar::random(&mut rng);
        let nonce_key = Scalar::random(&mut rng);
        let oracle = oracle_key.base_point_mul();
        let nonce = nonce_key.base_point_mul();
        let messages: Vec<&[u8]> = vec![b"winner wins", b"loser wins"];
        let locking_points = messages
            .iter()
            .map(|message| attestation_locking_point(oracle, nonce, message))
            .collect();
        let attest = |message: &[u8]| -> [u8; 32] {
            dlctix::attestation_secret(oracle_key, nonce_key, message).serialize()
        };
        let params = ContractParameters {
            market_maker: MarketMaker {
                pubkey: Scalar::random(&mut rng).base_point_mul(),
            },
            players: vec![player(winner_key, &mut rng), player(loser_key, &mut rng)],
            event: dlctix::EventLockingConditions {
                locking_points,
                expiry: None,
            },
            outcome_payouts: BTreeMap::from([
                (Outcome::Attestation(0), PayoutWeights::from([(0, 100)])),
                (Outcome::Attestation(1), PayoutWeights::from([(1, 100)])),
            ]),
            fee_rate: FeeRate::from_sat_per_vb_u32(1),
            funding_value: Amount::from_sat(100_000),
            relative_locktime_block_delta: 72,
        };
        Fixture {
            commitment: ContractCommitment {
                contract_parameters: params,
                funding_outpoint: OutPoint::new(Txid::all_zeros(), 0),
            },
            winner_key,
            loser_key,
            attestation: attest(b"winner wins"),
            other_attestation: attest(b"loser wins"),
        }
    }

    fn signed_messages(commitment: &ContractCommitment) -> Vec<[u8; 32]> {
        contract_sighashes(commitment)
            .unwrap()
            .into_iter()
            .collect()
    }

    const METADATA: &str = r#"[["text/plain","Pay alice"],["text/identifier","alice@cash.app"]]"#;

    fn proof<'a>(invoice: &'a str, metadata: &'a str, preimage: &'a [u8; 32]) -> PaymentProof<'a> {
        PaymentProof {
            invoice,
            lnurl_metadata: metadata,
            payment_preimage: preimage,
        }
    }

    const PAYEE_NODE_KEY: [u8; 32] = [0x11; 32];

    fn invoice(amount_msat: u64, preimage: &[u8; 32], metadata: &str) -> String {
        invoice_from(PAYEE_NODE_KEY, amount_msat, preimage, metadata)
    }

    fn invoice_from(
        node_key: [u8; 32],
        amount_msat: u64,
        preimage: &[u8; 32],
        metadata: &str,
    ) -> String {
        let secp = Secp256k1::new();
        let node_key = SecretKey::from_slice(&node_key).unwrap();
        let payment_hash = sha256::Hash::hash(preimage);
        let description_hash = sha256::Hash::hash(metadata.as_bytes());
        InvoiceBuilder::new(Currency::Regtest)
            .description_hash(description_hash)
            .payment_hash(payment_hash)
            .payment_secret(PaymentSecret([7; 32]))
            .amount_milli_satoshis(amount_msat)
            .current_timestamp()
            .min_final_cltv_expiry_delta(144)
            .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &node_key))
            .unwrap()
            .to_string()
    }

    fn policy() -> PayoutPolicy {
        let node_key = SecretKey::from_slice(&PAYEE_NODE_KEY).unwrap();
        PayoutPolicy {
            lightning_address: "Alice@cash.app".into(),
            payee_node_id: hex::encode(
                PublicKey::from_secret_key(&Secp256k1::new(), &node_key).serialize(),
            ),
        }
    }

    #[test]
    fn rejects_invoices_signed_by_another_node() {
        let preimage = [5u8; 32];
        let forged = invoice_from([0x12; 32], 1_000_000, &preimage, METADATA);
        let proof = PaymentProof {
            invoice: &forged,
            lnurl_metadata: METADATA,
            payment_preimage: &preimage,
        };
        assert_eq!(
            verify_payment_proof(&policy(), 1_000, &proof),
            Err(PayoutError::PayeeMismatch)
        );
        let genuine = invoice(1_000_000, &preimage, METADATA);
        let proof = PaymentProof {
            invoice: &genuine,
            lnurl_metadata: METADATA,
            payment_preimage: &preimage,
        };
        assert_eq!(verify_payment_proof(&policy(), 1_000, &proof), Ok(()));
    }

    #[test]
    fn the_signed_batch_must_be_exactly_the_contract_sighashes() {
        let f = fixture();
        let messages = signed_messages(&f.commitment);
        assert!(verify_contract_binding(&f.commitment, &messages).is_ok());

        let missing = &messages[1..];
        assert!(matches!(
            verify_contract_binding(&f.commitment, missing),
            Err(PayoutError::ContractMismatch(_))
        ));
        let mut extra = messages.clone();
        extra.push([9; 32]);
        assert!(matches!(
            verify_contract_binding(&f.commitment, &extra),
            Err(PayoutError::ContractMismatch(_))
        ));

        let mut cheaper = f.commitment.clone();
        cheaper.contract_parameters.funding_value = Amount::from_sat(50_000);
        assert!(matches!(
            verify_contract_binding(&cheaper, &messages),
            Err(PayoutError::ContractMismatch(_))
        ));
    }

    #[test]
    fn owed_amount_follows_the_attested_outcome() {
        let f = fixture();
        let params = &f.commitment.contract_parameters;
        let winner = f.winner_key.base_point_mul().serialize();
        let loser = f.loser_key.base_point_mul().serialize();

        let outcome = attested_outcome(params, &f.attestation).unwrap();
        assert_eq!(outcome, Outcome::Attestation(0));
        assert_eq!(owed_sats(params, &outcome, &winner), Ok(100_000));
        assert_eq!(
            owed_sats(params, &outcome, &loser),
            Err(PayoutError::NotAWinner)
        );
        assert_eq!(
            owed_sats(params, &outcome, &[2; 33]),
            Err(PayoutError::NotAPlayer)
        );

        let other = attested_outcome(params, &f.other_attestation).unwrap();
        assert_eq!(other, Outcome::Attestation(1));
        assert_eq!(owed_sats(params, &other, &loser), Ok(100_000));
        assert_eq!(
            attested_outcome(params, &[3; 32]),
            Err(PayoutError::UnknownOutcome)
        );
    }

    #[test]
    fn payment_proof_requires_the_address_amount_and_preimage() {
        let preimage = [5u8; 32];
        let good = invoice(100_000_000, &preimage, METADATA);
        assert!(
            verify_payment_proof(&policy(), 100_000, &proof(&good, METADATA, &preimage)).is_ok()
        );
        // Paying more than owed is fine.
        assert!(
            verify_payment_proof(&policy(), 90_000, &proof(&good, METADATA, &preimage)).is_ok()
        );

        assert!(matches!(
            verify_payment_proof(&policy(), 100_001, &proof(&good, METADATA, &preimage)),
            Err(PayoutError::Underpaid { .. })
        ));
        assert_eq!(
            verify_payment_proof(&policy(), 100_000, &proof(&good, METADATA, &[6; 32])),
            Err(PayoutError::PreimageMismatch)
        );

        let other_metadata = r#"[["text/identifier","mallory@cash.app"]]"#;
        let for_mallory = invoice(100_000_000, &preimage, other_metadata);
        assert_eq!(
            verify_payment_proof(
                &policy(),
                100_000,
                &proof(&for_mallory, other_metadata, &preimage)
            ),
            Err(PayoutError::AddressMismatch)
        );
        // Presenting Alice's metadata with Mallory's invoice fails the hash commitment.
        assert_eq!(
            verify_payment_proof(
                &policy(),
                100_000,
                &proof(&for_mallory, METADATA, &preimage)
            ),
            Err(PayoutError::UncommittedInvoice)
        );

        assert!(matches!(
            verify_payment_proof(&policy(), 1, &proof("lnbcrt1garbage", METADATA, &preimage)),
            Err(PayoutError::InvalidInvoice(_))
        ));
    }

    #[test]
    fn release_derives_the_preimage_only_for_a_paid_winner() {
        let f = fixture();
        let messages = signed_messages(&f.commitment);
        let winner_pubkey = f.winner_key.base_point_mul().serialize();
        let private_key = f.winner_key.serialize();
        let preimage = [8u8; 32];
        let paid = invoice(100_000_000, &preimage, METADATA);
        let proof = PaymentProof {
            invoice: &paid,
            lnurl_metadata: METADATA,
            payment_preimage: &preimage,
        };

        let released = release_payout_preimage(
            &f.commitment,
            &messages,
            &f.attestation,
            &winner_pubkey,
            &policy(),
            &proof,
            &private_key,
        )
        .unwrap();
        assert_eq!(
            released,
            crate::crypto::derive_payout_preimage(&private_key)
        );
        assert_ne!(released, private_key);

        // The same payment cannot release the preimage of a losing outcome.
        assert_eq!(
            release_payout_preimage(
                &f.commitment,
                &messages,
                &f.other_attestation,
                &winner_pubkey,
                &policy(),
                &proof,
                &private_key,
            ),
            Err(PayoutError::NotAWinner)
        );
    }
}
