//! Release a participant's payout preimage to a claimant against proof of a
//! Lightning payment.
//!
//! The checks are in `keymeld_core::payout`; this module binds them to the
//! state this enclave holds for a completed keygen session: the pinned
//! manifest (whose signing key must authorize the claim), the participant's
//! private key and payout policy from their registration envelope, and the
//! session secret that decrypts the claim's batch messages and contract.

use super::states::keygen::Completed;
use keymeld_core::{
    crypto::SecureCrypto,
    payout::{release_payout_preimage, ContractCommitment, PaymentProof},
    protocol::{
        CryptoError, EnclaveError, PayoutPreimageReleasedResponse, ReleasePayoutPreimageCommand,
        ValidationError,
    },
    EncryptedData,
};
use zeroize::Zeroizing;

fn invalid(message: impl Into<String>) -> EnclaveError {
    EnclaveError::Validation(ValidationError::Other(message.into()))
}

fn crypto(context: &str, error: impl std::fmt::Display) -> EnclaveError {
    EnclaveError::Crypto(CryptoError::Other(format!("{context}: {error}")))
}

fn hex32(value: &str, what: &str) -> Result<[u8; 32], EnclaveError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value.trim(), &mut bytes)
        .map_err(|_| invalid(format!("{what} must be 32 bytes of hex")))?;
    Ok(bytes)
}

pub fn release(
    completed: &Completed,
    cmd: &ReleasePayoutPreimageCommand,
) -> Result<PayoutPreimageReleasedResponse, EnclaveError> {
    let claim = &cmd.claim;
    if claim.keygen_session_id != *completed.session_id() {
        return Err(invalid("Claim names a different keygen session"));
    }

    let metadata = completed.musig_processor().get_session_metadata_public();
    let manifest = metadata
        .authorization_manifest
        .as_ref()
        .ok_or_else(|| invalid("Session has no authorization manifest"))?;
    manifest.verify().map_err(|e| invalid(e.to_string()))?;
    let signing_pubkey = &manifest.manifest.signing_pubkey;

    // Only the session's signing authority may claim, and only for the batch
    // it authorized for signing.
    cmd.authorization
        .verify(signing_pubkey, claim)
        .map_err(|e| invalid(format!("Payout release is not authorized: {e}")))?;
    claim
        .signing_authorization
        .verify(
            signing_pubkey,
            &claim.keygen_session_id,
            &claim.signing_session_id,
            &claim.batch_items,
        )
        .map_err(|e| invalid(format!("Signed batch is not authorized: {e}")))?;

    let participant = completed
        .musig_processor()
        .get_user_session_data(&claim.user_id)
        .ok_or_else(|| invalid("Participant is not held by this enclave"))?;
    let policy = participant
        .payout_policy
        .as_ref()
        .ok_or_else(|| invalid("Participant registered no payout policy"))?;
    let private_key = participant
        .private_key
        .as_ref()
        .ok_or_else(|| invalid("Participant key is not held by this enclave"))?;
    let private_key = Zeroizing::new(
        <[u8; 32]>::try_from(private_key.as_bytes())
            .map_err(|_| invalid("Participant key must be 32 bytes"))?,
    );
    let player_pubkey = metadata
        .participant_public_keys
        .get(&claim.user_id)
        .ok_or_else(|| invalid("Participant has no public key in this session"))?
        .serialize();

    let session_secret = completed.session_secret();
    let session_secret_hex = hex::encode(session_secret.as_bytes());
    let mut signed_messages = Vec::with_capacity(claim.batch_items.len());
    for item in &claim.batch_items {
        let encrypted = EncryptedData::from_hex(&item.encrypted_message)
            .map_err(|e| crypto("batch item message", e))?;
        let message_hex = SecureCrypto::decrypt_session_data(&encrypted, &session_secret_hex)
            .map_err(|e| crypto("batch item message", e))?;
        signed_messages.push(hex32(&message_hex, "batch item message")?);
    }
    let encrypted_contract = EncryptedData::from_hex(&claim.encrypted_contract)
        .map_err(|e| crypto("contract commitment", e))?;
    let commitment: ContractCommitment = session_secret
        .decrypt_value(&encrypted_contract, "payout_contract")
        .map_err(|e| crypto("contract commitment", e))?;

    let attestation = hex32(&claim.attestation, "attestation")?;
    let payment_preimage = hex32(&claim.payment_preimage, "payment preimage")?;
    let proof = PaymentProof {
        invoice: &claim.invoice,
        lnurl_metadata: &claim.lnurl_metadata,
        payment_preimage: &payment_preimage,
    };

    let payout_preimage = Zeroizing::new(
        release_payout_preimage(
            &commitment,
            &signed_messages,
            &attestation,
            &player_pubkey,
            policy,
            &proof,
            &private_key,
        )
        .map_err(|e| invalid(e.to_string()))?,
    );
    let encrypted_payout_preimage = session_secret
        .encrypt(&payout_preimage[..], "payout_preimage")
        .and_then(|encrypted| encrypted.to_hex())
        .map_err(|e| crypto("payout preimage", e))?;

    Ok(PayoutPreimageReleasedResponse {
        keygen_session_id: claim.keygen_session_id.clone(),
        user_id: claim.user_id.clone(),
        encrypted_payout_preimage,
    })
}
