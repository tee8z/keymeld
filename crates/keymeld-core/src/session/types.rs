use crate::{
    identifiers::{EnclaveId, UserId},
    KeyMeldError,
};
use musig2::secp256k1::PublicKey;
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ParticipantData {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub encrypted_private_key: String,
    #[schema(value_type = String)]
    pub public_key: PublicKey,
    pub enclave_key_epoch: u64,
    #[schema(value_type = String)]
    pub public_nonces: Option<PubNonce>,
    #[schema(value_type = String)]
    pub partial_signature: Option<PartialSignature>,
}

impl ParticipantData {
    pub fn new_with_epoch(
        user_id: UserId,
        enclave_id: EnclaveId,
        encrypted_private_key: String,
        public_key: PublicKey,
        enclave_key_epoch: u64,
    ) -> Self {
        Self {
            user_id,
            enclave_id,
            encrypted_private_key,
            public_key,
            enclave_key_epoch,
            public_nonces: None,
            partial_signature: None,
        }
    }

    pub fn validate_epoch(
        &self,
        enclave_manager: &crate::enclave::EnclaveManager,
    ) -> Result<(), KeyMeldError> {
        match enclave_manager.get_enclave_key_epoch(&self.enclave_id) {
                Some(current_epoch) if current_epoch == self.enclave_key_epoch => Ok(()),
                Some(current_epoch) => {
                    Err(KeyMeldError::InvalidState(format!(
                        "Participant {} keys invalid. Enclave {} epoch {} -> {}. Re-encrypt with fresh keys.",
                        self.user_id, self.enclave_id, self.enclave_key_epoch, current_epoch
                    )))
                }
                None => {
                    Err(KeyMeldError::InvalidState(format!(
                        "Participant {} enclave {} not found. Enclave may have been removed.",
                        self.user_id, self.enclave_id
                    )))
                }
            }
    }

    pub fn is_expired(&self) -> bool {
        false // Participants don't expire based on time, only on enclave epochs
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AggregatePublicKey {
    pub key_bytes: Vec<u8>,
    pub participant_count: u32,
    pub participant_ids: Vec<UserId>,
    pub participant_keys_hash: Vec<u8>,
    pub aggregated_at: u64,
    pub algorithm_version: String,
}

impl AggregatePublicKey {
    pub fn new(
        key_bytes: Vec<u8>,
        participant_ids: Vec<UserId>,
        participant_keys_hash: Vec<u8>,
    ) -> Self {
        Self {
            key_bytes,
            participant_count: participant_ids.len() as u32,
            participant_ids,
            participant_keys_hash,
            aggregated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            algorithm_version: "musig2-v0.3".to_string(),
        }
    }

    pub fn from_participants(participants: &[ParticipantData], key_bytes: Vec<u8>) -> Self {
        let participant_ids = participants.iter().map(|p| p.user_id.clone()).collect();
        let participant_keys_hash = Self::hash_participant_keys(participants);
        Self::new(key_bytes, participant_ids, participant_keys_hash)
    }

    pub fn verify_participants(
        &self,
        participants: &[ParticipantData],
    ) -> Result<(), KeyMeldError> {
        let expected_hash = Self::hash_participant_keys(participants);
        if self.participant_keys_hash != expected_hash {
            return Err(KeyMeldError::ValidationError(
                "Participant keys hash mismatch".to_string(),
            ));
        }
        Ok(())
    }

    pub fn to_secp256k1_pubkey(&self) -> Result<PublicKey, KeyMeldError> {
        PublicKey::from_slice(&self.key_bytes)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid public key: {}", e)))
    }

    fn hash_participant_keys(participants: &[ParticipantData]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for participant in participants {
            hasher.update(participant.user_id.as_bytes());
            hasher.update(participant.public_key.serialize());
        }
        hasher.finalize().to_vec()
    }
}
