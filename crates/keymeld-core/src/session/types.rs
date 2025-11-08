use crate::{
    identifiers::{EnclaveId, UserId},
    KeyMeldError,
};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ParticipantData {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub encrypted_private_key: String,
    #[schema(value_type = String)]
    pub encrypted_public_key: String,
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
        encrypted_public_key: String,
        enclave_key_epoch: u64,
    ) -> Self {
        Self {
            user_id,
            enclave_id,
            encrypted_private_key,
            encrypted_public_key,
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
}
