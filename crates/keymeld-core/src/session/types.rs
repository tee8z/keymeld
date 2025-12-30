use crate::{
    identifiers::{EnclaveId, UserId},
    KeyMeldError,
};

use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ParticipantData {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_key_epoch: u64,
    pub session_encrypted_data: String,
    pub enclave_encrypted_data: String,
}

impl fmt::Debug for ParticipantData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParticipantData")
            .field("user_id", &self.user_id)
            .field("enclave_id", &self.enclave_id)
            .field("enclave_key_epoch", &self.enclave_key_epoch)
            .field("session_encrypted_data", &"[REDACTED]")
            .field("enclave_encrypted_data", &"[REDACTED]")
            .finish()
    }
}

impl ParticipantData {
    pub fn new_with_epoch(
        user_id: UserId,
        enclave_id: EnclaveId,
        enclave_key_epoch: u64,
        session_encrypted_data: String,
        enclave_encrypted_data: String,
    ) -> Self {
        Self {
            user_id,
            enclave_id,
            enclave_key_epoch,

            session_encrypted_data,
            enclave_encrypted_data,
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
