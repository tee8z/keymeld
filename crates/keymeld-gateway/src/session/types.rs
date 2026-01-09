use crate::{
    identifiers::{EnclaveId, UserId},
    KeyMeldError,
};

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;
use utoipa::ToSchema;

#[derive(Clone, Serialize, Deserialize, ToSchema, FromRow)]
#[serde(rename_all = "snake_case")]
pub struct ParticipantData {
    pub user_id: UserId,
    /// Reference to the user_keys table
    pub user_key_id: i64,
    pub enclave_id: EnclaveId,
    pub enclave_key_epoch: u64,
    pub session_encrypted_data: Option<String>,
    /// Encrypted private key (hex-encoded ECIES ciphertext)
    pub enclave_encrypted_data: String,
    /// Auth public key for verifying signing approval signatures
    pub auth_pubkey: Vec<u8>,
    /// Whether this user requires explicit approval before signing
    pub require_signing_approval: bool,
}

impl fmt::Debug for ParticipantData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParticipantData")
            .field("user_id", &self.user_id)
            .field("user_key_id", &self.user_key_id)
            .field("enclave_id", &self.enclave_id)
            .field("enclave_key_epoch", &self.enclave_key_epoch)
            .field("session_encrypted_data", &"[REDACTED]")
            .field("enclave_encrypted_data", &"[REDACTED]")
            .field(
                "auth_pubkey",
                &format!("[{} bytes]", self.auth_pubkey.len()),
            )
            .field("require_signing_approval", &self.require_signing_approval)
            .finish()
    }
}

impl ParticipantData {
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
