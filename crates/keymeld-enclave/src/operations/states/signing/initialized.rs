use keymeld_core::{
    api::validation::decrypt_session_data,
    enclave::{CryptoError, EnclaveCommand, EnclaveError, SessionError, ValidationError},
    musig::MusigProcessor,
    SessionId, SessionSecret, UserId,
};

use std::{sync::Arc, time::SystemTime};
use tracing::info;

use crate::operations::{
    context::EnclaveContext,
    states::{
        signing::{decrypt_adaptor_configs, CoordinatorData},
        KeygenCompleted, OperatorStatus, SigningStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug, Clone)]
pub struct Initialized {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Initialized {
    pub fn new(session_id: SessionId, keygen: KeygenCompleted) -> Self {
        info!(
            "Creating signing Initialized state from keygen - session: {}",
            session_id
        );

        let coordinator_data = keygen.coordinator_data;

        Self {
            session_id,
            session_secret: keygen.session_secret.clone(),
            coordinator_data,
            created_at: SystemTime::now(),
            musig_processor: keygen.musig_processor,
        }
    }

    /// Get participant count from MuSig processor metadata
    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.participant_public_keys.len())
            .unwrap_or(0)
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .and_then(|metadata| metadata.expected_participant_count)
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.expected_participants.clone())
            .unwrap_or_default()
    }
}

impl EnclaveAdvanceable<OperatorStatus> for Initialized {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing Initialized state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::InitSigningSession(init_cmd) => {
                info!(
                    "Processing initialize signing session command for session {}",
                    self.session_id
                );

                let updated_state = self.clone();
                if init_cmd.encrypted_message.is_empty() {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Encrypted message cannot be empty".to_string(),
                    )));
                }

                if init_cmd.expected_participant_count == 0 {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Expected participant count must be greater than 0".to_string(),
                    )));
                }

                if init_cmd.timeout_secs == 0 {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Timeout seconds must be greater than 0".to_string(),
                    )));
                }

                let session_secret = updated_state.session_secret.clone();

                let decrypted_message_hex = decrypt_session_data(
                    &init_cmd.encrypted_message,
                    &hex::encode(session_secret.as_bytes()),
                )
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::DecryptionFailed {
                        context: "data".to_string(),
                        error: format!("Failed to decrypt message: {e}"),
                    })
                })?;

                if decrypted_message_hex.is_empty() {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Decrypted message is empty".to_string(),
                    )));
                }

                let message = hex::decode(&decrypted_message_hex).map_err(|e| {
                    EnclaveError::Crypto(CryptoError::DecryptionFailed {
                        context: "data".to_string(),
                        error: format!("Hex decode failed: {e}"),
                    })
                })?;

                if message.is_empty() {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Message cannot be empty after decryption".to_string(),
                    )));
                }

                //TODO(@tee8z): make message max size configurable
                if message.len() > 4_000_000 {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Message too large (>4MB)".to_string(),
                    )));
                }

                updated_state
                    .musig_processor
                    .copy_session_metadata_for_signing(
                        &init_cmd.keygen_session_id,
                        updated_state.session_id.clone(),
                    )
                    .map_err(|e| {
                        EnclaveError::Session(SessionError::MusigInitialization(format!(
                            "Failed to copy session metadata from keygen to signing: {e}"
                        )))
                    })?;

                updated_state
                    .musig_processor
                    .update_session_message(&updated_state.session_id, message.clone())
                    .map_err(|e| {
                        EnclaveError::Session(SessionError::MusigInitialization(format!(
                            "Failed to update session message: {e}"
                        )))
                    })?;

                let adaptor_configs = if let Some(ref encrypted_adapator_configs) =
                    init_cmd.encrypted_adaptor_configs
                {
                    decrypt_adaptor_configs(encrypted_adapator_configs, &self.session_secret)?
                } else {
                    vec![]
                };

                if !adaptor_configs.is_empty() {
                    info!("Adaptor configs will be stored in SessionMetadata");

                    // Store the adaptor configs in the session metadata
                    updated_state
                        .musig_processor
                        .set_adaptor_configs(&updated_state.session_id, adaptor_configs)
                        .map_err(|e| {
                            EnclaveError::Session(SessionError::MusigInitialization(format!(
                                "Failed to store adaptor configs: {e}"
                            )))
                        })?;
                }

                let _aggregate_public_key = updated_state
                    .musig_processor
                    .get_aggregate_pubkey(&updated_state.session_id)
                    .map_err(|e| {
                        EnclaveError::Session(SessionError::MusigInitialization(format!(
                            "Failed to get aggregate public key: {e}"
                        )))
                    })?;

                let participant_count = updated_state.get_participant_count();
                info!(
                    "Signing session {} initialized successfully - participants: {} (from MuSig processor: {})",
                    updated_state.session_id,
                    init_cmd.expected_participant_count,
                    participant_count
                );

                Ok(OperatorStatus::Signing(SigningStatus::GeneratingNonces(
                    updated_state.into(),
                )))
            }

            _ => {
                info!(
                    "Command not applicable to signing Initialized state for session {}, staying in current state",
                    self.session_id
                );
                Ok(OperatorStatus::Signing(SigningStatus::Initialized(self)))
            }
        }
    }
}
