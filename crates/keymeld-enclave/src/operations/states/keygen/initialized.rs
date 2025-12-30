use keymeld_core::{
    enclave::{
        protocol::EncryptedParticipantPublicKey, CryptoError, EnclaveCommand, EnclaveError,
        SessionError, ValidationError,
    },
    KeyMaterial, SessionId, SessionSecret, UserId,
};
use std::time::SystemTime;
use tracing::info;

use crate::operations::{
    context::EnclaveContext,
    states::{keygen::DistributingSecrets, signing::CoordinatorData, KeygenStatus, OperatorStatus},
    EnclaveAdvanceable,
};

#[derive(Debug, Clone)]
pub struct Initialized {
    pub session_id: SessionId,
    pub session_secret: Option<SessionSecret>,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    pub musig_processor: std::sync::Arc<keymeld_core::musig::MusigProcessor>,
}

impl Initialized {
    /// Get participant count from MuSig processor metadata
    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.participant_public_keys.len())
            .unwrap_or(0)
    }

    /// Get expected participant count from MuSig processor metadata
    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .and_then(|metadata| metadata.expected_participant_count)
    }

    /// Get participants list from MuSig processor metadata
    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.expected_participants.clone())
            .unwrap_or_default()
    }

    pub fn new(
        session_id: SessionId,
        musig_processor: std::sync::Arc<keymeld_core::musig::MusigProcessor>,
    ) -> Self {
        Self {
            session_id,
            created_at: SystemTime::now(),
            session_secret: None,
            coordinator_data: None,
            encrypted_public_keys_for_response: vec![],
            musig_processor,
        }
    }
}
impl EnclaveAdvanceable<OperatorStatus> for Initialized {
    fn process(
        self,
        ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from keygen Initialized state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::InitKeygenSession(init_cmd) => {
                info!(
                    "Processing initialize keygen session command for session {}",
                    self.session_id
                );

                let mut updated_state = self.clone();

                if let Some(encrypted_secret) = &init_cmd.encrypted_session_secret {
                    let decrypted_secret_bytes = ctx
                        .decrypt_with_ecies(encrypted_secret, "session secret")
                        .map_err(|e| {
                            EnclaveError::Crypto(CryptoError::DecryptionFailed {
                                context: "data".to_string(),
                                error: format!("Failed to decrypt session secret: {e}"),
                            })
                        })?;

                    if decrypted_secret_bytes.len() != 32 {
                        return Err(EnclaveError::Session(SessionError::InvalidSecretLength {
                            actual: decrypted_secret_bytes.len(),
                        }));
                    }
                    let mut secret_array = [0u8; 32];
                    secret_array.copy_from_slice(&decrypted_secret_bytes);
                    updated_state.session_secret =
                        Some(keymeld_core::SessionSecret::from_bytes(secret_array));
                }

                if let Some(encrypted_key) = &init_cmd.coordinator_encrypted_private_key {
                    let decrypted_key = ctx
                        .decrypt_private_key_from_coordinator(encrypted_key)
                        .map_err(|e| {
                            EnclaveError::Crypto(CryptoError::DecryptionFailed {
                                context: "data".to_string(),
                                error: format!("Failed to decrypt coordinator private key: {e}"),
                            })
                        })?;

                    // Create CoordinatorData with the user_id from the command
                    if let Some(coordinator_user_id) = &init_cmd.coordinator_user_id {
                        updated_state.coordinator_data = Some(CoordinatorData {
                            user_id: coordinator_user_id.clone(),
                            private_key: KeyMaterial::new(decrypted_key),
                        });
                    } else {
                        return Err(EnclaveError::Validation(ValidationError::Other(
                            "Coordinator private key provided but coordinator user ID missing"
                                .to_string(),
                        )));
                    }
                }

                if updated_state.coordinator_data.is_some() {
                    // This enclave is the coordinator
                }

                for enclave_key_info in &init_cmd.enclave_public_keys {
                    ctx.enclave_public_keys.insert(
                        enclave_key_info.enclave_id,
                        enclave_key_info.public_key.clone(),
                    );
                }
                info!(
                    "Stored {} enclave public keys in context for session {}",
                    init_cmd.enclave_public_keys.len(),
                    updated_state.session_id
                );

                updated_state
                    .musig_processor
                    .init_session(
                        &updated_state.session_id,
                        vec![], // Empty message for keygen
                        init_cmd.taproot_tweak.clone(),
                        Some(init_cmd.expected_participant_count),
                        init_cmd.expected_participants.clone(), // Pass the sorted expected_participants list
                    )
                    .map_err(|e| {
                        EnclaveError::Session(SessionError::MusigInitialization(format!(
                            "Failed to initialize MuSig2 for keygen: {e}"
                        )))
                    })?;

                info!(
                    "Keygen session {} initialized successfully (coordinator: {})",
                    updated_state.session_id,
                    updated_state.coordinator_data.is_some()
                );

                if updated_state.session_secret.is_some() {
                    info!(
                        "Coordinator keygen session {} transitioning to DistributingSecrets after initialization",
                        updated_state.session_id
                    );
                    Ok(OperatorStatus::Keygen(KeygenStatus::Distributing(
                        DistributingSecrets::try_from(updated_state)?,
                    )))
                } else {
                    info!(
                        "Non-coordinator keygen session {} staying in Initialized state, waiting for session secret",
                        updated_state.session_id
                    );
                    Ok(OperatorStatus::Keygen(KeygenStatus::Initialized(
                        updated_state,
                    )))
                }
            }
            EnclaveCommand::DistributeSessionSecret(distribute_cmd) => {
                info!(
                    "Processing session secret distribution for keygen session {}",
                    self.session_id
                );

                let decrypted_bytes = ctx
                    .decrypt_with_ecies(&distribute_cmd.encrypted_session_secret, "session secret")
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::DecryptionFailed {
                            context: "data".to_string(),
                            error: format!("Failed to decrypt session secret: {e}"),
                        })
                    })?;

                if decrypted_bytes.len() != 32 {
                    return Err(EnclaveError::Session(SessionError::InvalidSecretLength {
                        actual: decrypted_bytes.len(),
                    }));
                }

                let mut secret_array = [0u8; 32];
                secret_array.copy_from_slice(&decrypted_bytes);
                let session_secret = SessionSecret::from_bytes(secret_array);

                info!(
                    "Enclave {} received session secret for keygen session {} (secret length: {} bytes)",
                    ctx.enclave_id.as_u32(),
                    self.session_id,
                    decrypted_bytes.len()
                );

                let mut updated_state = self.clone();
                updated_state.session_secret = Some(session_secret);

                info!(
                    "Keygen session {} transitioning to DistributingSecrets after receiving session secret",
                    self.session_id
                );

                Ok(OperatorStatus::Keygen(KeygenStatus::Distributing(
                    DistributingSecrets::try_from(updated_state)?,
                )))
            }
            _ => Err(EnclaveError::Validation(ValidationError::Other(format!(
                "Command {:?} not applicable to keygen Initialized state for session {}",
                cmd, self.session_id
            )))),
        }
    }
}
