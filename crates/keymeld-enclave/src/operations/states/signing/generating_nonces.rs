use keymeld_core::{
    enclave::{
        protocol::NonceData, EnclaveCommand, EnclaveError, NonceError, PrivateKeyError,
        ValidationError,
    },
    musig::{MusigError, MusigProcessor},
    SessionId, SessionSecret, UserId,
};
use musig2::PubNonce;
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, info};

use crate::operations::{
    context::EnclaveContext,
    states::{
        signing::{CollectingNonces, CoordinatorData, GeneratingPartialSignatures, Initialized},
        OperatorStatus, SigningStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug)]
pub struct GeneratingNonces {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Clone for GeneratingNonces {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            session_secret: self.session_secret.clone(),
            coordinator_data: self.coordinator_data.clone(),
            created_at: self.created_at,
            musig_processor: Arc::clone(&self.musig_processor),
        }
    }
}

impl GeneratingNonces {
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
        let result = self
            .musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| {
                debug!(
                    "GeneratingNonces::get_participants() - metadata.expected_participants = {:?}",
                    metadata.expected_participants
                );
                metadata.expected_participants.clone()
            })
            .unwrap_or_default();
        result
    }

    pub fn get_message(&self) -> Vec<u8> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.message.clone())
            .unwrap_or_default()
    }

    pub fn get_nonce_count(&self) -> Result<usize, EnclaveError> {
        Ok(self.musig_processor.get_nonce_count(&self.session_id))
    }

    pub fn get_user_nonce(&self, user_id: &UserId) -> Result<PubNonce, EnclaveError> {
        self.musig_processor
            .get_user_nonce(&self.session_id, user_id)
            .ok_or(EnclaveError::Musig(MusigError::NotReady(format!(
                "No nonce found for user {}",
                user_id
            ))))
    }

    pub fn has_user_nonce(&self, user_id: &UserId) -> Result<(), EnclaveError> {
        self.get_user_nonce(user_id).map(|_| ())
    }
}

impl EnclaveAdvanceable<OperatorStatus> for GeneratingNonces {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing GeneratingNonces state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::GenerateNonce(generate_nonce_cmd) => {
                info!(
                    "Generating nonce for user {} in signing session {}",
                    generate_nonce_cmd.user_id, self.session_id
                );

                let expected_count = self.get_expected_participant_count().unwrap_or(0);
                if generate_nonce_cmd.signer_index >= expected_count {
                    return Err(EnclaveError::Validation(ValidationError::Other(format!(
                        "Signer index {} exceeds expected participant count {}",
                        generate_nonce_cmd.signer_index, expected_count
                    ))));
                }

                if expected_count == 0 {
                    return Err(EnclaveError::Validation(ValidationError::Other(
                        "Expected participant count must be greater than 0".to_string(),
                    )));
                }

                if let Some(_existing_nonce) = self
                    .musig_processor
                    .get_user_nonce(&self.session_id, &generate_nonce_cmd.user_id)
                {
                    info!(
                        "Nonce already exists for user {} in signing session {}, moving to CollectingNonces",
                        generate_nonce_cmd.user_id, self.session_id
                    );

                    return Ok(OperatorStatus::Signing(SigningStatus::CollectingNonces(
                        self.into(),
                    )));
                }

                let expected_participants = self.get_participants();
                if !expected_participants.contains(&generate_nonce_cmd.user_id) {
                    return Err(EnclaveError::Validation(ValidationError::Other(format!(
                        "User {} not found in expected participants",
                        generate_nonce_cmd.user_id
                    ))));
                }

                let signer_index = expected_participants
                    .iter()
                    .position(|id| id == &generate_nonce_cmd.user_id)
                    .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                        "User {} not found in expected participants",
                        generate_nonce_cmd.user_id
                    ))))?;

                debug!(
                    "generate_nonce for user {} - computed signer_index={} from expected_participants={:?}",
                    generate_nonce_cmd.user_id, signer_index, expected_participants
                );

                let private_key = self
                    .musig_processor
                    .get_private_key(&self.session_id, &generate_nonce_cmd.user_id)
                    .ok_or(EnclaveError::PrivateKey(PrivateKeyError::Invalid(format!(
                        "Missing private key for user {}",
                        generate_nonce_cmd.user_id
                    ))))?;

                let nonce_data = self
                    .musig_processor
                    .generate_nonce(
                        &self.session_id,
                        &generate_nonce_cmd.user_id,
                        signer_index,
                        &private_key,
                    )
                    .map_err(|e| {
                        EnclaveError::Nonce(NonceError::GenerationFailed {
                            user_id: generate_nonce_cmd.user_id.clone(),
                            error: format!("Failed to generate nonce: {e}"),
                        })
                    })?;

                // Validate nonce data based on type
                match &nonce_data {
                    NonceData::Regular(nonce) => {
                        if nonce.serialize().len() != 66 {
                            return Err(EnclaveError::Nonce(NonceError::GenerationFailed {
                                user_id: generate_nonce_cmd.user_id.clone(),
                                error: format!(
                                    "Invalid regular nonce length: expected 66 bytes, got {}",
                                    nonce.serialize().len()
                                ),
                            }));
                        }
                    }
                    NonceData::Adaptor(adaptor_nonces) => {
                        for (config_id, nonce) in adaptor_nonces {
                            if nonce.serialize().len() != 66 {
                                return Err(EnclaveError::Nonce(NonceError::GenerationFailed {
                                    user_id: generate_nonce_cmd.user_id.clone(),
                                    error: format!(
                                        "Invalid adaptor nonce length for config {}: expected 66 bytes, got {}",
                                        config_id,
                                        nonce.serialize().len()
                                    ),
                                }));
                            }
                        }
                    }
                }

                let nonce_info = match &nonce_data {
                    keymeld_core::enclave::protocol::NonceData::Regular(nonce) => {
                        format!("regular nonce: {} bytes", nonce.serialize().len())
                    }
                    keymeld_core::enclave::protocol::NonceData::Adaptor(adaptor_nonces) => {
                        format!("adaptor nonces: {} configs", adaptor_nonces.len())
                    }
                };

                info!(
                    "Successfully generated nonce for user {} in signing session {} ({})",
                    generate_nonce_cmd.user_id, self.session_id, nonce_info
                );

                Ok(OperatorStatus::Signing(SigningStatus::CollectingNonces(
                    self.into(),
                )))
            }

            _ => Ok(OperatorStatus::Signing(SigningStatus::GeneratingNonces(
                self,
            ))),
        }
    }
}

impl From<GeneratingNonces> for GeneratingPartialSignatures {
    fn from(state: GeneratingNonces) -> Self {
        GeneratingPartialSignatures {
            session_id: state.session_id,
            session_secret: state.session_secret,
            coordinator_data: state.coordinator_data.clone(),
            created_at: state.created_at,
            musig_processor: Arc::clone(&state.musig_processor),
        }
    }
}

impl From<GeneratingNonces> for CollectingNonces {
    fn from(state: GeneratingNonces) -> Self {
        CollectingNonces {
            session_id: state.session_id,
            session_secret: state.session_secret,
            coordinator_data: state.coordinator_data,
            created_at: state.created_at,
            musig_processor: Arc::clone(&state.musig_processor),
        }
    }
}

impl From<Initialized> for GeneratingNonces {
    fn from(state: Initialized) -> Self {
        GeneratingNonces {
            session_id: state.session_id,
            session_secret: state.session_secret,
            coordinator_data: state.coordinator_data,
            created_at: state.created_at,
            musig_processor: Arc::clone(&state.musig_processor),
        }
    }
}
