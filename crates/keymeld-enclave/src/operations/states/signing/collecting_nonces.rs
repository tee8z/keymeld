use keymeld_core::{
    enclave::{CryptoError, EnclaveCommand, EnclaveError, ValidationError},
    musig::{MusigError, MusigProcessor},
    SessionId, SessionSecret, UserId,
};
use musig2::PubNonce;
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, info};

use crate::operations::{
    context::EnclaveContext,
    states::{
        signing::{CoordinatorData, GeneratingPartialSignatures},
        OperatorStatus, SigningStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug)]
pub struct CollectingNonces {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Clone for CollectingNonces {
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

impl CollectingNonces {
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
        match self.get_user_nonce(user_id) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn get_aggregate_pubkey(&self) -> Result<musig2::secp256k1::PublicKey, EnclaveError> {
        self.musig_processor
            .get_aggregate_pubkey(&self.session_id)
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to aggregate pubkey for session {}: {}",
                    self.session_id, e
                )))
            })
    }

    pub fn can_aggregate_nonces(&self) -> bool {
        let expected_count = self.get_expected_participant_count().unwrap_or(0);

        // Check if this session uses adaptor signatures
        let session_metadata = self
            .musig_processor
            .get_session_metadata_public(&self.session_id);
        let has_adaptor_configs = session_metadata
            .map(|metadata| !metadata.adaptor_configs.is_empty())
            .unwrap_or(false);

        tracing::info!(
            "can_aggregate_nonces for session {}: has_adaptor_configs={}, expected_count={}",
            self.session_id,
            has_adaptor_configs,
            expected_count
        );

        if has_adaptor_configs {
            // For adaptor sessions, check if all participants have completed adaptor nonces
            let result = self.all_adaptor_nonces_collected();
            tracing::info!(
                "Adaptor nonce aggregation check for session {}: {}",
                self.session_id,
                result
            );
            result
        } else {
            // For regular sessions, use the existing logic
            let nonce_count = self.get_nonce_count().unwrap_or(0);
            let result = nonce_count >= expected_count;
            tracing::info!(
                "Regular nonce aggregation check for session {}: {}/{} = {}",
                self.session_id,
                nonce_count,
                expected_count,
                result
            );
            result
        }
    }

    fn all_adaptor_nonces_collected(&self) -> bool {
        // For adaptor sessions, check if all participants have their adaptor first rounds complete
        let result = self
            .musig_processor
            .all_adaptor_first_rounds_complete(&self.session_id)
            .unwrap_or(false);

        tracing::info!(
            "all_adaptor_nonces_collected for session {}: {}",
            self.session_id,
            result
        );

        result
    }
}

impl EnclaveAdvanceable<OperatorStatus> for CollectingNonces {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing CollectingNonces state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::AddNonce(add_nonce_cmd) => {
                info!(
                    "Adding nonce from user {} to signing session {}",
                    add_nonce_cmd.user_id, self.session_id
                );

                let expected_participants = self.get_participants();
                let signer_index = expected_participants
                    .iter()
                    .position(|id| id == &add_nonce_cmd.user_id)
                    .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                        "User {} not found in expected participants",
                        add_nonce_cmd.user_id
                    ))))?;

                match &add_nonce_cmd.nonce_data {
                    keymeld_core::enclave::protocol::NonceData::Regular(nonce) => {
                        self.musig_processor
                            .add_nonce(
                                &self.session_id,
                                &add_nonce_cmd.user_id,
                                signer_index,
                                nonce.clone(),
                            )
                            .map_err(|e| {
                                EnclaveError::Crypto(CryptoError::Other(format!(
                                    "Failed to add regular nonce for user {}: {}",
                                    add_nonce_cmd.user_id, e
                                )))
                            })?;
                    }
                    keymeld_core::enclave::protocol::NonceData::Adaptor(adaptor_nonces) => {
                        self.musig_processor
                            .add_adaptor_nonces(
                                &self.session_id,
                                &add_nonce_cmd.user_id,
                                adaptor_nonces.clone(),
                            )
                            .map_err(|e| {
                                EnclaveError::Crypto(CryptoError::Other(format!(
                                    "Failed to add adaptor nonces for user {}: {}",
                                    add_nonce_cmd.user_id, e
                                )))
                            })?;
                    }
                }

                info!(
                    "Successfully added nonce for user {} in signing session {}",
                    add_nonce_cmd.user_id, self.session_id
                );

                if self.can_aggregate_nonces() {
                    info!(
                        "All nonces collected for signing session {}, aggregating and transitioning to GeneratingPartialSignatures",
                        self.session_id
                    );

                    Ok(OperatorStatus::Signing(
                        SigningStatus::GeneratingPartialSignatures(self.into()),
                    ))
                } else {
                    let nonce_count = self.get_nonce_count()?;
                    let expected_count = self.get_expected_participant_count().unwrap_or(0);
                    debug!(
                        "Signing session {} still collecting nonces: {}/{}",
                        self.session_id, nonce_count, expected_count
                    );
                    Ok(OperatorStatus::Signing(SigningStatus::CollectingNonces(
                        self,
                    )))
                }
            }

            _ => Ok(OperatorStatus::Signing(SigningStatus::CollectingNonces(
                self,
            ))),
        }
    }
}

impl From<CollectingNonces> for GeneratingPartialSignatures {
    fn from(state: CollectingNonces) -> Self {
        GeneratingPartialSignatures {
            session_id: state.session_id,
            session_secret: state.session_secret,
            coordinator_data: state.coordinator_data,
            created_at: state.created_at,
            musig_processor: Arc::clone(&state.musig_processor),
        }
    }
}
