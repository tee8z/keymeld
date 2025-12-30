use crate::operations::states::signing::CoordinatorData;
use keymeld_core::{
    enclave::{protocol::SignatureData, EnclaveCommand, EnclaveError, ValidationError},
    musig::{MusigError, MusigProcessor},
    SessionId, SessionSecret, UserId,
};
use musig2::PartialSignature;
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, info};

use crate::operations::{
    context::EnclaveContext,
    states::{signing::FinalizingSignature, OperatorStatus, SigningStatus},
    EnclaveAdvanceable,
};

#[derive(Debug)]
pub struct CollectingPartialSignatures {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Clone for CollectingPartialSignatures {
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

impl CollectingPartialSignatures {
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

    pub fn get_partial_signature_count(&self) -> Result<usize, EnclaveError> {
        // Check if this session uses adaptor signatures
        let session_metadata = self
            .musig_processor
            .get_session_metadata_public(&self.session_id);
        let has_adaptor_configs = session_metadata
            .map(|metadata| !metadata.adaptor_configs.is_empty())
            .unwrap_or(false);

        if has_adaptor_configs {
            // For adaptor signatures, use the completion count that verifies all configs are signed
            Ok(self
                .musig_processor
                .get_adaptor_signature_completion_count(&self.session_id))
        } else {
            // For regular signatures, use the existing method
            Ok(self
                .musig_processor
                .get_partial_signature_count(&self.session_id))
        }
    }

    pub fn get_user_partial_signature(
        &self,
        user_id: &UserId,
    ) -> Result<PartialSignature, EnclaveError> {
        // Check if this session uses adaptor signatures
        let session_metadata = self
            .musig_processor
            .get_session_metadata_public(&self.session_id);
        let has_adaptor_configs = session_metadata
            .map(|metadata| !metadata.adaptor_configs.is_empty())
            .unwrap_or(false);

        if has_adaptor_configs {
            // For adaptor signatures, check if user has completed all adaptor signatures
            if self
                .musig_processor
                .user_has_all_adaptor_signatures(&self.session_id, user_id)
            {
                // Return a representative signature (first one found) for compatibility
                self.musig_processor
                    .get_user_partial_signature(&self.session_id, user_id)
                    .ok_or(EnclaveError::Musig(MusigError::NotReady(format!(
                        "No adaptor signatures found for user {}",
                        user_id
                    ))))
            } else {
                Err(EnclaveError::Musig(MusigError::NotReady(format!(
                    "User {} has not completed all adaptor signatures",
                    user_id
                ))))
            }
        } else {
            // For regular signatures, use the existing method
            self.musig_processor
                .get_user_partial_signature(&self.session_id, user_id)
                .ok_or(EnclaveError::Musig(MusigError::NotReady(format!(
                    "No partial signature found for user {}",
                    user_id
                ))))
        }
    }

    pub fn can_aggregate_signatures(&self) -> Result<bool, EnclaveError> {
        let Some(coordinator_user_id) = self.coordinator_data.as_ref().map(|cd| &cd.user_id) else {
            return Err(EnclaveError::Musig(MusigError::NotReady(
                "No coordinator user ID".to_string(),
            )));
        };
        self.musig_processor
            .can_aggregate_signatures(&self.session_id, coordinator_user_id)
            .map_err(|e| {
                EnclaveError::Musig(MusigError::NotReady(format!(
                    "Failed to check aggregation: {}",
                    e
                )))
            })
    }

    pub fn has_all_partial_signatures(&self) -> bool {
        let expected_count = self.get_expected_participant_count().unwrap_or(0);

        // Check if this session uses adaptor signatures
        let session_metadata = self
            .musig_processor
            .get_session_metadata_public(&self.session_id);
        let has_adaptor_configs = session_metadata
            .map(|metadata| !metadata.adaptor_configs.is_empty())
            .unwrap_or(false);

        if has_adaptor_configs {
            // For adaptor signatures, use the dedicated method that checks all configs
            self.musig_processor
                .has_all_adaptor_signatures(&self.session_id)
        } else {
            // For regular signatures, use the existing logic
            self.get_partial_signature_count().unwrap_or(0) >= expected_count
        }
    }
}

impl EnclaveAdvanceable<OperatorStatus> for CollectingPartialSignatures {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing CollectingPartialSignatures state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::AddPartialSignature(add_sig_cmd) => {
                let expected_participants = self.get_participants();
                let signer_index = expected_participants
                    .iter()
                    .position(|id| id == &add_sig_cmd.user_id)
                    .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                        "User {} not found in expected participants",
                        add_sig_cmd.user_id
                    ))))?;

                match &add_sig_cmd.signature_data {
                    SignatureData::Regular(partial_signature) => {
                        // Handle regular partial signature
                        info!(
                            "Adding regular partial signature from user {} to signing session {}",
                            add_sig_cmd.user_id, self.session_id
                        );

                        self.musig_processor
                            .add_partial_signature(
                                &self.session_id,
                                signer_index,
                                *partial_signature,
                            )
                            .map_err(|e| {
                                EnclaveError::Musig(MusigError::NotReady(format!(
                                    "Failed to add partial signature: {e}"
                                )))
                            })?;

                        info!(
                            "Successfully added regular partial signature for user {} in signing session {}",
                            add_sig_cmd.user_id, self.session_id
                        );
                    }
                    SignatureData::Adaptor(adaptor_signatures) => {
                        // Handle adaptor partial signatures
                        info!(
                            "Adding {} adaptor partial signatures from user {} to signing session {}",
                            adaptor_signatures.len(),
                            add_sig_cmd.user_id,
                            self.session_id
                        );

                        self.musig_processor
                            .add_adaptor_partial_signatures(
                                &self.session_id,
                                &add_sig_cmd.user_id,
                                adaptor_signatures.clone(),
                            )
                            .map_err(|e| {
                                EnclaveError::Musig(MusigError::NotReady(format!(
                                    "Failed to add adaptor partial signatures: {e}"
                                )))
                            })?;

                        info!(
                            "Successfully added adaptor partial signatures for user {} in signing session {}",
                            add_sig_cmd.user_id, self.session_id
                        );
                    }
                }

                let sig_count = self.get_partial_signature_count()?;
                if self.has_all_partial_signatures() {
                    info!(
                        "All partial signatures collected for signing session {}, transitioning to FinalizingSignature",
                        self.session_id
                    );

                    Ok(OperatorStatus::Signing(SigningStatus::FinalizingSignature(
                        self.into(),
                    )))
                } else {
                    let expected_count = self.get_expected_participant_count().unwrap_or(0);
                    debug!(
                        "Signing session {} still collecting partial signatures: {}/{}",
                        self.session_id, sig_count, expected_count,
                    );

                    Ok(OperatorStatus::Signing(
                        SigningStatus::CollectingPartialSignatures(self),
                    ))
                }
            }

            _ => {
                debug!(
                    "Command not applicable to signing CollectingPartialSignatures state for session {}, staying in current state",
                    self.session_id
                );
                Ok(OperatorStatus::Signing(
                    SigningStatus::CollectingPartialSignatures(self),
                ))
            }
        }
    }
}

impl From<CollectingPartialSignatures> for FinalizingSignature {
    fn from(state: CollectingPartialSignatures) -> Self {
        FinalizingSignature {
            session_id: state.session_id,
            session_secret: state.session_secret,
            coordinator_data: state.coordinator_data,
            created_at: state.created_at,
            musig_processor: Arc::clone(&state.musig_processor),
        }
    }
}
