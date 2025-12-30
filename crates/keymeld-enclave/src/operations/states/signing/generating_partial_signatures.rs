use keymeld_core::{
    enclave::{
        EnclaveCommand, EnclaveError, ParitialSignatureCommand, PrivateKeyError, SigningError,
        ValidationError,
    },
    musig::{MusigError, MusigProcessor},
    SessionId, SessionSecret, UserId,
};
use musig2::PartialSignature;
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, info};

use crate::operations::{
    context::EnclaveContext,
    states::{
        signing::{CollectingPartialSignatures, CoordinatorData},
        OperatorStatus, SigningStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug)]
pub struct GeneratingPartialSignatures {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Clone for GeneratingPartialSignatures {
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

impl GeneratingPartialSignatures {
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

impl EnclaveAdvanceable<OperatorStatus> for GeneratingPartialSignatures {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing GeneratingPartialSignatures state",
            self.session_id
        );

        // Finalize nonce rounds to transition from FirstRound to SecondRound
        // We'll finalize when we get the first SignPartialSignature command

        match cmd {
            EnclaveCommand::SignPartialSignature(generate_sig_cmd) => {
                info!(
                    "Generating partial signature for user {} in signing session {}",
                    generate_sig_cmd.user_id, self.session_id
                );

                // Check if we have adaptor configs from the MuSig processor metadata
                let session_metadata = self
                    .musig_processor
                    .get_session_metadata_public(&self.session_id);
                let use_adaptor = session_metadata
                    .map(|metadata| !metadata.adaptor_configs.is_empty())
                    .unwrap_or(false);

                if use_adaptor {
                    // For adaptor signatures, generate them BEFORE finalizing nonce rounds
                    // since adaptor signing needs access to the first_round
                    self.generate_adaptor_partial_signature(generate_sig_cmd)
                } else {
                    // For regular signatures, finalize nonce rounds first
                    if let Err(e) = self
                        .musig_processor
                        .finalize_nonce_rounds(&self.session_id, &generate_sig_cmd.user_id)
                    {
                        info!(
                            "Nonce rounds already finalized for user {} in session {} or not ready: {}",
                            generate_sig_cmd.user_id, self.session_id, e
                        );
                    }

                    self.generate_regular_partial_signature(generate_sig_cmd)
                }
            }

            _ => {
                debug!(
                    "Command not applicable to signing GeneratingPartialSignatures state for session {}, staying in current state",
                    self.session_id
                );
                Ok(OperatorStatus::Signing(
                    SigningStatus::GeneratingPartialSignatures(self),
                ))
            }
        }
    }
}

impl GeneratingPartialSignatures {
    fn generate_adaptor_partial_signature(
        self,
        cmd: &ParitialSignatureCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Generating adaptor partial signature for user {}",
            cmd.user_id
        );

        let participants = self.get_participants();
        participants
            .iter()
            .position(|p| p == &cmd.user_id)
            .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                "User {} not found in participants",
                cmd.user_id
            ))))?;

        let private_key = self
            .musig_processor
            .get_private_key(&self.session_id, &cmd.user_id)
            .ok_or(EnclaveError::PrivateKey(PrivateKeyError::Invalid(format!(
                "Missing private key for user {}",
                cmd.user_id
            ))))?;

        let (signature_bytes, _nonce_bytes) = self
            .musig_processor
            .sign_for_user(&self.session_id, &cmd.user_id, &private_key)
            .map_err(|e| {
                EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                    "Adaptor partial signature generation failed: {e}"
                )))
            })?;

        let _partial_signature = PartialSignature::from_slice(&signature_bytes).map_err(|e| {
            EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                "Failed to deserialize adaptor partial signature: {e}"
            )))
        })?;

        let session_id = self.session_id.clone();
        let user_id = cmd.user_id.clone();

        info!(
            "Successfully generated adaptor partial signature for user {} in session {}, transitioning to CollectingPartialSignatures",
            user_id, session_id
        );

        Ok(OperatorStatus::Signing(
            SigningStatus::CollectingPartialSignatures(CollectingPartialSignatures::from(
                self.clone(),
            )),
        ))
    }

    fn generate_regular_partial_signature(
        self,
        cmd: &ParitialSignatureCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Generating regular partial signature for user {}",
            cmd.user_id
        );

        let participants = self.get_participants();
        participants
            .iter()
            .position(|p| p == &cmd.user_id)
            .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                "User {} not found in participants",
                cmd.user_id
            ))))?;

        let private_key = self
            .musig_processor
            .get_private_key(&self.session_id, &cmd.user_id)
            .ok_or(EnclaveError::PrivateKey(PrivateKeyError::Invalid(format!(
                "Missing private key for user {}",
                cmd.user_id
            ))))?;

        let (signature_bytes, _nonce_bytes) = self
            .musig_processor
            .sign_for_user(&self.session_id, &cmd.user_id, &private_key)
            .map_err(|e| {
                EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                    "MuSig2 partial signature generation failed: {e}"
                )))
            })?;

        let _partial_signature = PartialSignature::from_slice(&signature_bytes).map_err(|e| {
            EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                "Failed to deserialize partial signature: {e}"
            )))
        })?;

        let session_id = self.session_id.clone();
        let user_id = cmd.user_id.clone();

        info!(
            "Successfully generated regular partial signature for user {} in session {}, transitioning to CollectingPartialSignatures",
            user_id, session_id
        );

        Ok(OperatorStatus::Signing(
            SigningStatus::CollectingPartialSignatures(CollectingPartialSignatures::from(
                self.clone(),
            )),
        ))
    }
}

impl From<GeneratingPartialSignatures> for CollectingPartialSignatures {
    fn from(state: GeneratingPartialSignatures) -> Self {
        CollectingPartialSignatures {
            session_id: state.session_id,
            session_secret: state.session_secret,
            coordinator_data: state.coordinator_data,
            created_at: state.created_at,
            musig_processor: Arc::clone(&state.musig_processor),
        }
    }
}
