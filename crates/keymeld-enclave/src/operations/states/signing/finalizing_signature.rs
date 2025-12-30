use keymeld_core::{
    enclave::{CryptoError, EnclaveCommand, EnclaveError, SessionError, SigningError},
    musig::{MusigError, MusigProcessor},
    SessionId, SessionSecret, UserId,
};
use musig2::PartialSignature;
use std::{sync::Arc, time::SystemTime};
use tracing::info;

use crate::operations::{
    context::EnclaveContext,
    states::{
        signing::{Completed, CoordinatorData},
        OperatorStatus, SigningStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug)]
pub struct FinalizingSignature {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Clone for FinalizingSignature {
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

impl FinalizingSignature {
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

    pub fn has_all_partial_signatures(&self) -> Result<bool, EnclaveError> {
        // Check if this session uses adaptor signatures
        let session_metadata = self
            .musig_processor
            .get_session_metadata_public(&self.session_id);
        let has_adaptor_configs = session_metadata
            .map(|metadata| !metadata.adaptor_configs.is_empty())
            .unwrap_or(false);

        if has_adaptor_configs {
            // For adaptor signatures, use the dedicated method that checks all configs
            Ok(self
                .musig_processor
                .has_all_adaptor_signatures(&self.session_id))
        } else {
            // For regular signatures, use the existing logic
            let count = self.get_partial_signature_count()?;
            let expected_count = self.get_expected_participant_count().unwrap_or(0);
            Ok(count >= expected_count)
        }
    }

    pub fn finalize_signatures(&self) -> Result<Vec<u8>, EnclaveError> {
        self.musig_processor
            .finalize(&self.session_id)
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to finalize signature: {}",
                    e
                )))
            })
    }
}

impl EnclaveAdvanceable<OperatorStatus> for FinalizingSignature {
    fn process(
        self,
        ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing FinalizingSignature state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::Finalize(_) => {
                info!(
                    "Finalizing signature for signing session {}",
                    self.session_id
                );

                let Some(coordinator) = self.coordinator_data.clone() else {
                    return Err(EnclaveError::Session(SessionError::InvalidId(
                        String::from("Only coordinator enclave can finalize "),
                    )));
                };

                let session_metadata = self
                    .musig_processor
                    .get_session_metadata_public(&self.session_id);
                let use_adaptor = session_metadata
                    .map(|metadata| !metadata.adaptor_configs.is_empty())
                    .unwrap_or(false);

                if use_adaptor {
                    info!(
                        "Finalizing adaptor signatures for signing session {}",
                        self.session_id
                    );

                    let final_signature = self
                        .musig_processor
                        .aggregate_signatures(&self.session_id, &coordinator.user_id)
                        .map_err(|e| {
                            EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                                "Adaptor signature aggregation failed: {e}"
                            )))
                        })?;

                    let adaptor_signature_results = self
                        .musig_processor
                        .get_adaptor_signature_results(&self.session_id)
                        .map_err(|e| {
                            EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                                "Failed to get adaptor signature results: {e}"
                            )))
                        })?;

                    info!(
                        "Successfully finalized {} adaptor signatures for signing session {}",
                        adaptor_signature_results.len(),
                        self.session_id
                    );

                    let encrypted_signature =
                        ctx.finalize_and_encrypt_signature(&final_signature, &self.session_secret)?;

                    let adaptor_results: Vec<_> =
                        adaptor_signature_results.values().cloned().collect();
                    let encrypted_adaptor_signatures =
                        ctx.encrypt_adaptor_signatures(&adaptor_results, &self.session_secret)?;

                    let expected_count = self.get_expected_participant_count().unwrap_or(0);

                    Ok(OperatorStatus::Signing(SigningStatus::Completed(
                        Completed::builder(
                            self.session_id,
                            self.session_secret,
                            encrypted_signature,
                            Arc::clone(&self.musig_processor),
                        )
                        .participant_count(expected_count as u32)
                        .created_at(self.created_at)
                        .coordinator_data(self.coordinator_data)
                        .with_adaptor_signatures(encrypted_adaptor_signatures)
                        .build(),
                    )))
                } else {
                    info!(
                        "Finalizing regular signature for signing session {}",
                        self.session_id
                    );

                    let final_signature = self
                        .musig_processor
                        .aggregate_signatures(&self.session_id, &coordinator.user_id)
                        .map_err(|e| {
                            EnclaveError::Signing(SigningError::SignatureAggregation(format!(
                                "MuSig2 signature aggregation failed: {e}"
                            )))
                        })?;

                    info!(
                        "Successfully finalized regular signature for signing session {}",
                        self.session_id
                    );

                    let encrypted_signature =
                        ctx.finalize_and_encrypt_signature(&final_signature, &self.session_secret)?;

                    let expected_count = self.get_expected_participant_count().unwrap_or(0);

                    Ok(OperatorStatus::Signing(SigningStatus::Completed(
                        Completed::builder(
                            self.session_id,
                            self.session_secret,
                            encrypted_signature,
                            Arc::clone(&self.musig_processor),
                        )
                        .participant_count(expected_count as u32)
                        .created_at(self.created_at)
                        .coordinator_data(self.coordinator_data)
                        .build(),
                    )))
                }
            }

            _ => Ok(OperatorStatus::Signing(SigningStatus::FinalizingSignature(
                self,
            ))),
        }
    }
}
