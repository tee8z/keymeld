use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, InternalError, SignatureData, ValidationError},
    SessionSecret,
};
use musig2::PubNonce;
use std::time::SystemTime;
use tracing::info;

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{signing::CoordinatorData, SigningStatus},
    FinalizingSignature,
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct CollectingPartialSignatures {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl CollectingPartialSignatures {
    pub(crate) fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        coordinator_data: Option<CoordinatorData>,
        created_at: SystemTime,
        musig_processor: MusigProcessor,
    ) -> Self {
        Self {
            session_id,
            session_secret,
            coordinator_data,
            created_at,
            musig_processor,
        }
    }

    pub fn from_signing_context(
        signing_ctx: &mut SigningSessionContext,
        musig_processor: MusigProcessor,
    ) -> Result<Self, EnclaveError> {
        let session_secret = signing_ctx
            .session_secret
            .clone()
            .ok_or(EnclaveError::Session(
                keymeld_core::protocol::SessionError::SecretNotInitialized,
            ))?;

        Ok(Self::new(
            signing_ctx.session_id.clone(),
            session_secret,
            signing_ctx.coordinator_data.clone(),
            signing_ctx.created_at,
            musig_processor,
        ))
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    pub fn coordinator_data(&self) -> &Option<CoordinatorData> {
        &self.coordinator_data
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn musig_processor(&self) -> &MusigProcessor {
        &self.musig_processor
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participants
            .clone()
    }

    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .get_session_metadata_public()
            .participant_public_keys
            .len()
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }

    pub fn get_message(&self) -> Vec<u8> {
        self.musig_processor
            .get_session_metadata_public()
            .message
            .clone()
    }

    pub fn get_current_partial_signature_count(&self) -> Result<usize, EnclaveError> {
        // Use existing method from signatures.rs
        Ok(self.musig_processor.get_partial_signature_count())
    }

    pub fn get_current_user_partial_signature(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<u8>, EnclaveError> {
        // Use existing method from signatures.rs
        self.musig_processor
            .get_user_partial_signature(user_id)
            .map_err(|e| EnclaveError::Musig(e.to_string()))
    }

    pub fn can_aggregate_signatures(&self) -> Result<bool, EnclaveError> {
        // Check if all partial signatures have been collected
        Ok(self.has_all_partial_signatures())
    }

    pub fn has_all_partial_signatures(&self) -> bool {
        // Check if this session uses adaptor signatures
        let session_metadata = self.musig_processor.get_session_metadata_public();
        let has_adaptor_configs = !session_metadata.adaptor_configs.is_empty();

        if has_adaptor_configs {
            // For adaptor signatures, use the dedicated method
            self.musig_processor.has_all_adaptor_signatures()
        } else {
            // For regular signatures, check if we have enough count
            let signature_count = self.musig_processor.get_partial_signature_count();
            let expected_count = session_metadata.expected_participants.len();
            signature_count >= expected_count
        }
    }

    pub fn get_user_nonce(&self, user_id: &UserId) -> Option<PubNonce> {
        self.musig_processor.get_user_nonce(user_id)
    }

    pub fn get_user_nonce_data(
        &self,
        user_id: &UserId,
    ) -> Option<keymeld_core::protocol::NonceData> {
        self.musig_processor.get_user_nonce_data(user_id)
    }

    pub fn get_nonce_count(&self) -> usize {
        self.musig_processor.get_nonce_count()
    }
}

impl CollectingPartialSignatures {
    /// Process FinalizeSignature command - collect partial signatures.
    /// Returns: FinalizingSignature | CollectingPartialSignatures (if still waiting)
    pub fn collect_partial_signatures(
        mut self,
        finalize_cmd: &keymeld_core::protocol::FinalizeSignatureCommand,
        signing_ctx: &mut SigningSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Processing partial signature collection for signing session {}",
            self.session_id
        );

        let encrypted_partial_signatures = &finalize_cmd.partial_signatures;

        // Get session secret for decryption
        let session_secret = signing_ctx.session_secret.as_ref().ok_or_else(|| {
            EnclaveError::Internal(InternalError::Other(
                "Session secret not available for decryption".to_string(),
            ))
        })?;

        let expected_participants = self.get_participants();
        let mut added_count = 0;

        // Process all incoming encrypted partial signatures
        for (user_id, encrypted_signature_hex) in encrypted_partial_signatures {
            // Decrypt the signature data
            let encrypted_signature = keymeld_core::crypto::EncryptedData::from_hex(
                encrypted_signature_hex,
            )
            .map_err(|e| {
                EnclaveError::Internal(InternalError::Other(format!(
                    "Failed to decode encrypted signature hex for user {}: {}",
                    user_id, e
                )))
            })?;

            let signature_data: keymeld_core::protocol::SignatureData = session_secret
                .decrypt_value(&encrypted_signature, "signature_data")
                .map_err(|e| {
                    EnclaveError::Internal(InternalError::Other(format!(
                        "Failed to decrypt signature data for user {}: {}",
                        user_id, e
                    )))
                })?;
            // Validate user is expected participant
            let signer_index = expected_participants
                .iter()
                .position(|id| id == user_id)
                .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                    "User {} not found in expected participants",
                    user_id
                ))))?;

            // Add partial signature to MuSig processor
            // The musig2 library handles duplicate signature checks internally
            match signature_data {
                SignatureData::Regular(partial_sig) => {
                    self.musig_processor
                        .add_partial_signature(signer_index, partial_sig)
                        .map_err(|e| {
                            EnclaveError::Internal(InternalError::Other(format!(
                                "Failed to add regular partial signature for user {}: {:?}",
                                user_id, e
                            )))
                        })?;
                    info!(
                        "Added regular partial signature for user {} at index {}",
                        user_id, signer_index
                    );
                }
                SignatureData::Adaptor(adaptor_sigs) => {
                    // Convert adaptor signatures to the format expected by the processor
                    let adaptor_sigs_bytes: Vec<(uuid::Uuid, Vec<u8>)> = adaptor_sigs
                        .iter()
                        .map(|(id, sig)| (*id, sig.serialize().to_vec()))
                        .collect();

                    self.musig_processor
                        .add_adaptor_partial_signatures(signer_index, adaptor_sigs_bytes)
                        .map_err(|e| {
                            EnclaveError::Internal(InternalError::Other(format!(
                                "Failed to add adaptor partial signatures for user {}: {:?}",
                                user_id, e
                            )))
                        })?;
                    info!(
                        "Added {} adaptor partial signatures for user {} at index {}",
                        adaptor_sigs.len(),
                        user_id,
                        signer_index
                    );
                }
            }

            info!(
                "Added partial signature for user {} in signing session {}",
                user_id, self.session_id
            );

            added_count += 1;
        }

        info!(
            "Processed {} partial signatures for signing session {}",
            added_count, self.session_id
        );

        // Check if we have enough signatures to finalize and transition to FinalizingSignature
        if self.can_finalize_signature() {
            info!(
                "All partial signatures collected for signing session {}, transitioning to FinalizingSignature",
                self.session_id
            );

            // Only coordinator enclave should finalize
            if let Some(_coordinator_data) = &self.coordinator_data {
                let finalizing_signature = FinalizingSignature::try_from(self)?;
                // Auto-chain to finalize and transition to Completed
                finalizing_signature.finalize(finalize_cmd, signing_ctx, enclave_ctx)
            } else {
                info!(
                    "Non-coordinator enclave completed partial signature collection for session {}",
                    self.session_id
                );
                Ok(SigningStatus::CollectingPartialSignatures(self))
            }
        } else {
            let signature_count = self.musig_processor.get_partial_signature_count();
            let expected_count = self.get_expected_participant_count().unwrap_or(0);
            info!(
                "Signing session {} still collecting partial signatures: {}/{}",
                self.session_id, signature_count, expected_count
            );
            Ok(SigningStatus::CollectingPartialSignatures(self))
        }
    }
}

impl CollectingPartialSignatures {
    /// Check if we can finalize the signature (all partial signatures collected)
    fn can_finalize_signature(&self) -> bool {
        let signature_count = self.musig_processor.get_partial_signature_count();
        let expected_count = self.get_expected_participant_count().unwrap_or(0);
        signature_count >= expected_count && expected_count > 0
    }
}

impl TryFrom<CollectingPartialSignatures>
    for crate::operations::states::signing::FinalizingSignature
{
    type Error = EnclaveError;

    fn try_from(value: CollectingPartialSignatures) -> Result<Self, Self::Error> {
        value.musig_processor.get_aggregate_pubkey().map_err(|e| {
            EnclaveError::Session(keymeld_core::protocol::SessionError::MusigInitialization(
                format!(
                    "Cannot finalize signature, aggregate pubkey not ready: {}",
                    e
                ),
            ))
        })?;

        Ok(FinalizingSignature::new(
            value.session_id,
            value.session_secret,
            value.coordinator_data,
            value.created_at,
            value.musig_processor,
        ))
    }
}
