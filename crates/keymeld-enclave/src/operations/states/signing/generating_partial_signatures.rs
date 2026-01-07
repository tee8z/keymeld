use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, PrivateKeyError, ValidationError},
    SessionSecret,
};
use musig2::PubNonce;
use std::time::SystemTime;
use tracing::{error, info};

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{signing::CoordinatorData, SigningStatus},
    CollectingPartialSignatures,
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct GeneratingPartialSignatures {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl GeneratingPartialSignatures {
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

    pub fn get_partial_signature_count(&self) -> usize {
        // Use existing method from signatures.rs
        self.musig_processor.get_partial_signature_count()
    }

    pub fn get_user_partial_signature(&self, user_id: &UserId) -> Result<Vec<u8>, EnclaveError> {
        self.musig_processor
            .get_user_partial_signature(user_id)
            .map_err(|e| EnclaveError::Musig(e.to_string()))
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

impl GeneratingPartialSignatures {
    /// Generate regular partial signature for a specific user
    fn generate_regular_partial_signature_for_user(
        &mut self,
        user_id: &UserId,
        _signing_ctx: &mut SigningSessionContext,
    ) -> Result<(), EnclaveError> {
        let participants = self.get_participants();
        let _signer_index =
            participants
                .iter()
                .position(|p| p == user_id)
                .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                    "User {} not found in participants",
                    user_id
                ))))?;

        let private_key =
            self.musig_processor
                .get_private_key(user_id)
                .ok_or(EnclaveError::PrivateKey(PrivateKeyError::Invalid(format!(
                    "Missing private key for user {}",
                    user_id
                ))))?;

        // Generate partial signature using MusigProcessor
        let result = self.musig_processor.sign(user_id, &private_key);

        match result {
            Ok((signature_bytes, _nonce_bytes)) => {
                info!(
                    "Generated regular partial signature for user {} in session {} (signature length: {})",
                    user_id, self.session_id, signature_bytes.len()
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to generate regular partial signature for user {} in session {}: {}",
                    user_id,
                    self.session_id,
                    e
                );
                Err(EnclaveError::Session(
                    keymeld_core::protocol::SessionError::ProcessingFailed(format!(
                        "Failed to generate partial signature: {}",
                        e
                    )),
                ))
            }
        }
    }

    /// Generate adaptor partial signature for a specific user
    fn generate_adaptor_partial_signature_for_user(
        &mut self,
        user_id: &UserId,
        _signing_ctx: &mut SigningSessionContext,
    ) -> Result<(), EnclaveError> {
        let participants = self.get_participants();
        let _signer_index =
            participants
                .iter()
                .position(|p| p == user_id)
                .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                    "User {} not found in participants",
                    user_id
                ))))?;

        let private_key =
            self.musig_processor
                .get_private_key(user_id)
                .ok_or(EnclaveError::PrivateKey(PrivateKeyError::Invalid(format!(
                    "Missing private key for user {}",
                    user_id
                ))))?;

        // Generate adaptor partial signatures using MusigProcessor
        let result = self.musig_processor.sign(user_id, &private_key);

        match result {
            Ok((signature_bytes, adaptor_bytes)) => {
                info!(
                    "Generated adaptor partial signatures for user {} in session {} (signature: {} bytes, adaptor: {} bytes)",
                    user_id, self.session_id, signature_bytes.len(), adaptor_bytes.len()
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to generate adaptor partial signatures for user {} in session {}: {}",
                    user_id,
                    self.session_id,
                    e
                );
                Err(EnclaveError::Session(
                    keymeld_core::protocol::SessionError::ProcessingFailed(format!(
                        "Failed to generate adaptor partial signatures: {}",
                        e
                    )),
                ))
            }
        }
    }
}

impl TryFrom<GeneratingPartialSignatures> for CollectingPartialSignatures {
    type Error = EnclaveError;

    fn try_from(value: GeneratingPartialSignatures) -> Result<Self, Self::Error> {
        value.musig_processor.get_aggregate_pubkey().map_err(|e| {
            EnclaveError::Session(keymeld_core::protocol::SessionError::MusigInitialization(
                format!(
                    "Cannot collect partial signatures, aggregate pubkey not ready: {}",
                    e
                ),
            ))
        })?;

        Ok(CollectingPartialSignatures::new(
            value.session_id,
            value.session_secret,
            value.coordinator_data,
            value.created_at,
            value.musig_processor,
        ))
    }
}

impl GeneratingPartialSignatures {
    /// Auto-processing: generate partial signatures for all users this enclave represents.
    /// Returns: CollectingPartialSignatures
    pub fn generate_partial_signatures(
        mut self,
        signing_ctx: &mut SigningSessionContext,
        _enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Auto-processing partial signature generation for all users in signing session {}",
            self.session_id
        );

        // Check if we have adaptor configs from the MuSig processor metadata
        let session_metadata = self.musig_processor.get_session_metadata_public();
        let use_adaptor = !session_metadata.adaptor_configs.is_empty();

        // Get all users this enclave has private keys for
        let users_in_session = self.musig_processor.get_users_in_session();
        let expected_participants = self.get_participants();

        info!(
            "Generating partial signatures for {} users this enclave represents in signing session {}",
            users_in_session.len(),
            self.session_id
        );

        let mut generated_count = 0;

        // Generate partial signatures for all users this enclave represents
        for user_id in &users_in_session {
            if !expected_participants.contains(user_id) {
                info!(
                    "User {} not in expected participants for this signing session, skipping",
                    user_id
                );
                continue;
            }

            let generation_result = if use_adaptor {
                self.generate_adaptor_partial_signature_for_user(user_id, signing_ctx)
            } else {
                self.generate_regular_partial_signature_for_user(user_id, signing_ctx)
            };

            match generation_result {
                Ok(_) => {
                    info!(
                        "successfully generated partial signature for user {} in signing session {}",
                        user_id, self.session_id
                    );
                    generated_count += 1;
                }
                Err(e) => {
                    error!(
                        "failed to generate partial signature for user {} in signing session {}: {}",
                        user_id, self.session_id, e
                    );
                    // Continue with next user instead of failing the entire operation
                }
            }
        }

        info!(
            "generated {} partial signatures in signing session {}",
            generated_count, self.session_id
        );

        // Auto-transition to CollectingPartialSignatures state
        let collecting_partial_signatures = CollectingPartialSignatures::try_from(self)?;
        Ok(SigningStatus::CollectingPartialSignatures(
            collecting_partial_signatures,
        ))
    }
}
