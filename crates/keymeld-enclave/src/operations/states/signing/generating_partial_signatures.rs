use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::EnclaveError,
    SessionSecret,
};
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
        // Return participants in BIP327 order (sorted by compressed public key)
        // This matches the order used in KeyAggContext for consistent signer indices
        self.musig_processor
            .get_session_metadata_public()
            .get_all_participant_ids()
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

    /// Check if all batch signatures are complete
    pub fn has_all_batch_signatures(&self) -> bool {
        self.musig_processor.all_batch_signatures_complete()
    }

    /// Get the count of batch items with signatures
    pub fn get_batch_signature_count(&self) -> usize {
        self.musig_processor.get_batch_signature_count()
    }
}

impl GeneratingPartialSignatures {
    /// Generate batch partial signatures for a specific user
    fn generate_batch_partial_signature_for_user(
        &mut self,
        user_id: &UserId,
        _signing_ctx: &mut SigningSessionContext,
    ) -> Result<(), EnclaveError> {
        // Get batch partial signatures using MusigProcessor
        // The SecondRounds were already created in finalize_batch_nonce_rounds
        let result = self
            .musig_processor
            .get_user_batch_partial_signatures(user_id);

        match result {
            Ok(batch_sigs) => {
                info!(
                    "Generated batch partial signatures for user {} in session {} ({} batch items)",
                    user_id,
                    self.session_id,
                    batch_sigs.len()
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to generate batch partial signatures for user {} in session {}: {}",
                    user_id,
                    self.session_id,
                    e
                );
                Err(EnclaveError::Session(
                    keymeld_core::protocol::SessionError::ProcessingFailed(format!(
                        "Failed to generate batch partial signatures: {}",
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
    /// All signing is now batch mode.
    /// Returns: CollectingPartialSignatures
    pub fn generate_partial_signatures(
        mut self,
        signing_ctx: &mut SigningSessionContext,
        _enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Auto-processing batch partial signature generation for all users in signing session {}",
            self.session_id
        );

        // Get all users this enclave has private keys for
        let users_in_session = self.musig_processor.get_users_in_session();
        let expected_participants = self.get_participants();

        info!(
            "Generating batch partial signatures for {} users this enclave represents in signing session {}",
            users_in_session.len(),
            self.session_id,
        );

        let mut generated_count = 0;

        // Generate batch partial signatures for all users this enclave represents
        for user_id in &users_in_session {
            if !expected_participants.contains(user_id) {
                info!(
                    "User {} not in expected participants for this signing session, skipping",
                    user_id
                );
                continue;
            }

            let generation_result =
                self.generate_batch_partial_signature_for_user(user_id, signing_ctx);

            match generation_result {
                Ok(_) => {
                    info!(
                        "Successfully generated batch partial signature for user {} in signing session {}",
                        user_id, self.session_id
                    );
                    generated_count += 1;
                }
                Err(e) => {
                    error!(
                        "Failed to generate batch partial signature for user {} in signing session {}: {}",
                        user_id, self.session_id, e
                    );
                    // Continue with next user instead of failing the entire operation
                }
            }
        }

        info!(
            "Generated {} batch partial signatures in signing session {}",
            generated_count, self.session_id
        );

        // Auto-transition to CollectingPartialSignatures state
        let collecting_partial_signatures = CollectingPartialSignatures::try_from(self)?;
        Ok(SigningStatus::CollectingPartialSignatures(
            collecting_partial_signatures,
        ))
    }
}
