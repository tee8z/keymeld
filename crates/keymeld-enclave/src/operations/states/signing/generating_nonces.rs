use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, NonceError, PrivateKeyError, SessionError, ValidationError},
    SessionSecret,
};
use std::time::SystemTime;
use tracing::{debug, info};

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{signing::CoordinatorData, SigningStatus},
    CollectingNonces,
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct GeneratingNonces {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl GeneratingNonces {
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
            .ok_or(EnclaveError::Session(SessionError::SecretNotInitialized))?;

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

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }

    /// Check if user has batch nonces
    pub fn has_user_nonce(&self, user_id: &UserId) -> bool {
        self.musig_processor
            .get_user_batch_nonce_data(user_id)
            .is_some()
    }
}

impl GeneratingNonces {
    /// Auto-processing: generate nonces for all users this enclave represents.
    /// Returns: CollectingNonces
    pub fn generate_nonces(
        mut self,
        signing_ctx: &mut SigningSessionContext,
        _enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "nonce generation for all users in signing session {}",
            self.session_id
        );

        let expected_count = self.get_expected_participant_count().unwrap_or(0);
        if expected_count == 0 {
            return Err(EnclaveError::Validation(ValidationError::Other(
                "Expected participant count must be greater than 0".to_string(),
            )));
        }

        let expected_participants = self.get_participants();

        // Get all users this enclave has private keys for
        let users_in_session = self.musig_processor.get_users_in_session();

        debug!(
            "Generating nonces for {} users this enclave represents in signing session {}",
            users_in_session.len(),
            self.session_id
        );

        let mut generated_count = 0;

        // Generate nonces for all users this enclave represents
        for user_id in &users_in_session {
            // Check if nonce already exists for this user
            if self.has_user_nonce(user_id) {
                debug!(
                    "Nonce already exists for user {} in signing session {}, skipping",
                    user_id, self.session_id
                );
                continue;
            }

            if !expected_participants.contains(user_id) {
                debug!(
                    "User {} not in expected participants for this signing session, skipping",
                    user_id
                );
                continue;
            }

            let signer_index = expected_participants
                .iter()
                .position(|id| id == user_id)
                .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                    "User {} not found in expected participants",
                    user_id
                ))))?;

            debug!(
                "generating nonce for user {} - computed signer_index={} from expected_participants={:?}",
                user_id, signer_index, expected_participants
            );

            // Get private key first to avoid borrowing conflicts
            let private_key = {
                self.musig_processor
                    .get_private_key(user_id)
                    .ok_or(EnclaveError::PrivateKey(PrivateKeyError::Invalid(format!(
                        "Missing private key for user {}",
                        user_id
                    ))))?
            };

            // Generate nonces for all batch items (single message = batch of 1)
            let batch_nonces = self
                .musig_processor
                .generate_batch_nonces(user_id, signer_index, &private_key)
                .map_err(|e| {
                    EnclaveError::Nonce(NonceError::GenerationFailed {
                        user_id: user_id.clone(),
                        error: format!("Failed to generate batch nonces: {e}"),
                    })
                })?;

            info!(
                "successfully generated batch nonces for user {} in signing session {} ({} batch items)",
                user_id, self.session_id, batch_nonces.len()
            );

            generated_count += 1;
        }

        info!(
            "generated nonces for {} users in signing session {}",
            generated_count, self.session_id
        );

        // Transition to CollectingNonces state and wait for DistributeNonces command
        let collecting_nonces =
            CollectingNonces::from_signing_context(signing_ctx, self.musig_processor)?;

        info!(
            "Signing session {} transitioning to CollectingNonces, waiting for DistributeNonces command",
            self.session_id
        );

        Ok(SigningStatus::CollectingNonces(collecting_nonces))
    }
}

impl TryFrom<GeneratingNonces> for CollectingNonces {
    type Error = EnclaveError;

    fn try_from(value: GeneratingNonces) -> Result<Self, Self::Error> {
        value.musig_processor.get_aggregate_pubkey().map_err(|e| {
            EnclaveError::Session(SessionError::MusigInitialization(format!(
                "Cannot collect nonces, aggregate pubkey not ready: {}",
                e
            )))
        })?;

        Ok(CollectingNonces::new(
            value.session_id,
            value.session_secret,
            value.coordinator_data,
            value.created_at,
            value.musig_processor,
        ))
    }
}
