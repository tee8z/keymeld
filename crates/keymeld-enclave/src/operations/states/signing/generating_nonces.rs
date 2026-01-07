use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{
        EnclaveError, NonceData, NonceError, PrivateKeyError, SessionError, ValidationError,
    },
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
        self.musig_processor
            .get_session_metadata_public()
            .expected_participants
            .clone()
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }

    /// Check if user has any nonce (regular or adaptor)
    pub fn has_user_nonce(&self, user_id: &UserId) -> bool {
        self.musig_processor.get_user_nonce_data(user_id).is_some()
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
            // Check if nonce already exists for this user (handles both regular and adaptor)
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

            let nonce_data = self
                .musig_processor
                .generate_nonce(user_id, signer_index, &private_key)
                .map_err(|e| {
                    EnclaveError::Nonce(NonceError::GenerationFailed {
                        user_id: user_id.clone(),
                        error: format!("Failed to generate nonce: {e}"),
                    })
                })?;

            // Validate nonce data based on type
            match &nonce_data {
                NonceData::Regular(nonce) => {
                    if nonce.serialize().len() != 66 {
                        return Err(EnclaveError::Nonce(NonceError::GenerationFailed {
                            user_id: user_id.clone(),
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
                                user_id: user_id.clone(),
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
                keymeld_core::protocol::NonceData::Regular(nonce) => {
                    format!("regular nonce: {} bytes", nonce.serialize().len())
                }
                keymeld_core::protocol::NonceData::Adaptor(adaptor_nonces) => {
                    format!("adaptor nonces: {} configs", adaptor_nonces.len())
                }
            };

            info!(
                "successfully generated nonce for user {} in signing session {} ({})",
                user_id, self.session_id, nonce_info
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
