use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{
        CryptoError, EnclaveError, InternalError, NonceData, NonceError, SessionError,
        ValidationError,
    },
    SessionSecret,
};
use musig2::PubNonce;
use std::time::SystemTime;
use tracing::info;

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{signing::CoordinatorData, SigningStatus},
    GeneratingPartialSignatures,
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct CollectingNonces {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl CollectingNonces {
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

    pub fn get_aggregate_pubkey(&self) -> Result<musig2::secp256k1::PublicKey, EnclaveError> {
        self.musig_processor.get_aggregate_pubkey().map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to aggregate pubkey for session {}: {}",
                self.session_id, e
            )))
        })
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }

    pub fn get_user_nonce(&self, user_id: &UserId) -> Option<PubNonce> {
        self.musig_processor.get_user_nonce(user_id)
    }

    /// Get user nonce data (handles both regular and adaptor nonces)
    pub fn get_user_nonce_data(&self, user_id: &UserId) -> Option<NonceData> {
        self.musig_processor.get_user_nonce_data(user_id)
    }

    pub fn can_aggregate_nonces(&self) -> bool {
        let expected_count = self.get_expected_participant_count().unwrap_or(0);

        // Check if this session uses adaptor signatures
        let session_metadata = self.musig_processor.get_session_metadata_public();
        let has_adaptor_configs = !session_metadata.adaptor_configs.is_empty();

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
            let nonce_count = self.musig_processor.get_nonce_count();
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
        let result = self
            .musig_processor
            .all_adaptor_first_rounds_complete()
            .unwrap_or(false);

        tracing::info!(
            "all_adaptor_nonces_collected for session {}: {}",
            self.session_id,
            result
        );

        result
    }
}

impl TryFrom<CollectingNonces> for GeneratingPartialSignatures {
    type Error = EnclaveError;

    fn try_from(mut value: CollectingNonces) -> Result<Self, Self::Error> {
        if !value.can_aggregate_nonces() {
            return Err(EnclaveError::Session(SessionError::MusigInitialization(
                "Cannot generate partial signatures, not all nonces collected".to_string(),
            )));
        }

        // Update session phase to NonceAggregation before finalizing nonce rounds
        value
            .musig_processor
            .update_session_phase(crate::musig::types::SessionPhase::NonceAggregation)
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to update session phase to NonceAggregation: {}",
                    e
                )))
            })?;

        let participants_with_sessions = value.musig_processor.get_users_in_session();

        for participant in &participants_with_sessions {
            if let Err(e) = value.musig_processor.finalize_nonce_rounds(participant) {
                return Err(EnclaveError::Session(SessionError::MusigInitialization(
                    format!(
                        "Failed to finalize nonce rounds for participant {}: {}",
                        participant, e
                    ),
                )));
            }
        }

        info!(
            "Finalized nonce rounds for {} participants in session {}",
            participants_with_sessions.len(),
            value.session_id
        );

        Ok(GeneratingPartialSignatures::new(
            value.session_id,
            value.session_secret,
            value.coordinator_data,
            value.created_at,
            value.musig_processor,
        ))
    }
}

impl CollectingNonces {
    /// Process DistributeNonces command.
    /// Returns: GeneratingPartialSignatures | CollectingNonces (if still waiting for nonces)
    pub fn distribute_nonces(
        mut self,
        distribute_cmd: &keymeld_core::protocol::DistributeNoncesCommand,
        signing_ctx: &mut SigningSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Processing nonce distribution for signing session {}",
            self.session_id
        );

        let encrypted_nonces = &distribute_cmd.nonces;

        // Get session secret for decryption
        let session_secret = signing_ctx.session_secret.as_ref().ok_or_else(|| {
            EnclaveError::Internal(InternalError::Other(
                "Session secret not available for decryption".to_string(),
            ))
        })?;

        let expected_participants = self.get_participants();
        let mut added_count = 0;

        // Process all incoming encrypted nonces
        for (user_id, encrypted_nonce_hex) in encrypted_nonces {
            // Decrypt the nonce data
            let encrypted_nonce = keymeld_core::crypto::EncryptedData::from_hex(
                encrypted_nonce_hex,
            )
            .map_err(|e| {
                EnclaveError::Internal(InternalError::Other(format!(
                    "Failed to decode encrypted nonce hex for user {}: {}",
                    user_id, e
                )))
            })?;

            let nonce_data: keymeld_core::protocol::NonceData = session_secret
                .decrypt_value(&encrypted_nonce, "nonce_data")
                .map_err(|e| {
                    EnclaveError::Internal(InternalError::Other(format!(
                        "Failed to decrypt nonce data for user {}: {}",
                        user_id, e
                    )))
                })?;
            // Validate user is expected participant
            expected_participants
                .iter()
                .position(|id| id == user_id)
                .ok_or(EnclaveError::Validation(ValidationError::Other(format!(
                    "User {} not found in expected participants",
                    user_id
                ))))?;

            // Add nonce to MuSig processor (handles duplicates gracefully)
            match nonce_data {
                NonceData::Regular(nonce) => {
                    // Validate nonce length
                    if nonce.serialize().len() != 66 {
                        return Err(EnclaveError::Nonce(NonceError::GenerationFailed {
                            user_id: user_id.clone(),
                            error: format!(
                                "Invalid regular nonce length: expected 66 bytes, got {}",
                                nonce.serialize().len()
                            ),
                        }));
                    }

                    self.musig_processor
                        .add_participant_nonce(user_id, nonce.clone())
                        .map_err(|e| {
                            EnclaveError::Nonce(NonceError::AddFailed {
                                user_id: user_id.clone(),
                                error: format!("Failed to add regular nonce: {}", e),
                            })
                        })?;
                }
                NonceData::Adaptor(adaptor_nonces) => {
                    // Validate each adaptor nonce
                    for (config_id, nonce) in &adaptor_nonces {
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

                    // Store adaptor nonces - this properly adds to adaptor_first_rounds
                    self.musig_processor
                        .store_adaptor_nonces(user_id, adaptor_nonces)
                        .map_err(|e| {
                            EnclaveError::Nonce(NonceError::AddFailed {
                                user_id: user_id.clone(),
                                error: format!("Failed to store adaptor nonces: {}", e),
                            })
                        })?;
                }
            }

            info!(
                "Added nonce for user {} in signing session {}",
                user_id, self.session_id
            );

            added_count += 1;
        }

        info!(
            "Processed {} nonces for signing session {}",
            added_count, self.session_id
        );

        // Check if we can now aggregate nonces and transition to next state
        if self.can_aggregate_nonces() {
            info!(
                "All nonces collected for signing session {}, transitioning to GeneratingPartialSignatures",
                self.session_id
            );

            let generating_partial_signatures = GeneratingPartialSignatures::try_from(self)?;

            // Chain to partial signature generation
            generating_partial_signatures.generate_partial_signatures(signing_ctx, enclave_ctx)
        } else {
            let nonce_count = self.musig_processor.get_nonce_count();
            let expected_count = self.get_expected_participant_count().unwrap_or(0);
            info!(
                "Signing session {} still collecting nonces: {}/{}",
                self.session_id, nonce_count, expected_count
            );
            Ok(SigningStatus::CollectingNonces(self))
        }
    }
}
