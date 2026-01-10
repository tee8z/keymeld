use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{
        CryptoError, EnclaveError, InternalError, NonceData, NonceError, SessionError,
        ValidationError,
    },
    SessionSecret,
};
use std::collections::BTreeMap;
use std::time::SystemTime;
use tracing::info;
use uuid::Uuid;

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
        // Return participants in BIP327 order (sorted by compressed public key)
        // This matches the order used in KeyAggContext for consistent signer indices
        self.musig_processor
            .get_session_metadata_public()
            .get_all_participant_ids()
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

    /// Get user batch nonce data (batch-only mode)
    pub fn get_user_batch_nonce_data(&self, user_id: &UserId) -> Option<BTreeMap<Uuid, NonceData>> {
        self.musig_processor.get_user_batch_nonce_data(user_id)
    }

    pub fn can_aggregate_nonces(&self) -> bool {
        // All signing is now batch mode - check if all batch nonces are collected
        let result = self.musig_processor.all_batch_nonces_complete();
        tracing::info!(
            "Batch nonce aggregation check for session {}: {}",
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

        // All signing is batch mode - finalize batch nonce rounds
        for participant in &participants_with_sessions {
            if let Err(e) = value
                .musig_processor
                .finalize_batch_nonce_rounds(participant)
            {
                return Err(EnclaveError::Session(SessionError::MusigInitialization(
                    format!(
                        "Failed to finalize batch nonce rounds for participant {}: {}",
                        participant, e
                    ),
                )));
            }
        }

        info!(
            "Finalized batch nonce rounds for {} participants in session {}",
            participants_with_sessions.len(),
            value.session_id,
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

            // All nonces now come as batch nonces
            match nonce_data {
                NonceData::Regular(_nonce) => {
                    // For backwards compatibility, wrap single nonce as batch
                    // This shouldn't happen in batch-only mode but handle gracefully
                    return Err(EnclaveError::Nonce(NonceError::GenerationFailed {
                        user_id: user_id.clone(),
                        error: "Expected batch nonces, got regular nonce. Use batch mode."
                            .to_string(),
                    }));
                }
                NonceData::Adaptor(_adaptor_nonces) => {
                    // For backwards compatibility
                    return Err(EnclaveError::Nonce(NonceError::GenerationFailed {
                        user_id: user_id.clone(),
                        error: "Expected batch nonces, got adaptor nonces. Use batch mode."
                            .to_string(),
                    }));
                }
                NonceData::Batch(batch_nonces) => {
                    // Convert Box<NonceData> to NonceData for store_batch_nonces
                    let batch_nonces_unboxed: BTreeMap<Uuid, NonceData> =
                        batch_nonces.into_iter().map(|(k, v)| (k, *v)).collect();

                    // Store batch nonces - adds to batch_first_rounds/batch_adaptor_first_rounds
                    self.musig_processor
                        .store_batch_nonces(user_id, batch_nonces_unboxed)
                        .map_err(|e| {
                            EnclaveError::Nonce(NonceError::AddFailed {
                                user_id: user_id.clone(),
                                error: format!("Failed to store batch nonces: {}", e),
                            })
                        })?;

                    info!(
                        "Stored batch nonces for user {} in signing session {}",
                        user_id, self.session_id
                    );
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
            let batch_item_count = self
                .musig_processor
                .get_session_metadata_public()
                .batch_items
                .len();
            let expected_count = self.get_expected_participant_count().unwrap_or(0);
            info!(
                "Signing session {} still collecting nonces: batch_items={}, expected_participants={}",
                self.session_id, batch_item_count, expected_count
            );
            Ok(SigningStatus::CollectingNonces(self))
        }
    }
}
