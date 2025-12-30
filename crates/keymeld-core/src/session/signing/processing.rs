use crate::{
    enclave::{manager::SigningSessionInitParams, EnclaveManager},
    session::signing::{
        SigningCollectingNonces, SigningCollectingPartialSignatures, SigningCollectingParticipants,
        SigningCompleted, SigningFinalizingSignature, SigningGeneratingNonces,
        SigningGeneratingPartialSignatures, SigningSessionFull, SigningSessionStatus,
    },
    Advanceable, KeyMeldError,
};
use tracing::info;

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningSessionStatus {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        match self {
            SigningSessionStatus::CollectingParticipants(state) => {
                state.process(enclave_manager).await
            }
            SigningSessionStatus::SessionFull(state) => state.process(enclave_manager).await,
            SigningSessionStatus::GeneratingNonces(state) => state.process(enclave_manager).await,
            SigningSessionStatus::CollectingNonces(state) => state.process(enclave_manager).await,

            SigningSessionStatus::GeneratingPartialSignatures(state) => {
                state.process(enclave_manager).await
            }
            SigningSessionStatus::CollectingPartialSignatures(state) => {
                state.process(enclave_manager).await
            }
            SigningSessionStatus::FinalizingSignature(state) => {
                state.process(enclave_manager).await
            }
            SigningSessionStatus::Completed(_) => Ok(self),
            SigningSessionStatus::Failed(_) => Ok(self),
        }
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningCollectingParticipants {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        // Check if signing session has been initialized in enclaves
        let session_assignment = enclave_manager
            .get_session_assignment(&self.signing_session_id)
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to check session assignment: {e}"))
            })?;

        if session_assignment.is_none() {
            info!(
                "Signing session {} not yet initialized in enclaves, initializing now",
                self.signing_session_id
            );

            let init_params = SigningSessionInitParams {
                keygen_session_id: self.keygen_session_id.clone(),
                signing_session_id: self.signing_session_id.clone(),
                encrypted_message: self.encrypted_message.clone(),
                participants: self.registered_participants.clone(),
                coordinator_encrypted_private_key: self.coordinator_encrypted_private_key.clone(),
                encrypted_session_secret: self.encrypted_session_secret.clone(),
                taproot_tweak: self.taproot_tweak.clone(),
                encrypted_adaptor_configs: self.encrypted_adaptor_configs.clone(),
            };

            enclave_manager
                .orchestrate_signing_session_initialization(init_params)
                .await
                .map_err(|e| {
                    KeyMeldError::EnclaveError(format!(
                        "Failed to initialize signing session in enclaves: {e}"
                    ))
                })?;

            info!(
                "Successfully initialized signing session {} in enclaves",
                self.signing_session_id
            );
        } else {
            info!(
                "Signing session {} already initialized in enclaves",
                self.signing_session_id
            );
        }

        let expected_count = self.expected_participants.len();
        let registered_count = self.registered_participants.len();

        if registered_count < expected_count {
            info!(
                "Signing session {} still collecting participants: {}/{} - Expected: {:?}, Registered: {:?}",
                self.signing_session_id,
                registered_count,
                expected_count,
                self.expected_participants,
                self.registered_participants.keys().collect::<Vec<_>>()
            );
            return Ok(SigningSessionStatus::CollectingParticipants(self));
        }

        if !self.participants_requiring_approval.is_empty() {
            let all_approved = self
                .participants_requiring_approval
                .iter()
                .all(|user_id| self.approved_participants.contains(user_id));

            if !all_approved {
                info!(
                    "Signing session {} waiting for approvals. Required: {:?}, Approved: {:?}",
                    self.signing_session_id,
                    self.participants_requiring_approval,
                    self.approved_participants
                );
                return Ok(SigningSessionStatus::CollectingParticipants(self));
            }

            info!(
                "All required participants have approved signing session {}",
                self.signing_session_id
            );
        }

        info!(
            "All participants registered for signing session {}, checking initialization status",
            self.signing_session_id
        );

        let aggregate_public_key_bytes = enclave_manager
            .get_aggregate_public_key(&self.keygen_session_id)
            .await?;

        let aggregate_public_key = aggregate_public_key_bytes;

        info!(
            "All participants registered and approved for signing session {}, transitioning to SessionFull",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::SessionFull(
            SigningSessionFull::from_collecting_with_aggregate_key(self, aggregate_public_key),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningSessionFull {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Initializing MuSig2 session {} with {} participants",
            self.signing_session_id,
            self.registered_participants.len()
        );

        info!(
            "Session {} has all participants registered and is already initialized, proceeding to nonce generation",
            self.signing_session_id
        );

        // Get the real aggregate public key from the coordinator enclave
        let aggregate_public_key_bytes = enclave_manager
            .get_aggregate_public_key(&self.keygen_session_id)
            .await?;

        let aggregate_key = musig2::secp256k1::PublicKey::from_slice(&aggregate_public_key_bytes)
            .map_err(|e| {
            KeyMeldError::EnclaveError(format!("Invalid aggregate key from enclave: {e}"))
        })?;

        info!(
            "Session {} computed aggregate public key: {}",
            self.signing_session_id,
            hex::encode(aggregate_key.serialize())
        );

        Ok(SigningSessionStatus::GeneratingNonces(self.into()))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningGeneratingNonces {
    async fn process(
        mut self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Generating nonces for signing session {} with {} participants",
            self.signing_session_id,
            self.registered_participants.len()
        );

        enclave_manager
            .orchestrate_nonce_generation(
                &self.keygen_session_id,
                &self.signing_session_id,
                &self.registered_participants,
            )
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to orchestrate nonce generation: {e}"))
            })?;
        info!(
            "Generated all nonces for signing session {}, proceeding to collection",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::CollectingNonces(self.into()))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningCollectingNonces {
    async fn process(
        self,
        _enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Collecting and validating nonces for signing session {}",
            self.signing_session_id
        );

        // Nonce validation will happen implicitly during aggregation
        info!(
            "All nonces collected for signing session {}, proceeding to aggregation",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::GeneratingPartialSignatures(
            self.into(),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningGeneratingPartialSignatures {
    async fn process(
        mut self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Generating partial signatures for signing session {} with {} participants",
            self.signing_session_id,
            self.registered_participants.len()
        );

        enclave_manager
            .orchestrate_partial_signatures(
                &self.keygen_session_id,
                &self.signing_session_id,
                &self.registered_participants,
            )
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to orchestrate partial signatures: {e}"))
            })?;

        Ok(SigningSessionStatus::CollectingPartialSignatures(
            self.into(),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningCollectingPartialSignatures {
    async fn process(
        self,
        _enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Collecting and validating partial signatures for signing session {}",
            self.signing_session_id
        );

        // If signatures are invalid, finalization will fail
        info!(
            "All partial signatures collected for signing session {}, proceeding to finalization",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::FinalizingSignature(self.into()))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningFinalizingSignature {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Finalizing signature for signing session {}",
            self.signing_session_id
        );

        let (final_signature_bytes, encrypted_adaptor_signatures) = enclave_manager
            .finalize_signature(&self.keygen_session_id, &self.signing_session_id)
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!(
                    "Failed to finalize signature for signing session {}: {}",
                    self.signing_session_id, e
                ))
            })?;

        // Convert signature bytes to hex string for storage
        let final_signature = hex::encode(final_signature_bytes);

        info!(
            "Successfully finalized signature for signing session {}: {} bytes",
            self.signing_session_id,
            final_signature.len() / 2 // hex string length / 2 = byte count
        );

        // Handle adaptor signatures if present
        if let Some(adaptor_bytes) = encrypted_adaptor_signatures {
            let encrypted_adaptor_signatures_hex = hex::encode(adaptor_bytes);
            info!(
                "Successfully received encrypted adaptor signatures for signing session {}: {} bytes",
                self.signing_session_id,
                encrypted_adaptor_signatures_hex.len() / 2
            );

            Ok(SigningSessionStatus::Completed(
                SigningCompleted::from_finalizing_with_signature_and_adaptors(
                    self,
                    final_signature,
                    encrypted_adaptor_signatures_hex,
                ),
            ))
        } else {
            Ok(SigningSessionStatus::Completed(
                SigningCompleted::from_finalizing_with_signature(self, final_signature),
            ))
        }
    }
}
