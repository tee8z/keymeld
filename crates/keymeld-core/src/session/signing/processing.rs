use crate::{
    enclave::{manager::SigningSessionInitParams, EnclaveManager},
    session::{
        signing::{
            SigningAggregatingNonces, SigningCollectingNonces, SigningCollectingPartialSignatures,
            SigningCollectingParticipants, SigningCompleted, SigningFinalizingSignature,
            SigningGeneratingNonces, SigningGeneratingPartialSignatures, SigningSessionFull,
            SigningSessionStatus,
        },
        types::AggregatePublicKey,
    },
    Advanceable, KeyMeldError,
};
use tracing::{debug, info};

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
            SigningSessionStatus::AggregatingNonces(state) => state.process(enclave_manager).await,
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
        info!(
            "Processing SigningCollectingParticipants for session {}",
            self.signing_session_id
        );

        let expected_count = self.expected_participants.len();
        let registered_count = self.registered_participants.len();

        if registered_count < expected_count {
            info!(
                "Signing session {} still collecting participants: {}/{}",
                self.signing_session_id, registered_count, expected_count
            );
            return Ok(SigningSessionStatus::CollectingParticipants(self));
        }

        // Check if all required participants have approved before transitioning to SessionFull
        if !self.participants_requiring_approval.is_empty() {
            let mut all_approved = true;
            for required_participant in &self.participants_requiring_approval {
                if !self.approved_participants.contains(required_participant) {
                    all_approved = false;
                    break;
                }
            }

            if !all_approved {
                info!(
                    "Signing session {} waiting for approvals before transitioning to SessionFull. Required: {:?}, Approved: {:?}",
                    self.signing_session_id, self.participants_requiring_approval, self.approved_participants
                );
                return Ok(SigningSessionStatus::CollectingParticipants(self));
            }

            info!(
                "All required participants have approved signing session {}, ready to transition to SessionFull",
                self.signing_session_id
            );
        }

        info!(
            "All participants registered for signing session {}, transitioning to SessionFull",
            self.signing_session_id
        );

        // Check if any participants require signing approval
        let participants_requiring_approval = database
            .get_participants_requiring_approval(&self.keygen_session_id)
            .await
            .map_err(|e| {
                KeyMeldError::ValidationError(format!(
                    "Failed to get participants requiring approval: {}",
                    e
                ))
            })?;

        // If any participants require approval, check if all have approved
        if !participants_requiring_approval.is_empty() {
            let approved_participants = database
                .get_signing_session_approvals(&self.signing_session_id)
                .await
                .map_err(|e| {
                    KeyMeldError::ValidationError(format!(
                        "Failed to get signing session approvals: {}",
                        e
                    ))
                })?;

            // Check if all required participants have approved
            for required_participant in &participants_requiring_approval {
                if !approved_participants.contains(required_participant) {
                    debug!(
                        "Signing session {} waiting for approval from user {}. Required: {:?}, Approved: {:?}",
                        self.signing_session_id, required_participant, participants_requiring_approval, approved_participants
                    );
                    // Stay in CollectingParticipants state until all approvals received
                    return Ok(SigningSessionStatus::CollectingParticipants(self));
                }
            }

            info!(
                "All required participants have approved signing session {}, proceeding to SessionFull",
                self.signing_session_id
            );
        } else {
            info!(
                "No approval requirements for signing session {}, transitioning to SessionFull",
                self.signing_session_id
            );
        }

        // Copy exact session assignment from keygen session (same enclave assignments)
        enclave_manager.copy_session_assignment_for_signing(
            &self.keygen_session_id,
            self.signing_session_id.clone(),
        )?;

        info!(
            "Created session assignment for signing session {} inheriting from keygen session {}",
            self.signing_session_id, self.keygen_session_id
        );

        // Get the aggregate public key from the keygen session
        let aggregate_public_key_bytes = enclave_manager
            .get_aggregate_public_key(&self.keygen_session_id)
            .await?;

        let aggregate_public_key = AggregatePublicKey::new(
            aggregate_public_key_bytes,
            self.expected_participants.clone(),
            vec![],
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

        let (Some(coordinator_encrypted_private_key), Some(encrypted_session_secret)) = (
            self.coordinator_encrypted_private_key.clone(),
            self.encrypted_session_secret.clone(),
        ) else {
            return Err(KeyMeldError::EnclaveError(
                "Failed to orchestrate signing session missing session information".to_string(),
            ));
        };

        // Use the orchestration function to initialize the signing session
        let init_params = SigningSessionInitParams {
            keygen_session_id: self.keygen_session_id.clone(),
            signing_session_id: self.signing_session_id.clone(),
            encrypted_message: self.encrypted_message.clone(),
            participants: self.registered_participants.clone(),
            coordinator_encrypted_private_key: Some(coordinator_encrypted_private_key.clone()),
            encrypted_session_secret: Some(encrypted_session_secret.clone()),
            taproot_tweak: self.taproot_tweak.clone().unwrap_or_default(),
        };

        enclave_manager
            .orchestrate_signing_session_initialization(init_params)
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!(
                    "Failed to orchestrate signing session initialization: {}",
                    e
                ))
            })?;

        info!(
            "Session {} has all participants registered, proceeding to nonce generation",
            self.signing_session_id
        );

        // Get the real aggregate public key from the coordinator enclave
        let aggregate_public_key_bytes = enclave_manager
            .get_aggregate_public_key(&self.keygen_session_id)
            .await?;

        let aggregate_key = musig2::secp256k1::PublicKey::from_slice(&aggregate_public_key_bytes)
            .map_err(|e| {
            KeyMeldError::EnclaveError(format!("Invalid aggregate key from enclave: {}", e))
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

        // Generate nonces using the orchestration function
        let nonces = enclave_manager
            .orchestrate_nonce_generation(
                &self.keygen_session_id,
                &self.signing_session_id,
                &self.registered_participants,
            )
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to orchestrate nonce generation: {}", e))
            })?;

        // Store the generated nonces in participant data
        for (user_id, nonce) in nonces {
            if let Some(participant_data) = self.registered_participants.get_mut(&user_id) {
                participant_data.public_nonces = Some(nonce);
            }
        }

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

        // Validate that all participants have provided nonces
        for (user_id, participant) in &self.registered_participants {
            if participant.public_nonces.is_none() {
                return Err(KeyMeldError::ValidationError(format!(
                    "Participant {} has not provided nonce for signing session {}",
                    user_id, self.signing_session_id
                )));
            }
        }

        info!(
            "All nonces collected for signing session {}, proceeding to aggregation",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::AggregatingNonces(self.into()))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningAggregatingNonces {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Aggregating nonces for signing session {}",
            self.signing_session_id
        );

        // For now, we'll collect the nonces but the actual aggregation happens at the protocol level
        let mut all_nonces_collected = true;
        for participant in self.registered_participants.values() {
            if participant.public_nonces.is_none() {
                all_nonces_collected = false;
                break;
            }
        }

        if !all_nonces_collected {
            return Err(KeyMeldError::ValidationError(
                "Not all nonces have been generated yet".to_string(),
            ));
        }

        // Get the actual aggregate nonce from the enclave manager
        let agg_nonce = enclave_manager
            .get_aggregate_nonce(&self.keygen_session_id, &self.signing_session_id)
            .await?;
        let aggregate_nonce = agg_nonce.serialize().to_vec();

        info!(
            "Aggregated nonces for signing session {}, proceeding to partial signature generation",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::GeneratingPartialSignatures(
            SigningGeneratingPartialSignatures::from_aggregating_with_nonce(self, aggregate_nonce),
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

        // Generate partial signatures using the orchestration function
        let aggregate_nonce = musig2::PubNonce::from_bytes(&self.aggregate_nonce)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid aggregate nonce: {}", e)))?;

        let partial_signatures = enclave_manager
            .orchestrate_partial_signatures(
                &self.keygen_session_id,
                &self.signing_session_id,
                &self.registered_participants,
                &aggregate_nonce,
            )
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!(
                    "Failed to orchestrate partial signatures: {}",
                    e
                ))
            })?;

        // Store the generated partial signatures
        for (user_id, partial_sig) in partial_signatures {
            if let Some(participant_data) = self.registered_participants.get_mut(&user_id) {
                participant_data.partial_signature = Some(partial_sig);
            }
        }

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

        // Validate that all participants have provided partial signatures
        for (user_id, participant) in &self.registered_participants {
            if participant.partial_signature.is_none() {
                return Err(KeyMeldError::ValidationError(format!(
                    "Participant {} has not provided partial signature for signing session {}",
                    user_id, self.signing_session_id
                )));
            }
        }

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

        // Collect all partial signatures
        let mut partial_signatures = std::collections::BTreeMap::new();
        for (user_id, participant) in &self.registered_participants {
            if let Some(partial_sig) = &participant.partial_signature {
                partial_signatures.insert(user_id.clone(), *partial_sig);
            }
        }

        // Get the encrypted signature from the enclave (already encrypted by the enclave)
        let encrypted_signature_bytes = enclave_manager
            .finalize_signature(&self.keygen_session_id, &self.signing_session_id)
            .await?;

        // Encrypted signature is already base64-encoded by the enclave
        let final_signature_encrypted =
            String::from_utf8(encrypted_signature_bytes).map_err(|e| {
                KeyMeldError::EnclaveError(format!("Invalid UTF-8 in encrypted signature: {}", e))
            })?;

        info!(
            "Signature finalization completed for session {} with {} partial signatures",
            self.signing_session_id,
            partial_signatures.len()
        );

        info!(
            "Signature finalized and encrypted for signing session {}, encrypted signature length: {} bytes",
            self.signing_session_id,
            final_signature_encrypted.len()
        );

        Ok(SigningSessionStatus::Completed(
            SigningCompleted::from_finalizing_with_signature(self, final_signature_encrypted),
        ))
    }
}
