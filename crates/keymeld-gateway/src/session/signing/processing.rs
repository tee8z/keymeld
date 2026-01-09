use crate::{
    enclave::{manager::SigningSessionInitParams, EnclaveManager},
    session::signing::{
        SigningCollectingParticipants, SigningCompleted, SigningDistributingNonces,
        SigningFinalizingSignature, SigningInitializingSession, SigningSessionStatus,
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
            SigningSessionStatus::InitializingSession(state) => {
                state.process(enclave_manager).await
            }
            SigningSessionStatus::DistributingNonces(state) => state.process(enclave_manager).await,
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
        // Ensure session assignment exists (copy from keygen) so approval handler can work.
        // This is idempotent - if already exists, it just returns the existing one.
        let session_assignment = enclave_manager
            .get_session_assignment(&self.signing_session_id)
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to check session assignment: {e}"))
            })?;

        if session_assignment.is_none() {
            // Copy the session assignment from keygen to signing
            enclave_manager
                .copy_session_assignment_for_signing(
                    &self.keygen_session_id,
                    self.signing_session_id.clone(),
                )
                .map_err(|e| {
                    KeyMeldError::EnclaveError(format!(
                        "Failed to copy session assignment for signing: {e}"
                    ))
                })?;
        }

        let expected_count = self.expected_participants.len();
        let registered_count = self.registered_participants.len();

        tracing::debug!(
            "Signing session {} participant collection: {}/{} registered",
            self.signing_session_id,
            registered_count,
            expected_count
        );

        if registered_count < expected_count {
            let missing_participants: Vec<_> = self
                .expected_participants
                .iter()
                .filter(|p| !self.registered_participants.contains_key(p))
                .collect();

            tracing::debug!(
                "Signing session {} still collecting participants: {}/{} - missing: {:?}",
                self.signing_session_id,
                registered_count,
                expected_count,
                missing_participants
            );
            return Ok(SigningSessionStatus::CollectingParticipants(self));
        }

        if !self.participants_requiring_approval.is_empty() {
            let all_approved = self
                .participants_requiring_approval
                .iter()
                .all(|user_id| self.approved_participants.contains(user_id));

            if !all_approved {
                tracing::debug!(
                    "Signing session {} waiting for approvals: {}/{} approved",
                    self.signing_session_id,
                    self.approved_participants.len(),
                    self.participants_requiring_approval.len()
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

        // Get encrypted aggregate public key (gateway doesn't decrypt)
        let encrypted_aggregate_public_key = enclave_manager
            .get_aggregate_public_key(&self.keygen_session_id)
            .await?;

        info!(
            "All participants registered and approved for signing session {}, transitioning to InitializingSession",
            self.signing_session_id
        );

        Ok(SigningSessionStatus::InitializingSession(
            SigningInitializingSession::from_collecting_with_aggregate_key(
                self,
                encrypted_aggregate_public_key,
            ),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningInitializingSession {
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
            "Session {} has all participants registered, proceeding to session initialization",
            self.signing_session_id
        );

        // Validate an aggregate public key exsits from the coordinator enclave
        enclave_manager
            .get_aggregate_public_key(&self.keygen_session_id)
            .await?;

        info!(
            "Session {} retrieved encrypted aggregate public key from enclave",
            self.signing_session_id
        );

        // Step 1: Initialize signing session and collect nonces
        let init_params = SigningSessionInitParams {
            keygen_session_id: self.keygen_session_id.clone(),
            signing_session_id: self.signing_session_id.clone(),
            batch_items: self.batch_items.clone(),
            participants: self.registered_participants.clone(),
            coordinator_encrypted_private_key: self.coordinator_encrypted_private_key.clone(),
            encrypted_session_secret: self.encrypted_session_secret.clone(),
            encrypted_taproot_tweak: self.encrypted_taproot_tweak.clone(),
        };

        let collected_nonces = enclave_manager
            .orchestrate_init_signing_session(init_params)
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!(
                    "Failed to initialize signing session and collect nonces: {e}"
                ))
            })?;

        info!(
            "Step 1 complete: Collected {} nonces for session {}",
            collected_nonces.len(),
            self.signing_session_id
        );

        Ok(SigningSessionStatus::DistributingNonces(
            SigningDistributingNonces::new_with_nonces(self, collected_nonces),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningDistributingNonces {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Distributing {} nonces for signing session {} to {} participants",
            self.collected_nonces.len(),
            self.signing_session_id,
            self.registered_participants.len()
        );

        // Step 2: Distribute nonces (auto-generates partial signatures)
        let collected_partial_signatures = enclave_manager
            .orchestrate_distribute_nonces(
                &self.signing_session_id,
                &self.registered_participants,
                self.collected_nonces.clone(),
            )
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!(
                    "Failed to distribute nonces and collect partial signatures: {e}"
                ))
            })?;

        info!(
            "Step 2 complete: Collected {} partial signatures for signing session {}",
            collected_partial_signatures.len(),
            self.signing_session_id
        );

        Ok(SigningSessionStatus::FinalizingSignature(
            SigningFinalizingSignature::new_with_partial_signatures(
                self,
                collected_partial_signatures,
            ),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<SigningSessionStatus> for SigningFinalizingSignature {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<SigningSessionStatus, KeyMeldError> {
        info!(
            "Finalizing signature for signing session {} with {} partial signatures",
            self.signing_session_id,
            self.collected_partial_signatures.len()
        );

        // Step 3: Finalize signature
        // Returns batch results from the enclave
        let batch_results = enclave_manager
            .orchestrate_finalize_signature(
                &self.keygen_session_id,
                &self.signing_session_id,
                &self.registered_participants,
                self.collected_partial_signatures.clone(),
            )
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!(
                    "Failed to finalize signature for signing session {}: {}",
                    self.signing_session_id, e
                ))
            })?;

        info!(
            "Step 3 complete: Finalized {} batch results for signing session {}",
            batch_results.len(),
            self.signing_session_id,
        );

        Ok(SigningSessionStatus::Completed(
            SigningCompleted::from_finalizing_with_batch_results(self, batch_results),
        ))
    }
}
