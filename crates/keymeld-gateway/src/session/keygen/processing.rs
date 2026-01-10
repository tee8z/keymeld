use crate::{
    enclave::EnclaveManager,
    session::{
        keygen::{
            KeygenCollectingParticipants, KeygenCompleted, KeygenReserved, KeygenSessionStatus,
        },
        validation,
    },
    Advanceable, KeyMeldError,
};
use tracing::{error, info};

#[async_trait::async_trait]
impl Advanceable<KeygenSessionStatus> for KeygenSessionStatus {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<KeygenSessionStatus, KeyMeldError> {
        match self {
            KeygenSessionStatus::Reserved(state) => state.process(enclave_manager).await,
            KeygenSessionStatus::CollectingParticipants(state) => {
                state.process(enclave_manager).await
            }
            KeygenSessionStatus::Completed(_) => Ok(self),
            KeygenSessionStatus::Failed(_) => Ok(self),
        }
    }
}

#[async_trait::async_trait]
impl Advanceable<KeygenSessionStatus> for KeygenCollectingParticipants {
    async fn process(
        self,
        enclave_manager: &EnclaveManager,
    ) -> Result<KeygenSessionStatus, KeyMeldError> {
        info!(
            "Processing keygen session {} from CollectingParticipants",
            self.keygen_session_id
        );

        let expected_count = self.expected_participants.len();
        let registered_count = self.registered_participants.len();

        tracing::debug!(
            "Keygen session {} participant counts - registered: {}, expected: {}",
            self.keygen_session_id,
            registered_count,
            expected_count
        );

        if registered_count < expected_count {
            info!(
                "Keygen session {} still collecting participants: {}/{} - No delay (simplified for debugging)",
                self.keygen_session_id, registered_count, expected_count
            );
            // Removed sleep delay for simplified debugging
            return Ok(KeygenSessionStatus::CollectingParticipants(self));
        }

        info!(
            "All participants registered for keygen session {}, proceeding to completion",
            self.keygen_session_id
        );

        validation::validate_all_participants_epochs(
            &self.registered_participants,
            enclave_manager,
        )?;

        let user_ids: Vec<_> = self.expected_participants.to_vec();

        // Find the coordinator user_id from registered participants
        // The coordinator is the one assigned to coordinator_enclave_id
        let coordinator_user_id = self.registered_participants.keys().next().ok_or_else(|| {
            KeyMeldError::EnclaveError(
                "No registered participants found to determine coordinator".to_string(),
            )
        })?;

        enclave_manager
            .create_session_assignment_with_coordinator(
                self.keygen_session_id.clone(),
                &user_ids,
                coordinator_user_id,
                self.coordinator_enclave_id,
            )
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to create session assignment: {e}"))
            })?;

        info!(
            "Created session assignment for keygen session {}",
            self.keygen_session_id
        );

        let start_time = std::time::Instant::now();
        let keygen_result = enclave_manager
            .orchestrate_keygen_session_initialization(
                &self.keygen_session_id,
                &self.coordinator_enclave_id,
                &self.coordinator_encrypted_private_key,
                &self.encrypted_session_secret,
                &self.registered_participants,
                &self.encrypted_taproot_tweak,
                &self.subset_definitions,
            )
            .await
            .map_err(|e| {
                let elapsed = start_time.elapsed();
                error!(
                    "Failed to initialize keygen session {} after {:?}: {}",
                    self.keygen_session_id, elapsed, e
                );
                KeyMeldError::EnclaveError(format!("Failed to initialize keygen session: {e}"))
            })?;

        info!(
            "Session {} computed aggregate public key: {}",
            self.keygen_session_id,
            hex::encode(&keygen_result.aggregate_public_key)
        );

        Ok(KeygenSessionStatus::Completed(
            KeygenCompleted::from_collecting_with_aggregate_key(
                self,
                keygen_result.aggregate_public_key,
                keygen_result.participant_encrypted_public_keys,
                keygen_result.enclave_encrypted_session_secrets,
                keygen_result.encrypted_subset_aggregates,
            ),
        ))
    }
}

#[async_trait::async_trait]
impl Advanceable<KeygenSessionStatus> for KeygenReserved {
    async fn process(
        self,
        _enclave_manager: &EnclaveManager,
    ) -> Result<KeygenSessionStatus, KeyMeldError> {
        info!(
            "Processing keygen session {} from Reserved state - waiting for initialization",
            self.keygen_session_id
        );

        // Reserved sessions don't advance automatically - they wait for the initialize endpoint
        Ok(KeygenSessionStatus::Reserved(self))
    }
}
