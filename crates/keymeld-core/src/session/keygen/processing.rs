use crate::{
    enclave::EnclaveManager,
    session::{
        keygen::{KeygenCollectingParticipants, KeygenCompleted, KeygenSessionStatus},
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

        if registered_count < expected_count {
            info!(
                "Keygen session {} still collecting participants: {}/{}",
                self.keygen_session_id, registered_count, expected_count
            );
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
        let _assignment = enclave_manager
            .create_session_assignment_with_coordinator(
                self.keygen_session_id.clone(),
                &user_ids,
                self.coordinator_enclave_id,
            )
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to create session assignment: {}", e))
            })?;

        info!(
            "Created session assignment for keygen session {}",
            self.keygen_session_id
        );

        let start_time = std::time::Instant::now();
        let aggregate_public_key = enclave_manager
            .orchestrate_keygen_session_initialization(
                &self.keygen_session_id,
                &self.coordinator_enclave_id,
                &self.coordinator_encrypted_private_key,
                &self.encrypted_session_secret,
                &self.registered_participants,
                &self.taproot_tweak_config,
            )
            .await
            .map_err(|e| {
                let elapsed = start_time.elapsed();
                error!(
                    "Failed to initialize keygen session {} after {:?}: {}",
                    self.keygen_session_id, elapsed, e
                );
                KeyMeldError::EnclaveError(format!("Failed to initialize keygen session: {}", e))
            })?;

        info!(
            "Session {} computed aggregate public key with {} bytes",
            self.keygen_session_id,
            aggregate_public_key.len()
        );

        Ok(KeygenSessionStatus::Completed(
            KeygenCompleted::from_collecting_with_aggregate_key(self, aggregate_public_key),
        ))
    }
}
