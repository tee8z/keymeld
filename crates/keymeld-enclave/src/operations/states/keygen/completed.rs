use keymeld_core::{
    enclave::{EnclaveCommand, EnclaveError},
    SessionId, SessionSecret, UserId,
};
use std::time::SystemTime;
use tracing::debug;

use crate::operations::{
    context::EnclaveContext,
    states::{signing::CoordinatorData, KeygenStatus, OperatorStatus},
    DistributingSecrets, EnclaveAdvanceable,
};
use keymeld_core::enclave::protocol::EncryptedParticipantPublicKey;

#[derive(Debug, Clone)]
pub struct Completed {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub participant_count: u32,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub completed_at: SystemTime,
    pub encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    pub musig_processor: std::sync::Arc<keymeld_core::musig::MusigProcessor>,
}

impl Completed {
    /// Get participant count from MuSig processor metadata
    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.participant_public_keys.len())
            .unwrap_or(0)
    }

    /// Get expected participant count from MuSig processor metadata
    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .and_then(|metadata| metadata.expected_participant_count)
    }

    /// Get participants list from MuSig processor metadata
    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.expected_participants.clone())
            .unwrap_or_default()
    }
}

impl From<DistributingSecrets> for Completed {
    fn from(distributing: DistributingSecrets) -> Self {
        let expected_participant_count = distributing.get_expected_participant_count().unwrap_or(0);
        Self {
            session_id: distributing.session_id,
            session_secret: distributing.session_secret,
            participant_count: expected_participant_count as u32,
            created_at: distributing.created_at,
            completed_at: SystemTime::now(),
            coordinator_data: distributing.coordinator_data,
            encrypted_public_keys_for_response: distributing.encrypted_public_keys_for_response,
            musig_processor: distributing.musig_processor,
        }
    }
}

impl EnclaveAdvanceable<OperatorStatus> for Completed {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        match cmd {
            EnclaveCommand::InitKeygenSession(_) => {
                debug!(
                    "Received InitKeygenSession command for already completed session {}, ignoring gracefully",
                    self.session_id
                );
                Ok(OperatorStatus::Keygen(KeygenStatus::Completed(self)))
            }
            EnclaveCommand::AddParticipant(add_cmd) => {
                debug!(
                    "Received AddParticipant command for participant {} in completed session {}, ignoring gracefully",
                    add_cmd.user_id, self.session_id
                );
                Ok(OperatorStatus::Keygen(KeygenStatus::Completed(self)))
            }
            EnclaveCommand::DistributeParticipantPublicKey(distribute_cmd) => {
                debug!(
                    "Received DistributeParticipantPublicKey command for participant {} in completed session {}, ignoring gracefully",
                    distribute_cmd.user_id, self.session_id
                );
                Ok(OperatorStatus::Keygen(KeygenStatus::Completed(self)))
            }
            EnclaveCommand::DistributeSessionSecret(_) => {
                debug!(
                    "Received DistributeSessionSecret command for completed session {}, ignoring gracefully",
                    self.session_id
                );
                Ok(OperatorStatus::Keygen(KeygenStatus::Completed(self)))
            }
            _ => {
                debug!(
                    "Received {:?} command for completed keygen session {}, ignoring gracefully",
                    cmd, self.session_id
                );
                Ok(OperatorStatus::Keygen(KeygenStatus::Completed(self)))
            }
        }
    }
}
