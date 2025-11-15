use crate::{
    api::TaprootTweak,
    identifiers::{EnclaveId, SessionId, UserId},
    session::{types::ParticipantData, validation},
    AggregatePublicKey, KeyMeldError,
};
use musig2::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;

pub mod processing;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenCollectingParticipants {
    pub keygen_session_id: SessionId,
    #[schema(value_type = String)]
    pub coordinator_pubkey: PublicKey,
    pub coordinator_encrypted_private_key: String,
    pub encrypted_session_secret: String,
    pub coordinator_enclave_id: EnclaveId,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub created_at: u64,
    pub expires_at: u64,
    pub required_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak_config: TaprootTweak,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenCompleted {
    pub keygen_session_id: SessionId,
    #[schema(value_type = String)]
    pub coordinator_pubkey: PublicKey,
    pub coordinator_encrypted_private_key: String,
    pub encrypted_session_secret: String,
    pub coordinator_enclave_id: EnclaveId,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: AggregatePublicKey,
    pub created_at: u64,
    pub completed_at: u64,
    pub completed_with_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak_config: TaprootTweak,
}

impl KeygenCompleted {
    pub fn from_collecting_with_aggregate_key(
        collecting: KeygenCollectingParticipants,
        aggregate_public_key: AggregatePublicKey,
    ) -> Self {
        let completed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            keygen_session_id: collecting.keygen_session_id,
            coordinator_pubkey: collecting.coordinator_pubkey,
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            encrypted_session_secret: collecting.encrypted_session_secret,
            coordinator_enclave_id: collecting.coordinator_enclave_id,
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key,
            created_at: collecting.created_at,
            completed_at,
            completed_with_epochs: collecting.required_enclave_epochs,
            taproot_tweak_config: collecting.taproot_tweak_config,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenFailed {
    pub keygen_session_id: SessionId,
    #[schema(value_type = String)]
    pub coordinator_pubkey: Option<PublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub coordinator_enclave_id: Option<EnclaveId>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub created_at: u64,
    pub failed_at: u64,
    pub error: String,
    pub failed_due_to_enclave_restart: Option<EnclaveId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum KeygenSessionStatus {
    CollectingParticipants(KeygenCollectingParticipants),
    Completed(KeygenCompleted),
    Failed(KeygenFailed),
}

impl KeygenSessionStatus {
    pub fn extract_status_info(
        &self,
    ) -> (KeygenStatusKind, usize, Option<AggregatePublicKey>, u64) {
        match self {
            KeygenSessionStatus::CollectingParticipants(ref status) => (
                KeygenStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            KeygenSessionStatus::Completed(ref status) => (
                KeygenStatusKind::from(self),
                status.expected_participants.len(),
                Some(status.aggregate_public_key.clone()),
                0u64,
            ),
            KeygenSessionStatus::Failed(_) => (KeygenStatusKind::from(self), 0, None, 0u64),
        }
    }

    pub fn kind(&self) -> KeygenStatusKind {
        self.into()
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            KeygenSessionStatus::Completed(_) | KeygenSessionStatus::Failed(_)
        )
    }

    pub fn coordinator_encrypted_private_key(&self) -> Option<&str> {
        match self {
            KeygenSessionStatus::CollectingParticipants(s) => {
                Some(s.coordinator_encrypted_private_key.as_str())
            }
            KeygenSessionStatus::Completed(s) => Some(s.coordinator_encrypted_private_key.as_str()),
            KeygenSessionStatus::Failed(s) => s.coordinator_encrypted_private_key.as_deref(),
        }
    }

    pub fn coordinator_enclave_id(&self) -> Option<EnclaveId> {
        match self {
            KeygenSessionStatus::CollectingParticipants(s) => Some(s.coordinator_enclave_id),
            KeygenSessionStatus::Completed(s) => Some(s.coordinator_enclave_id),
            KeygenSessionStatus::Failed(s) => s.coordinator_enclave_id,
        }
    }

    pub fn registered_participants(&self) -> Option<&BTreeMap<UserId, ParticipantData>> {
        match self {
            KeygenSessionStatus::CollectingParticipants(s) => Some(&s.registered_participants),
            KeygenSessionStatus::Completed(s) => Some(&s.registered_participants),
            KeygenSessionStatus::Failed(_) => None,
        }
    }

    pub fn expected_participants_count(&self) -> usize {
        match self {
            KeygenSessionStatus::CollectingParticipants(s) => s.expected_participants.len(),
            KeygenSessionStatus::Completed(s) => s.expected_participants.len(),
            KeygenSessionStatus::Failed(s) => s.expected_participants.len(),
        }
    }

    pub fn merge_fresh_participant_data(
        &mut self,
        fresh_participants: BTreeMap<UserId, ParticipantData>,
    ) {
        let participants = match self {
            KeygenSessionStatus::CollectingParticipants(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            KeygenSessionStatus::Completed(ref mut completed) => {
                &mut completed.registered_participants
            }
            _ => return, // No participant data to merge for Failed state
        };

        for (user_id, fresh_participant) in fresh_participants {
            participants.insert(user_id, fresh_participant);
        }
    }

    pub fn validate_enclave_epochs(
        &self,
        enclave_manager: &crate::enclave::EnclaveManager,
    ) -> Result<(), KeyMeldError> {
        let required_epochs = match self {
            KeygenSessionStatus::CollectingParticipants(ref collecting) => {
                &collecting.required_enclave_epochs
            }
            KeygenSessionStatus::Completed(ref completed) => &completed.completed_with_epochs,
            KeygenSessionStatus::Failed(_) => return Ok(()),
        };

        validation::validate_enclave_epochs(required_epochs, enclave_manager)
    }

    pub fn merge_participants(
        &mut self,
        fresh_participants: BTreeMap<UserId, ParticipantData>,
    ) -> Result<(), KeyMeldError> {
        let participants = match self {
            KeygenSessionStatus::CollectingParticipants(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            KeygenSessionStatus::Completed(ref mut completed) => {
                &mut completed.registered_participants
            }
            _ => return Ok(()), // No participant data to merge for Failed state
        };

        validation::merge_participants(participants, fresh_participants)
    }

    pub fn is_expired(&self) -> bool {
        let expires_at = match self {
            KeygenSessionStatus::CollectingParticipants(collecting) => collecting.expires_at,
            KeygenSessionStatus::Completed(_) => return false, // Completed sessions don't expire
            KeygenSessionStatus::Failed(_) => return false,    // Failed sessions don't expire
        };

        validation::is_expired(expires_at)
    }

    pub fn expires_at(&self) -> Option<u64> {
        match self {
            KeygenSessionStatus::CollectingParticipants(collecting) => Some(collecting.expires_at),
            KeygenSessionStatus::Completed(_) => None,
            KeygenSessionStatus::Failed(_) => None,
        }
    }
}

impl AsRef<str> for KeygenSessionStatus {
    fn as_ref(&self) -> &str {
        match self {
            KeygenSessionStatus::CollectingParticipants(_) => "collecting_participants",
            KeygenSessionStatus::Completed(_) => "completed",
            KeygenSessionStatus::Failed(_) => "failed",
        }
    }
}

impl fmt::Display for KeygenSessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeygenStatusKind {
    CollectingParticipants,
    Completed,
    Failed,
}

impl From<&KeygenSessionStatus> for KeygenStatusKind {
    fn from(status: &KeygenSessionStatus) -> Self {
        match status {
            KeygenSessionStatus::CollectingParticipants(_) => {
                KeygenStatusKind::CollectingParticipants
            }
            KeygenSessionStatus::Completed(_) => KeygenStatusKind::Completed,
            KeygenSessionStatus::Failed(_) => KeygenStatusKind::Failed,
        }
    }
}

impl AsRef<str> for KeygenStatusKind {
    fn as_ref(&self) -> &str {
        match self {
            KeygenStatusKind::CollectingParticipants => "collecting_participants",
            KeygenStatusKind::Completed => "completed",
            KeygenStatusKind::Failed => "failed",
        }
    }
}

impl fmt::Display for KeygenStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}
