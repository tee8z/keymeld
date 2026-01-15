use crate::{
    identifiers::{EnclaveId, SessionId, UserId},
    session::{types::ParticipantData, validation},
    AggregatePublicKey, KeyMeldError,
};
use keymeld_core::protocol::{
    EncryptedParticipantPublicKey, EncryptedSessionSecret, KeygenStatusKind, SubsetDefinition,
};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use utoipa::ToSchema;
use uuid::Uuid;

pub mod processing;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenReserved {
    pub keygen_session_id: SessionId,
    pub coordinator_user_id: UserId,
    pub coordinator_enclave_id: EnclaveId,
    pub expected_participants: Vec<UserId>,
    pub created_at: u64,
    pub expires_at: u64,
    pub max_signing_sessions: Option<u32>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    /// Subset definitions for computing additional aggregate keys
    #[serde(default)]
    pub subset_definitions: Vec<SubsetDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenCollectingParticipants {
    pub keygen_session_id: SessionId,
    #[schema(value_type = String)]
    pub coordinator_pubkey: PublicKey,
    pub coordinator_encrypted_private_key: String,
    pub session_public_key: Vec<u8>,
    pub encrypted_session_secret: String,
    pub coordinator_enclave_id: EnclaveId,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub created_at: u64,
    pub expires_at: u64,
    pub required_enclave_epochs: BTreeMap<EnclaveId, u64>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    /// Subset definitions for computing additional aggregate keys
    #[serde(default)]
    pub subset_definitions: Vec<SubsetDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenCompleted {
    pub keygen_session_id: SessionId,
    #[schema(value_type = String)]
    pub coordinator_pubkey: PublicKey,
    pub coordinator_encrypted_private_key: String,
    pub session_public_key: Vec<u8>,
    pub encrypted_session_secret: String,
    pub coordinator_enclave_id: EnclaveId,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: AggregatePublicKey,
    pub created_at: u64,
    pub completed_at: u64,
    pub completed_with_epochs: BTreeMap<EnclaveId, u64>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    /// Encrypted public keys for all participants, used for session restoration.
    /// Each entry contains (user_id, vec of encrypted keys for each target enclave).
    #[serde(default)]
    #[schema(value_type = Vec<(String, Vec<String>)>)]
    pub participant_encrypted_public_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
    /// Encrypted session secrets for each enclave, used for session restoration.
    /// Each enclave needs its own encrypted version of the session secret.
    #[serde(default)]
    #[schema(value_type = Vec<String>)]
    pub enclave_encrypted_session_secrets: Vec<EncryptedSessionSecret>,
    /// Subset definitions for computing additional aggregate keys
    #[serde(default)]
    pub subset_definitions: Vec<SubsetDefinition>,
    /// Encrypted aggregate keys for each defined subset.
    /// Keys are subset_id -> encrypted_aggregate_public_key (hex-encoded).
    #[serde(default)]
    pub encrypted_subset_aggregates: BTreeMap<Uuid, String>,
}

impl KeygenCompleted {
    pub fn from_collecting_with_aggregate_key(
        collecting: KeygenCollectingParticipants,
        aggregate_public_key: AggregatePublicKey,
        participant_encrypted_public_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
        enclave_encrypted_session_secrets: Vec<EncryptedSessionSecret>,
        encrypted_subset_aggregates: BTreeMap<Uuid, String>,
    ) -> Self {
        let completed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            keygen_session_id: collecting.keygen_session_id,
            coordinator_pubkey: collecting.coordinator_pubkey,
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            session_public_key: collecting.session_public_key,
            encrypted_session_secret: collecting.encrypted_session_secret,
            coordinator_enclave_id: collecting.coordinator_enclave_id,
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key,
            created_at: collecting.created_at,
            completed_at,
            completed_with_epochs: collecting.required_enclave_epochs,
            encrypted_taproot_tweak: collecting.encrypted_taproot_tweak,
            participant_encrypted_public_keys,
            enclave_encrypted_session_secrets,
            subset_definitions: collecting.subset_definitions,
            encrypted_subset_aggregates,
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
    pub session_public_key: Option<Vec<u8>>,
    pub coordinator_enclave_id: Option<EnclaveId>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub created_at: u64,
    pub failed_at: u64,
    pub error: String,
    pub failed_due_to_enclave_restart: Option<EnclaveId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeygenSessionStatus {
    Reserved(KeygenReserved),
    CollectingParticipants(KeygenCollectingParticipants),
    Completed(KeygenCompleted),
    Failed(KeygenFailed),
}

impl KeygenSessionStatus {
    pub fn active_states() -> Vec<KeygenStatusKind> {
        vec![
            KeygenStatusKind::Reserved,
            KeygenStatusKind::CollectingParticipants,
        ]
    }

    pub fn extract_status_info(
        &self,
    ) -> (KeygenStatusKind, usize, Option<AggregatePublicKey>, u64) {
        match self {
            KeygenSessionStatus::Reserved(ref status) => (
                KeygenStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
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
            KeygenSessionStatus::Reserved(_) => None,
            KeygenSessionStatus::CollectingParticipants(s) => {
                Some(s.coordinator_encrypted_private_key.as_str())
            }
            KeygenSessionStatus::Completed(s) => Some(s.coordinator_encrypted_private_key.as_str()),
            KeygenSessionStatus::Failed(s) => s.coordinator_encrypted_private_key.as_deref(),
        }
    }

    pub fn coordinator_enclave_id(&self) -> Option<EnclaveId> {
        match self {
            KeygenSessionStatus::Reserved(s) => Some(s.coordinator_enclave_id),
            KeygenSessionStatus::CollectingParticipants(s) => Some(s.coordinator_enclave_id),
            KeygenSessionStatus::Completed(s) => Some(s.coordinator_enclave_id),
            KeygenSessionStatus::Failed(s) => s.coordinator_enclave_id,
        }
    }

    pub fn registered_participants(&self) -> Option<&BTreeMap<UserId, ParticipantData>> {
        match self {
            KeygenSessionStatus::Reserved(_) => None,
            KeygenSessionStatus::CollectingParticipants(s) => Some(&s.registered_participants),
            KeygenSessionStatus::Completed(s) => Some(&s.registered_participants),
            KeygenSessionStatus::Failed(_) => None,
        }
    }

    pub fn expected_participants_count(&self) -> usize {
        match self {
            KeygenSessionStatus::Reserved(s) => s.expected_participants.len(),
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
            KeygenSessionStatus::Reserved(_) => return,
            KeygenSessionStatus::CollectingParticipants(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            KeygenSessionStatus::Completed(ref mut completed) => {
                &mut completed.registered_participants
            }
            _ => return,
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
            KeygenSessionStatus::Reserved(_) => return Ok(()),
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
            KeygenSessionStatus::Reserved(_) => return Ok(()),
            KeygenSessionStatus::CollectingParticipants(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            KeygenSessionStatus::Completed(ref mut completed) => {
                &mut completed.registered_participants
            }
            _ => return Ok(()),
        };

        validation::merge_participants(participants, fresh_participants)
    }

    pub fn is_expired(&self) -> bool {
        let expires_at = match self {
            KeygenSessionStatus::Reserved(reserved) => reserved.expires_at,
            KeygenSessionStatus::CollectingParticipants(collecting) => collecting.expires_at,
            KeygenSessionStatus::Completed(_) => return false,
            KeygenSessionStatus::Failed(_) => return false,
        };

        validation::is_expired(expires_at)
    }

    pub fn expires_at(&self) -> Option<u64> {
        match self {
            KeygenSessionStatus::Reserved(reserved) => Some(reserved.expires_at),
            KeygenSessionStatus::CollectingParticipants(collecting) => Some(collecting.expires_at),
            KeygenSessionStatus::Completed(_) => None,
            KeygenSessionStatus::Failed(_) => None,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        match self {
            KeygenSessionStatus::Reserved(s) => &s.keygen_session_id,
            KeygenSessionStatus::CollectingParticipants(s) => &s.keygen_session_id,
            KeygenSessionStatus::Completed(s) => &s.keygen_session_id,
            KeygenSessionStatus::Failed(s) => &s.keygen_session_id,
        }
    }

    pub fn created_at(&self) -> u64 {
        match self {
            KeygenSessionStatus::Reserved(s) => s.created_at,
            KeygenSessionStatus::CollectingParticipants(s) => s.created_at,
            KeygenSessionStatus::Completed(s) => s.created_at,
            KeygenSessionStatus::Failed(s) => s.created_at,
        }
    }
}

impl AsRef<str> for KeygenSessionStatus {
    fn as_ref(&self) -> &str {
        match self {
            KeygenSessionStatus::Reserved(_) => "reserved",
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

impl From<&KeygenSessionStatus> for KeygenStatusKind {
    fn from(status: &KeygenSessionStatus) -> Self {
        match status {
            KeygenSessionStatus::Reserved(_) => KeygenStatusKind::Reserved,
            KeygenSessionStatus::CollectingParticipants(_) => {
                KeygenStatusKind::CollectingParticipants
            }
            KeygenSessionStatus::Completed(_) => KeygenStatusKind::Completed,
            KeygenSessionStatus::Failed(_) => KeygenStatusKind::Failed,
        }
    }
}
