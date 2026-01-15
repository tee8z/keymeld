use crate::{
    enclave::EnclaveManager,
    identifiers::{EnclaveId, SessionId, UserId},
    session::types::ParticipantData,
    AggregatePublicKey, KeyMeldError,
};
use keymeld_core::protocol::SigningStatusKind;
use keymeld_sdk::{BatchItemResult, SigningBatchItem};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use utoipa::ToSchema;

pub mod processing;

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCollectingParticipants {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    /// Batch items to sign (single message = batch of 1)
    pub batch_items: Vec<SigningBatchItem>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub required_enclave_epochs: BTreeMap<EnclaveId, u64>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    pub participants_requiring_approval: Vec<UserId>,
    pub approved_participants: Vec<UserId>,
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningInitializingSession {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    /// Batch items to sign (single message = batch of 1)
    pub batch_items: Vec<SigningBatchItem>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
}

impl From<SigningCollectingParticipants> for SigningInitializingSession {
    fn from(collecting: SigningCollectingParticipants) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            batch_items: collecting.batch_items,
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: None,
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            encrypted_session_secret: collecting.encrypted_session_secret,
            created_at: collecting.created_at,
            expires_at: collecting.expires_at,
            inherited_enclave_epochs: collecting.required_enclave_epochs,
            encrypted_taproot_tweak: collecting.encrypted_taproot_tweak,
        }
    }
}

impl SigningInitializingSession {
    pub fn from_collecting_with_aggregate_key(
        collecting: SigningCollectingParticipants,
        aggregate_public_key: AggregatePublicKey,
    ) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            batch_items: collecting.batch_items,
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: Some(aggregate_public_key),
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            encrypted_session_secret: collecting.encrypted_session_secret,
            created_at: collecting.created_at,
            expires_at: collecting.expires_at,
            inherited_enclave_epochs: collecting.required_enclave_epochs,
            encrypted_taproot_tweak: collecting.encrypted_taproot_tweak,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningDistributingNonces {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    /// Batch items to sign (single message = batch of 1)
    pub batch_items: Vec<SigningBatchItem>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    // Nonces collected from Step 1 (InitSigningSession) - always present in this state
    // Note: Skipped in API schema because NonceData contains musig2 types without ToSchema
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    #[schema(value_type = Object)]
    pub collected_nonces: BTreeMap<UserId, String>,
}

impl SigningDistributingNonces {
    pub fn new_with_nonces(
        initializing: SigningInitializingSession,
        nonces: BTreeMap<UserId, String>,
    ) -> Self {
        Self {
            signing_session_id: initializing.signing_session_id,
            keygen_session_id: initializing.keygen_session_id,
            batch_items: initializing.batch_items,
            expected_participants: initializing.expected_participants,
            registered_participants: initializing.registered_participants,
            aggregate_public_key: initializing.aggregate_public_key,
            coordinator_encrypted_private_key: initializing.coordinator_encrypted_private_key,
            created_at: initializing.created_at,
            expires_at: initializing.expires_at,
            inherited_enclave_epochs: initializing.inherited_enclave_epochs,
            encrypted_taproot_tweak: initializing.encrypted_taproot_tweak,
            collected_nonces: nonces,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningFinalizingSignature {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    /// Batch items to sign (single message = batch of 1)
    pub batch_items: Vec<SigningBatchItem>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    // Partial signatures collected from Step 2 (DistributeNonces) - always present in this state
    // Note: Skipped in API schema because encrypted strings
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    #[schema(value_type = Object)]
    pub collected_partial_signatures: BTreeMap<UserId, String>,
}

impl SigningFinalizingSignature {
    pub fn new_with_partial_signatures(
        distributing: SigningDistributingNonces,
        partial_signatures: BTreeMap<UserId, String>,
    ) -> Self {
        Self {
            signing_session_id: distributing.signing_session_id,
            keygen_session_id: distributing.keygen_session_id,
            batch_items: distributing.batch_items,
            expected_participants: distributing.expected_participants,
            registered_participants: distributing.registered_participants,
            aggregate_public_key: distributing.aggregate_public_key,
            coordinator_encrypted_private_key: distributing.coordinator_encrypted_private_key,
            created_at: distributing.created_at,
            expires_at: distributing.expires_at,
            inherited_enclave_epochs: distributing.inherited_enclave_epochs,
            collected_partial_signatures: partial_signatures,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCompleted {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    /// Batch results (single message = batch of 1)
    pub batch_results: Vec<BatchItemResult>,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl SigningCompleted {
    pub fn from_finalizing_with_batch_results(
        finalizing: SigningFinalizingSignature,
        batch_results: Vec<BatchItemResult>,
    ) -> Self {
        Self {
            signing_session_id: finalizing.signing_session_id,
            keygen_session_id: finalizing.keygen_session_id,
            expected_participants: finalizing.expected_participants,
            registered_participants: finalizing.registered_participants,
            aggregate_public_key: finalizing.aggregate_public_key,
            coordinator_encrypted_private_key: finalizing.coordinator_encrypted_private_key,
            created_at: finalizing.created_at,
            expires_at: finalizing.expires_at,
            batch_results,
            inherited_enclave_epochs: finalizing.inherited_enclave_epochs,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningFailed {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub error: String,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum SigningSessionStatus {
    CollectingParticipants(SigningCollectingParticipants),
    InitializingSession(SigningInitializingSession),
    DistributingNonces(SigningDistributingNonces),
    FinalizingSignature(SigningFinalizingSignature),
    Completed(SigningCompleted),
    Failed(SigningFailed),
}

impl SigningSessionStatus {
    pub fn active_states() -> Vec<SigningStatusKind> {
        vec![
            SigningStatusKind::CollectingParticipants,
            SigningStatusKind::InitializingSession,
            SigningStatusKind::DistributingNonces,
            SigningStatusKind::FinalizingSignature,
        ]
    }

    pub fn get_batch_items(&self) -> Option<&Vec<SigningBatchItem>> {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => Some(&status.batch_items),
            SigningSessionStatus::InitializingSession(ref status) => Some(&status.batch_items),
            SigningSessionStatus::DistributingNonces(ref status) => Some(&status.batch_items),
            SigningSessionStatus::FinalizingSignature(ref status) => Some(&status.batch_items),
            SigningSessionStatus::Completed(_) | SigningSessionStatus::Failed(_) => None,
        }
    }

    pub fn get_batch_results(&self) -> Option<&Vec<BatchItemResult>> {
        match self {
            SigningSessionStatus::Completed(ref status) => Some(&status.batch_results),
            _ => None,
        }
    }

    pub fn extract_status_info(&self) -> (SigningStatusKind, usize, u64, Vec<UserId>, Vec<UserId>) {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                status.expires_at,
                status.participants_requiring_approval.clone(),
                status.approved_participants.clone(),
            ),
            SigningSessionStatus::InitializingSession(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                status.expires_at,
                Vec::new(),
                Vec::new(),
            ),
            SigningSessionStatus::DistributingNonces(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                status.expires_at,
                Vec::new(),
                Vec::new(),
            ),
            SigningSessionStatus::FinalizingSignature(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                status.expires_at,
                Vec::new(),
                Vec::new(),
            ),
            SigningSessionStatus::Completed(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                status.expires_at,
                Vec::new(),
                Vec::new(),
            ),
            SigningSessionStatus::Failed(_) => {
                (SigningStatusKind::from(self), 0, 0, Vec::new(), Vec::new())
            }
        }
    }

    pub fn kind(&self) -> SigningStatusKind {
        self.into()
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SigningSessionStatus::Completed(_) | SigningSessionStatus::Failed(_)
        )
    }

    pub fn coordinator_encrypted_private_key(&self) -> Option<&str> {
        match self {
            SigningSessionStatus::CollectingParticipants(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::InitializingSession(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::DistributingNonces(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::FinalizingSignature(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::Completed(s) => s.coordinator_encrypted_private_key.as_deref(),
            SigningSessionStatus::Failed(s) => s.coordinator_encrypted_private_key.as_deref(),
        }
    }

    pub fn registered_participants(&self) -> Option<&BTreeMap<UserId, ParticipantData>> {
        match self {
            SigningSessionStatus::CollectingParticipants(s) => Some(&s.registered_participants),
            SigningSessionStatus::InitializingSession(s) => Some(&s.registered_participants),
            SigningSessionStatus::DistributingNonces(s) => Some(&s.registered_participants),
            SigningSessionStatus::FinalizingSignature(s) => Some(&s.registered_participants),
            SigningSessionStatus::Completed(s) => Some(&s.registered_participants),
            SigningSessionStatus::Failed(s) => Some(&s.registered_participants),
        }
    }

    pub fn registered_signing_participants(&self) -> Vec<&UserId> {
        match self.registered_participants() {
            Some(participants) => participants.keys().collect(),
            None => vec![],
        }
    }

    pub fn session_id(&self) -> &SessionId {
        match self {
            SigningSessionStatus::CollectingParticipants(s) => &s.signing_session_id,
            SigningSessionStatus::InitializingSession(s) => &s.signing_session_id,
            SigningSessionStatus::DistributingNonces(s) => &s.signing_session_id,
            SigningSessionStatus::FinalizingSignature(s) => &s.signing_session_id,
            SigningSessionStatus::Completed(s) => &s.signing_session_id,
            SigningSessionStatus::Failed(s) => &s.signing_session_id,
        }
    }

    pub fn created_at(&self) -> u64 {
        match self {
            SigningSessionStatus::CollectingParticipants(s) => s.created_at,
            SigningSessionStatus::InitializingSession(s) => s.created_at,
            SigningSessionStatus::DistributingNonces(s) => s.created_at,
            SigningSessionStatus::FinalizingSignature(s) => s.created_at,
            SigningSessionStatus::Completed(s) => s.created_at,
            SigningSessionStatus::Failed(s) => s.created_at,
        }
    }

    pub fn expires_at(&self) -> Option<u64> {
        match self {
            SigningSessionStatus::CollectingParticipants(s) => Some(s.expires_at),
            SigningSessionStatus::InitializingSession(s) => Some(s.expires_at),
            SigningSessionStatus::DistributingNonces(s) => Some(s.expires_at),
            SigningSessionStatus::FinalizingSignature(s) => Some(s.expires_at),
            SigningSessionStatus::Completed(s) => Some(s.expires_at),
            SigningSessionStatus::Failed(_) => None,
        }
    }

    pub fn approved_participants(&self) -> Vec<UserId> {
        match self {
            SigningSessionStatus::CollectingParticipants(s) => s.approved_participants.clone(),
            // After collecting, all participants are effectively "approved"
            SigningSessionStatus::InitializingSession(s) => s.expected_participants.clone(),
            SigningSessionStatus::DistributingNonces(s) => s.expected_participants.clone(),
            SigningSessionStatus::FinalizingSignature(s) => s.expected_participants.clone(),
            SigningSessionStatus::Completed(s) => s.expected_participants.clone(),
            SigningSessionStatus::Failed(s) => s.expected_participants.clone(),
        }
    }

    pub fn merge_fresh_participant_data(
        &mut self,
        fresh_participants: BTreeMap<UserId, ParticipantData>,
    ) {
        let participants = match self {
            SigningSessionStatus::CollectingParticipants(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            SigningSessionStatus::InitializingSession(ref mut initializing) => {
                &mut initializing.registered_participants
            }
            SigningSessionStatus::DistributingNonces(ref mut distributing) => {
                &mut distributing.registered_participants
            }
            SigningSessionStatus::FinalizingSignature(ref mut finalizing) => {
                &mut finalizing.registered_participants
            }
            SigningSessionStatus::Completed(ref mut completed) => {
                &mut completed.registered_participants
            }
            SigningSessionStatus::Failed(ref mut failed) => &mut failed.registered_participants,
        };

        for (user_id, fresh_participant) in fresh_participants {
            participants.insert(user_id, fresh_participant);
        }
    }
}

impl AsRef<str> for SigningSessionStatus {
    fn as_ref(&self) -> &str {
        match self {
            SigningSessionStatus::CollectingParticipants(_) => "collecting_participants",
            SigningSessionStatus::InitializingSession(_) => "initializing_session",
            SigningSessionStatus::DistributingNonces(_) => "distributing_nonces",
            SigningSessionStatus::FinalizingSignature(_) => "finalizing_signature",
            SigningSessionStatus::Completed(_) => "completed",
            SigningSessionStatus::Failed(_) => "failed",
        }
    }
}

impl fmt::Display for SigningSessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl From<&SigningSessionStatus> for SigningStatusKind {
    fn from(status: &SigningSessionStatus) -> Self {
        match status {
            SigningSessionStatus::CollectingParticipants(_) => {
                SigningStatusKind::CollectingParticipants
            }
            SigningSessionStatus::InitializingSession(_) => SigningStatusKind::InitializingSession,
            SigningSessionStatus::DistributingNonces(_) => SigningStatusKind::DistributingNonces,
            SigningSessionStatus::FinalizingSignature(_) => SigningStatusKind::FinalizingSignature,
            SigningSessionStatus::Completed(_) => SigningStatusKind::Completed,
            SigningSessionStatus::Failed(_) => SigningStatusKind::Failed,
        }
    }
}

impl SigningSessionStatus {
    pub fn validate_enclave_epochs(
        &self,
        enclave_manager: &EnclaveManager,
    ) -> Result<(), KeyMeldError> {
        let required_epochs = match self {
            SigningSessionStatus::CollectingParticipants(ref collecting) => {
                &collecting.required_enclave_epochs
            }
            SigningSessionStatus::InitializingSession(ref initializing) => {
                &initializing.inherited_enclave_epochs
            }
            SigningSessionStatus::DistributingNonces(ref distributing) => {
                &distributing.inherited_enclave_epochs
            }
            SigningSessionStatus::FinalizingSignature(ref finalizing) => {
                &finalizing.inherited_enclave_epochs
            }
            SigningSessionStatus::Completed(ref completed) => &completed.inherited_enclave_epochs,
            SigningSessionStatus::Failed(ref failed) => &failed.inherited_enclave_epochs,
        };

        for (enclave_id, required_epoch) in required_epochs {
            match enclave_manager.get_enclave_key_epoch(enclave_id) {
                Some(current_epoch) if current_epoch == *required_epoch => continue,
                Some(current_epoch) => {
                    return Err(KeyMeldError::InvalidState(format!(
                        "Enclave {enclave_id} restarted during signing (epoch {required_epoch} -> {current_epoch}). Restart signing session with fresh keys."
                    )));
                }
                None => {
                    return Err(KeyMeldError::InvalidState(format!(
                        "Enclave {enclave_id} not found during signing. Enclave may have been removed."
                    )));
                }
            }
        }
        Ok(())
    }
}
