use crate::{
    api::TaprootTweak,
    enclave::EnclaveManager,
    identifiers::{EnclaveId, SessionId, UserId},
    session::types::{AggregatePublicKey, ParticipantData},
    KeyMeldError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use utoipa::ToSchema;

pub mod processing;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCollectingParticipants {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message_hash: Vec<u8>,
    pub encrypted_message: String,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub required_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak: Option<TaprootTweak>,
    pub participants_requiring_approval: Vec<UserId>,
    pub approved_participants: Vec<UserId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningSessionFull {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak: Option<TaprootTweak>,
}

impl From<SigningCollectingParticipants> for SigningSessionFull {
    fn from(collecting: SigningCollectingParticipants) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            message: collecting.encrypted_message,
            message_hash: collecting.message_hash.clone(),
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: None, // Will be set during processing
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            encrypted_session_secret: collecting.encrypted_session_secret,
            created_at: collecting.created_at,
            expires_at: collecting.expires_at,
            inherited_enclave_epochs: collecting.required_enclave_epochs,
            taproot_tweak: collecting.taproot_tweak,
        }
    }
}

impl SigningSessionFull {
    pub fn from_collecting_with_aggregate_key(
        collecting: SigningCollectingParticipants,
        aggregate_public_key: AggregatePublicKey,
    ) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            message: collecting.encrypted_message,
            message_hash: collecting.message_hash.clone(),
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: Some(aggregate_public_key),
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            encrypted_session_secret: collecting.encrypted_session_secret,
            created_at: collecting.created_at,
            expires_at: collecting.expires_at,
            inherited_enclave_epochs: collecting.required_enclave_epochs,
            taproot_tweak: collecting.taproot_tweak,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningGeneratingNonces {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak: Option<TaprootTweak>,
}

impl From<SigningSessionFull> for SigningGeneratingNonces {
    fn from(full: SigningSessionFull) -> Self {
        Self {
            signing_session_id: full.signing_session_id,
            keygen_session_id: full.keygen_session_id,
            message: full.message,
            message_hash: full.message_hash,
            expected_participants: full.expected_participants,
            registered_participants: full.registered_participants,
            aggregate_public_key: full.aggregate_public_key,
            coordinator_encrypted_private_key: full.coordinator_encrypted_private_key,
            created_at: full.created_at,
            expires_at: full.expires_at,
            inherited_enclave_epochs: full.inherited_enclave_epochs,
            taproot_tweak: full.taproot_tweak,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCollectingNonces {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl From<SigningGeneratingNonces> for SigningCollectingNonces {
    fn from(generating: SigningGeneratingNonces) -> Self {
        Self {
            signing_session_id: generating.signing_session_id,
            keygen_session_id: generating.keygen_session_id,
            message: generating.message,
            message_hash: generating.message_hash,
            expected_participants: generating.expected_participants,
            registered_participants: generating.registered_participants,
            aggregate_public_key: generating.aggregate_public_key,
            coordinator_encrypted_private_key: generating.coordinator_encrypted_private_key,
            created_at: generating.created_at,
            expires_at: generating.expires_at,
            inherited_enclave_epochs: generating.inherited_enclave_epochs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningAggregatingNonces {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl From<SigningCollectingNonces> for SigningAggregatingNonces {
    fn from(collecting: SigningCollectingNonces) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            message: collecting.message,
            message_hash: collecting.message_hash,
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: collecting.aggregate_public_key,
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            created_at: collecting.created_at,
            expires_at: collecting.expires_at,
            inherited_enclave_epochs: collecting.inherited_enclave_epochs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningGeneratingPartialSignatures {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub aggregate_nonce: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl SigningGeneratingPartialSignatures {
    pub fn from_aggregating_with_nonce(
        aggregating: SigningAggregatingNonces,
        aggregate_nonce: Vec<u8>,
    ) -> Self {
        Self {
            signing_session_id: aggregating.signing_session_id,
            keygen_session_id: aggregating.keygen_session_id,
            message: aggregating.message,
            message_hash: aggregating.message_hash,
            expected_participants: aggregating.expected_participants,
            registered_participants: aggregating.registered_participants,
            aggregate_public_key: aggregating.aggregate_public_key,
            coordinator_encrypted_private_key: aggregating.coordinator_encrypted_private_key,
            aggregate_nonce,
            created_at: aggregating.created_at,
            expires_at: aggregating.expires_at,
            inherited_enclave_epochs: aggregating.inherited_enclave_epochs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCollectingPartialSignatures {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl From<SigningGeneratingPartialSignatures> for SigningCollectingPartialSignatures {
    fn from(generating: SigningGeneratingPartialSignatures) -> Self {
        Self {
            signing_session_id: generating.signing_session_id,
            keygen_session_id: generating.keygen_session_id,
            message: generating.message,
            message_hash: generating.message_hash,
            expected_participants: generating.expected_participants,
            registered_participants: generating.registered_participants,
            aggregate_public_key: generating.aggregate_public_key,
            coordinator_encrypted_private_key: generating.coordinator_encrypted_private_key,
            created_at: generating.created_at,
            expires_at: generating.expires_at,
            inherited_enclave_epochs: generating.inherited_enclave_epochs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningFinalizingSignature {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl From<SigningCollectingPartialSignatures> for SigningFinalizingSignature {
    fn from(collecting: SigningCollectingPartialSignatures) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            message: collecting.message,
            message_hash: collecting.message_hash,
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: collecting.aggregate_public_key,
            coordinator_encrypted_private_key: collecting.coordinator_encrypted_private_key,
            created_at: collecting.created_at,
            expires_at: collecting.expires_at,
            inherited_enclave_epochs: collecting.inherited_enclave_epochs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
    pub final_signature: String,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

impl SigningCompleted {
    pub fn from_finalizing_with_signature(
        finalizing: SigningFinalizingSignature,
        final_signature: String,
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
            final_signature,
            inherited_enclave_epochs: finalizing.inherited_enclave_epochs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum SigningSessionStatus {
    CollectingParticipants(SigningCollectingParticipants),
    SessionFull(SigningSessionFull),
    GeneratingNonces(SigningGeneratingNonces),
    CollectingNonces(SigningCollectingNonces),
    AggregatingNonces(SigningAggregatingNonces),
    GeneratingPartialSignatures(SigningGeneratingPartialSignatures),
    CollectingPartialSignatures(SigningCollectingPartialSignatures),
    FinalizingSignature(SigningFinalizingSignature),
    Completed(SigningCompleted),
    Failed(SigningFailed),
}

impl SigningSessionStatus {
    pub fn get_message(&self) -> Option<&Vec<u8>> {
        match self {
            SigningSessionStatus::CollectingParticipants(_) => None, // Only has message_hash, not raw message
            SigningSessionStatus::SessionFull(ref status) => Some(&status.message),
            SigningSessionStatus::GeneratingNonces(ref status) => Some(&status.message),
            SigningSessionStatus::CollectingNonces(ref status) => Some(&status.message),
            SigningSessionStatus::AggregatingNonces(ref status) => Some(&status.message),
            SigningSessionStatus::GeneratingPartialSignatures(ref status) => Some(&status.message),
            SigningSessionStatus::CollectingPartialSignatures(ref status) => Some(&status.message),
            SigningSessionStatus::FinalizingSignature(ref status) => Some(&status.message),
            SigningSessionStatus::Completed(_) | SigningSessionStatus::Failed(_) => None,
        }
    }

    pub fn get_message_hash(&self) -> Option<&Vec<u8>> {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => Some(&status.message_hash),
            SigningSessionStatus::SessionFull(ref status) => Some(&status.message_hash),
            SigningSessionStatus::GeneratingNonces(ref status) => Some(&status.message_hash),
            SigningSessionStatus::CollectingNonces(ref status) => Some(&status.message_hash),
            SigningSessionStatus::AggregatingNonces(ref status) => Some(&status.message_hash),
            SigningSessionStatus::GeneratingPartialSignatures(ref status) => {
                Some(&status.message_hash)
            }
            SigningSessionStatus::CollectingPartialSignatures(ref status) => {
                Some(&status.message_hash)
            }
            SigningSessionStatus::FinalizingSignature(ref status) => Some(&status.message_hash),
            SigningSessionStatus::Completed(_) | SigningSessionStatus::Failed(_) => None,
        }
    }

    pub fn extract_status_info(&self) -> (SigningStatusKind, usize, Option<String>, u64) {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::SessionFull(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::GeneratingNonces(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::CollectingNonces(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::AggregatingNonces(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::GeneratingPartialSignatures(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::CollectingPartialSignatures(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::FinalizingSignature(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
            ),
            SigningSessionStatus::Completed(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                Some(status.final_signature.clone()),
                status.expires_at,
            ),
            SigningSessionStatus::Failed(_) => (SigningStatusKind::from(self), 0, None, 0),
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
            SigningSessionStatus::SessionFull(s) => s.coordinator_encrypted_private_key.as_deref(),
            SigningSessionStatus::GeneratingNonces(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::CollectingNonces(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::AggregatingNonces(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::GeneratingPartialSignatures(s) => {
                s.coordinator_encrypted_private_key.as_deref()
            }
            SigningSessionStatus::CollectingPartialSignatures(s) => {
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
            SigningSessionStatus::SessionFull(s) => Some(&s.registered_participants),
            SigningSessionStatus::GeneratingNonces(s) => Some(&s.registered_participants),
            SigningSessionStatus::CollectingNonces(s) => Some(&s.registered_participants),
            SigningSessionStatus::AggregatingNonces(s) => Some(&s.registered_participants),
            SigningSessionStatus::GeneratingPartialSignatures(s) => {
                Some(&s.registered_participants)
            }
            SigningSessionStatus::CollectingPartialSignatures(s) => {
                Some(&s.registered_participants)
            }
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

    pub fn merge_fresh_participant_data(
        &mut self,
        fresh_participants: BTreeMap<UserId, ParticipantData>,
    ) {
        let participants = match self {
            SigningSessionStatus::CollectingParticipants(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            SigningSessionStatus::SessionFull(ref mut full) => &mut full.registered_participants,
            SigningSessionStatus::GeneratingNonces(ref mut generating) => {
                &mut generating.registered_participants
            }
            SigningSessionStatus::CollectingNonces(ref mut collecting) => {
                &mut collecting.registered_participants
            }
            SigningSessionStatus::AggregatingNonces(ref mut aggregating) => {
                &mut aggregating.registered_participants
            }
            SigningSessionStatus::GeneratingPartialSignatures(ref mut generating) => {
                &mut generating.registered_participants
            }
            SigningSessionStatus::CollectingPartialSignatures(ref mut collecting) => {
                &mut collecting.registered_participants
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
            SigningSessionStatus::SessionFull(_) => "session_full",
            SigningSessionStatus::GeneratingNonces(_) => "generating_nonces",
            SigningSessionStatus::CollectingNonces(_) => "collecting_nonces",
            SigningSessionStatus::AggregatingNonces(_) => "aggregating_nonces",
            SigningSessionStatus::GeneratingPartialSignatures(_) => "generating_partial_signatures",
            SigningSessionStatus::CollectingPartialSignatures(_) => "collecting_partial_signatures",
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningStatusKind {
    CollectingParticipants,
    SessionFull,
    GeneratingNonces,
    CollectingNonces,
    AggregatingNonces,
    GeneratingPartialSignatures,
    CollectingPartialSignatures,
    FinalizingSignature,
    Completed,
    Failed,
}

impl From<&SigningSessionStatus> for SigningStatusKind {
    fn from(status: &SigningSessionStatus) -> Self {
        match status {
            SigningSessionStatus::CollectingParticipants(_) => {
                SigningStatusKind::CollectingParticipants
            }
            SigningSessionStatus::SessionFull(_) => SigningStatusKind::SessionFull,
            SigningSessionStatus::GeneratingNonces(_) => SigningStatusKind::GeneratingNonces,
            SigningSessionStatus::CollectingNonces(_) => SigningStatusKind::CollectingNonces,
            SigningSessionStatus::AggregatingNonces(_) => SigningStatusKind::AggregatingNonces,
            SigningSessionStatus::GeneratingPartialSignatures(_) => {
                SigningStatusKind::GeneratingPartialSignatures
            }
            SigningSessionStatus::CollectingPartialSignatures(_) => {
                SigningStatusKind::CollectingPartialSignatures
            }
            SigningSessionStatus::FinalizingSignature(_) => SigningStatusKind::FinalizingSignature,
            SigningSessionStatus::Completed(_) => SigningStatusKind::Completed,
            SigningSessionStatus::Failed(_) => SigningStatusKind::Failed,
        }
    }
}

impl AsRef<str> for SigningStatusKind {
    fn as_ref(&self) -> &str {
        match self {
            SigningStatusKind::CollectingParticipants => "collecting_participants",
            SigningStatusKind::SessionFull => "session_full",
            SigningStatusKind::GeneratingNonces => "generating_nonces",
            SigningStatusKind::CollectingNonces => "collecting_nonces",
            SigningStatusKind::AggregatingNonces => "aggregating_nonces",
            SigningStatusKind::GeneratingPartialSignatures => "generating_partial_signatures",
            SigningStatusKind::CollectingPartialSignatures => "collecting_partial_signatures",
            SigningStatusKind::FinalizingSignature => "finalizing_signature",
            SigningStatusKind::Completed => "completed",
            SigningStatusKind::Failed => "failed",
        }
    }
}

impl fmt::Display for SigningStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

// Additional methods for SigningSessionStatus
impl SigningSessionStatus {
    pub fn validate_enclave_epochs(
        &self,
        enclave_manager: &EnclaveManager,
    ) -> Result<(), KeyMeldError> {
        let required_epochs = match self {
            SigningSessionStatus::CollectingParticipants(ref collecting) => {
                &collecting.required_enclave_epochs
            }
            SigningSessionStatus::SessionFull(ref full) => &full.inherited_enclave_epochs,
            SigningSessionStatus::GeneratingNonces(ref generating) => {
                &generating.inherited_enclave_epochs
            }
            SigningSessionStatus::CollectingNonces(ref collecting) => {
                &collecting.inherited_enclave_epochs
            }
            SigningSessionStatus::AggregatingNonces(ref aggregating) => {
                &aggregating.inherited_enclave_epochs
            }
            SigningSessionStatus::GeneratingPartialSignatures(ref generating) => {
                &generating.inherited_enclave_epochs
            }
            SigningSessionStatus::CollectingPartialSignatures(ref collecting) => {
                &collecting.inherited_enclave_epochs
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
                        "Enclave {} restarted during signing (epoch {} -> {}). Restart signing session with fresh keys.",
                        enclave_id, required_epoch, current_epoch
                    )));
                }
                None => {
                    return Err(KeyMeldError::InvalidState(format!(
                        "Enclave {} not found during signing. Enclave may have been removed.",
                        enclave_id
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn merge_participants_from_keygen(
        &mut self,
        keygen_participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<(), KeyMeldError> {
        match self {
            SigningSessionStatus::CollectingParticipants(ref mut collecting) => {
                Self::set_participant_data_from_keygen_static(
                    &mut collecting.registered_participants,
                    keygen_participants,
                )
            }
            _ => Ok(()),
        }
    }

    fn set_participant_data_from_keygen_static(
        signing_participants: &mut BTreeMap<UserId, ParticipantData>,
        keygen_participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<(), KeyMeldError> {
        for (user_id, keygen_participant) in keygen_participants {
            let mut keygen_participant = keygen_participant.clone();
            // Clear signing-specific data when inheriting from keygen
            keygen_participant.public_nonces = None;
            keygen_participant.partial_signature = None;

            if let Some(existing) = signing_participants.get(user_id) {
                // Preserve any signing-specific data that was already set
                keygen_participant.public_nonces = existing.public_nonces.clone();
                keygen_participant.partial_signature = existing.partial_signature;
            }

            signing_participants.insert(user_id.clone(), keygen_participant);
        }
        Ok(())
    }
}
