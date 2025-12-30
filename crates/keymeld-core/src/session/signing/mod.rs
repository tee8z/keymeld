use crate::{
    api::TaprootTweak,
    enclave::EnclaveManager,
    identifiers::{EnclaveId, SessionId, UserId},
    session::types::ParticipantData,
    AggregatePublicKey, KeyMeldError,
};
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
    pub message_hash: Vec<u8>,
    pub encrypted_message: String,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub required_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak: TaprootTweak,
    pub encrypted_adaptor_configs: String,
    pub participants_requiring_approval: Vec<UserId>,
    pub approved_participants: Vec<UserId>,
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningSessionFull {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub encrypted_message: String,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak: TaprootTweak,
}

impl From<SigningCollectingParticipants> for SigningSessionFull {
    fn from(collecting: SigningCollectingParticipants) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            encrypted_message: collecting.encrypted_message.clone(),
            message_hash: collecting.message_hash.clone(),
            expected_participants: collecting.expected_participants,
            registered_participants: collecting.registered_participants,
            aggregate_public_key: None,
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
            encrypted_message: collecting.encrypted_message.clone(),
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

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningGeneratingNonces {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub encrypted_message: String,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub taproot_tweak: TaprootTweak,
}

impl From<SigningSessionFull> for SigningGeneratingNonces {
    fn from(full: SigningSessionFull) -> Self {
        Self {
            signing_session_id: full.signing_session_id,
            keygen_session_id: full.keygen_session_id,
            encrypted_message: full.encrypted_message,
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

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCollectingNonces {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub encrypted_message: String,
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
            encrypted_message: generating.encrypted_message,
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

impl From<SigningCollectingNonces> for SigningGeneratingPartialSignatures {
    fn from(collecting: SigningCollectingNonces) -> Self {
        Self {
            signing_session_id: collecting.signing_session_id,
            keygen_session_id: collecting.keygen_session_id,
            encrypted_message: collecting.encrypted_message,
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

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningGeneratingPartialSignatures {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub encrypted_message: String,
    pub message_hash: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub registered_participants: BTreeMap<UserId, ParticipantData>,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub created_at: u64,
    pub expires_at: u64,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
}

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningCollectingPartialSignatures {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub encrypted_message: String,
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
            encrypted_message: generating.encrypted_message,
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

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningFinalizingSignature {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub encrypted_message: String,
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
            encrypted_message: collecting.encrypted_message,
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
    pub final_signature: String,
    pub inherited_enclave_epochs: BTreeMap<EnclaveId, u64>,
    pub encrypted_adaptor_signatures: Option<String>,
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
            encrypted_adaptor_signatures: None,
        }
    }

    pub fn from_finalizing_with_signature_and_adaptors(
        finalizing: SigningFinalizingSignature,
        final_signature: String,
        encrypted_adaptor_signatures: String,
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
            encrypted_adaptor_signatures: Some(encrypted_adaptor_signatures),
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
    SessionFull(SigningSessionFull),
    GeneratingNonces(SigningGeneratingNonces),
    CollectingNonces(SigningCollectingNonces),
    GeneratingPartialSignatures(SigningGeneratingPartialSignatures),
    CollectingPartialSignatures(SigningCollectingPartialSignatures),
    FinalizingSignature(SigningFinalizingSignature),
    Completed(SigningCompleted),
    Failed(SigningFailed),
}

impl SigningSessionStatus {
    pub fn active_states() -> Vec<SigningStatusKind> {
        vec![
            SigningStatusKind::CollectingParticipants,
            SigningStatusKind::SessionFull,
            SigningStatusKind::GeneratingNonces,
            SigningStatusKind::CollectingNonces,
            SigningStatusKind::GeneratingPartialSignatures,
            SigningStatusKind::CollectingPartialSignatures,
            SigningStatusKind::FinalizingSignature,
        ]
    }

    pub fn get_encrypted_message(&self) -> Option<String> {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => {
                Some(status.encrypted_message.clone())
            }
            SigningSessionStatus::SessionFull(ref status) => Some(status.encrypted_message.clone()),
            SigningSessionStatus::GeneratingNonces(ref status) => {
                Some(status.encrypted_message.clone())
            }
            SigningSessionStatus::CollectingNonces(ref status) => {
                Some(status.encrypted_message.clone())
            }

            SigningSessionStatus::GeneratingPartialSignatures(ref status) => {
                Some(status.encrypted_message.clone())
            }
            SigningSessionStatus::CollectingPartialSignatures(ref status) => {
                Some(status.encrypted_message.clone())
            }
            SigningSessionStatus::FinalizingSignature(ref status) => {
                Some(status.encrypted_message.clone())
            }
            SigningSessionStatus::Completed(_) | SigningSessionStatus::Failed(_) => None,
        }
    }

    pub fn get_message_hash(&self) -> Option<&Vec<u8>> {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => Some(&status.message_hash),
            SigningSessionStatus::SessionFull(ref status) => Some(&status.message_hash),
            SigningSessionStatus::GeneratingNonces(ref status) => Some(&status.message_hash),
            SigningSessionStatus::CollectingNonces(ref status) => Some(&status.message_hash),

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

    pub fn extract_status_info(
        &self,
    ) -> (
        SigningStatusKind,
        usize,
        Option<String>,
        u64,
        Vec<UserId>,
        Vec<UserId>,
        String,
    ) {
        match self {
            SigningSessionStatus::CollectingParticipants(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                status.participants_requiring_approval.clone(),
                status.approved_participants.clone(),
                String::new(),
            ),
            SigningSessionStatus::SessionFull(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),
            SigningSessionStatus::GeneratingNonces(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),
            SigningSessionStatus::CollectingNonces(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),

            SigningSessionStatus::GeneratingPartialSignatures(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),
            SigningSessionStatus::CollectingPartialSignatures(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),
            SigningSessionStatus::FinalizingSignature(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                None,
                status.expires_at,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),
            SigningSessionStatus::Completed(ref status) => (
                SigningStatusKind::from(self),
                status.expected_participants.len(),
                Some(status.final_signature.clone()),
                status.expires_at,
                Vec::new(),
                Vec::new(),
                status
                    .encrypted_adaptor_signatures
                    .clone()
                    .unwrap_or_default(),
            ),
            SigningSessionStatus::Failed(_) => (
                SigningStatusKind::from(self),
                0,
                None,
                0,
                Vec::new(),
                Vec::new(),
                String::new(),
            ),
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

    pub fn merge_participants_from_keygen(
        &mut self,
        keygen_participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<(), KeyMeldError> {
        match self {
            SigningSessionStatus::CollectingParticipants(ref mut collecting) => {
                Self::merge_participants_from_keygen_static(
                    &mut collecting.registered_participants,
                    keygen_participants,
                )
            }
            _ => Ok(()),
        }
    }

    fn merge_participants_from_keygen_static(
        signing_participants: &mut BTreeMap<UserId, ParticipantData>,
        keygen_participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<(), KeyMeldError> {
        for (user_id, keygen_participant) in keygen_participants {
            let keygen_participant = keygen_participant.clone();
            signing_participants.insert(user_id.clone(), keygen_participant);
        }
        Ok(())
    }
}
