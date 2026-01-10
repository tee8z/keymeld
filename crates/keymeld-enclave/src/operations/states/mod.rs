use crate::musig::MusigProcessor;

use keymeld_core::{
    crypto::SessionSecret,
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, InternalError},
};
use std::time::SystemTime;

pub mod keygen;
pub mod signing;

pub use keygen::{
    Completed as KeygenCompleted, DistributingSecrets, Failed as KeygenFailed,
    Initialized as KeygenInitialized,
};
pub use signing::{
    CollectingNonces, CollectingPartialSignatures, Completed as SigningCompleted,
    Failed as SigningFailed, FinalizingSignature, GeneratingNonces, GeneratingPartialSignatures,
    Initialized as SigningInitialized,
};

#[derive(Debug, Clone)]
pub enum SessionKind {
    Keygen,
    Signing,
}

pub struct ParticipantInfo {
    pub user_id: UserId,
    pub public_key: Vec<u8>,
    pub has_private_key: bool,
}

impl ParticipantInfo {
    pub fn new(user_id: UserId, public_key: Vec<u8>, has_private_key: bool) -> Self {
        Self {
            user_id,
            public_key,
            has_private_key,
        }
    }
}

#[derive(Debug)]
pub enum KeygenStatus {
    Initialized(keygen::Initialized),
    Distributing(keygen::DistributingSecrets),
    Completed(keygen::Completed),
    Failed(keygen::Failed),
}

#[derive(Debug)]
pub enum SigningStatus {
    Initialized(signing::Initialized),
    GeneratingNonces(signing::GeneratingNonces),
    CollectingNonces(signing::CollectingNonces),
    GeneratingPartialSignatures(signing::GeneratingPartialSignatures),
    CollectingPartialSignatures(signing::CollectingPartialSignatures),
    FinalizingSignature(signing::FinalizingSignature),
    Completed(signing::Completed),
    Failed(signing::Failed),
}

impl KeygenStatus {
    pub fn session_id(&self) -> &keymeld_core::SessionId {
        match self {
            KeygenStatus::Initialized(state) => &state.session_id,
            KeygenStatus::Distributing(state) => &state.session_id,
            KeygenStatus::Completed(state) => &state.session_id,
            KeygenStatus::Failed(state) => &state.session_id,
        }
    }

    pub fn created_at(&self) -> SystemTime {
        match self {
            KeygenStatus::Initialized(state) => state.created_at,
            KeygenStatus::Distributing(state) => state.created_at,
            KeygenStatus::Completed(state) => state.created_at,
            KeygenStatus::Failed(state) => state.created_at,
        }
    }
}

impl SigningStatus {
    pub fn session_id(&self) -> &keymeld_core::SessionId {
        match self {
            SigningStatus::Initialized(state) => &state.session_id,
            SigningStatus::GeneratingNonces(state) => &state.session_id,
            SigningStatus::CollectingNonces(state) => &state.session_id,
            SigningStatus::GeneratingPartialSignatures(state) => &state.session_id,
            SigningStatus::CollectingPartialSignatures(state) => &state.session_id,
            SigningStatus::FinalizingSignature(state) => &state.session_id,
            SigningStatus::Completed(state) => &state.session_id,
            SigningStatus::Failed(state) => &state.session_id,
        }
    }

    pub fn created_at(&self) -> SystemTime {
        match self {
            SigningStatus::Initialized(state) => state.created_at,
            SigningStatus::GeneratingNonces(state) => state.created_at,
            SigningStatus::CollectingNonces(state) => state.created_at,
            SigningStatus::GeneratingPartialSignatures(state) => state.created_at,
            SigningStatus::CollectingPartialSignatures(state) => state.created_at,
            SigningStatus::FinalizingSignature(state) => state.created_at,
            SigningStatus::Completed(state) => state.created_at,
            SigningStatus::Failed(state) => state.created_at,
        }
    }
}

impl std::fmt::Display for KeygenStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeygenStatus::Initialized(_) => write!(f, "initialized"),
            KeygenStatus::Distributing(_) => write!(f, "distributing"),
            KeygenStatus::Completed(_) => write!(f, "completed"),
            KeygenStatus::Failed(_) => write!(f, "failed"),
        }
    }
}

impl std::fmt::Display for SigningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningStatus::Initialized(_) => write!(f, "initialized"),
            SigningStatus::GeneratingNonces(_) => write!(f, "generating_nonces"),
            SigningStatus::CollectingNonces(_) => write!(f, "collecting_nonces"),
            SigningStatus::GeneratingPartialSignatures(_) => {
                write!(f, "generating_partial_signatures")
            }
            SigningStatus::CollectingPartialSignatures(_) => {
                write!(f, "collecting_partial_signatures")
            }
            SigningStatus::FinalizingSignature(_) => write!(f, "finalizing_signature"),
            SigningStatus::Completed(_) => write!(f, "completed"),
            SigningStatus::Failed(_) => write!(f, "failed"),
        }
    }
}

impl SigningStatus {
    /// Get the count of batch items that have been processed
    pub fn get_batch_item_count(&self) -> usize {
        match self {
            SigningStatus::Initialized(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::GeneratingNonces(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::CollectingNonces(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::GeneratingPartialSignatures(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::CollectingPartialSignatures(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::FinalizingSignature(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::Completed(state) => state
                .musig_processor()
                .get_session_metadata_public()
                .batch_items
                .len(),
            SigningStatus::Failed(_) => 0,
        }
    }
}

#[derive(Debug)]
pub enum OperatorStatus {
    Keygen(KeygenStatus),
    Signing(SigningStatus),
}

impl Default for OperatorStatus {
    fn default() -> Self {
        OperatorStatus::Keygen(KeygenStatus::Failed(keygen::Failed {
            session_id: keymeld_core::SessionId::new_v7(),
            error: "Default placeholder".to_string(),
            created_at: std::time::SystemTime::now(),
        }))
    }
}

impl std::fmt::Display for OperatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperatorStatus::Keygen(status) => write!(f, "Keygen({:?})", status),
            OperatorStatus::Signing(status) => write!(f, "Signing({:?})", status),
        }
    }
}

pub fn create_failed_state(
    kind: SessionKind,
    session_id: SessionId,
    created_at: SystemTime,
    error: String,
) -> OperatorStatus {
    match kind {
        SessionKind::Keygen => OperatorStatus::Keygen(KeygenStatus::Failed(keygen::Failed::new(
            session_id, created_at, error,
        ))),
        SessionKind::Signing => OperatorStatus::Signing(SigningStatus::Failed(
            signing::Failed::new(session_id, created_at, error),
        )),
    }
}

impl OperatorStatus {
    pub fn kind(&self) -> SessionKind {
        match self {
            OperatorStatus::Keygen(_) => SessionKind::Keygen,
            OperatorStatus::Signing(_) => SessionKind::Signing,
        }
    }

    pub fn get_musig_processor(&self) -> Option<&MusigProcessor> {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.musig_processor().as_ref(),
                KeygenStatus::Distributing(state) => Some(state.musig_processor()),
                KeygenStatus::Completed(state) => Some(state.musig_processor()),
                KeygenStatus::Failed(_) => None,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => Some(state.musig_processor()),
                SigningStatus::GeneratingNonces(state) => Some(state.musig_processor()),
                SigningStatus::CollectingNonces(state) => Some(state.musig_processor()),
                SigningStatus::GeneratingPartialSignatures(state) => Some(state.musig_processor()),
                SigningStatus::CollectingPartialSignatures(state) => Some(state.musig_processor()),
                SigningStatus::FinalizingSignature(state) => Some(state.musig_processor()),
                SigningStatus::Completed(state) => Some(state.musig_processor()),
                SigningStatus::Failed(_) => None,
            },
        }
    }

    pub fn is_coordinator(&self) -> bool {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.coordinator_data().is_some(),
                KeygenStatus::Distributing(state) => state.coordinator_data().is_some(),
                KeygenStatus::Completed(state) => state.coordinator_data().is_some(),
                KeygenStatus::Failed(_) => false,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => state.coordinator_data().is_some(),
                SigningStatus::GeneratingNonces(state) => state.coordinator_data().is_some(),
                SigningStatus::CollectingNonces(state) => state.coordinator_data().is_some(),
                SigningStatus::GeneratingPartialSignatures(state) => {
                    state.coordinator_data().is_some()
                }
                SigningStatus::CollectingPartialSignatures(state) => {
                    state.coordinator_data().is_some()
                }
                SigningStatus::FinalizingSignature(state) => state.coordinator_data().is_some(),
                SigningStatus::Completed(state) => state.coordinator_data().is_some(),
                SigningStatus::Failed(_) => false,
            },
        }
    }

    pub fn get_session_secret(&self) -> Option<&SessionSecret> {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.session_secret().as_ref(),
                KeygenStatus::Distributing(state) => Some(state.session_secret()),
                KeygenStatus::Completed(state) => Some(state.session_secret()),
                KeygenStatus::Failed(_) => None,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => Some(state.session_secret()),
                SigningStatus::GeneratingNonces(state) => Some(state.session_secret()),
                SigningStatus::CollectingNonces(state) => Some(state.session_secret()),
                SigningStatus::GeneratingPartialSignatures(state) => Some(state.session_secret()),
                SigningStatus::CollectingPartialSignatures(state) => Some(state.session_secret()),
                SigningStatus::FinalizingSignature(state) => Some(state.session_secret()),
                SigningStatus::Completed(state) => Some(state.session_secret()),
                SigningStatus::Failed(_) => None,
            },
        }
    }

    pub fn created_at(&self) -> SystemTime {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.created_at,
                KeygenStatus::Distributing(state) => state.created_at,
                KeygenStatus::Completed(state) => state.created_at,
                KeygenStatus::Failed(state) => state.created_at,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => state.created_at,
                SigningStatus::GeneratingNonces(state) => state.created_at,
                SigningStatus::CollectingNonces(state) => state.created_at,
                SigningStatus::GeneratingPartialSignatures(state) => state.created_at,
                SigningStatus::CollectingPartialSignatures(state) => state.created_at,
                SigningStatus::FinalizingSignature(state) => state.created_at,
                SigningStatus::Completed(state) => state.created_at,
                SigningStatus::Failed(state) => state.created_at,
            },
        }
    }

    pub fn session_id(&self) -> SessionId {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.session_id.clone(),
                KeygenStatus::Distributing(state) => state.session_id.clone(),
                KeygenStatus::Completed(state) => state.session_id.clone(),
                KeygenStatus::Failed(state) => state.session_id.clone(),
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => state.session_id.clone(),
                SigningStatus::GeneratingNonces(state) => state.session_id.clone(),
                SigningStatus::CollectingNonces(state) => state.session_id.clone(),
                SigningStatus::GeneratingPartialSignatures(state) => state.session_id.clone(),
                SigningStatus::CollectingPartialSignatures(state) => state.session_id.clone(),
                SigningStatus::FinalizingSignature(state) => state.session_id.clone(),
                SigningStatus::Completed(state) => state.session_id.clone(),
                SigningStatus::Failed(state) => state.session_id.clone(),
            },
        }
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        match self {
            OperatorStatus::Keygen(_) => vec![], // Keygen states don't need this method
            OperatorStatus::Signing(status) => match status {
                SigningStatus::GeneratingNonces(state) => state.get_participants(),
                SigningStatus::CollectingNonces(state) => state.get_participants(),
                SigningStatus::GeneratingPartialSignatures(state) => state.get_participants(),
                SigningStatus::CollectingPartialSignatures(state) => state.get_participants(),
                _ => vec![],
            },
        }
    }

    pub fn check_for_failure(&self) -> Result<(), EnclaveError> {
        match self {
            OperatorStatus::Keygen(KeygenStatus::Failed(failed_state)) => {
                Err(EnclaveError::Internal(InternalError::Other(format!(
                    "Keygen session {} failed: {}",
                    failed_state.session_id, failed_state.error
                ))))
            }
            OperatorStatus::Signing(SigningStatus::Failed(failed_state)) => {
                Err(EnclaveError::Internal(InternalError::Other(format!(
                    "Signing session failed: {}",
                    failed_state.error()
                ))))
            }
            _ => Ok(()),
        }
    }
}
