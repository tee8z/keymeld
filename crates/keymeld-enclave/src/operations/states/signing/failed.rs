use keymeld_core::{
    enclave::{EnclaveCommand, EnclaveError, ValidationError},
    musig::MusigProcessor,
    SessionId,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::info;

use crate::operations::{
    context::EnclaveContext,
    states::{
        signing::{
            CollectingNonces, CollectingPartialSignatures, Completed, FinalizingSignature,
            GeneratingNonces, GeneratingPartialSignatures, Initialized,
        },
        OperatorStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug, Clone)]
pub struct Failed {
    pub session_id: SessionId,
    pub error: String,
    pub created_at: SystemTime,
    pub failed_at: Duration,
    pub musig_processor: Arc<MusigProcessor>,
}

impl Failed {
    pub fn new(
        session_id: SessionId,
        error: String,
        created_at: SystemTime,
        musig_processor: Arc<MusigProcessor>,
    ) -> Self {
        Self {
            session_id,
            error,
            created_at,
            failed_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default(),
            musig_processor,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn error(&self) -> &str {
        &self.error
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn failed_at(&self) -> Duration {
        self.failed_at
    }

    pub fn is_failed(&self) -> bool {
        true
    }

    pub fn failure_reason(&self) -> &str {
        &self.error
    }
}

impl EnclaveAdvanceable<OperatorStatus> for Failed {
    fn process(
        self,
        _ctx: &mut EnclaveContext,
        _cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from signing Failed state",
            self.session_id
        );

        info!(
            "Rejecting command in failed signing session {}: {}",
            self.session_id, self.error
        );
        Err(EnclaveError::Validation(ValidationError::Other(format!(
            "Cannot process commands in failed state: {}",
            self.error
        ))))
    }
}

// From implementations to convert any signing state to Failed while preserving session data
impl From<Initialized> for Failed {
    fn from(state: Initialized) -> Self {
        Failed::new(
            state.session_id,
            "Session failed during initialization".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

impl From<GeneratingNonces> for Failed {
    fn from(state: GeneratingNonces) -> Self {
        Failed::new(
            state.session_id,
            "Session failed during nonce generation".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

impl From<CollectingNonces> for Failed {
    fn from(state: CollectingNonces) -> Self {
        Failed::new(
            state.session_id,
            "Session failed during nonce collection".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

impl From<GeneratingPartialSignatures> for Failed {
    fn from(state: GeneratingPartialSignatures) -> Self {
        Failed::new(
            state.session_id,
            "Session failed during partial signature generation".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

impl From<CollectingPartialSignatures> for Failed {
    fn from(state: CollectingPartialSignatures) -> Self {
        Failed::new(
            state.session_id,
            "Session failed during partial signature collection".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

impl From<FinalizingSignature> for Failed {
    fn from(state: FinalizingSignature) -> Self {
        Failed::new(
            state.session_id,
            "Session failed during signature finalization".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

impl From<Completed> for Failed {
    fn from(state: Completed) -> Self {
        Failed::new(
            state.session_id,
            "Session transitioned to failed from completed state".to_string(),
            state.created_at,
            state.musig_processor,
        )
    }
}

// Helper function to create Failed state with custom error message
impl Failed {
    pub fn from_state_with_error<T: Into<Failed>>(state: T, error: String) -> Self {
        let mut failed = state.into();
        failed.error = error;
        failed
    }
}
