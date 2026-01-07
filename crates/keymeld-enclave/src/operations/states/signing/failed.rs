use keymeld_core::{
    identifiers::SessionId,
    protocol::{EnclaveCommand, EnclaveError, ValidationError},
};
use std::time::SystemTime;
use tracing::{info, warn};

use crate::operations::{
    context::EnclaveSharedContext, session_context::SigningSessionContext, states::SigningStatus,
};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct Failed {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    error: String,
}

impl Failed {
    pub(crate) fn new(session_id: SessionId, created_at: SystemTime, error: String) -> Self {
        let failed_at = SystemTime::now();
        let duration = failed_at.duration_since(created_at).unwrap_or_default();

        warn!(
            "Signing session {} failed after {:.2}s with error: {}",
            session_id,
            duration.as_secs_f64(),
            error
        );

        Self {
            session_id,
            error,
            created_at,
        }
    }

    pub fn error(&self) -> &str {
        &self.error
    }
}

impl Failed {
    pub fn process_with_context(
        self,
        _signing_ctx: &mut SigningSessionContext,
        _enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
        _cmd: &EnclaveCommand,
    ) -> Result<SigningStatus, EnclaveError> {
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
