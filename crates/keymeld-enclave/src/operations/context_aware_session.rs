use crate::operations::{
    context::EnclaveSharedContext,
    keygen_data::KeygenSessionData,
    session_context::SessionContext,
    states::{create_failed_state, KeygenStatus, OperatorStatus},
    SessionKind,
};
use keymeld_core::{
    identifiers::SessionId,
    protocol::{EnclaveCommand, EnclaveError, InternalError, PhaseError},
};
use std::{
    sync::{Arc, RwLock},
    time::SystemTime,
};
use tracing::{debug, error};

#[derive(Debug)]
pub struct ContextAwareSession {
    pub status: OperatorStatus,
    pub session_context: SessionContext,
    pub enclave_context: Arc<RwLock<EnclaveSharedContext>>, // Read-only access to shared data
}

impl ContextAwareSession {
    pub fn new(
        status: OperatorStatus,
        session_context: SessionContext,
        enclave_context: Arc<RwLock<EnclaveSharedContext>>,
    ) -> Self {
        Self {
            status,
            session_context,
            enclave_context,
        }
    }

    pub fn process(&mut self, cmd: &EnclaveCommand) -> Result<(), EnclaveError> {
        debug!(
            "Processing command {:?} for session {}",
            cmd,
            self.session_context.session_id()
        );

        // Take ownership of the current status for processing
        let current_status = std::mem::take(&mut self.status);

        let new_status = match (current_status, &mut self.session_context) {
            (OperatorStatus::Keygen(keygen_status), SessionContext::Keygen(keygen_ctx)) => {
                let new_keygen_status =
                    keygen_status.dispatch(keygen_ctx, &self.enclave_context, cmd)?;
                debug!(
                    "Keygen session {} processed successfully",
                    keygen_ctx.session_id
                );
                OperatorStatus::Keygen(new_keygen_status)
            }
            (OperatorStatus::Signing(signing_status), SessionContext::Signing(signing_ctx)) => {
                let new_signing_status =
                    signing_status.dispatch(signing_ctx, &self.enclave_context, cmd)?;
                debug!(
                    "Signing session {} processed successfully",
                    signing_ctx.session_id
                );
                OperatorStatus::Signing(new_signing_status)
            }
            _ => {
                error!(
                    "Session context type mismatch with operator status for session {}",
                    self.session_context.session_id()
                );
                return Err(EnclaveError::Internal(InternalError::Other(
                    "Session context type mismatch with operator status".to_string(),
                )));
            }
        };

        self.status = new_status;
        Ok(())
    }

    pub fn extract_keygen_data(&self) -> Result<KeygenSessionData<'_>, EnclaveError> {
        match (&self.status, &self.session_context) {
            (
                OperatorStatus::Keygen(KeygenStatus::Completed(completed)),
                SessionContext::Keygen(keygen_ctx),
            ) => Ok(KeygenSessionData {
                session_secret: keygen_ctx
                    .session_secret
                    .clone()
                    .ok_or(EnclaveError::Session(
                        keymeld_core::protocol::SessionError::SecretNotInitialized,
                    ))?,
                coordinator_data: keygen_ctx.coordinator_data.clone(),
                // Use musig processor from completed state, not session context
                musig_processor: completed.musig_processor(),
                participants: completed.get_participants(),
                aggregate_public_key: completed
                    .musig_processor()
                    .get_aggregate_pubkey()
                    .map(|pk| pk.serialize().to_vec())
                    .unwrap_or_default(),
            }),
            _ => Err(EnclaveError::Phase(PhaseError::KeygenInWrongState {
                state: self.status.to_string(),
            })),
        }
    }

    pub fn check_for_failure(&self) -> Result<(), EnclaveError> {
        self.status.check_for_failure()
    }

    pub fn session_id(&self) -> &SessionId {
        self.session_context.session_id()
    }

    pub fn kind(&self) -> SessionKind {
        match &self.session_context {
            SessionContext::Keygen(_) => SessionKind::Keygen,
            SessionContext::Signing(_) => SessionKind::Signing,
        }
    }

    pub fn created_at(&self) -> SystemTime {
        match &self.session_context {
            SessionContext::Keygen(ctx) => ctx.created_at,
            SessionContext::Signing(ctx) => ctx.created_at,
        }
    }

    /// Create a failed session from an error
    pub fn create_failed_from_error(mut self, error: EnclaveError) -> Self {
        let kind = match &self.session_context {
            SessionContext::Keygen(_) => SessionKind::Keygen,
            SessionContext::Signing(_) => SessionKind::Signing,
        };

        self.status = create_failed_state(
            kind,
            self.session_context.session_id().clone(),
            self.created_at(),
            error.to_string(),
        );

        self
    }
}

impl std::fmt::Display for ContextAwareSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Session({}, {})",
            self.session_context.session_id(),
            self.status
        )
    }
}
