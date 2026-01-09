//! State Dispatch Module
//!
//! Command routing logic for keygen and signing state machines.
//!
//! Keygen Flow:  Initialized -> Distributing -> Completed
//! Signing Flow: Initialized -> GeneratingNonces -> CollectingNonces
//!               -> GeneratingPartialSignatures -> CollectingPartialSignatures
//!               -> FinalizingSignature -> Completed

use crate::operations::states::{keygen, signing, KeygenStatus, SigningStatus};
use crate::operations::{EnclaveSharedContext, KeygenSessionContext, SigningSessionContext};
use keymeld_core::identifiers::SessionId;
use keymeld_core::protocol::{
    Command, EnclaveCommand, EnclaveError, KeygenCommand, MusigCommand, SigningCommand,
    ValidationError,
};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, warn};

use KeygenCommand::{
    AddParticipantsBatch, DistributeParticipantPublicKeysBatch, GetAggregatePublicKey,
    InitSession as KgInitSession,
};
use KeygenStatus::{
    Completed as KgCompleted, Distributing, Failed as KgFailed, Initialized as KgInitialized,
};
use SigningCommand::{DistributeNonces, FinalizeSignature, InitSession as SigInitSession};
use SigningStatus::{
    CollectingNonces, CollectingPartialSignatures, Completed as SigCompleted, Failed as SigFailed,
    FinalizingSignature, GeneratingNonces, GeneratingPartialSignatures,
    Initialized as SigInitialized,
};

fn extract_keygen_command(cmd: &EnclaveCommand) -> Result<&KeygenCommand, EnclaveError> {
    match cmd {
        EnclaveCommand::Musig(MusigCommand::Keygen(keygen_cmd)) => Ok(keygen_cmd),
        _ => Err(EnclaveError::Validation(ValidationError::Other(
            "Expected keygen command".to_string(),
        ))),
    }
}

fn extract_signing_command(cmd: &EnclaveCommand) -> Result<&SigningCommand, EnclaveError> {
    match cmd {
        EnclaveCommand::Musig(MusigCommand::Signing(signing_cmd)) => Ok(signing_cmd),
        _ => Err(EnclaveError::Validation(ValidationError::Other(
            "Expected signing command".to_string(),
        ))),
    }
}

fn invalid_transition<S: std::fmt::Display, C: std::fmt::Debug>(
    state: &S,
    cmd: &C,
    session_id: &SessionId,
) -> EnclaveError {
    error!(
        "Invalid command {:?} for state {} in session {}",
        cmd, state, session_id
    );
    EnclaveError::Validation(ValidationError::Other(format!(
        "Command {:?} not valid for current state {}",
        cmd, state
    )))
}

fn terminal_state_error(state_type: &str) -> EnclaveError {
    warn!("Command in terminal {} state", state_type);
    EnclaveError::Validation(ValidationError::Other(format!(
        "Cannot process commands in terminal {} state",
        state_type
    )))
}

impl KeygenStatus {
    pub fn dispatch(
        self,
        keygen_ctx: &mut KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
        cmd: &EnclaveCommand,
    ) -> Result<KeygenStatus, EnclaveError> {
        let keygen_cmd = extract_keygen_command(cmd)?;
        let session_id = self.session_id().clone();
        let created_at = self.created_at();

        debug!("Keygen dispatch: state={}, command={:?}", self, keygen_cmd);

        let result = match (self, keygen_cmd) {
            // Initialized + InitSession => Distributing | Initialized
            (KgInitialized(s), KgInitSession(c)) => s.init_session(c, keygen_ctx, enclave_ctx),

            // Distributing + AddParticipantsBatch => Distributing | Completed
            (Distributing(s), AddParticipantsBatch(c)) => {
                s.add_participants(c, keygen_ctx, enclave_ctx)
            }

            // Distributing + DistributeParticipantPublicKeysBatch => Distributing | Completed
            (Distributing(s), DistributeParticipantPublicKeysBatch(c)) => {
                s.distribute_keys(c, keygen_ctx, enclave_ctx)
            }

            // Completed + GetAggregatePublicKey => Completed
            (KgCompleted(s), GetAggregatePublicKey(c)) => s.get_aggregate_key(c),

            // Idempotent: late-arriving commands on completed session
            (KgCompleted(s), KgInitSession(_))
            | (KgCompleted(s), AddParticipantsBatch(_))
            | (KgCompleted(s), DistributeParticipantPublicKeysBatch(_)) => {
                debug!("Idempotent command on completed session {}", session_id);
                Ok(KgCompleted(s))
            }

            // Terminal state
            (KgFailed(_), _) => return Err(terminal_state_error("keygen failed")),

            // Invalid transition
            (state, cmd) => return Err(invalid_transition(&state, cmd, &session_id)),
        };

        result.or_else(|e| {
            warn!("Keygen session {} failed: {}", session_id, e);
            Ok(KeygenStatus::Failed(keygen::Failed::new(
                session_id,
                created_at,
                e.to_string(),
            )))
        })
    }
}

impl SigningStatus {
    pub fn dispatch(
        self,
        signing_ctx: &mut SigningSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
        cmd: &EnclaveCommand,
    ) -> Result<SigningStatus, EnclaveError> {
        let signing_cmd = extract_signing_command(cmd)?;
        let session_id = self.session_id().clone();
        let created_at = self.created_at();

        debug!(
            "Signing dispatch: state={}, command={:?}",
            self, signing_cmd
        );

        if signing_ctx.check_command_idempotency(cmd)? {
            debug!("Command already processed for session {}", session_id);
            return Ok(self);
        }

        let result = match (self, signing_cmd) {
            // Initialized + InitSession => GeneratingNonces
            (SigInitialized(s), SigInitSession(c)) => s.init_session(c, signing_ctx, enclave_ctx),

            // GeneratingNonces (auto-processing) => CollectingNonces
            (GeneratingNonces(s), _) => s.generate_nonces(signing_ctx, enclave_ctx),

            // CollectingNonces + DistributeNonces => GeneratingPartialSignatures | CollectingNonces
            (CollectingNonces(s), DistributeNonces(c)) => {
                s.distribute_nonces(c, signing_ctx, enclave_ctx)
            }

            // GeneratingPartialSignatures (auto-processing) => CollectingPartialSignatures
            (GeneratingPartialSignatures(s), _) => {
                s.generate_partial_signatures(signing_ctx, enclave_ctx)
            }

            // CollectingPartialSignatures + FinalizeSignature => FinalizingSignature
            (CollectingPartialSignatures(s), FinalizeSignature(c)) => {
                s.collect_partial_signatures(c, signing_ctx, enclave_ctx)
            }

            // FinalizingSignature + FinalizeSignature => Completed
            (FinalizingSignature(s), FinalizeSignature(c)) => {
                s.finalize(c, signing_ctx, enclave_ctx)
            }

            // Completed + FinalizeSignature => Completed (return cached signature)
            (SigCompleted(s), FinalizeSignature(_)) => Ok(SigCompleted(s)),

            // Completed + other => Error
            (SigCompleted(_), cmd) => {
                return Err(invalid_transition(&"Completed", cmd, &session_id))
            }

            // Terminal state
            (SigFailed(_), _) => return Err(terminal_state_error("signing failed")),

            // Invalid transition
            (state, cmd) => return Err(invalid_transition(&state, cmd, &session_id)),
        };

        result
            .inspect(|_| {
                let command = Command::from(cmd.clone());
                signing_ctx.add_processed_command(command);
            })
            .or_else(|e| {
                warn!("Signing session {} failed: {}", session_id, e);
                Ok(SigningStatus::Failed(signing::Failed::new(
                    session_id,
                    created_at,
                    e.to_string(),
                )))
            })
    }
}
