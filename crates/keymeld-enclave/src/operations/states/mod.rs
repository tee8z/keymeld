use keymeld_core::enclave::{EnclaveError, InternalError, SessionError, ValidationError};
use keymeld_core::{SessionId, SessionSecret, UserId};
use sha2::{Digest, Sha256};
use std::time::SystemTime;
use tracing::{info, warn};

use crate::operations::context::EnclaveContext;

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
    pub user_id: keymeld_core::identifiers::UserId,
    pub public_key: Vec<u8>,
    pub has_private_key: bool,
}

impl ParticipantInfo {
    pub fn new(
        user_id: keymeld_core::identifiers::UserId,
        public_key: Vec<u8>,
        has_private_key: bool,
    ) -> Self {
        Self {
            user_id,
            public_key,
            has_private_key,
        }
    }
}

//TODO(@tee8z): move to core so clients can create the same hash
pub fn hash_message(message: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone)]
pub enum KeygenStatus {
    Initialized(keygen::Initialized),
    Distributing(keygen::DistributingSecrets),
    Completed(keygen::Completed),
    Failed(keygen::Failed),
}

#[derive(Debug, Clone)]
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

impl SigningStatus {
    pub fn get_user_nonce(
        &self,
        user_id: &keymeld_core::identifiers::UserId,
    ) -> Result<Option<musig2::PubNonce>, EnclaveError> {
        let (session_id, musig_processor) = match self {
            SigningStatus::Initialized(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::CollectingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::CollectingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::FinalizingSignature(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::Completed(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::Failed(state) => (&state.session_id, &state.musig_processor),
        };
        Ok(musig_processor.get_user_nonce(session_id, user_id))
    }

    pub fn get_user_nonce_data(
        &self,
        user_id: &keymeld_core::identifiers::UserId,
    ) -> Result<Option<keymeld_core::enclave::protocol::NonceData>, EnclaveError> {
        let (session_id, musig_processor) = match self {
            SigningStatus::Initialized(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::CollectingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::CollectingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::FinalizingSignature(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::Completed(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::Failed(state) => (&state.session_id, &state.musig_processor),
        };
        Ok(musig_processor.get_user_nonce_data(session_id, user_id))
    }

    pub fn has_user_nonce(
        &self,
        user_id: &keymeld_core::identifiers::UserId,
    ) -> Result<(), EnclaveError> {
        match self.get_user_nonce(user_id)? {
            Some(_) => Ok(()),
            None => Err(EnclaveError::Musig(
                keymeld_core::musig::MusigError::NotReady(format!(
                    "No nonce found for user {}",
                    user_id
                )),
            )),
        }
    }

    pub fn get_nonce_count(&self) -> Result<usize, EnclaveError> {
        let (session_id, musig_processor) = match self {
            SigningStatus::Initialized(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::CollectingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::CollectingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::FinalizingSignature(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::Completed(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::Failed(state) => (&state.session_id, &state.musig_processor),
        };
        Ok(musig_processor.get_nonce_count(session_id))
    }

    pub fn get_partial_signature_count(&self) -> Result<usize, EnclaveError> {
        let (session_id, musig_processor) = match self {
            SigningStatus::Initialized(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::CollectingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::CollectingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::FinalizingSignature(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::Completed(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::Failed(state) => (&state.session_id, &state.musig_processor),
        };
        Ok(musig_processor.get_partial_signature_count(session_id))
    }

    pub fn get_user_partial_signature(
        &self,
        user_id: &keymeld_core::identifiers::UserId,
    ) -> Result<Option<musig2::PartialSignature>, EnclaveError> {
        let (session_id, musig_processor) = match self {
            SigningStatus::Initialized(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::CollectingNonces(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::GeneratingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::CollectingPartialSignatures(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::FinalizingSignature(state) => {
                (&state.session_id, &state.musig_processor)
            }
            SigningStatus::Completed(state) => (&state.session_id, &state.musig_processor),
            SigningStatus::Failed(state) => (&state.session_id, &state.musig_processor),
        };
        Ok(musig_processor.get_user_partial_signature(session_id, user_id))
    }

    pub fn has_all_partial_signatures(&self) -> Result<bool, EnclaveError> {
        match self {
            SigningStatus::CollectingPartialSignatures(state) => {
                Ok(state.has_all_partial_signatures())
            }
            SigningStatus::FinalizingSignature(state) => state.has_all_partial_signatures(),
            _ => Ok(false),
        }
    }

    pub fn get_session_metadata_public(
        &self,
        session_id: &keymeld_core::identifiers::SessionId,
    ) -> Option<keymeld_core::musig::SessionMetadata> {
        match self {
            SigningStatus::Initialized(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            SigningStatus::GeneratingNonces(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            SigningStatus::CollectingNonces(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            SigningStatus::GeneratingPartialSignatures(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            SigningStatus::CollectingPartialSignatures(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            SigningStatus::FinalizingSignature(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            SigningStatus::Completed(state) => state
                .musig_processor
                .get_session_metadata_public(session_id),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum OperatorStatus {
    Keygen(KeygenStatus),
    Signing(SigningStatus),
}

impl OperatorStatus {
    pub fn kind(&self) -> SessionKind {
        match self {
            OperatorStatus::Keygen(_) => SessionKind::Keygen,
            OperatorStatus::Signing(_) => SessionKind::Signing,
        }
    }

    // Private keys are now managed by the MusigProcessor directly
    // This method has been removed as part of the refactor

    /// Extract musig_processor from the current state
    pub fn get_musig_processor(
        &self,
    ) -> Option<&std::sync::Arc<keymeld_core::musig::MusigProcessor>> {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => Some(&state.musig_processor),
                KeygenStatus::Distributing(state) => Some(&state.musig_processor),
                KeygenStatus::Completed(state) => Some(&state.musig_processor),
                KeygenStatus::Failed(_) => None,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => Some(&state.musig_processor),
                SigningStatus::GeneratingNonces(state) => Some(&state.musig_processor),
                SigningStatus::CollectingNonces(state) => Some(&state.musig_processor),
                SigningStatus::GeneratingPartialSignatures(state) => Some(&state.musig_processor),
                SigningStatus::CollectingPartialSignatures(state) => Some(&state.musig_processor),
                SigningStatus::FinalizingSignature(state) => Some(&state.musig_processor),
                _ => None,
            },
        }
    }

    /// Get session ID from the current state
    pub fn get_session_id(&self) -> SessionId {
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

    /// Get user key material for a specific user
    pub fn get_user_key_material(&self, user_id: &UserId) -> Option<keymeld_core::KeyMaterial> {
        // Get private key from MusigProcessor instead of state
        let session_id = self.get_session_id();
        self.get_musig_processor()
            .and_then(|processor| processor.get_private_key(&session_id, user_id))
    }

    /// Check if this is a coordinator state
    pub fn is_coordinator(&self) -> bool {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.coordinator_data.is_some(),
                KeygenStatus::Distributing(state) => state.coordinator_data.is_some(),
                KeygenStatus::Completed(state) => state.coordinator_data.is_some(),
                KeygenStatus::Failed(_) => false,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => state.coordinator_data.is_some(),
                SigningStatus::GeneratingNonces(state) => state.coordinator_data.is_some(),
                SigningStatus::CollectingNonces(state) => state.coordinator_data.is_some(),
                SigningStatus::GeneratingPartialSignatures(state) => {
                    state.coordinator_data.is_some()
                }
                SigningStatus::CollectingPartialSignatures(state) => {
                    state.coordinator_data.is_some()
                }
                SigningStatus::FinalizingSignature(state) => state.coordinator_data.is_some(),
                SigningStatus::Completed(_) => false,
                SigningStatus::Failed(_) => false,
            },
        }
    }

    /// Get coordinator data if this is a coordinator
    pub fn get_coordinator_data(&self) -> Option<&signing::CoordinatorData> {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.coordinator_data.as_ref(),
                KeygenStatus::Distributing(state) => state.coordinator_data.as_ref(),
                KeygenStatus::Completed(state) => state.coordinator_data.as_ref(),
                KeygenStatus::Failed(_) => None,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => state.coordinator_data.as_ref(),
                SigningStatus::GeneratingNonces(state) => state.coordinator_data.as_ref(),
                SigningStatus::CollectingNonces(state) => state.coordinator_data.as_ref(),
                SigningStatus::GeneratingPartialSignatures(state) => {
                    state.coordinator_data.as_ref()
                }
                SigningStatus::CollectingPartialSignatures(state) => {
                    state.coordinator_data.as_ref()
                }
                SigningStatus::FinalizingSignature(state) => state.coordinator_data.as_ref(),
                SigningStatus::Completed(_) => None,
                SigningStatus::Failed(_) => None,
            },
        }
    }

    pub fn session_id(&self) -> &SessionId {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => &state.session_id,
                KeygenStatus::Distributing(state) => &state.session_id,
                KeygenStatus::Completed(state) => &state.session_id,
                KeygenStatus::Failed(state) => &state.session_id,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => &state.session_id,
                SigningStatus::GeneratingNonces(state) => &state.session_id,
                SigningStatus::CollectingNonces(state) => &state.session_id,
                SigningStatus::GeneratingPartialSignatures(state) => &state.session_id,
                SigningStatus::CollectingPartialSignatures(state) => &state.session_id,
                SigningStatus::FinalizingSignature(state) => &state.session_id,
                SigningStatus::Completed(state) => &state.session_id,
                SigningStatus::Failed(state) => &state.session_id,
            },
        }
    }

    pub fn state_name(&self) -> &'static str {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(_) => "KeygenInitialized",
                KeygenStatus::Distributing(_) => "DistributingSecrets",
                KeygenStatus::Completed(_) => "KeygenCompleted",
                KeygenStatus::Failed(_) => "KeygenFailed",
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(_) => "SigningInitialized",
                SigningStatus::GeneratingNonces(_) => "GeneratingNonces",
                SigningStatus::CollectingNonces(_) => "CollectingNonces",
                SigningStatus::GeneratingPartialSignatures(_) => "GeneratingPartialSignatures",
                SigningStatus::CollectingPartialSignatures(_) => "CollectingPartialSignatures",
                SigningStatus::FinalizingSignature(_) => "FinalizingSignature",

                SigningStatus::Completed(_) => "SigningCompleted",
                SigningStatus::Failed(_) => "SigningFailed",
            },
        }
    }

    pub fn get_session_secret(&self) -> Option<&SessionSecret> {
        match self {
            OperatorStatus::Keygen(status) => match status {
                KeygenStatus::Initialized(state) => state.session_secret.as_ref(),
                KeygenStatus::Distributing(state) => Some(&state.session_secret),
                KeygenStatus::Completed(state) => Some(&state.session_secret),
                KeygenStatus::Failed(_) => None,
            },
            OperatorStatus::Signing(status) => match status {
                SigningStatus::Initialized(state) => Some(&state.session_secret),
                SigningStatus::GeneratingNonces(state) => Some(&state.session_secret),
                SigningStatus::CollectingNonces(state) => Some(&state.session_secret),
                SigningStatus::GeneratingPartialSignatures(state) => Some(&state.session_secret),
                SigningStatus::CollectingPartialSignatures(state) => Some(&state.session_secret),
                SigningStatus::FinalizingSignature(state) => Some(&state.session_secret),

                SigningStatus::Completed(state) => Some(&state.session_secret),
                SigningStatus::Failed(_) => None,
            },
        }
    }

    pub fn get_aggregate_public_key(&self) -> Result<musig2::secp256k1::PublicKey, EnclaveError> {
        let musig_processor =
            self.get_musig_processor()
                .ok_or(EnclaveError::Validation(ValidationError::Other(
                    "No MuSig processor available".to_string(),
                )))?;

        let session_id = self.session_id();
        musig_processor
            .get_aggregate_pubkey(session_id)
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to get aggregate public key: {e}"
                )))
            })
    }

    pub fn process(
        self,
        ctx: &mut EnclaveContext,
        cmd: &keymeld_core::enclave::EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        match self {
            OperatorStatus::Keygen(status) => status.process(ctx, cmd),
            OperatorStatus::Signing(status) => status.process(ctx, cmd),
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
                    "Signing session {} failed: {}",
                    failed_state.session_id, failed_state.error
                ))))
            }
            _ => Ok(()),
        }
    }
}

impl KeygenStatus {
    fn process(
        self,
        ctx: &mut EnclaveContext,
        cmd: &keymeld_core::enclave::EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        use crate::operations::EnclaveAdvanceable;

        match self {
            KeygenStatus::Initialized(state) => {
                let session_id = state.session_id.clone();
                handle_keygen_processing(state.process(ctx, cmd), &session_id)
            }
            KeygenStatus::Distributing(state) => {
                let session_id = state.session_id.clone();
                handle_keygen_processing(state.process(ctx, cmd), &session_id)
            }
            KeygenStatus::Completed(state) => {
                let session_id = state.session_id.clone();
                handle_keygen_processing(state.process(ctx, cmd), &session_id)
            }
            KeygenStatus::Failed(_) => Err(EnclaveError::Validation(ValidationError::Other(
                "Cannot process commands in failed state".to_string(),
            ))),
        }
    }
}

impl SigningStatus {
    fn process(
        self,
        ctx: &mut EnclaveContext,
        cmd: &keymeld_core::enclave::EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        use crate::operations::EnclaveAdvanceable;

        match self {
            SigningStatus::Initialized(state) => {
                let state_clone = state.clone();
                handle_signing_processing(state.process(ctx, cmd), state_clone)
            }
            SigningStatus::GeneratingNonces(state) => {
                let state_clone = state.clone();
                handle_signing_processing(state.process(ctx, cmd), state_clone)
            }
            SigningStatus::CollectingNonces(state) => {
                let state_clone = state.clone();
                handle_signing_processing(state.process(ctx, cmd), state_clone)
            }
            SigningStatus::GeneratingPartialSignatures(state) => {
                let state_clone = state.clone();
                handle_signing_processing(state.process(ctx, cmd), state_clone)
            }
            SigningStatus::CollectingPartialSignatures(state) => {
                let state_clone = state.clone();
                handle_signing_processing(state.process(ctx, cmd), state_clone)
            }
            SigningStatus::FinalizingSignature(state) => {
                let state_clone = state.clone();
                handle_signing_processing(state.process(ctx, cmd), state_clone)
            }
            SigningStatus::Completed(_) => Err(EnclaveError::Validation(ValidationError::Other(
                "Cannot process commands in completed state".to_string(),
            ))),
            SigningStatus::Failed(_) => Err(EnclaveError::Validation(ValidationError::Other(
                "Cannot process commands in failed state".to_string(),
            ))),
        }
    }
}

fn handle_keygen_processing(
    result: Result<OperatorStatus, EnclaveError>,
    session_id: &SessionId,
) -> Result<OperatorStatus, EnclaveError> {
    match result {
        Ok(status) => Ok(status),
        Err(e) => {
            warn!(
                "Keygen session {} failed during processing: {}",
                session_id, e
            );
            let failed_state =
                keygen::Failed::new(session_id.clone(), e.to_string(), SystemTime::now());
            info!("Keygen session {} transitioned to Failed state", session_id);
            Ok(OperatorStatus::Keygen(KeygenStatus::Failed(failed_state)))
        }
    }
}

fn handle_signing_processing<T>(
    result: Result<OperatorStatus, EnclaveError>,
    state: T,
) -> Result<OperatorStatus, EnclaveError>
where
    T: Into<signing::Failed>,
{
    match result {
        Ok(status) => Ok(status),
        Err(e) => {
            let failed_state = signing::Failed::from_state_with_error(state, e.to_string());
            warn!(
                "Signing session {} failed during processing: {}",
                failed_state.session_id, e
            );
            info!(
                "Signing session {} transitioned to Failed state with preserved MuSig processor",
                failed_state.session_id
            );
            Ok(OperatorStatus::Signing(SigningStatus::Failed(failed_state)))
        }
    }
}
