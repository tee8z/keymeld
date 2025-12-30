use anyhow::Result;
use dashmap::{
    mapref::one::{Ref, RefMut},
    DashMap,
};
use hex;
use keymeld_core::{
    crypto::{SecureCrypto, SessionSecret},
    enclave::{
        protocol::{
            DistributeParticipantPublicKeyCommand, DistributeSessionSecretCommand,
            EnclavePublicKeyInfo, EncryptedSessionSecret, KeygenInitializedResponse,
            ParticipantAddedResponse, SignatureData,
        },
        AddNonceCommand, AddPartialSignatureCommand, AddParticipantCommand,
        AggregatePublicKeyResponse, AttestationError, ConfigureCommand, CryptoError,
        EnclaveCommand, EnclaveError, EnclaveResponse, FinalSignatureResponse, FinalizeCommand,
        GenerateNonceCommand, GetAggregatePublicKeyCommand, InitKeygenSessionCommand,
        InitSigningSessionCommand, InternalError, NonceError, NonceResponse,
        ParitialSignatureCommand, ParticipantError, PhaseError, PublicInfoResponse, SessionError,
        SignatureResponse, ValidationError,
    },
    identifiers::{EnclaveId, SessionId},
};
use std::{
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

use crate::{
    attestation::AttestationManager,
    operations::{
        states::{KeygenStatus, OperatorStatus, SigningInitialized, SigningStatus},
        EnclaveContext, KeygenInitialized,
    },
};

#[derive(Debug, Clone)]
pub struct SecurePrivateKey {
    pub key: Vec<u8>,
}

pub struct EnclaveOperator {
    pub enclave_id: EnclaveId,
    pub sessions: DashMap<SessionId, OperatorStatus>,
    /// Attestation manager for generating attestations
    pub attestation_manager: Option<AttestationManager>,
    /// Enclave public key
    pub public_key: Vec<u8>,
    /// Enclave private key (zeroized on drop)
    pub private_key: Vec<u8>,
    /// Stored public keys of other enclaves for session secret distribution
    pub enclave_public_keys: DashMap<EnclaveId, String>,
    /// Enclave startup time
    startup_time: u64,
    /// Key generation time
    key_generation_time: u64,
    /// Key epoch (managed by enclave manager)
    key_epoch: Arc<RwLock<u32>>,
}

impl EnclaveOperator {
    pub fn handle_command(&self, command: EnclaveCommand) -> Result<EnclaveResponse, EnclaveError> {
        match command {
            EnclaveCommand::Ping => Ok(EnclaveResponse::Pong),
            //TODO(@tee8z): pull key from KMS when first starting up and one exists that enclave has access
            EnclaveCommand::Configure(cmd) => self.handle_configure(cmd),
            EnclaveCommand::InitKeygenSession(cmd) => self.handle_init_keygen_session(cmd),
            EnclaveCommand::DistributeSessionSecret(cmd) => {
                self.handle_distribute_session_secret(cmd)
            }
            EnclaveCommand::AddParticipant(cmd) => self.handle_add_participant(cmd),
            EnclaveCommand::DistributeParticipantPublicKey(cmd) => {
                self.handle_distribute_participant_public_key(cmd)
            }
            EnclaveCommand::InitSigningSession(cmd) => self.handle_init_signing_session(cmd),
            EnclaveCommand::GenerateNonce(cmd) => self.handle_generate_nonce(cmd),
            EnclaveCommand::AddNonce(cmd) => self.handle_add_nonce(cmd),
            EnclaveCommand::SignPartialSignature(cmd) => self.handle_sign_partial_signature(cmd),
            EnclaveCommand::AddPartialSignature(cmd) => self.handle_add_partial_signature(cmd),
            EnclaveCommand::GetAggregatePublicKey(cmd) => self.handle_get_aggregate_public_key(cmd),
            EnclaveCommand::Finalize(cmd) => self.handle_finalize(cmd),
            EnclaveCommand::ClearSession(cmd) => {
                let session_id = cmd.keygen_session_id.or(cmd.signing_session_id).ok_or(
                    EnclaveError::Session(SessionError::InvalidId(
                        "Either keygen_session_id or signing_session_id must be provided"
                            .to_string(),
                    )),
                )?;

                self.clear_session(session_id)?;
                Ok(EnclaveResponse::Success)
            }

            EnclaveCommand::GetPublicInfo => {
                let active_sessions_count = self.sessions.iter().count() as u32;
                let attestation_document =
                    if let Some(attestation_manager) = &self.attestation_manager {
                        match attestation_manager
                            .get_identity_attestation_with_data(Some(self.get_public_key()))
                        {
                            Ok(Some(attestation_doc)) => Some(attestation_doc),
                            Ok(None) => None,
                            Err(e) => {
                                return Err(EnclaveError::Attestation(
                                    AttestationError::GenerationFailed(format!("{e}")),
                                ));
                            }
                        }
                    } else {
                        None
                    };

                Ok(EnclaveResponse::PublicInfo(PublicInfoResponse {
                    public_key: hex::encode(&self.public_key),
                    attestation_document,
                    active_sessions: active_sessions_count,
                    uptime_seconds: self.get_uptime_seconds(),
                    key_epoch: *self.key_epoch.read().unwrap() as u64,
                    key_generation_time: self.key_generation_time,
                }))
            }
        }
    }

    pub fn new(enclave_id: EnclaveId) -> Result<Self, EnclaveError> {
        let keypair = SecureCrypto::generate_enclave_keypair()
            .map_err(|e| EnclaveError::Crypto(CryptoError::KeypairGeneration(format!("{e}"))))?;
        let startup_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                error!("Failed to get system time: {}", e);
                EnclaveError::Internal(InternalError::SystemTime)
            })?
            .as_secs();

        info!(
            "Enclave {} starting with startup time: {}",
            enclave_id, startup_time
        );

        Ok(EnclaveOperator {
            enclave_id,
            sessions: DashMap::new(),
            attestation_manager: None,
            public_key: keypair.1.serialize().to_vec(),
            private_key: keypair.0.secret_bytes().to_vec(),
            enclave_public_keys: DashMap::new(),
            startup_time,
            key_generation_time: startup_time,
            key_epoch: Arc::new(RwLock::new(1)),
        })
    }

    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn handle_configure(&self, cmd: ConfigureCommand) -> Result<EnclaveResponse, EnclaveError> {
        info!(
            "Configuring enclave {}, key_epoch: {:?}",
            cmd.enclave_id, cmd.key_epoch
        );

        // The configure command is used by the manager to set/update our epoch
        // This happens when the manager detects this enclave has restarted (new keys)
        if let Some(new_epoch) = cmd.key_epoch {
            let new_epoch = new_epoch as u32;
            let current_epoch = *self.key_epoch.read().unwrap();

            if new_epoch != current_epoch {
                info!(
                    "Manager updating epoch from {} to {} (enclave restart detected)",
                    current_epoch, new_epoch
                );
                *self.key_epoch.write().unwrap() = new_epoch;
            } else {
                info!("Epoch {} confirmed by manager", current_epoch);
            }
        }

        let current_epoch = *self.key_epoch.read().unwrap();
        info!(
            "Enclave {} configured successfully. Current epoch: {}, public key: {}",
            cmd.enclave_id,
            current_epoch,
            hex::encode(&self.public_key[..8])
        );

        Ok(EnclaveResponse::Success)
    }

    fn handle_init_keygen_session(
        &self,
        cmd: InitKeygenSessionCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.keygen_session_id.clone();

        info!(
            "Initializing keygen session {} for {} participants",
            session_id, cmd.expected_participant_count
        );

        if !self.sessions.contains_key(&session_id) {
            // Create new MusigProcessor for this keygen session
            let musig_processor = Arc::new(keymeld_core::musig::MusigProcessor::new());
            let initial_state = KeygenInitialized::new(session_id.clone(), musig_processor);
            let operator_status = OperatorStatus::Keygen(KeygenStatus::Initialized(initial_state));
            self.sessions.insert(session_id.clone(), operator_status);
        }

        let final_state =
            self.execute_operation(&session_id, EnclaveCommand::InitKeygenSession(cmd.clone()))?;

        match &final_state {
            OperatorStatus::Keygen(_) => {
                let session = self.get_session(&session_id)?;
                if let Some(session_secret) = session.get_session_secret() {
                    if session.is_coordinator() {
                        let encrypted_secrets = self
                            .encrypt_session_secret_for_other_enclaves(
                                session_secret,
                                &cmd.enclave_public_keys,
                            )
                            .map_err(|e| {
                                error!(
                                    "Critical failure: Unable to encrypt session secrets for other enclaves: {}",
                                    e
                                );
                                EnclaveError::Crypto(CryptoError::EncryptionFailed {
                                    context: "multi-enclave session secrets".to_string(),
                                    error: format!("{e}"),
                                })
                            })?;

                        return Ok(EnclaveResponse::KeygenInitialized(
                            KeygenInitializedResponse {
                                keygen_session_id: session_id,
                                encrypted_session_secrets: encrypted_secrets,
                            },
                        ));
                    }
                }
                Ok(EnclaveResponse::Success)
            }
            _ => Err(EnclaveError::Validation(ValidationError::Other(
                "Unexpected state after keygen initialization".to_string(),
            ))),
        }
    }

    fn handle_init_signing_session(
        &self,
        cmd: InitSigningSessionCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let signing_session_id = cmd.signing_session_id.clone();

        if self.get_session(&signing_session_id).is_ok() {
            return Ok(EnclaveResponse::Success);
        }

        let keygen_session = self.get_session(&cmd.keygen_session_id)?;
        let OperatorStatus::Keygen(KeygenStatus::Completed(ref completed)) = keygen_session.value()
        else {
            return Err(EnclaveError::Phase(PhaseError::KeygenInWrongState {
                state: keygen_session.value().state_name().to_string(),
            }));
        };

        let participants = completed.get_participants();
        let expected_participant_count = completed.get_expected_participant_count().unwrap_or(0);

        debug!(
            "Creating signing session from completed keygen - participants: {}, expected: {}",
            participants.len(),
            expected_participant_count
        );
        debug!("Completed keygen participants: {:?}", participants);

        let initial_state =
            SigningInitialized::new(signing_session_id.clone(), completed.to_owned());

        // Private keys are now managed by the MusigProcessor directly
        debug!(
            "Signing session {} will use private keys stored in MusigProcessor from keygen session {}",
            signing_session_id,
            cmd.keygen_session_id
        );

        let operator_status = OperatorStatus::Signing(SigningStatus::Initialized(initial_state));
        self.sessions
            .insert(signing_session_id.clone(), operator_status);

        self.execute_operation(
            &signing_session_id,
            EnclaveCommand::InitSigningSession(cmd.clone()),
        )?;

        Ok(EnclaveResponse::Success)
    }

    fn handle_add_participant(
        &self,
        cmd: AddParticipantCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd
            .signing_session_id
            .clone()
            .or(cmd.keygen_session_id.clone())
            .ok_or(EnclaveError::Session(SessionError::InvalidId(
                "Either keygen_session_id or signing_session_id must be provided".to_string(),
            )))?;

        let final_state = self
            .execute_operation(&session_id, EnclaveCommand::AddParticipant(cmd.clone()))
            .map_err(|e| match e {
                EnclaveError::Signing(_) => {
                    error!(
                        "Failed to process participant {} through operations: {}",
                        cmd.user_id, e
                    );
                    EnclaveError::Participant(ParticipantError::Other(format!(
                        "Failed to process participant: {e}"
                    )))
                }
                other => other,
            })?;

        let encrypted_public_keys = match &final_state {
            OperatorStatus::Keygen(KeygenStatus::Initialized(state)) => {
                state.encrypted_public_keys_for_response.clone()
            }
            OperatorStatus::Keygen(KeygenStatus::Distributing(state)) => {
                state.encrypted_public_keys_for_response.clone()
            }
            OperatorStatus::Keygen(KeygenStatus::Completed(state)) => {
                // Return encrypted keys from completed state if they exist
                state.encrypted_public_keys_for_response.clone()
            }
            _ => {
                // For signing sessions or other states, return empty
                vec![]
            }
        };

        info!(
            "Participant {} added to session {} successfully",
            cmd.user_id, session_id
        );

        if !encrypted_public_keys.is_empty() {
            let key_count = encrypted_public_keys.len();
            // Return the encrypted public keys for distribution to other enclaves
            Ok(EnclaveResponse::ParticipantAdded(
                ParticipantAddedResponse {
                    user_id: cmd.user_id.clone(),
                    encrypted_public_keys,
                    message: format!(
                        "Participant {} added to session with encrypted public keys for {} enclaves",
                        cmd.user_id,
                        key_count
                    ),
                },
            ))
        } else {
            Ok(EnclaveResponse::Success)
        }
    }

    fn handle_distribute_participant_public_key(
        &self,
        cmd: DistributeParticipantPublicKeyCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        self.execute_operation(
            &cmd.keygen_session_id,
            EnclaveCommand::DistributeParticipantPublicKey(cmd.clone()),
        )?;

        info!(
            "Participant {} public key distributed to session {} successfully",
            cmd.user_id, cmd.keygen_session_id
        );

        Ok(EnclaveResponse::Success)
    }

    fn create_enclave_context(&self) -> EnclaveContext {
        //TODO(@tee8z): add the keys in the new() function, not an additional builder
        let ctx = EnclaveContext::new(
            self.enclave_id,
            self.public_key.clone(),
            self.private_key.clone(),
            self.attestation_manager.clone(),
        );

        for entry in self.enclave_public_keys.iter() {
            ctx.add_enclave_public_key(*entry.key(), entry.value().clone());
        }

        ctx
    }

    fn execute_operation(
        &self,
        session_id: &SessionId,
        command: EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        let initial_enclave_keys_count = self.create_enclave_context().enclave_public_keys.len();

        let (final_state, updated_enclave_keys) = {
            let mut session = self.get_session_mut(session_id)?;
            let operation_state = session.value().clone();
            let mut ctx = self.create_enclave_context();

            let final_state = operation_state
                .process(&mut ctx, &command)
                .map_err(|e| EnclaveError::Internal(InternalError::Other(e.to_string())))?;

            *session = final_state.clone();

            let updated_keys = if ctx.enclave_public_keys.len() > initial_enclave_keys_count {
                Some(ctx.enclave_public_keys.clone())
            } else {
                None
            };

            (final_state, updated_keys)
        };

        if let Some(updated_keys) = updated_enclave_keys {
            info!(
                "Context enclave keys updated during operation: {} -> {} keys, syncing back",
                initial_enclave_keys_count,
                updated_keys.len()
            );
            for entry in updated_keys.iter() {
                self.enclave_public_keys
                    .insert(*entry.key(), entry.value().clone());
            }
        }

        final_state.check_for_failure()?;

        Ok(final_state)
    }

    fn handle_distribute_session_secret(
        &self,
        cmd: DistributeSessionSecretCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.keygen_session_id.clone();
        self.execute_operation(&session_id, EnclaveCommand::DistributeSessionSecret(cmd))?;

        Ok(EnclaveResponse::Success)
    }

    pub fn encrypt_session_secret_for_other_enclaves(
        &self,
        session_secret: &SessionSecret,
        target_enclaves: &[EnclavePublicKeyInfo],
    ) -> Result<Vec<EncryptedSessionSecret>, EnclaveError> {
        let ctx = self.create_enclave_context();
        let mut encrypted_secrets = Vec::new();

        for enclave_info in target_enclaves {
            if enclave_info.enclave_id == self.enclave_id {
                continue;
            }

            let encrypted_session_secret = ctx
                .encrypt_session_secret_for_enclave(&enclave_info.public_key, session_secret)
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::EncryptionFailed {
                        context: format!("session secret for enclave {}", enclave_info.enclave_id),
                        error: format!("{e}"),
                    })
                })?;

            encrypted_secrets.push(EncryptedSessionSecret {
                target_enclave_id: enclave_info.enclave_id,
                encrypted_session_secret,
            });
        }

        Ok(encrypted_secrets)
    }

    pub fn get_uptime_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| {
                error!("Failed to get system time for uptime calculation: {}", e);
                Duration::from_secs(0)
            })
            .as_secs()
            - self.startup_time
    }

    pub fn clear_session(&self, session_id: SessionId) -> Result<(), EnclaveError> {
        let session_exists_before = self.sessions.contains_key(&session_id);
        info!(
            "Clearing session {} (exists_before={})",
            session_id, session_exists_before
        );

        if let Some(session) = self.sessions.get(&session_id) {
            if let Some(processor) = session.get_musig_processor() {
                processor.clear_session(&session_id);
                info!("Cleared MuSig processor state for session {}", session_id);
            } else {
                warn!("No MuSig processor found for session {}", session_id);
            }
        } else {
            info!(
                "Session {} not found in sessions map during clear",
                session_id
            );
        }

        if self.sessions.remove(&session_id).is_some() {
            info!("Session {} cleared successfully", session_id);
        } else {
            warn!("Session {} was not found during clear", session_id);
        }

        Ok(())
    }

    fn get_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Ref<'_, SessionId, OperatorStatus>, EnclaveError> {
        self.sessions
            .get(session_id)
            .ok_or(EnclaveError::Session(SessionError::NotFound(
                session_id.clone(),
            )))
            .inspect_err(|err| error!("{err}"))
    }

    fn get_session_mut(
        &self,
        session_id: &SessionId,
    ) -> Result<RefMut<'_, SessionId, OperatorStatus>, EnclaveError> {
        self.sessions
            .get_mut(session_id)
            .ok_or(EnclaveError::Session(SessionError::NotFound(
                session_id.clone(),
            )))
            .inspect_err(|err| error!("{err}"))
    }

    fn handle_generate_nonce(
        &self,
        cmd: GenerateNonceCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.signing_session_id.clone();

        let final_state =
            self.execute_operation(&session_id, EnclaveCommand::GenerateNonce(cmd.clone()))?;

        let nonce = match &final_state {
            OperatorStatus::Signing(signing_status) => {
                signing_status.get_user_nonce_data(&cmd.user_id).map_err(|e| {
                    EnclaveError::Internal(InternalError::Other(format!(
                        "Failed to get nonce data for user {} in session {}: {}",
                        cmd.user_id, session_id, e
                    )))
                })?.ok_or(
                    EnclaveError::Internal(InternalError::StateInconsistency(format!(
                        "Nonce data not found after generation for user {} in session {} (state has {} nonces)",
                        cmd.user_id, session_id,
                        signing_status.get_nonce_count().unwrap_or(0)
                    )))
                )?
            }
            _ => {
                return Err(EnclaveError::Internal(InternalError::StateInconsistency(
                    format!(
                        "Unexpected state after nonce generation: expected Signing state, got different state for session {}",
                        session_id
                    )
                )))
            }
        };

        Ok(EnclaveResponse::Nonce(NonceResponse {
            signing_session_id: session_id,
            keygen_session_id: cmd.keygen_session_id,
            user_id: cmd.user_id,
            nonce_data: nonce,
        }))
    }

    fn handle_add_nonce(&self, cmd: AddNonceCommand) -> Result<EnclaveResponse, EnclaveError> {
        self.execute_operation(
            &cmd.signing_session_id,
            EnclaveCommand::AddNonce(cmd.clone()),
        )
        .map_err(|e| match e {
            EnclaveError::Signing(_) => EnclaveError::Nonce(NonceError::AddFailed {
                user_id: cmd.user_id.clone(),
                error: format!("{e}"),
            }),
            other => other,
        })?;

        Ok(EnclaveResponse::Success)
    }

    fn handle_sign_partial_signature(
        &self,
        cmd: ParitialSignatureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let signing_session_id = cmd.signing_session_id.clone();
        let keygen_session_id = cmd.keygen_session_id.clone();
        let user_id = cmd.user_id.clone();

        let final_state = self.execute_operation(
            &signing_session_id,
            EnclaveCommand::SignPartialSignature(cmd),
        )?;

        let signature = match &final_state {
            OperatorStatus::Signing(signing_status) => {
                signing_status.get_user_partial_signature(&user_id).map_err(|e| {
                    EnclaveError::Internal(InternalError::Other(format!(
                        "Failed to get partial signature for user {} in session {}: {}",
                        user_id, signing_session_id, e
                    )))
                })?.ok_or(
                    EnclaveError::Internal(InternalError::StateInconsistency(format!(
                        "Partial signature not found after generation for user {} in session {} (state has {} signatures)",
                        user_id, signing_session_id,
                        signing_status.get_partial_signature_count().unwrap_or(0)
                    )))
                )?
            }
            _ => {
                return Err(EnclaveError::Internal(InternalError::StateInconsistency(
                    format!(
                        "Unexpected state after partial signature generation: expected Signing state, got different state for session {}",
                        signing_session_id
                    )
                )))
            }
        };

        // Check if this is an adaptor signatures session and get signatures
        match &final_state {
            OperatorStatus::Signing(
                crate::operations::states::SigningStatus::GeneratingPartialSignatures(state),
            ) => {
                let has_adaptor_configs = state
                    .musig_processor
                    .get_session_metadata_public(&signing_session_id)
                    .map(|metadata| !metadata.adaptor_configs.is_empty())
                    .unwrap_or(false);

                if has_adaptor_configs {
                    // For adaptor signatures, get all adaptor signatures for this user
                    let adaptor_signatures = state
                        .musig_processor
                        .get_user_adaptor_signatures(&signing_session_id, &user_id);

                    Ok(EnclaveResponse::Signature(SignatureResponse {
                        signing_session_id,
                        keygen_session_id,
                        user_id,
                        signature_data: SignatureData::Adaptor(adaptor_signatures),
                    }))
                } else {
                    // For regular signatures, use the single signature
                    Ok(EnclaveResponse::Signature(SignatureResponse {
                        signing_session_id,
                        keygen_session_id,
                        user_id,
                        signature_data: SignatureData::Regular(signature),
                    }))
                }
            }
            OperatorStatus::Signing(
                crate::operations::states::SigningStatus::CollectingPartialSignatures(state),
            ) => {
                let has_adaptor_configs = state
                    .musig_processor
                    .get_session_metadata_public(&signing_session_id)
                    .map(|metadata| !metadata.adaptor_configs.is_empty())
                    .unwrap_or(false);

                if has_adaptor_configs {
                    let adaptor_signatures = state
                        .musig_processor
                        .get_user_adaptor_signatures(&signing_session_id, &user_id);

                    Ok(EnclaveResponse::Signature(SignatureResponse {
                        signing_session_id,
                        keygen_session_id,
                        user_id,
                        signature_data: SignatureData::Adaptor(adaptor_signatures),
                    }))
                } else {
                    Ok(EnclaveResponse::Signature(SignatureResponse {
                        signing_session_id,
                        keygen_session_id,
                        user_id,
                        signature_data: SignatureData::Regular(signature),
                    }))
                }
            }
            _ => {
                // For other states or regular signatures, use the single signature
                Ok(EnclaveResponse::Signature(SignatureResponse {
                    signing_session_id,
                    keygen_session_id,
                    user_id,
                    signature_data: SignatureData::Regular(signature),
                }))
            }
        }
    }

    fn handle_add_partial_signature(
        &self,
        cmd: AddPartialSignatureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        self.execute_operation(
            &cmd.signing_session_id,
            EnclaveCommand::AddPartialSignature(cmd.clone()),
        )?;

        Ok(EnclaveResponse::Success)
    }

    fn handle_get_aggregate_public_key(
        &self,
        cmd: GetAggregatePublicKeyCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session = self.get_session(&cmd.keygen_session_id)?;

        let aggregate_public_key =
            self.get_aggregate_public_key_from_session(&session, &cmd.keygen_session_id)?;

        let participant_count = session
            .get_musig_processor()
            .map(|processor| processor.get_user_session_count(&cmd.keygen_session_id))
            .unwrap_or(0);
        let aggregate_public_key = aggregate_public_key.serialize().to_vec();
        Ok(EnclaveResponse::AggregatePublicKey(
            AggregatePublicKeyResponse {
                keygen_session_id: cmd.keygen_session_id,
                aggregate_public_key,
                participant_count,
            },
        ))
    }

    fn get_aggregate_public_key_from_session(
        &self,
        session: &OperatorStatus,
        keygen_session_id: &SessionId,
    ) -> Result<musig2::secp256k1::PublicKey, EnclaveError> {
        let musig_processor = session
            .get_musig_processor()
            .ok_or(EnclaveError::Internal(InternalError::MissingMusigProcessor))?;
        musig_processor
            .get_aggregate_pubkey(keygen_session_id)
            .map_err(|e| EnclaveError::Session(SessionError::AggregateKeyRetrieval(format!("{e}"))))
    }

    fn handle_finalize(&self, cmd: FinalizeCommand) -> Result<EnclaveResponse, EnclaveError> {
        let signing_session_id = cmd.signing_session_id.clone();
        let keygen_session_id = cmd.keygen_session_id.clone();
        self.execute_operation(&signing_session_id, EnclaveCommand::Finalize(cmd))?;

        let session = self.get_session(&signing_session_id)?;
        if let OperatorStatus::Signing(SigningStatus::Completed(completed_state)) = session.value()
        {
            Ok(EnclaveResponse::FinalSignature(FinalSignatureResponse {
                signing_session_id,
                keygen_session_id,
                final_signature: completed_state
                    .encrypted_signed_message
                    .to_bytes()
                    .map_err(|e| {
                        EnclaveError::Internal(InternalError::Serialization(format!(
                            "encrypted signature: {e}"
                        )))
                    })?,
                participant_count: completed_state.participant_count as usize,
                encrypted_adaptor_signatures: completed_state
                    .encrypted_adaptor_signatures
                    .as_ref()
                    .map(|encrypted_data| {
                        encrypted_data.to_bytes().map_err(|e| {
                            EnclaveError::Internal(InternalError::Serialization(format!(
                                "encrypted adaptor signatures: {e}"
                            )))
                        })
                    })
                    .transpose()?,
            }))
        } else {
            Err(EnclaveError::Internal(InternalError::StateInconsistency(
                "Failed to finalize signature - session not in completed state".to_string(),
            )))
        }
    }
}

impl Drop for EnclaveOperator {
    fn drop(&mut self) {
        info!("Dropping EnclaveOperator and zeroizing sensitive data");
        self.private_key.zeroize();
    }
}
