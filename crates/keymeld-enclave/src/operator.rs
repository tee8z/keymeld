use anyhow::Result;
use dashmap::DashMap;
use hex;
use keymeld_core::{
    identifiers::{EnclaveId, SessionId},
    managed_vsock::ServerCommandHandler,
    protocol::{
        AggregatePublicKeyResponse, AttestationError, Command, ConfigureCommand,
        ConfiguredResponse, EnclaveCommand, EnclaveError, EnclaveOutcome, FinalSignatureResponse,
        InitKeygenSessionCommand, InitSigningSessionCommand, InternalError, KeygenCommand,
        KeygenInitializedResponse, KeygenOutcome, MusigCommand, MusigOutcome, NonceError,
        NoncesResponse, Outcome, PartialSignatureResponse, ParticipantsAddedBatchResponse,
        PublicInfoResponse, SessionError, SigningCommand, SigningOutcome, SystemCommand,
        SystemOutcome,
    },
};

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info};
use zeroize::Zeroize;

use crate::{
    attestation::AttestationManager,
    musig::MusigProcessor,
    operations::{
        context_aware_session::ContextAwareSession,
        create_signing_musig_from_keygen,
        session_context::{create_signing_session_context, KeygenSessionContext, SessionContext},
        states::{KeygenStatus, OperatorStatus, SigningStatus},
        user_key_handler::handle_user_key_command,
        user_key_store::UserKeyStore,
        EnclaveSharedContext, KeygenInitialized, SigningInitialized,
    },
    queue::Queue,
};

#[derive(Debug, Clone)]
pub struct SecurePrivateKey {
    pub key: Vec<u8>,
}

pub struct EnclaveCommandHandler {
    operator: Arc<EnclaveOperator>,
}

impl EnclaveCommandHandler {
    pub fn new(operator: Arc<EnclaveOperator>) -> Self {
        Self { operator }
    }
}

impl ServerCommandHandler<Command, Outcome> for EnclaveCommandHandler {
    fn handle_command(
        &self,
        command: Command,
    ) -> Pin<Box<dyn Future<Output = Result<Outcome, anyhow::Error>> + Send + '_>> {
        Box::pin(async move {
            self.operator
                .handle_command(command)
                .await
                .map_err(|e| anyhow::anyhow!("Enclave operation failed: {}", e))
        })
    }
}

pub struct EnclaveOperator {
    pub enclave_id: EnclaveId,
    pub sessions: Arc<DashMap<SessionId, ContextAwareSession>>,
    /// Keygen sessions for accessing participant data (used by UserKey commands)
    pub keygen_sessions: Arc<DashMap<SessionId, Arc<MusigProcessor>>>,
    /// User key store for single-signer operations
    pub user_key_store: Arc<UserKeyStore>,
    pub attestation_manager: Option<AttestationManager>,
    pub public_key: Arc<RwLock<Vec<u8>>>,
    pub private_key: Arc<RwLock<Vec<u8>>>,
    master_dek: Arc<RwLock<Option<[u8; 32]>>>,
    pub enclave_public_keys: Arc<DashMap<EnclaveId, String>>,
    context: Arc<RwLock<EnclaveSharedContext>>,
    queue: Queue,
    startup_time: u64,
    key_generation_time: u64,
    key_epoch: AtomicU32,
    keys_initialized: AtomicBool,
}

impl EnclaveOperator {
    pub async fn handle_command(&self, command: Command) -> Result<Outcome, EnclaveError> {
        info!("command: {}", command.command);

        let enclave_outcome = match &command.command {
            EnclaveCommand::System(system_cmd) => {
                self.handle_system_command(system_cmd.clone()).await
            }
            EnclaveCommand::Musig(musig_cmd) => {
                self.handle_musig_command(command.clone(), musig_cmd.clone())
                    .await
            }
            EnclaveCommand::UserKey(user_key_cmd) => {
                // Get the enclave context for crypto operations
                let enclave_ctx = self.context.read().unwrap().clone();

                // Handle user key command
                let outcome = handle_user_key_command(
                    user_key_cmd.clone(),
                    &self.user_key_store,
                    &enclave_ctx,
                    Some(&self.keygen_sessions),
                )
                .await?;

                Ok(EnclaveOutcome::UserKey(outcome))
            }
        }?;

        Ok(Outcome::new(command, enclave_outcome))
    }

    async fn handle_system_command(
        &self,
        command: SystemCommand,
    ) -> Result<EnclaveOutcome, EnclaveError> {
        match command {
            SystemCommand::Ping => Ok(EnclaveOutcome::System(SystemOutcome::Pong)),
            SystemCommand::Configure(cmd) => {
                self.handle_configure(cmd)
                    .await
                    .map(|response| match response {
                        Some(configured) => {
                            EnclaveOutcome::System(SystemOutcome::Configured(configured))
                        }
                        None => EnclaveOutcome::System(SystemOutcome::Success),
                    })
            }
            SystemCommand::GetPublicInfo => self.handle_get_public_info().await,
            SystemCommand::GetAttestation => self.handle_get_attestation().await,
            SystemCommand::ClearSession(cmd) => {
                let session_id = cmd.keygen_session_id.or(cmd.signing_session_id).ok_or(
                    EnclaveError::Session(SessionError::InvalidId(
                        "Either keygen_session_id or signing_session_id must be provided"
                            .to_string(),
                    )),
                )?;

                self.sessions.remove(&session_id);
                Ok(EnclaveOutcome::System(SystemOutcome::Success))
            }
        }
    }

    async fn handle_musig_command(
        &self,
        command: Command,
        musig_command: MusigCommand,
    ) -> Result<EnclaveOutcome, EnclaveError> {
        let session_id = command.command.session_id()?;

        info!(
            "Routing command {} to session {} through queue",
            command.command, session_id
        );

        if !self.sessions.contains_key(&session_id) {
            self.create_session_if_init_command(&musig_command).await?;
        }

        self.queue
            .process_command(session_id.clone(), command)
            .await?;

        self.extract_response_from_session(&session_id, &musig_command)
            .await
    }

    async fn create_session_if_init_command(
        &self,
        command: &MusigCommand,
    ) -> Result<(), EnclaveError> {
        match command {
            MusigCommand::Signing(SigningCommand::InitSession(cmd)) => {
                self.create_signing_session(cmd).await
            }
            MusigCommand::Keygen(KeygenCommand::InitSession(cmd)) => {
                self.create_keygen_session(cmd).await
            }
            _ => {
                // Non-init commands expect session to already exist
                let session_id = EnclaveCommand::Musig(command.clone()).session_id()?;
                Err(EnclaveError::Session(SessionError::NotFound(session_id)))
            }
        }
    }

    async fn create_signing_session(
        &self,
        cmd: &InitSigningSessionCommand,
    ) -> Result<(), EnclaveError> {
        info!(
            "Creating new signing session: {} from keygen session: {}",
            cmd.signing_session_id, cmd.keygen_session_id
        );

        // Build the session while holding the keygen session lock, then drop the lock
        // before inserting to avoid DashMap deadlock when keygen and signing session
        // IDs hash to the same shard
        let session = {
            let keygen_session =
                self.sessions
                    .get(&cmd.keygen_session_id)
                    .ok_or(EnclaveError::Session(SessionError::NotFound(
                        cmd.keygen_session_id.clone(),
                    )))?;

            let keygen_data = keygen_session.extract_keygen_data()?;

            let signing_processor = create_signing_musig_from_keygen(&keygen_data, cmd)?;

            let signing_context = create_signing_session_context(cmd, &keygen_data)?;

            let initial_state = SigningInitialized::new(
                cmd.signing_session_id.clone(),
                keygen_data.session_secret.clone(),
                keygen_data.coordinator_data.clone(),
                signing_processor,
            );

            ContextAwareSession::new(
                OperatorStatus::Signing(SigningStatus::Initialized(initial_state)),
                SessionContext::Signing(Box::new(signing_context)),
                self.context.clone(),
            )
            // keygen_session lock is dropped here at end of block
        };

        self.sessions
            .insert(cmd.signing_session_id.clone(), session);

        info!("Created signing session: {}", cmd.signing_session_id);
        Ok(())
    }

    async fn create_keygen_session(
        &self,
        cmd: &InitKeygenSessionCommand,
    ) -> Result<(), EnclaveError> {
        info!("Creating new keygen session: {}", cmd.keygen_session_id);

        let keygen_context = KeygenSessionContext::from((cmd, &self.context));
        let session_context = SessionContext::Keygen(Box::new(keygen_context));

        let initial_state = KeygenInitialized::new(cmd.keygen_session_id.clone());

        let session = ContextAwareSession::new(
            OperatorStatus::Keygen(KeygenStatus::Initialized(initial_state)),
            session_context,
            self.context.clone(),
        );

        self.sessions.insert(cmd.keygen_session_id.clone(), session);

        info!("Created keygen session: {}", cmd.keygen_session_id);
        Ok(())
    }

    async fn extract_response_from_session(
        &self,
        session_id: &SessionId,
        command: &MusigCommand,
    ) -> Result<EnclaveOutcome, EnclaveError> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EnclaveError::Session(SessionError::NotFound(session_id.clone())))?;

        match command {
            MusigCommand::Keygen(keygen_cmd) => {
                self.extract_keygen_response(&session, keygen_cmd).await
            }
            MusigCommand::Signing(signing_cmd) => {
                self.extract_signing_response(&session, signing_cmd).await
            }
        }
    }

    async fn extract_keygen_response(
        &self,
        session: &ContextAwareSession,
        command: &KeygenCommand,
    ) -> Result<EnclaveOutcome, EnclaveError> {
        match command {
            KeygenCommand::InitSession(_cmd) => match &session.status {
                OperatorStatus::Keygen(keygen_status) => {
                    let response = Self::extract_keygen_init_response(
                        keygen_status,
                        &session.session_context,
                    )?;
                    Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(response)))
                }
                _ => Err(EnclaveError::Internal(InternalError::Other(
                    "Expected keygen status for keygen command".to_string(),
                ))),
            },
            KeygenCommand::GetAggregatePublicKey(_cmd) => {
                let keygen_data = session.extract_keygen_data()?;

                // Get session secret for encryption
                let session_secret = match &session.session_context {
                    SessionContext::Keygen(ctx) => {
                        ctx.session_secret.as_ref().ok_or_else(|| {
                            EnclaveError::Internal(InternalError::Other(
                                "Session secret not available for encryption".to_string(),
                            ))
                        })?
                    }
                    _ => {
                        return Err(EnclaveError::Internal(InternalError::Other(
                            "Expected keygen session context for aggregate public key".to_string(),
                        )))
                    }
                };

                // Encrypt the aggregate public key
                let encrypted = session_secret
                    .encrypt(&keygen_data.aggregate_public_key, "aggregate_public_key")
                    .map_err(|e| {
                        EnclaveError::Internal(InternalError::Other(format!(
                            "Failed to encrypt aggregate public key: {}",
                            e
                        )))
                    })?;

                let encrypted_aggregate_public_key = encrypted.to_hex().map_err(|e| {
                    EnclaveError::Internal(InternalError::Other(format!(
                        "Failed to encode encrypted aggregate public key: {}",
                        e
                    )))
                })?;

                Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(
                    KeygenOutcome::AggregatePublicKey(AggregatePublicKeyResponse {
                        keygen_session_id: session.session_id().to_owned(),
                        encrypted_aggregate_public_key,
                        participant_count: keygen_data.participants.len(),
                    }),
                )))
            }
            KeygenCommand::AddParticipantsBatch(_cmd) => {
                // Extract batch response data from the session state
                match &session.status {
                    OperatorStatus::Keygen(KeygenStatus::Distributing(distributing)) => {
                        let batch_data = distributing.batch_encrypted_keys();
                        let participant_ids: Vec<_> =
                            batch_data.iter().map(|(uid, _)| uid.clone()).collect();

                        Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(
                            KeygenOutcome::ParticipantsAddedBatch(ParticipantsAddedBatchResponse {
                                participants: participant_ids,
                                encrypted_public_keys: batch_data,
                            }),
                        )))
                    }
                    OperatorStatus::Keygen(KeygenStatus::Completed(completed)) => {
                        let batch_data = completed.batch_encrypted_keys();
                        let participant_ids: Vec<_> =
                            batch_data.iter().map(|(uid, _)| uid.clone()).collect();

                        Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(
                            KeygenOutcome::ParticipantsAddedBatch(ParticipantsAddedBatchResponse {
                                participants: participant_ids,
                                encrypted_public_keys: batch_data,
                            }),
                        )))
                    }
                    _ => {
                        // Return empty batch response if not in expected state
                        Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(
                            KeygenOutcome::ParticipantsAddedBatch(ParticipantsAddedBatchResponse {
                                participants: Vec::new(),
                                encrypted_public_keys: Vec::new(),
                            }),
                        )))
                    }
                }
            }

            KeygenCommand::DistributeParticipantPublicKeysBatch(_cmd) => {
                // Check if the session completed after distributing keys
                match &session.status {
                    OperatorStatus::Keygen(KeygenStatus::Completed(_completed)) => {
                        // Session completed - return aggregate public key
                        let keygen_data = session.extract_keygen_data()?;

                        // Get session secret for encryption
                        let session_secret = match &session.session_context {
                            SessionContext::Keygen(ctx) => {
                                ctx.session_secret.as_ref().ok_or_else(|| {
                                    EnclaveError::Internal(InternalError::Other(
                                        "Session secret not available for encryption".to_string(),
                                    ))
                                })?
                            }
                            _ => {
                                return Err(EnclaveError::Internal(InternalError::Other(
                                    "Expected keygen session context for aggregate public key"
                                        .to_string(),
                                )))
                            }
                        };

                        // Encrypt the aggregate public key
                        let encrypted = session_secret
                            .encrypt(&keygen_data.aggregate_public_key, "aggregate_public_key")
                            .map_err(|e| {
                                EnclaveError::Internal(InternalError::Other(format!(
                                    "Failed to encrypt aggregate public key: {}",
                                    e
                                )))
                            })?;

                        let encrypted_aggregate_public_key = encrypted.to_hex().map_err(|e| {
                            EnclaveError::Internal(InternalError::Other(format!(
                                "Failed to encode encrypted aggregate public key: {}",
                                e
                            )))
                        })?;

                        Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(
                            KeygenOutcome::AggregatePublicKey(AggregatePublicKeyResponse {
                                keygen_session_id: session.session_id().to_owned(),
                                encrypted_aggregate_public_key,
                                participant_count: keygen_data.participants.len(),
                            }),
                        )))
                    }
                    _ => {
                        // Still in progress or other state
                        Ok(EnclaveOutcome::Musig(MusigOutcome::Keygen(
                            KeygenOutcome::Success,
                        )))
                    }
                }
            }
        }
    }

    async fn extract_signing_response(
        &self,
        session: &ContextAwareSession,
        command: &SigningCommand,
    ) -> Result<EnclaveOutcome, EnclaveError> {
        match command {
            SigningCommand::InitSession(cmd) => match &session.status {
                OperatorStatus::Signing(signing_status) => {
                    let response = Self::extract_nonces_response(
                        signing_status,
                        &session.session_context,
                        cmd,
                    )?;
                    Ok(EnclaveOutcome::Musig(MusigOutcome::Signing(
                        SigningOutcome::Nonces(response),
                    )))
                }
                _ => Err(EnclaveError::Internal(InternalError::Other(
                    "Expected signing status for signing command".to_string(),
                ))),
            },
            SigningCommand::DistributeNonces(_cmd) => match &session.status {
                OperatorStatus::Signing(signing_status) => {
                    let response = Self::extract_partial_signature_response(
                        signing_status,
                        &session.session_context,
                    )?;
                    Ok(EnclaveOutcome::Musig(MusigOutcome::Signing(
                        SigningOutcome::PartialSignature(response),
                    )))
                }
                _ => Err(EnclaveError::Internal(InternalError::Other(
                    "Expected signing status for signing command".to_string(),
                ))),
            },
            SigningCommand::FinalizeSignature(_cmd) => match &session.status {
                OperatorStatus::Signing(signing_status) => {
                    let response = Self::extract_final_signature_response(
                        signing_status,
                        &session.session_context,
                    )?;
                    Ok(EnclaveOutcome::Musig(MusigOutcome::Signing(
                        SigningOutcome::FinalSignature(response),
                    )))
                }
                _ => Err(EnclaveError::Internal(InternalError::Other(
                    "Expected signing status for signing command".to_string(),
                ))),
            },
        }
    }

    fn extract_keygen_init_response(
        keygen_status: &KeygenStatus,
        session_context: &SessionContext,
    ) -> Result<KeygenOutcome, EnclaveError> {
        // Get the session ID from whatever state we're in
        let session_id = match keygen_status {
            KeygenStatus::Initialized(state) => state.session_id.clone(),
            KeygenStatus::Distributing(state) => state.session_id().clone(),
            KeygenStatus::Completed(state) => state.session_id().clone(),
            KeygenStatus::Failed(state) => state.session_id.clone(),
        };

        debug!(
            "extract_keygen_init_response for session {} in state {}",
            session_id, keygen_status
        );

        // Extract encrypted session secrets from session context
        // This works regardless of which keygen state we're in, since the session context
        // persists the session_secret and enclave public keys after initialization
        match session_context {
            SessionContext::Keygen(keygen_ctx) => {
                debug!(
                    "Keygen context - session_secret: {}, enclave_public_keys: {}",
                    keygen_ctx.session_secret.is_some(),
                    keygen_ctx.session_enclave_public_keys.len()
                );

                if let Some(session_secret) = &keygen_ctx.session_secret {
                    // This is a coordinator enclave - create encrypted session secrets for each enclave
                    let mut secrets = Vec::new();
                    for (enclave_id, enclave_public_key) in &keygen_ctx.session_enclave_public_keys
                    {
                        // Encrypt session secret with target enclave's public key
                        match keymeld_core::crypto::SecureCrypto::ecies_encrypt_from_hex(
                            enclave_public_key,
                            session_secret.as_bytes(),
                        ) {
                            Ok(encrypted_bytes) => {
                                secrets.push(keymeld_core::protocol::EncryptedSessionSecret {
                                    target_enclave_id: *enclave_id,
                                    encrypted_session_secret: hex::encode(encrypted_bytes),
                                });
                            }
                            Err(e) => {
                                info!(
                                    "Failed to encrypt session secret for enclave {}: {}",
                                    enclave_id, e
                                );
                            }
                        }
                    }
                    debug!(
                        "Coordinator returning KeygenInitialized with {} encrypted secrets",
                        secrets.len()
                    );
                    Ok(KeygenOutcome::KeygenInitialized(
                        KeygenInitializedResponse {
                            keygen_session_id: session_id,
                            encrypted_session_secrets: secrets,
                        },
                    ))
                } else {
                    // Non-coordinator enclave - return Success (gateway expects this)
                    debug!(
                        "Non-coordinator returning Success for session {}",
                        session_id
                    );
                    Ok(KeygenOutcome::Success)
                }
            }
            _ => Ok(KeygenOutcome::Success),
        }
    }

    async fn handle_get_public_info(&self) -> Result<EnclaveOutcome, EnclaveError> {
        let active_sessions_count = self.sessions.iter().count() as u32;
        let attestation_document = if let Some(attestation_manager) = &self.attestation_manager {
            let public_key = self.get_public_key();
            match attestation_manager.get_identity_attestation_with_data(Some(&public_key)) {
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

        Ok(EnclaveOutcome::System(SystemOutcome::PublicInfo(
            PublicInfoResponse {
                public_key: hex::encode(&*self.public_key.read().unwrap()),
                attestation_document,
                active_sessions: active_sessions_count,
                uptime_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    .saturating_sub(self.startup_time),
                key_epoch: self.key_epoch.load(Ordering::Relaxed) as u64,
                key_generation_time: self.key_generation_time,
            },
        )))
    }

    async fn handle_get_attestation(&self) -> Result<EnclaveOutcome, EnclaveError> {
        if let Some(attestation_manager) = &self.attestation_manager {
            let public_key = self.get_public_key();
            match attestation_manager.get_identity_attestation_with_data(Some(&public_key)) {
                Ok(Some(attestation_doc)) => Ok(EnclaveOutcome::System(
                    SystemOutcome::Attestation(attestation_doc),
                )),
                Ok(None) => Err(EnclaveError::Attestation(
                    AttestationError::GenerationFailed("No attestation available".to_string()),
                )),
                Err(e) => Err(EnclaveError::Attestation(
                    AttestationError::GenerationFailed(format!("{e}")),
                )),
            }
        } else {
            Err(EnclaveError::Attestation(
                AttestationError::GenerationFailed("Attestation manager not available".to_string()),
            ))
        }
    }

    pub fn new(enclave_id: EnclaveId) -> Result<Self, EnclaveError> {
        let startup_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                error!("Failed to get system time: {}", e);
                EnclaveError::Internal(InternalError::SystemTime)
            })?
            .as_secs();

        info!(
            "Enclave {} starting with startup time: {} (keys will be initialized via Configure command)",
            enclave_id, startup_time
        );

        let sessions: Arc<DashMap<SessionId, ContextAwareSession>> = Arc::new(DashMap::new());
        let keygen_sessions: Arc<DashMap<SessionId, Arc<MusigProcessor>>> =
            Arc::new(DashMap::new());
        let user_key_store = Arc::new(UserKeyStore::new());
        let enclave_public_keys = Arc::new(DashMap::new());
        let queue = Queue::new(sessions.clone());

        // Initialize context with empty keys - will be populated during Configure command
        let context = Arc::new(RwLock::new(EnclaveSharedContext::new(
            enclave_id,
            Vec::new(), // Will be set during Configure
            Vec::new(), // Will be set during Configure
            None,       // Attestation manager will be set during Configure command
            keymeld_core::managed_vsock::config::TimeoutConfig::default(),
        )));

        Ok(EnclaveOperator {
            enclave_id,
            sessions,
            keygen_sessions,
            user_key_store,
            attestation_manager: None,
            public_key: Arc::new(RwLock::new(Vec::new())),
            private_key: Arc::new(RwLock::new(Vec::new())),
            master_dek: Arc::new(RwLock::new(None)),
            enclave_public_keys,
            context,
            queue,
            startup_time,
            key_generation_time: startup_time,
            key_epoch: AtomicU32::new(1),
            keys_initialized: AtomicBool::new(false),
        })
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.read().unwrap().clone()
    }

    async fn handle_configure(
        &self,
        cmd: ConfigureCommand,
    ) -> Result<Option<ConfiguredResponse>, EnclaveError> {
        info!(
            "Configuring enclave {}, key_epoch: {:?}, kms_config: {}",
            cmd.enclave_id,
            cmd.key_epoch,
            if cmd.kms_endpoint.is_some() {
                "provided"
            } else {
                "not provided"
            }
        );

        if let Some(new_epoch) = cmd.key_epoch {
            let new_epoch = new_epoch as u32;
            let current_epoch = self.key_epoch.load(Ordering::Relaxed);

            if new_epoch != current_epoch {
                info!(
                    "Manager updating epoch from {} to {} (enclave restart detected)",
                    current_epoch, new_epoch
                );
                self.key_epoch.store(new_epoch, Ordering::Relaxed);
            } else {
                info!("Epoch {} confirmed by manager", current_epoch);
            }
        }

        // Track whether we received keys (restart) or generated new ones
        let provided_keys = cmd.encrypted_dek.is_some() && cmd.encrypted_private_key.is_some();

        let configured_response =
            if let (Some(kms_endpoint), Some(kms_key_id)) = (cmd.kms_endpoint, cmd.kms_key_id) {
                let already_initialized = self.keys_initialized.load(Ordering::Relaxed);

                if already_initialized {
                    info!("Keys already initialized, skipping KMS initialization");
                    // Return current keys
                    let public_key = self.public_key.read().unwrap().clone();
                    if !public_key.is_empty() {
                        // We can't return encrypted keys here since we don't store them
                        // But this case shouldn't happen in normal flow
                        None
                    } else {
                        None
                    }
                } else {
                    info!("Initializing enclave keys via KMS");

                    // Configure AWS SDK with endpoint
                    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                        .endpoint_url(&kms_endpoint)
                        .load()
                        .await;

                    let kms_client = aws_sdk_kms::Client::new(&aws_config);

                    let mut temp_context = EnclaveSharedContext::new(
                        self.enclave_id,
                        Vec::new(),
                        Vec::new(),
                        self.attestation_manager.clone(),
                        keymeld_core::managed_vsock::config::TimeoutConfig::default(),
                    );

                    let (encrypted_dek, encrypted_private_key, public_key): (
                        Vec<u8>,
                        Vec<u8>,
                        Vec<u8>,
                    ) = temp_context
                        .init_keys_with_kms(
                            &kms_client,
                            &kms_key_id,
                            cmd.encrypted_dek.clone(),
                            cmd.encrypted_private_key.clone(),
                        )
                        .await?;

                    *self.public_key.write().unwrap() = public_key.clone();
                    *self.private_key.write().unwrap() = temp_context.private_key.clone();
                    *self.master_dek.write().unwrap() = temp_context.master_dek;
                    self.keys_initialized.store(true, Ordering::Relaxed);

                    // Update operator-owned context with the new keys
                    {
                        let mut context = self.context.write().unwrap();
                        context.public_key = public_key.clone();
                        context.private_key = temp_context.private_key.clone();
                        context.master_dek = temp_context.master_dek;
                        context.attestation_manager = self.attestation_manager.clone();
                    }

                    info!(
                        "Keys initialized successfully, public_key: {}, newly_generated: {}",
                        hex::encode(&public_key[..8]),
                        !provided_keys
                    );

                    // Return the encrypted keys so gateway can store them
                    Some(ConfiguredResponse {
                        encrypted_dek,
                        encrypted_private_key,
                        public_key,
                        newly_generated: !provided_keys,
                    })
                }
            } else {
                // No KMS config - simple epoch sync only
                None
            };

        let current_epoch = self.key_epoch.load(Ordering::Relaxed);
        let public_key = self.public_key.read().unwrap();
        let public_key_str = if public_key.len() >= 8 {
            hex::encode(&public_key[..8])
        } else {
            "not initialized".to_string()
        };

        info!(
            "Enclave {} configured successfully. Current epoch: {}, public key: {}",
            cmd.enclave_id, current_epoch, public_key_str
        );

        Ok(configured_response)
    }

    // Helper methods to extract responses from signing states
    fn extract_nonces_response(
        signing_status: &SigningStatus,
        session_context: &SessionContext,
        cmd: &InitSigningSessionCommand,
    ) -> Result<NoncesResponse, EnclaveError> {
        match signing_status {
            SigningStatus::CollectingNonces(state) => {
                // Get session secret for encryption
                let session_secret = match session_context {
                    SessionContext::Signing(ctx) => {
                        ctx.session_secret.as_ref().ok_or_else(|| {
                            EnclaveError::Internal(InternalError::Other(
                                "Session secret not available for encryption".to_string(),
                            ))
                        })?
                    }
                    _ => {
                        return Err(EnclaveError::Internal(InternalError::Other(
                            "Expected signing session context for nonce response".to_string(),
                        )))
                    }
                };

                // Extract nonces for all user_ids in the command
                let mut nonces = Vec::new();
                for user_id in &cmd.user_ids {
                    // Use get_user_nonce_data which handles both regular and adaptor nonces
                    let nonce_data =
                        state
                            .get_user_nonce_data(user_id)
                            .ok_or(EnclaveError::Nonce(NonceError::GenerationFailed {
                                user_id: user_id.clone(),
                                error: "Nonce not found".to_string(),
                            }))?;

                    // Encrypt the nonce data (already in correct NonceData format)
                    let encrypted_nonce = session_secret
                        .encrypt_value(&nonce_data, "nonce_data")
                        .map_err(|e| {
                        EnclaveError::Internal(InternalError::Other(format!(
                            "Failed to encrypt nonce data for user {}: {}",
                            user_id, e
                        )))
                    })?;

                    let encrypted_nonce_data = encrypted_nonce.to_hex().map_err(|e| {
                        EnclaveError::Internal(InternalError::Other(format!(
                            "Failed to encode encrypted nonce for user {}: {}",
                            user_id, e
                        )))
                    })?;

                    nonces.push((user_id.clone(), encrypted_nonce_data));
                }

                Ok(NoncesResponse {
                    signing_session_id: cmd.signing_session_id.clone(),
                    keygen_session_id: cmd.keygen_session_id.clone(),
                    nonces,
                })
            }
            _ => Err(EnclaveError::Internal(InternalError::Other(
                "Nonce not available in current signing state".to_string(),
            ))),
        }
    }

    fn extract_partial_signature_response(
        signing_status: &SigningStatus,
        session_context: &SessionContext,
    ) -> Result<PartialSignatureResponse, EnclaveError> {
        match signing_status {
            SigningStatus::CollectingPartialSignatures(state) => {
                info!(
                    "Extracting partial signatures from CollectingPartialSignatures state for session {}",
                    state.session_id()
                );

                // Get session secret for encryption
                let session_secret = match session_context {
                    SessionContext::Signing(ctx) => {
                        ctx.session_secret.as_ref().ok_or_else(|| {
                            EnclaveError::Internal(InternalError::Other(
                                "Session secret not available for encryption".to_string(),
                            ))
                        })?
                    }
                    _ => {
                        return Err(EnclaveError::Internal(InternalError::Other(
                            "Expected signing session context for partial signature response"
                                .to_string(),
                        )))
                    }
                };

                // Extract partial signatures for ALL users on this enclave
                let users_in_session = state.musig_processor().get_users_in_session();

                if users_in_session.is_empty() {
                    return Err(EnclaveError::Internal(InternalError::Other(
                        "No users found in session for partial signature extraction".to_string(),
                    )));
                }

                // Check if we have adaptor configs for adaptor signatures
                let adaptor_configs = &state
                    .musig_processor()
                    .get_session_metadata_public()
                    .adaptor_configs;

                let mut partial_signatures = Vec::new();

                // Process each user on this enclave
                for user_id in &users_in_session {
                    let signature_data = if adaptor_configs.is_empty() {
                        // Regular signature - get directly from musig processor
                        let sig_bytes = state
                            .musig_processor()
                            .get_user_partial_signature(user_id)
                            .map_err(|e| {
                                EnclaveError::Internal(InternalError::Other(format!(
                                    "Failed to get partial signature for user {}: {}",
                                    user_id, e
                                )))
                            })?;

                        let partial_sig = musig2::PartialSignature::from_slice(&sig_bytes)
                            .map_err(|e| {
                                EnclaveError::Internal(InternalError::Other(format!(
                                    "Failed to deserialize partial signature: {:?}",
                                    e
                                )))
                            })?;

                        keymeld_core::protocol::SignatureData::Regular(partial_sig)
                    } else {
                        // Adaptor signatures - get directly from musig processor
                        let adaptor_sig_bytes = state
                            .musig_processor()
                            .get_user_adaptor_signatures(user_id)
                            .map_err(|e| {
                                EnclaveError::Internal(InternalError::Other(format!(
                                    "Failed to get adaptor signatures for user {}: {}",
                                    user_id, e
                                )))
                            })?;

                        if adaptor_sig_bytes.is_empty() {
                            return Err(EnclaveError::Internal(InternalError::Other(format!(
                                "No adaptor partial signatures available for user {}",
                                user_id
                            ))));
                        }

                        let mut adaptor_signatures = Vec::new();
                        for (config_id, sig_bytes) in adaptor_sig_bytes {
                            let partial_sig = musig2::PartialSignature::from_slice(&sig_bytes)
                                .map_err(|e| {
                                    EnclaveError::Internal(InternalError::Other(format!(
                                        "Failed to deserialize adaptor partial signature: {:?}",
                                        e
                                    )))
                                })?;
                            adaptor_signatures.push((config_id, partial_sig));
                        }

                        keymeld_core::protocol::SignatureData::Adaptor(adaptor_signatures)
                    };

                    // Encrypt the signature data
                    let encrypted_sig = session_secret
                        .encrypt_value(&signature_data, "signature_data")
                        .map_err(|e| {
                            EnclaveError::Internal(InternalError::Other(format!(
                                "Failed to encrypt signature data for user {}: {}",
                                user_id, e
                            )))
                        })?;

                    let encrypted_signature_data = encrypted_sig.to_hex().map_err(|e| {
                        EnclaveError::Internal(InternalError::Other(format!(
                            "Failed to encode encrypted signature for user {}: {}",
                            user_id, e
                        )))
                    })?;

                    partial_signatures.push((user_id.clone(), encrypted_signature_data));
                }

                info!(
                    "Extracted {} partial signatures for session {}",
                    partial_signatures.len(),
                    state.session_id()
                );

                Ok(PartialSignatureResponse { partial_signatures })
            }
            _ => Err(EnclaveError::Internal(InternalError::Other(
                "Partial signature not available in current signing state".to_string(),
            ))),
        }
    }

    fn extract_final_signature_response(
        signing_status: &SigningStatus,
        session_context: &SessionContext,
    ) -> Result<FinalSignatureResponse, EnclaveError> {
        match signing_status {
            SigningStatus::Completed(state) => {
                let (signing_session_id, keygen_session_id, _session_secret) = match session_context
                {
                    SessionContext::Signing(ctx) => {
                        let session_secret = ctx.session_secret.as_ref().ok_or_else(|| {
                            EnclaveError::Internal(InternalError::Other(
                                "Session secret not available for encryption".to_string(),
                            ))
                        })?;
                        (&ctx.session_id, &ctx.keygen_session_id, session_secret)
                    }
                    _ => {
                        return Err(EnclaveError::Internal(InternalError::Other(
                            "Expected signing session context for final signature".to_string(),
                        )))
                    }
                };

                info!(
                    "Extracting final signature from Completed state for session {}",
                    signing_session_id
                );

                // Get the already-encrypted signature from the Completed state
                let encrypted_final_signature =
                    state.encrypted_signed_message().to_hex().map_err(|e| {
                        EnclaveError::Internal(InternalError::Other(format!(
                            "Failed to encode encrypted signature: {}",
                            e
                        )))
                    })?;

                // Get adaptor signatures if available (already encrypted in Completed state)
                let encrypted_adaptor_signatures = match state.encrypted_adaptor_signatures() {
                    Some(encrypted) => Some(encrypted.to_hex().map_err(|e| {
                        EnclaveError::Internal(InternalError::Other(format!(
                            "Failed to encode encrypted adaptor signatures: {}",
                            e
                        )))
                    })?),
                    None => None,
                };

                let participant_count = state.participant_count() as usize;

                // Get batch_items from the musig processor metadata
                let batch_items = state
                    .musig_processor()
                    .get_session_metadata()
                    .batch_items
                    .clone();

                // Build batch results from batch_items or create a single result
                let batch_results = if batch_items.is_empty() {
                    // Single message mode: create a batch of 1 using UUIDv7
                    let batch_item_id = uuid::Uuid::now_v7();
                    vec![keymeld_core::protocol::EnclaveBatchResult {
                        batch_item_id,
                        encrypted_final_signature: Some(encrypted_final_signature),
                        encrypted_adaptor_signatures,
                        error: None,
                    }]
                } else {
                    // Batch mode: create results for each batch item
                    // For now, since we only support single message, this path won't be hit
                    // Full batch implementation would iterate over batch_items here
                    batch_items
                        .keys()
                        .map(|batch_item_id| keymeld_core::protocol::EnclaveBatchResult {
                            batch_item_id: *batch_item_id,
                            encrypted_final_signature: Some(encrypted_final_signature.clone()),
                            encrypted_adaptor_signatures: encrypted_adaptor_signatures.clone(),
                            error: None,
                        })
                        .collect()
                };

                Ok(FinalSignatureResponse {
                    signing_session_id: signing_session_id.clone(),
                    keygen_session_id: keygen_session_id.clone(),
                    participant_count,
                    batch_results,
                })
            }
            _ => Err(EnclaveError::Internal(InternalError::Other(
                "Final signature not available in current signing state".to_string(),
            ))),
        }
    }
}

impl Drop for EnclaveOperator {
    fn drop(&mut self) {
        info!("Dropping EnclaveOperator and zeroizing sensitive data");
        if let Ok(mut private_key) = self.private_key.write() {
            private_key.zeroize();
        }
        if let Ok(mut master_dek) = self.master_dek.write() {
            if let Some(ref mut dek) = *master_dek {
                dek.zeroize();
            }
        }
    }
}
