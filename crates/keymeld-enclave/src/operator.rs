use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use dashmap::DashMap;
use hex;
use keymeld_core::{
    crypto::{SecureCrypto, SessionSecret},
    enclave::{
        protocol::{
            BatchDistributeSessionSecretsCommand, DistributeSessionSecretCommand,
            EnclavePublicKeyInfo, EncryptedSessionSecret, KeygenInitializedResponse,
        },
        protocol::{ValidateUserSignatureCommand, ValidateUserSignatureResponse},
        AddParticipantCommand, AttestationResponse, ConfigureCommand, EnclaveCommand, EnclaveError,
        EnclaveResponse, InitKeygenSessionCommand, InitSigningSessionCommand, PublicInfoResponse,
        SuccessResponse,
    },
    encrypted_data::{
        KeygenParticipantEnclaveData, SigningParticipantEnclaveData, SigningParticipantSessionData,
    },
    identifiers::{EnclaveId, SessionId, UserId},
    musig::MusigProcessor,
    EncryptedData, KeyMaterial,
};

use musig2::secp256k1::{self, PublicKey, SecretKey};

use sha2::{Digest, Sha256};
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroize;

use crate::{
    attestation::AttestationManager,
    state::{OperationInitData, OperationInitialized, OperationState},
};

#[derive(Debug, Clone)]
pub struct SecurePrivateKey {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub encrypted_key: Vec<u8>,
    pub created_at: u64,
    pub key: Vec<u8>,
}

pub struct SessionState {
    pub session_id: SessionId,
    pub operation_state: OperationState,
    pub musig_processor: MusigProcessor,
    pub private_keys: BTreeMap<UserId, SecurePrivateKey>,
}

impl SessionState {
    pub fn get_user_key_material(&self, user_id: &UserId) -> Option<KeyMaterial> {
        self.private_keys
            .get(user_id)
            .map(|secure_key| KeyMaterial::new(secure_key.key.clone()))
    }
}

pub struct EnclaveOperator {
    pub enclave_id: EnclaveId,
    pub sessions: DashMap<SessionId, Arc<Mutex<SessionState>>>,
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
    /// Key epoch (incremented on key rotation)
    key_epoch: u32,
}

impl From<crate::attestation::AttestationDocument> for AttestationResponse {
    fn from(doc: crate::attestation::AttestationDocument) -> Self {
        Self {
            pcrs: doc.pcrs,
            timestamp: doc.timestamp,
            certificate: doc.certificate,
            signature: doc.signature,
            user_data: doc.user_data,
            public_key: doc.public_key,
        }
    }
}

impl EnclaveOperator {
    fn hash_message(message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn get_session_secret_bytes(&self, session_id: &SessionId) -> Result<Vec<u8>, EnclaveError> {
        let session_state_ref = self.sessions.get(session_id).ok_or_else(|| {
            error!("Session {} not found", session_id);
            EnclaveError::SessionNotFound(session_id.to_string())
        })?;

        let session_state = session_state_ref
            .lock()
            .map_err(|_| EnclaveError::Internal("Session lock poisoned".to_string()))?;

        let session_secret = session_state
            .operation_state
            .get_session_secret()
            .ok_or_else(|| {
                error!("Session secret not available for session {}", session_id);
                EnclaveError::InvalidSessionSecret(format!(
                    "Session secret not available for session {}",
                    session_id
                ))
            })?;

        Ok(session_secret.as_bytes().to_vec())
    }

    fn encrypt_session_secret_for_enclave(
        &self,
        target_public_key: &str,
        session_secret_bytes: &[u8],
    ) -> Result<String, EnclaveError> {
        let encrypted_bytes = SecureCrypto::ecies_encrypt_from_hex(
            target_public_key,
            session_secret_bytes,
        )
        .map_err(|e| {
            EnclaveError::CryptographicError(format!("Failed to encrypt session secret: {}", e))
        })?;

        Ok(hex::encode(encrypted_bytes))
    }
    pub fn new(enclave_id: EnclaveId) -> Result<Self, EnclaveError> {
        let keypair = SecureCrypto::generate_enclave_keypair().map_err(|e| {
            EnclaveError::CryptographicError(format!("Failed to generate keypair: {}", e))
        })?;
        let startup_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| {
                error!("Failed to get system time: {}", e);
                EnclaveError::Internal("System time error during startup".to_string())
            })?
            .as_secs();

        Ok(EnclaveOperator {
            enclave_id,
            sessions: DashMap::new(),
            attestation_manager: None,
            public_key: keypair.1.serialize().to_vec(),
            private_key: keypair.0.secret_bytes().to_vec(),
            enclave_public_keys: DashMap::new(),
            startup_time,
            key_generation_time: startup_time,
            key_epoch: 1,
        })
    }

    pub fn initialize_attestation(&mut self, attestation_manager: AttestationManager) {
        self.attestation_manager = Some(attestation_manager);
    }

    pub fn get_attestation_manager(&self) -> Option<&AttestationManager> {
        self.attestation_manager.as_ref()
    }

    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub async fn handle_command(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        match command {
            EnclaveCommand::Ping => Ok(EnclaveResponse::Pong),
            EnclaveCommand::Configure(cmd) => self.handle_configure(cmd).await,
            EnclaveCommand::InitKeygenSession(cmd) => self.handle_init_keygen_session(cmd).await,
            EnclaveCommand::InitSigningSession(cmd) => self.handle_init_signing_session(cmd).await,
            EnclaveCommand::AddParticipant(cmd) => self.handle_add_participant(cmd).await,
            EnclaveCommand::DistributeSessionSecret(cmd) => {
                self.handle_distribute_session_secret(cmd).await
            }
            EnclaveCommand::BatchDistributeSessionSecrets(cmd) => {
                self.handle_batch_distribute_session_secrets(cmd).await
            }
            EnclaveCommand::GenerateNonce(cmd) => self.handle_generate_nonce(cmd).await,
            EnclaveCommand::AddNonce(cmd) => self.handle_add_nonce(cmd).await,
            EnclaveCommand::SignPartialSignature(cmd) => {
                self.handle_sign_partial_signature(cmd).await
            }
            EnclaveCommand::AddPartialSignature(cmd) => {
                self.handle_add_partial_signature(cmd).await
            }
            EnclaveCommand::GetAggregatePublicKey(cmd) => {
                self.handle_get_aggregate_public_key(cmd).await
            }
            EnclaveCommand::Finalize(cmd) => self.handle_finalize(cmd).await,
            EnclaveCommand::GetAggregateNonce(cmd) => self.handle_get_aggregate_nonce(cmd).await,
            EnclaveCommand::ClearSession(cmd) => {
                let session_id = cmd
                    .keygen_session_id
                    .or(cmd.signing_session_id)
                    .ok_or_else(|| {
                        EnclaveError::InvalidSessionId(
                            "Either keygen_session_id or signing_session_id must be provided"
                                .to_string(),
                        )
                    })?;

                self.clear_session(session_id).await?;
                Ok(EnclaveResponse::Success(SuccessResponse {
                    message: "Session cleared".to_string(),
                }))
            }
            EnclaveCommand::InitiateAdaptorSigning(cmd) => {
                self.handle_initiate_adaptor_signing(cmd).await
            }
            EnclaveCommand::SignAdaptorPartialSignature(cmd) => {
                self.handle_sign_adaptor_partial_signature(cmd).await
            }
            EnclaveCommand::ProcessAdaptorSignatures(cmd) => {
                self.handle_process_adaptor_signatures(cmd).await
            }
            EnclaveCommand::ValidateUserSignature(cmd) => {
                self.handle_validate_user_signature(cmd).await
            }
            EnclaveCommand::GetPublicInfo => {
                let active_sessions_count = self.sessions.iter().count() as u32;
                let attestation_document =
                    if let Some(attestation_manager) = &self.attestation_manager {
                        match attestation_manager
                            .get_identity_attestation_with_data(Some(self.get_public_key()))
                        {
                            Ok(Some(attestation_doc)) => Some(attestation_doc.into()),
                            Ok(None) => None,
                            Err(e) => {
                                return Err(EnclaveError::InvalidAttestation(format!(
                                    "Failed to generate attestation: {}",
                                    e
                                )));
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
                    key_epoch: self.key_epoch as u64,
                    key_generation_time: self.key_generation_time,
                }))
            }
        }
    }

    async fn handle_configure(
        &self,
        _cmd: ConfigureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Enclave configured".to_string(),
        }))
    }

    async fn handle_init_keygen_session(
        &self,
        cmd: InitKeygenSessionCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.keygen_session_id.clone();

        let session_secret = if let Some(encrypted_secret) = &cmd.encrypted_session_secret {
            let private_key_array: [u8; 32] = self.private_key[..32].try_into().map_err(|_| {
                EnclaveError::CryptographicError("Private key must be exactly 32 bytes".to_string())
            })?;
            let secret_key = SecretKey::from_byte_array(private_key_array).map_err(|e| {
                EnclaveError::CryptographicError(format!("Invalid private key: {}", e))
            })?;

            let decoded_bytes = hex::decode(encrypted_secret).map_err(|e| {
                EnclaveError::DataDecodingError(format!("Hex decode failed: {}", e))
            })?;
            let decrypted_secret_bytes = SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes)
                .map_err(|e| {
                EnclaveError::DecryptionFailed(format!("Failed to decrypt session secret: {}", e))
            })?;

            let session_secret_str = String::from_utf8_lossy(&decrypted_secret_bytes);
            let secret_bytes = hex::decode(session_secret_str.as_ref()).map_err(|e| {
                EnclaveError::DataDecodingError(format!("Hex decode failed: {}", e))
            })?;

            if secret_bytes.len() != 32 {
                return Err(EnclaveError::InvalidSessionSecret(format!(
                    "Invalid length: expected 32 bytes, got {}",
                    secret_bytes.len()
                )));
            }
            let mut secret_array = [0u8; 32];
            secret_array.copy_from_slice(&secret_bytes);
            Some(SessionSecret::from_bytes(secret_array))
        } else {
            None
        };

        let mut musig_processor = MusigProcessor::new();
        musig_processor
            .init_session(
                &session_id,
                vec![], // Keygen sessions don't have a message
                cmd.taproot_tweak,
                Vec::new(),
                Some(cmd.expected_participant_count),
                Vec::new(), // No adaptor configs for keygen sessions
            )
            .map_err(|e| {
                EnclaveError::SessionInitializationFailed(format!(
                    "Failed to initialize MuSig2: {}",
                    e
                ))
            })?;

        let coordinator_private_key =
            if let Some(encrypted_key) = &cmd.coordinator_encrypted_private_key {
                match self
                    .decrypt_private_key_from_coordinator(encrypted_key)
                    .await
                {
                    Ok(key) => Some(key),
                    Err(e) => {
                        warn!(
                        "Failed to decrypt coordinator private key during init for session {}: {}",
                        session_id, e
                    );
                        None
                    }
                }
            } else {
                None
            };

        if cmd.coordinator_encrypted_private_key.is_some() {
            for enclave_key in &cmd.enclave_public_keys {
                self.enclave_public_keys
                    .insert(enclave_key.enclave_id, enclave_key.public_key.clone());
            }
        }

        let init_data = OperationInitData {
            session_id: session_id.clone(),
            session_secret,
            message: vec![],
            message_hash: vec![],
            participant_keys: vec![],
            aggregate_public_key: vec![],
            is_coordinator: cmd.coordinator_encrypted_private_key.is_some(),
            coordinator_private_key,
            session_encrypted_data: None,
            enclave_encrypted_data: None,
        };

        let session_secret_for_distribution = init_data.session_secret.clone();
        let is_coordinator = cmd.coordinator_encrypted_private_key.is_some();

        let operation: OperationInitialized = init_data.into();

        let session_state = SessionState {
            session_id: session_id.clone(),
            operation_state: OperationState::from(operation),
            musig_processor,
            private_keys: BTreeMap::new(),
        };

        self.sessions.insert(
            session_id.clone(),
            Arc::new(std::sync::Mutex::new(session_state)),
        );

        if is_coordinator {
            if let Some(session_secret) = session_secret_for_distribution.as_ref() {
                match self
                    .encrypt_session_secret_for_other_enclaves(
                        session_secret,
                        &cmd.enclave_public_keys,
                    )
                    .await
                {
                    Ok(encrypted_secrets) => {
                        return Ok(EnclaveResponse::KeygenInitialized(
                            KeygenInitializedResponse {
                                keygen_session_id: session_id,
                                encrypted_session_secrets: encrypted_secrets,
                            },
                        ));
                    }
                    Err(e) => {
                        warn!(
                            "Failed to encrypt session secrets for other enclaves: {}",
                            e
                        );
                        // Continue with normal response if encryption fails
                    }
                }
            }
        }

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Session initialized".to_string(),
        }))
    }

    async fn handle_init_signing_session(
        &self,
        cmd: InitSigningSessionCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.signing_session_id.clone();

        if let Err(e) = self.clear_session(session_id.clone()).await {
            warn!("Failed to clear existing session state: {}", e);
        }

        if cmd.encrypted_message.is_empty() {
            return Err(EnclaveError::ValidationFailed(
                "Message cannot be empty".to_string(),
            ));
        }

        let (keygen_participants, session_secret) = {
            let keygen_session_arc =
                self.sessions.get(&cmd.keygen_session_id).ok_or_else(|| {
                    EnclaveError::SessionNotFound(format!(
                        "Keygen session {} not found for signing session {}",
                        cmd.keygen_session_id, session_id
                    ))
                })?;

            let keygen_session = keygen_session_arc.lock().map_err(|e| {
                error!("Failed to acquire keygen session lock: {}", e);
                EnclaveError::Internal("Keygen session lock poisoned".to_string())
            })?;
            let session_metadata = keygen_session
                .musig_processor
                .get_session_metadata_public(&cmd.keygen_session_id)
                .ok_or_else(|| {
                    EnclaveError::SessionInitializationFailed(format!(
                        "No metadata found for keygen session {}",
                        cmd.keygen_session_id
                    ))
                })?;

            let participants = session_metadata.get_all_participants();

            // Inherit session secret from keygen session
            let inherited_session_secret = keygen_session
                .operation_state
                .get_session_secret()
                .ok_or_else(|| {
                    EnclaveError::InvalidSessionSecret(format!(
                        "No session secret available in keygen session {}",
                        cmd.keygen_session_id
                    ))
                })?
                .clone();

            (participants, inherited_session_secret)
        };

        let mut musig_processor = MusigProcessor::new();
        let message = hex::decode(&cmd.encrypted_message)
            .map_err(|e| EnclaveError::DataDecodingError(format!("Hex decode failed: {}", e)))?;

        let message_hash = Self::hash_message(&message);

        // Decrypt adaptor configs if provided
        let adaptor_configs = if let Some(encrypted_configs) = &cmd.encrypted_adaptor_configs {
            if !encrypted_configs.is_empty() {
                match keymeld_core::api::validation::decrypt_adaptor_configs(
                    encrypted_configs,
                    &hex::encode(session_secret.as_bytes()),
                ) {
                    Ok(configs) => configs,
                    Err(e) => {
                        return Err(EnclaveError::DataDecodingError(format!(
                            "Failed to decrypt adaptor configs: {}",
                            e
                        )));
                    }
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        info!("🔍 ENCLAVE DEBUG: Message being signed:");
        info!("🔍 ENCLAVE DEBUG: Message bytes: {:?}", message);
        info!("🔍 ENCLAVE DEBUG: Message hex: {}", hex::encode(&message));
        info!("🔍 ENCLAVE DEBUG: Message length: {} bytes", message.len());
        info!("🔍 ENCLAVE DEBUG: Message hash: {:?}", message_hash);
        info!(
            "🔍 ENCLAVE DEBUG: Message hash hex: {}",
            hex::encode(&message_hash)
        );
        info!(
            "🔍 ENCLAVE DEBUG: Message hash length: {} bytes",
            message_hash.len()
        );

        musig_processor
            .init_session(
                &session_id,
                message.clone(),
                cmd.taproot_tweak,
                keygen_participants, // Use participants from completed keygen session
                Some(cmd.expected_participant_count),
                adaptor_configs, // Pass decrypted adaptor configs
            )
            .map_err(|e| {
                EnclaveError::SessionInitializationFailed(format!(
                    "Failed to initialize MuSig2: {}",
                    e
                ))
            })?;

        let coordinator_private_key =
            if let Some(encrypted_key) = &cmd.coordinator_encrypted_private_key {
                match self
                    .decrypt_private_key_from_coordinator(encrypted_key)
                    .await
                {
                    Ok(key) => Some(key),
                    Err(e) => {
                        warn!(
                        "Failed to decrypt coordinator private key during init for session {}: {}",
                        session_id, e
                    );
                        None
                    }
                }
            } else {
                None
            };

        let init_data = OperationInitData {
            session_id: session_id.clone(),
            session_secret: Some(session_secret),
            message,      // The actual sighash to sign
            message_hash, // Hash of the sighash for validation
            participant_keys: vec![],
            aggregate_public_key: vec![],
            is_coordinator: cmd.coordinator_encrypted_private_key.is_some(),
            coordinator_private_key,
            session_encrypted_data: None,
            enclave_encrypted_data: None,
        };

        let operation: OperationInitialized = init_data.into();

        let session_state = SessionState {
            session_id: session_id.clone(),
            operation_state: OperationState::from(operation),
            musig_processor,
            private_keys: BTreeMap::new(),
        };

        self.sessions.insert(
            session_id.clone(),
            Arc::new(std::sync::Mutex::new(session_state)),
        );
        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Signing session initialized".to_string(),
        }))
    }

    async fn handle_add_participant(
        &self,
        cmd: AddParticipantCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.signing_session_id.or(cmd.keygen_session_id).ok_or(
            EnclaveError::InvalidSessionId(
                "Either keygen_session_id or signing_session_id must be provided".to_string(),
            ),
        )?;

        let session_arc = self.sessions.get(&session_id).ok_or_else(|| {
            error!("Session {} not found", session_id);
            EnclaveError::SessionNotFound(session_id.to_string())
        })?;

        let (participant_public_key, encrypted_private_key_hex) = {
            let session_state = session_arc.lock().map_err(|e| {
                error!(
                    "Failed to acquire session lock for participant validation: {}",
                    e
                );
                EnclaveError::Internal(
                    "Session lock poisoned during participant validation".to_string(),
                )
            })?;

            let _session_secret = session_state
                .operation_state
                .get_session_secret()
                .ok_or_else(|| {
                    error!("Session secret not available for session {}", session_id);
                    EnclaveError::InvalidSessionSecret(format!(
                        "Session secret not available for session {}",
                        session_id
                    ))
                })?;

            let _participant_session_data = if !cmd.session_encrypted_data.is_empty() {
                if let Ok(signing_data) = serde_json::from_str::<SigningParticipantSessionData>(
                    &cmd.session_encrypted_data,
                ) {
                    Some(signing_data)
                } else if let Ok(_keygen_data) = serde_json::from_str::<
                    keymeld_core::encrypted_data::KeygenParticipantSessionData,
                >(&cmd.session_encrypted_data)
                {
                    Some(SigningParticipantSessionData::new())
                } else {
                    error!(
                        "Failed to deserialize session data for participant {} - unrecognized format",
                        cmd.user_id
                    );
                    None
                }
            } else {
                None
            };

            let participant_public_key = vec![]; // Will be derived from encrypted private key if available

            let encrypted_private_key_hex = if !cmd.enclave_encrypted_data.is_empty() {
                let encrypted_bytes = hex::decode(&cmd.enclave_encrypted_data).map_err(|e| {
                    EnclaveError::DataDecodingError(format!("Failed to decode hex data: {}", e))
                })?;

                let private_key_array: [u8; 32] =
                    self.private_key[..32].try_into().map_err(|_| {
                        EnclaveError::CryptographicError(
                            "Private key must be exactly 32 bytes".to_string(),
                        )
                    })?;
                let secret_key = SecretKey::from_byte_array(private_key_array).map_err(|e| {
                    EnclaveError::CryptographicError(format!("Invalid private key: {}", e))
                })?;

                let decrypted_json = SecureCrypto::ecies_decrypt(&secret_key, &encrypted_bytes)
                    .map_err(|e| {
                        EnclaveError::DecryptionFailed(format!(
                            "Failed to decrypt enclave data: {}",
                            e
                        ))
                    })?;

                let decrypted_str = String::from_utf8(decrypted_json).map_err(|e| {
                    EnclaveError::DataDecodingError(format!(
                        "Failed to convert decrypted data to string: {}",
                        e
                    ))
                })?;

                if let Ok(keygen_data) =
                    serde_json::from_str::<KeygenParticipantEnclaveData>(&decrypted_str)
                {
                    Some(keygen_data.private_key)
                } else if let Ok(signing_data) =
                    serde_json::from_str::<SigningParticipantEnclaveData>(&decrypted_str)
                {
                    Some(signing_data.private_key)
                } else {
                    warn!(
                        "Failed to deserialize decrypted enclave data for participant {} - unrecognized format",
                        cmd.user_id
                    );
                    None
                }
            } else {
                debug!(
                    "No enclave encrypted data provided for participant {} - participant assigned to different enclave",
                    cmd.user_id
                );
                None
            };

            // Derive public key from private key if available
            let derived_public_key = if let Some(ref private_key_hex) = encrypted_private_key_hex {
                match hex::decode(private_key_hex) {
                    Ok(private_key_bytes) => {
                        if private_key_bytes.len() == 32 {
                            match SecretKey::from_byte_array(
                                private_key_bytes[..32].try_into().unwrap(),
                            ) {
                                Ok(secret_key) => {
                                    let public_key =
                                        secret_key.public_key(&secp256k1::Secp256k1::new());
                                    public_key.serialize().to_vec()
                                }
                                Err(_) => participant_public_key,
                            }
                        } else {
                            participant_public_key
                        }
                    }
                    Err(_) => participant_public_key,
                }
            } else {
                participant_public_key
            };

            (derived_public_key, encrypted_private_key_hex)
        }; // Lock is released here

        let decrypted_private_key = if let Some(encrypted_hex) = encrypted_private_key_hex {
            Some(
                self.decrypt_private_key_from_coordinator(&encrypted_hex)
                    .await?,
            )
        } else {
            None
        };

        {
            let mut session_state = session_arc.lock().map_err(|e| {
                error!(
                    "Failed to acquire session lock for participant storage: {}",
                    e
                );
                EnclaveError::Internal(
                    "Session lock poisoned during participant storage".to_string(),
                )
            })?;

            if let Some(private_key) = decrypted_private_key {
                let secure_key = SecurePrivateKey {
                    session_id: session_id.clone(),
                    user_id: cmd.user_id.clone(),
                    encrypted_key: private_key.clone(),
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| {
                            error!("Failed to get system time: {}", e);
                            EnclaveError::Internal(
                                "System time error during key storage".to_string(),
                            )
                        })?
                        .as_secs(),
                    key: private_key,
                };
                session_state
                    .private_keys
                    .insert(cmd.user_id.clone(), secure_key);
            }

            let public_key = PublicKey::from_slice(&participant_public_key).map_err(|e| {
                EnclaveError::InvalidPublicKey(format!("Invalid public key: {}", e))
            })?;

            session_state
                .musig_processor
                .add_participant(&session_id, cmd.user_id.clone(), public_key)
                .map_err(|e| {
                    EnclaveError::ParticipantError(format!(
                        "Failed to add participant to MuSig2: {}",
                        e
                    ))
                })?;
        }

        info!(
            "Participant {} added to session {} successfully",
            cmd.user_id, session_id
        );

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: format!("Participant {} added to session", cmd.user_id),
        }))
    }

    async fn handle_distribute_session_secret(
        &self,
        cmd: DistributeSessionSecretCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_arc = self.sessions.get(&cmd.keygen_session_id).ok_or_else(|| {
            error!("Session {} not found", cmd.keygen_session_id);
            EnclaveError::SessionNotFound(cmd.keygen_session_id.to_string())
        })?;

        let private_key_array: [u8; 32] = self.private_key[..32].try_into().map_err(|_| {
            EnclaveError::CryptographicError("Private key must be exactly 32 bytes".to_string())
        })?;
        let secret_key = SecretKey::from_byte_array(private_key_array)
            .map_err(|e| EnclaveError::CryptographicError(format!("Invalid private key: {}", e)))?;

        let encrypted_bytes = hex::decode(&cmd.encrypted_session_secret).map_err(|e| {
            EnclaveError::DataDecodingError(format!("Failed to decode session secret hex: {}", e))
        })?;

        let decrypted_bytes =
            SecureCrypto::ecies_decrypt(&secret_key, &encrypted_bytes).map_err(|e| {
                EnclaveError::DecryptionFailed(format!("Failed to decrypt session secret: {}", e))
            })?;

        let session_secret_str = String::from_utf8(decrypted_bytes).map_err(|e| {
            EnclaveError::DataDecodingError(format!(
                "Failed to convert session secret to string: {}",
                e
            ))
        })?;

        let secret_bytes = hex::decode(&session_secret_str).map_err(|e| {
            EnclaveError::DataDecodingError(format!("Failed to decode session secret hex: {}", e))
        })?;

        if secret_bytes.len() != 32 {
            return Err(EnclaveError::InvalidSessionSecret(format!(
                "Invalid length: expected 32 bytes, got {}",
                secret_bytes.len()
            )));
        }

        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&secret_bytes);
        let session_secret = SessionSecret::from_bytes(secret_array);

        {
            let mut session_state = session_arc.lock().map_err(|e| {
                error!(
                    "Failed to acquire session lock for secret distribution: {}",
                    e
                );
                EnclaveError::Internal(
                    "Session lock poisoned during secret distribution".to_string(),
                )
            })?;
            match &mut session_state.operation_state {
                OperationState::Initialized(ref mut op) => {
                    if let Some(existing_secret) = &op.session_secret {
                        let existing_bytes = existing_secret.as_bytes();
                        let new_bytes = session_secret.as_bytes();

                        if existing_bytes != new_bytes {
                            error!(
                                "Session secret mismatch for session {}: attempting to overwrite existing secret with different value",
                                cmd.keygen_session_id
                            );
                            return Err(EnclaveError::InvalidSessionSecret(
                                "Cannot overwrite existing session secret with different value"
                                    .to_string(),
                            ));
                        }

                        debug!(
                            "Session secret matches existing secret for session {}",
                            cmd.keygen_session_id
                        );
                    } else {
                        op.session_secret = Some(session_secret);
                        debug!(
                            "Successfully set session secret for session {}",
                            cmd.keygen_session_id
                        );
                    }
                }
                _ => {
                    return Err(EnclaveError::Internal(
                        "Session not in initialized state for secret distribution".to_string(),
                    ));
                }
            }
        }

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Session secret distributed successfully".to_string(),
        }))
    }

    async fn handle_batch_distribute_session_secrets(
        &self,
        cmd: BatchDistributeSessionSecretsCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_secret_bytes = self.get_session_secret_bytes(&cmd.keygen_session_id)?;

        let mut encrypted_secrets = Vec::new();

        for target_enclave_id in &cmd.target_enclaves {
            let target_public_key = self
                .enclave_public_keys
                .get(target_enclave_id)
                .ok_or_else(|| {
                    EnclaveError::CryptographicError(format!(
                        "No public key available for target enclave {}",
                        target_enclave_id
                    ))
                })?
                .clone();

            let encrypted_session_secret =
                self.encrypt_session_secret_for_enclave(&target_public_key, &session_secret_bytes)?;

            encrypted_secrets.push(EncryptedSessionSecret {
                target_enclave_id: *target_enclave_id,
                encrypted_session_secret,
            });
        }

        Ok(EnclaveResponse::BatchSessionSecrets(
            keymeld_core::enclave::protocol::BatchSessionSecretsResponse {
                keygen_session_id: cmd.keygen_session_id,
                encrypted_secrets,
            },
        ))
    }

    async fn encrypt_session_secret_for_other_enclaves(
        &self,
        session_secret: &SessionSecret,
        enclave_public_keys: &[EnclavePublicKeyInfo],
    ) -> Result<Vec<EncryptedSessionSecret>, EnclaveError> {
        let session_secret_bytes = session_secret.as_bytes();
        let session_secret_hex = hex::encode(session_secret_bytes);
        let mut encrypted_secrets = Vec::new();

        for enclave_key in enclave_public_keys {
            if enclave_key.enclave_id == self.enclave_id {
                continue;
            }

            let encrypted_session_secret = {
                let encrypted_bytes = SecureCrypto::ecies_encrypt_from_hex(
                    &enclave_key.public_key,
                    session_secret_hex.as_bytes(),
                )
                .map_err(|e| {
                    EnclaveError::CryptographicError(format!(
                        "Failed to encrypt session secret for enclave {}: {}",
                        enclave_key.enclave_id, e
                    ))
                })?;

                hex::encode(encrypted_bytes)
            };

            encrypted_secrets.push(keymeld_core::enclave::protocol::EncryptedSessionSecret {
                target_enclave_id: enclave_key.enclave_id,
                encrypted_session_secret,
            });
        }

        Ok(encrypted_secrets)
    }

    pub async fn get_status(&self) -> (EnclaveId, bool, Vec<u8>, u32) {
        let active_sessions_count = self.sessions.iter().count() as u32;
        let ready = true;

        (
            self.enclave_id,
            ready,
            self.public_key.clone(),
            active_sessions_count,
        )
    }

    pub fn get_startup_time(&self) -> u64 {
        self.startup_time
    }

    pub fn get_key_generation_time(&self) -> u64 {
        self.key_generation_time
    }

    pub fn get_key_epoch(&self) -> u32 {
        self.key_epoch
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

    pub async fn get_active_sessions_count(&self) -> usize {
        self.sessions.iter().count()
    }

    pub async fn clear_session(&self, session_id: SessionId) -> Result<(), EnclaveError> {
        let session_exists_before = self.sessions.contains_key(&session_id);
        info!(
            "Clearing session {} (exists_before={})",
            session_id, session_exists_before
        );

        if let Some(session_arc) = self.sessions.get(&session_id) {
            if let Ok(mut session_state) = session_arc.lock() {
                session_state.musig_processor.clear_session(&session_id);
                info!("Cleared MuSig processor state for session {}", session_id);
            } else {
                warn!(
                    "Failed to acquire lock for session {} during clearing",
                    session_id
                );
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

    pub async fn decrypt_private_key_from_coordinator(
        &self,
        encrypted_private_key: &str,
    ) -> Result<Vec<u8>, EnclaveError> {
        let private_key_array: [u8; 32] = self.private_key[..32].try_into().map_err(|_| {
            EnclaveError::CryptographicError("Private key must be exactly 32 bytes".to_string())
        })?;
        let secret_key = SecretKey::from_byte_array(private_key_array)
            .map_err(|e| EnclaveError::CryptographicError(format!("Invalid private key: {}", e)))?;

        let decoded_bytes = hex::decode(encrypted_private_key)
            .map_err(|e| EnclaveError::DataDecodingError(format!("Hex decode failed: {}", e)))?;
        SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes).map_err(|e| {
            EnclaveError::DecryptionFailed(format!("Failed to decrypt private key: {}", e))
        })
    }

    pub async fn decrypt_private_key_from_coordinator_with_session_secret(
        &self,
        session_id: &SessionId,
        encrypted_private_key: &str,
    ) -> Result<Vec<u8>, EnclaveError> {
        // Get the session state to access the session secret
        let session_arc = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EnclaveError::SessionNotFound(session_id.to_string()))?;

        let session_state = session_arc.lock().map_err(|e| {
            error!("Failed to acquire session lock: {}", e);
            EnclaveError::Internal("Session lock poisoned".to_string())
        })?;

        let session_secret = session_state
            .operation_state
            .get_session_secret()
            .ok_or_else(|| EnclaveError::Internal("Session secret not available".to_string()))?;

        // Parse the encrypted private key as EncryptedData
        let encrypted_data = EncryptedData::from_hex_json(encrypted_private_key).map_err(|e| {
            EnclaveError::DataDecodingError(format!("Failed to parse encrypted private key: {}", e))
        })?;

        // Decrypt using the session secret with "private_key" context
        session_secret
            .decrypt(&encrypted_data, "private_key")
            .map_err(|e| {
                EnclaveError::DecryptionFailed(format!("Failed to decrypt private key: {}", e))
            })
    }

    pub async fn decrypt_private_key(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<Vec<u8>, EnclaveError> {
        let session_arc = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EnclaveError::SessionNotFound(session_id.to_string()))?;

        let session_state = session_arc.lock().map_err(|e| {
            error!(
                "Failed to acquire session lock for private key decryption: {}",
                e
            );
            EnclaveError::Internal(
                "Session lock poisoned during private key decryption".to_string(),
            )
        })?;
        let secure_key = session_state.private_keys.get(user_id).ok_or_else(|| {
            EnclaveError::InvalidPrivateKey(format!(
                "Private key not found for user {} in session {}",
                user_id, session_id
            ))
        })?;

        Ok(secure_key.key.clone())
    }

    pub async fn get_coordinator_private_key(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<Vec<u8>>, EnclaveError> {
        let session_arc = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EnclaveError::SessionNotFound(session_id.to_string()))?;

        let session_state = session_arc.lock().map_err(|e| {
            error!(
                "Failed to acquire session lock for coordinator private key: {}",
                e
            );
            EnclaveError::Internal(
                "Session lock poisoned during coordinator private key access".to_string(),
            )
        })?;
        Ok(session_state.operation_state.get_coordinator_private_key())
    }

    pub async fn is_session_coordinator(
        &self,
        session_id: &SessionId,
    ) -> Result<bool, EnclaveError> {
        let session_arc = self
            .sessions
            .get(session_id)
            .ok_or_else(|| EnclaveError::SessionNotFound(session_id.to_string()))?;

        let session_state = session_arc.lock().map_err(|e| {
            error!(
                "Failed to acquire session lock for coordinator check: {}",
                e
            );
            EnclaveError::Internal("Session lock poisoned during coordinator check".to_string())
        })?;
        let is_coordinator = session_state.operation_state.is_coordinator();
        Ok(is_coordinator)
    }

    pub async fn get_session_state(
        &self,
        session_id: &SessionId,
    ) -> Option<Arc<std::sync::Mutex<SessionState>>> {
        self.sessions
            .get(session_id)
            .map(|guard| guard.value().clone())
    }

    pub async fn get_session_stats(&self) -> Result<String, EnclaveError> {
        let total_sessions = self.sessions.iter().count();
        let mut stats = format!("Total sessions: {}\n", total_sessions);

        for entry in self.sessions.iter() {
            let (session_id, session_arc) = (entry.key(), entry.value());
            if let Ok(session_state) = session_arc.lock() {
                stats.push_str(&format!(
                    "Session {}: {} participants\n",
                    session_id,
                    session_state.private_keys.len()
                ));
            }
        }

        Ok(stats)
    }

    /// Handle user signature validation using enclave-stored participant data
    async fn handle_validate_user_signature(
        &self,
        cmd: ValidateUserSignatureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        info!(
            "Validating user signature for user {} in keygen session {} and signing session {}",
            cmd.user_id, cmd.keygen_session_id, cmd.signing_session_id
        );

        // Parse the user signature (format: user_id:nonce:signature_hex)
        let signature_parts: Vec<&str> = cmd.user_signature.split(':').collect();
        if signature_parts.len() != 3 {
            return Ok(EnclaveResponse::ValidateUserSignature(
                ValidateUserSignatureResponse {
                    is_valid: false,
                    user_id: cmd.user_id,
                },
            ));
        }

        let signature_hex = signature_parts[2];

        // For now, we'll use a simplified validation approach
        // In a full implementation, this would:
        // 1. Look up the user's public key from encrypted participant data
        // 2. Validate the signature against the signing session ID
        // For demo purposes, we'll validate the signature format and return true
        let is_valid = match hex::decode(signature_hex) {
            Ok(sig_bytes) => {
                // Basic validation: signature should be 64 bytes (compact format)
                sig_bytes.len() == 64
            }
            Err(_) => false,
        };

        Ok(EnclaveResponse::ValidateUserSignature(
            ValidateUserSignatureResponse {
                is_valid,
                user_id: cmd.user_id,
            },
        ))
    }
}

impl EnclaveOperator {
    async fn handle_generate_nonce(
        &self,
        cmd: keymeld_core::enclave::GenerateNonceCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        let session_id = cmd.signing_session_id.clone();
        trace!(
            "🎲 Generating nonce for session {} and user {}",
            session_id,
            cmd.user_id
        );

        let session_arc = self
            .sessions
            .get(&session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!("Session {} not found for nonce generation", session_id);
                EnclaveError::SessionNotFound(session_id.to_string())
            })?;

        let (has_private_key, coordinator_key) = {
            let session_state = session_arc.lock().map_err(|e| {
                error!("Failed to acquire session lock for nonce generation: {}", e);
                EnclaveError::Internal("Session lock poisoned during nonce generation".to_string())
            })?;
            let has_private_key = session_state.private_keys.contains_key(&cmd.user_id);
            let coordinator_key = session_state.operation_state.get_coordinator_private_key();
            (has_private_key, coordinator_key)
        };

        let private_key = if has_private_key {
            self.decrypt_private_key(&session_id, &cmd.user_id).await?
        } else if let Some(coordinator_key) = coordinator_key {
            coordinator_key
        } else {
            return Err(EnclaveError::InvalidPrivateKey(format!(
                "No private key available for user {} in session {}",
                cmd.user_id, session_id
            )));
        };

        let pub_nonce = {
            let mut session_state = session_arc.lock().map_err(|e| {
                error!("Failed to acquire session lock for nonce generation: {}", e);
                EnclaveError::Internal("Session lock poisoned during nonce generation".to_string())
            })?;
            let key_material = KeyMaterial::new(private_key);
            session_state
                .musig_processor
                .generate_nonce(&session_id, &cmd.user_id, cmd.signer_index, &key_material)
                .map_err(|e| {
                    EnclaveError::NonceGenerationFailed(format!("Failed to generate nonce: {}", e))
                })?
        };

        debug!(
            "Nonce generated successfully for user {} in session {}",
            cmd.user_id, session_id
        );

        Ok(EnclaveResponse::Nonce(
            keymeld_core::enclave::NonceResponse {
                signing_session_id: session_id,
                keygen_session_id: cmd.keygen_session_id,
                user_id: cmd.user_id,
                public_nonce: pub_nonce,
            },
        ))
    }

    async fn handle_add_nonce(
        &self,
        cmd: keymeld_core::enclave::AddNonceCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        info!(
            "📝 Adding nonce for session {} user {} signer_index {}",
            cmd.signing_session_id, cmd.user_id, cmd.signer_index
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for adding nonce",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let mut session_state = session_arc.lock().map_err(|e| {
            error!("Failed to acquire session lock for adding nonce: {}", e);
            EnclaveError::Internal("Session lock poisoned during nonce addition".to_string())
        })?;

        session_state
            .musig_processor
            .add_nonce(
                &cmd.signing_session_id,
                &cmd.user_id,
                cmd.signer_index,
                cmd.nonce,
            )
            .map_err(|e| EnclaveError::NonceError(format!("Failed to add nonce: {}", e)))?;

        debug!(
            "Nonce added successfully for user {} in session {}",
            cmd.user_id, cmd.signing_session_id
        );

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Nonce added successfully".to_string(),
        }))
    }

    async fn handle_sign_partial_signature(
        &self,
        cmd: keymeld_core::enclave::ParitialSignatureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        trace!(
            "Signing partial signature for session {} and user {}",
            cmd.signing_session_id,
            cmd.user_id
        );

        let signing_session_arc = self.sessions.get(&cmd.signing_session_id).ok_or_else(|| {
            error!("Signing session {} not found", cmd.signing_session_id);
            EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
        })?;

        let keygen_session_arc = self.sessions.get(&cmd.keygen_session_id).ok_or_else(|| {
            error!("Keygen session {} not found", cmd.keygen_session_id);
            EnclaveError::SessionNotFound(cmd.keygen_session_id.to_string())
        })?;

        let (has_keygen_key, has_signing_key, coordinator_key) = {
            let keygen_session = keygen_session_arc.lock().map_err(|e| {
                error!("Failed to acquire keygen session lock: {}", e);
                EnclaveError::Internal("Keygen session lock poisoned".to_string())
            })?;
            let signing_session = signing_session_arc.lock().map_err(|e| {
                error!("Failed to acquire signing session lock: {}", e);
                EnclaveError::Internal("Signing session lock poisoned".to_string())
            })?;

            let has_keygen_key = keygen_session.private_keys.contains_key(&cmd.user_id);
            let has_signing_key = signing_session.private_keys.contains_key(&cmd.user_id);
            let coordinator_key = signing_session
                .operation_state
                .get_coordinator_private_key();
            (has_keygen_key, has_signing_key, coordinator_key)
        };

        let private_key = if has_keygen_key {
            self.decrypt_private_key(&cmd.keygen_session_id, &cmd.user_id)
                .await?
        } else if has_signing_key {
            self.decrypt_private_key(&cmd.signing_session_id, &cmd.user_id)
                .await?
        } else if let Some(coordinator_key) = coordinator_key {
            coordinator_key
        } else {
            return Err(EnclaveError::InvalidPrivateKey(format!(
                "No private key available for user {} in session {}",
                cmd.user_id, cmd.signing_session_id
            )));
        };

        let (partial_sig_bytes, pub_nonce_bytes) = {
            let mut signing_session = signing_session_arc.lock().map_err(|e| {
                error!(
                    "Failed to acquire signing session lock for signature generation: {}",
                    e
                );
                EnclaveError::Internal(
                    "Signing session lock poisoned during signature generation".to_string(),
                )
            })?;
            let key_material = KeyMaterial::new(private_key);
            signing_session
                .musig_processor
                .sign_for_user(&cmd.signing_session_id, &cmd.user_id, &key_material)
                .map_err(|e| {
                    EnclaveError::SigningFailed(format!(
                        "Failed to generate partial signature: {}",
                        e
                    ))
                })?
        };

        let partial_signature = musig2::PartialSignature::try_from(partial_sig_bytes.as_slice())
            .map_err(|e| {
                EnclaveError::SignatureError(format!("Failed to parse partial signature: {}", e))
            })?;
        let public_nonce = musig2::PubNonce::try_from(pub_nonce_bytes.as_slice()).map_err(|e| {
            EnclaveError::NonceError(format!("Failed to parse public nonce: {}", e))
        })?;

        debug!(
            "Partial signature generated for user {} in session {}",
            cmd.user_id, cmd.signing_session_id
        );

        Ok(EnclaveResponse::Signature(
            keymeld_core::enclave::SignatureResponse {
                signing_session_id: cmd.signing_session_id,
                keygen_session_id: cmd.keygen_session_id,
                user_id: cmd.user_id,
                partial_signature,
                public_nonce,
            },
        ))
    }

    async fn handle_add_partial_signature(
        &self,
        cmd: keymeld_core::enclave::AddPartialSignatureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        trace!(
            "📝 Adding partial signature for session {}",
            cmd.signing_session_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for adding partial signature",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let mut session_state = session_arc.lock().map_err(|e| {
            error!(
                "Failed to acquire session lock for adding partial signature: {}",
                e
            );
            EnclaveError::Internal(
                "Session lock poisoned during partial signature addition".to_string(),
            )
        })?;

        session_state
            .musig_processor
            .add_partial_signature(&cmd.signing_session_id, cmd.signer_index, cmd.signature)
            .map_err(|e| {
                EnclaveError::SignatureError(format!("Failed to add partial signature: {}", e))
            })?;

        debug!(
            "Partial signature added successfully for session {}",
            cmd.signing_session_id
        );

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Partial signature added successfully".to_string(),
        }))
    }

    async fn handle_get_aggregate_public_key(
        &self,
        cmd: keymeld_core::enclave::GetAggregatePublicKeyCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        trace!(
            "Getting aggregate public key for session {}",
            cmd.keygen_session_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.keygen_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for getting aggregate public key",
                    cmd.keygen_session_id
                );
                EnclaveError::SessionNotFound(cmd.keygen_session_id.to_string())
            })?;

        let session_state = session_arc.lock().map_err(|e| {
            error!(
                "Failed to acquire session lock for aggregate public key: {}",
                e
            );
            EnclaveError::Internal(
                "Session lock poisoned during aggregate public key access".to_string(),
            )
        })?;

        let aggregate_public_key = session_state
            .musig_processor
            .get_aggregate_pubkey(&cmd.keygen_session_id)
            .map_err(|e| {
                EnclaveError::AggregateKeyError(format!(
                    "Failed to get aggregate public key: {}",
                    e
                ))
            })?;

        let participant_count = session_state.private_keys.len();

        debug!(
            "Aggregate public key retrieved for session {} with {} participants",
            cmd.keygen_session_id, participant_count
        );

        Ok(EnclaveResponse::AggregatePublicKey(
            keymeld_core::enclave::AggregatePublicKeyResponse {
                keygen_session_id: cmd.keygen_session_id,
                aggregate_public_key,
                participant_count,
            },
        ))
    }

    async fn handle_finalize(
        &self,
        cmd: keymeld_core::enclave::FinalizeCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        trace!(
            "Finalizing signature for session {} (keygen: {})",
            cmd.signing_session_id,
            cmd.keygen_session_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for finalization",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let mut session_state = session_arc.lock().unwrap();

        let final_signature_bytes = session_state
            .musig_processor
            .aggregate_signatures(&cmd.signing_session_id)
            .map_err(|e| {
                EnclaveError::FinalizationFailed(format!("Failed to finalize signature: {}", e))
            })?;

        let participant_count = session_state.private_keys.len();

        let encrypted_signature = if let Some(session_secret) =
            session_state.operation_state.get_session_secret()
        {
            let encrypted = session_secret
                .encrypt_signature(&final_signature_bytes)
                .map_err(|e| {
                    EnclaveError::CryptographicError(format!("Failed to encrypt signature: {}", e))
                })?;

            encrypted.to_hex_json().map_err(|e| {
                EnclaveError::Internal(format!("Failed to serialize encrypted signature: {}", e))
            })?
        } else {
            hex::encode(final_signature_bytes.clone())
        };

        info!(
            "Signature finalized successfully for session {} with {} participants",
            cmd.signing_session_id, participant_count
        );

        Ok(EnclaveResponse::FinalSignature(
            keymeld_core::enclave::FinalSignatureResponse {
                signing_session_id: cmd.signing_session_id,
                keygen_session_id: cmd.keygen_session_id,
                final_signature: encrypted_signature.into_bytes(),
                participant_count,
            },
        ))
    }

    async fn handle_get_aggregate_nonce(
        &self,
        cmd: keymeld_core::enclave::GetAggregateNonceCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        trace!(
            "Getting aggregate nonce for session {}",
            cmd.signing_session_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for getting aggregate nonce",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let session_state = session_arc.lock().unwrap();

        let aggregated_nonce = session_state
            .musig_processor
            .get_aggregate_nonce(&cmd.signing_session_id)
            .map_err(|e| {
                EnclaveError::NonceError(format!("Failed to get aggregate nonce: {}", e))
            })?;

        let serialized = aggregated_nonce.serialize();
        let pubnonce = musig2::PubNonce::from_bytes(&serialized).map_err(|e| {
            EnclaveError::NonceError(format!("Failed to convert AggNonce to PubNonce: {}", e))
        })?;

        debug!(
            "Aggregate nonce retrieved for session {}",
            cmd.signing_session_id
        );

        Ok(EnclaveResponse::AggregateNonce(
            keymeld_core::enclave::AggregateNonceResponse {
                signing_session_id: cmd.signing_session_id,
                keygen_session_id: cmd.keygen_session_id,
                aggregate_nonce: pubnonce,
            },
        ))
    }

    async fn handle_initiate_adaptor_signing(
        &self,
        cmd: keymeld_core::enclave::InitiateAdaptorSigningCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        info!(
            "Initiating adaptor signing for session {}",
            cmd.signing_session_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for initiating adaptor signing",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let mut session_state = session_arc.lock().unwrap();

        if !session_state
            .musig_processor
            .has_adaptor_configs(&cmd.signing_session_id)
            .unwrap_or(false)
        {
            return Err(EnclaveError::InvalidRequest(
                "No adaptor configurations found for session".to_string(),
            ));
        }

        session_state
            .musig_processor
            .generate_adaptor_nonces(&cmd.signing_session_id)
            .map_err(|e| {
                EnclaveError::SigningError(format!("Failed to generate adaptor nonces: {}", e))
            })?;

        // Generate all partial signatures for all participants and adaptors internally
        let session_metadata = session_state
            .musig_processor
            .get_session_metadata_public(&cmd.signing_session_id)
            .ok_or_else(|| {
                EnclaveError::SessionNotFound(format!(
                    "No metadata found for session {}",
                    cmd.signing_session_id
                ))
            })?;

        let adaptor_configs = session_metadata.adaptor_configs.clone();
        let participants = session_metadata.expected_participants.clone();

        for user_id in &participants {
            let key_material = session_state
                .get_user_key_material(user_id)
                .ok_or_else(|| {
                    EnclaveError::KeyError(format!("Key material not found for user {}", user_id))
                })?;

            for config in &adaptor_configs {
                session_state
                    .musig_processor
                    .sign_adaptor_for_user(
                        &cmd.signing_session_id,
                        user_id,
                        &config.adaptor_id,
                        &key_material,
                    )
                    .map_err(|e| {
                        EnclaveError::SigningError(format!(
                            "Failed to sign adaptor partial for user {} adaptor {}: {}",
                            user_id, config.adaptor_id, e
                        ))
                    })?;
            }
        }

        info!(
            "Adaptor signing initiated and all partial signatures generated for session {}",
            cmd.signing_session_id
        );

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Adaptor signing initiated and partial signatures generated".to_string(),
        }))
    }

    async fn handle_sign_adaptor_partial_signature(
        &self,
        cmd: keymeld_core::enclave::SignAdaptorPartialSignatureCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        info!(
            "Signing adaptor partial signature for session {} user {} adaptor {}",
            cmd.signing_session_id, cmd.user_id, cmd.adaptor_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for adaptor partial signature",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let mut session_state = session_arc.lock().unwrap();

        let key_material = session_state
            .get_user_key_material(&cmd.user_id)
            .ok_or_else(|| {
                EnclaveError::KeyError(format!("Key material not found for user {}", cmd.user_id))
            })?;

        let partial_sig = session_state
            .musig_processor
            .sign_adaptor_for_user(
                &cmd.signing_session_id,
                &cmd.user_id,
                &cmd.adaptor_id,
                &key_material,
            )
            .map_err(|e| {
                EnclaveError::SigningError(format!("Failed to sign adaptor partial: {}", e))
            })?;

        info!(
            "Adaptor partial signature created for session {} user {} adaptor {}",
            cmd.signing_session_id, cmd.user_id, cmd.adaptor_id
        );

        Ok(EnclaveResponse::AdaptorPartialSignature(
            keymeld_core::enclave::AdaptorPartialSignatureResponse {
                signing_session_id: cmd.signing_session_id,
                user_id: cmd.user_id,
                adaptor_id: cmd.adaptor_id,
                partial_signature: hex::encode(partial_sig.serialize()),
            },
        ))
    }

    async fn handle_process_adaptor_signatures(
        &self,
        cmd: keymeld_core::enclave::ProcessAdaptorSignaturesCommand,
    ) -> Result<EnclaveResponse, EnclaveError> {
        info!(
            "Processing adaptor signatures for session {}",
            cmd.signing_session_id
        );

        let session_arc = self
            .sessions
            .get(&cmd.signing_session_id)
            .map(|guard| guard.value().clone())
            .ok_or_else(|| {
                error!(
                    "Session {} not found for processing adaptor signatures",
                    cmd.signing_session_id
                );
                EnclaveError::SessionNotFound(cmd.signing_session_id.to_string())
            })?;

        let mut session_state = session_arc.lock().unwrap();

        if !session_state
            .musig_processor
            .are_adaptor_signatures_ready(&cmd.signing_session_id)
            .unwrap_or(false)
        {
            return Err(EnclaveError::InvalidRequest(
                "Not all adaptor signatures are ready".to_string(),
            ));
        }

        let adaptor_signatures = session_state
            .musig_processor
            .process_adaptor_signatures(&cmd.signing_session_id)
            .map_err(|e| {
                EnclaveError::SigningError(format!("Failed to process adaptor signatures: {}", e))
            })?;

        let encrypted_adaptor_signatures =
            if let Some(session_secret) = session_state.operation_state.get_session_secret() {
                let encrypted = session_secret
                    .encrypt_adaptor_signatures(&adaptor_signatures)
                    .map_err(|e| {
                        EnclaveError::CryptographicError(format!(
                            "Failed to encrypt adaptor signatures: {}",
                            e
                        ))
                    })?;

                encrypted.to_hex_json().map_err(|e| {
                    EnclaveError::Internal(format!(
                        "Failed to serialize encrypted adaptor signatures: {}",
                        e
                    ))
                })?
            } else {
                serde_json::to_string(&adaptor_signatures).map_err(|e| {
                    EnclaveError::Internal(format!("Failed to serialize adaptor signatures: {}", e))
                })?
            };

        info!(
            "Processed {} adaptor signatures for session {}",
            adaptor_signatures.len(),
            cmd.signing_session_id
        );

        Ok(EnclaveResponse::AdaptorSignatures(
            keymeld_core::enclave::AdaptorSignaturesResponse {
                signing_session_id: cmd.signing_session_id,
                adaptor_signatures: encrypted_adaptor_signatures,
            },
        ))
    }
}

impl Drop for EnclaveOperator {
    fn drop(&mut self) {
        info!("Dropping EnclaveOperator and zeroizing sensitive data");
        self.private_key.zeroize();
    }
}
