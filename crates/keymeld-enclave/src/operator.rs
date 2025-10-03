use crate::{
    attestation::AttestationManager,
    state::{OperationCompleted, OperationInitData, OperationInitialized, OperationState},
};
use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use keymeld_core::enclave::protocol::PublicInfoResponse;
use keymeld_core::{
    crypto::{SecureCrypto, SessionSecret},
    enclave::{
        AddNonceCommand, AddPartialSignatureCommand, AddParticipantCommand, AggregateNonceResponse,
        AggregatePublicKeyResponse, AttestationResponse, ConfigureCommand, EnclaveCommand,
        EnclaveError, EnclaveResponse, ErrorResponse, FinalSignatureResponse, FinalizeCommand,
        GenerateNonceCommand, GetAggregateNonceCommand, GetAggregatePublicKeyCommand,
        InitSessionCommand, NonceResponse, SignatureResponse, SuccessResponse,
        ValidateKeygenParticipantHmacCommand, ValidateSessionHmacCommand,
    },
    identifiers::UserId,
    musig::{MusigError, MusigProcessor},
    session::AggregatePublicKey,
    EnclaveId, KeyMaterial, PartialSignature, PubNonce, SessionId,
};
use musig2::secp256k1::{schnorr::Signature, PublicKey, SecretKey};
use sha2::Sha256;
use std::collections::BTreeMap;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecurePrivateKey {
    key: Vec<u8>,
}

pub struct EnclaveOperator {
    pub enclave_id: EnclaveId,
    pub operations: RwLock<BTreeMap<SessionId, OperationState>>,
    /// MuSig2 processor for cryptographic operations
    pub musig_processor: RwLock<MusigProcessor>,
    /// Attestation manager for generating attestations
    pub attestation_manager: Option<AttestationManager>,
    /// Enclave public key
    pub public_key: Vec<u8>,
    /// Enclave private key (zeroized on drop)
    pub private_key: Vec<u8>,
    /// Securely stored private keys for participants
    private_keys: RwLock<BTreeMap<(SessionId, UserId), SecurePrivateKey>>,
    /// Enclave startup time
    startup_time: u64,
    /// Key generation time
    key_generation_time: u64,
    /// Key epoch (incremented on key rotation)
    key_epoch: u64,
}

type HmacSha256 = Hmac<Sha256>;
impl EnclaveOperator {
    pub fn new(enclave_id: EnclaveId) -> Result<Self> {
        let musig_processor = MusigProcessor::new();
        let keypair = SecureCrypto::generate_enclave_keypair()?;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            enclave_id,
            operations: RwLock::new(BTreeMap::new()),
            musig_processor: RwLock::new(musig_processor),
            attestation_manager: None,
            public_key: keypair.1.serialize().to_vec(),
            private_key: keypair.0.secret_bytes().to_vec(),
            private_keys: RwLock::new(BTreeMap::new()),
            startup_time: current_time,
            key_generation_time: current_time,
            key_epoch: 1,
        })
    }

    pub fn initialize_attestation(&mut self, attestation_manager: AttestationManager) {
        info!(
            "Initializing attestation manager for enclave {}",
            self.enclave_id
        );
        self.attestation_manager = Some(attestation_manager);
    }

    pub fn get_attestation_manager(&self) -> Option<&AttestationManager> {
        self.attestation_manager.as_ref()
    }

    pub fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub async fn handle_command(&self, command: EnclaveCommand) -> Result<EnclaveResponse> {
        match command {
            EnclaveCommand::Ping => Ok(EnclaveResponse::Pong),
            EnclaveCommand::Configure(cmd) => self.handle_configure(cmd).await,
            EnclaveCommand::InitSession(cmd) => self.handle_init_session(cmd).await,
            EnclaveCommand::AddParticipant(cmd) => self.handle_add_participant(cmd).await,
            EnclaveCommand::GenerateNonce(cmd) => self.handle_generate_nonce(cmd).await,
            EnclaveCommand::AddNonce(cmd) => self.handle_add_nonce(cmd).await,
            EnclaveCommand::GetAggregatePublicKey(cmd) => {
                self.handle_get_aggregate_public_key(cmd).await
            }
            EnclaveCommand::SignPartialSignature(cmd) => {
                self.handle_sign_partial_signature(cmd).await
            }
            EnclaveCommand::AddPartialSignature(cmd) => {
                self.handle_add_partial_signature(cmd).await
            }
            EnclaveCommand::Finalize(cmd) => self.handle_finalize(cmd).await,
            EnclaveCommand::GetAggregateNonce(cmd) => self.handle_get_aggregate_nonce(cmd).await,
            EnclaveCommand::ValidateSessionHmac(cmd) => {
                self.handle_validate_session_hmac(cmd).await
            }
            EnclaveCommand::ValidateKeygenParticipantHmac(cmd) => {
                self.handle_validate_keygen_participant_hmac(cmd).await
            }
            EnclaveCommand::ClearSession(cmd) => {
                let session_id = cmd
                    .keygen_session_id
                    .or(cmd.signing_session_id)
                    .ok_or_else(|| {
                        anyhow!("Either keygen_session_id or signing_session_id must be provided")
                    })?;

                self.clear_session(session_id)
                    .await
                    .map_err(|_| anyhow!("Clear session failed"))?;
                Ok(EnclaveResponse::Success(SuccessResponse {
                    message: "Session cleared".to_string(),
                }))
            }
            EnclaveCommand::GetPublicInfo => {
                let attestation_document =
                    if let Some(attestation_manager) = &self.attestation_manager {
                        match attestation_manager
                            .get_identity_attestation_with_data(Some(&self.get_public_key()))
                        {
                            Ok(Some(attestation_doc)) => Some(AttestationResponse {
                                pcrs: attestation_doc.pcrs,
                                timestamp: attestation_doc.timestamp,
                                certificate: attestation_doc.certificate,
                                signature: attestation_doc.signature,
                                user_data: self.get_public_key(),
                            }),
                            Ok(None) => {
                                warn!("Attestation generation is disabled");
                                None
                            }
                            Err(e) => {
                                warn!("Failed to generate attestation: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                Ok(EnclaveResponse::PublicInfo(PublicInfoResponse {
                    public_key: hex::encode(&self.public_key),
                    attestation_document,
                    active_sessions: self.get_active_sessions_count().await,
                    uptime_seconds: self.get_uptime_seconds(),
                    key_epoch: self.get_key_epoch(),
                    key_generation_time: self.get_key_generation_time(),
                }))
            }
        }
    }

    async fn handle_configure(&self, cmd: ConfigureCommand) -> Result<EnclaveResponse> {
        info!("Configuring enclave {}", cmd.enclave_id);
        Ok(EnclaveResponse::Success(SuccessResponse {
            message: format!("Enclave {} configured", cmd.enclave_id),
        }))
    }

    async fn handle_init_session(&self, cmd: InitSessionCommand) -> Result<EnclaveResponse> {
        // Determine session type and ID based on which fields are present
        let (session_id, session_type) = match (&cmd.keygen_session_id, &cmd.signing_session_id) {
            (Some(keygen_id), None) => (keygen_id.clone(), "keygen"),
            (Some(_keygen_id), Some(signing_id)) => (signing_id.clone(), "signing"),
            (None, Some(signing_id)) => (signing_id.clone(), "signing"),
            (None, None) => {
                return Err(anyhow!(
                    "Either keygen_session_id or signing_session_id must be provided"
                ))
            }
        };

        info!("Initializing {} session: {}", session_type, session_id);

        // Decrypt the session secret if provided (only for coordinator enclave)
        let session_secret = if let Some(encrypted_secret) = &cmd.encrypted_session_secret {
            // Decrypt the session secret using ECIES with our private key
            let private_key_array: [u8; 32] = self.private_key[..32]
                .try_into()
                .map_err(|_| anyhow!("Private key must be exactly 32 bytes"))?;
            let secret_key = SecretKey::from_byte_array(private_key_array)
                .map_err(|e| anyhow!("Invalid private key: {}", e))?;

            let decoded_bytes =
                hex::decode(encrypted_secret).map_err(|e| anyhow!("Hex decode failed: {}", e))?;

            let decrypted_secret_bytes =
                SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes)
                    .map_err(|e| anyhow!("Failed to decrypt session secret: {}", e))?;

            // The decrypted data should be a hex-encoded string representing 32 bytes
            // Convert to string and then hex-decode to get the actual secret bytes
            let session_secret_str = String::from_utf8_lossy(&decrypted_secret_bytes);
            let secret_bytes = hex::decode(session_secret_str.as_ref())
                .map_err(|e| anyhow!("Failed to decode hex session secret: {}", e))?;

            if secret_bytes.len() != 32 {
                return Err(anyhow!(
                    "Invalid session secret length: expected 32 bytes, got {}",
                    secret_bytes.len()
                ));
            }
            let mut secret_array = [0u8; 32];
            secret_array.copy_from_slice(&secret_bytes);
            Some(SessionSecret::from_bytes(secret_array))
        } else {
            // No session secret provided - this is expected for non-coordinator enclaves
            None
        };

        // Initialize session without participant pubkeys - they will be added during nonce collection
        let mut processor = self.musig_processor.write().await;
        processor
            .init_session(
                &session_id,
                cmd.message.clone(),
                cmd.taproot_tweak,
                Vec::new(),
                Some(cmd.expected_participant_count),
            )
            .map_err(|e| anyhow!("Failed to initialize MuSig2: {}", e))?;

        let message_hash = SessionSecret::hash_message(
            &String::from_utf8(cmd.message.clone()).unwrap_or_default(),
        );

        // Decrypt coordinator private key if provided
        let coordinator_private_key =
            if let Some(encrypted_key) = &cmd.coordinator_encrypted_private_key {
                match self
                    .decrypt_private_key_from_coordinator(encrypted_key)
                    .await
                {
                    Ok(key) => Some(key),
                    Err(e) => {
                        warn!(
                            "Failed to decrypt coordinator private key during init: {}",
                            e
                        );
                        None // Continue without coordinator key for now
                    }
                }
            } else {
                None
            };

        let init_data = OperationInitData {
            session_id: session_id.clone(),
            session_secret,
            message: cmd.message,
            message_hash,
            participant_keys: vec![],
            aggregate_public_key: vec![],
            is_coordinator: cmd.coordinator_encrypted_private_key.is_some(),
            coordinator_private_key,
        };
        let operation = OperationInitialized::new(init_data);

        let mut operations = self.operations.write().await;
        operations.insert(session_id.clone(), OperationState::from(operation));

        info!("Session {} initialized with session secret", session_id);
        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Session initialized".to_string(),
        }))
    }

    async fn handle_add_participant(&self, cmd: AddParticipantCommand) -> Result<EnclaveResponse> {
        let session_id = cmd
            .signing_session_id
            .or(cmd.keygen_session_id)
            .ok_or_else(|| {
                anyhow!("Either keygen_session_id or signing_session_id must be provided")
            })?;

        info!(
            "Adding participant {} to session {} (private_key: {})",
            cmd.user_id,
            session_id,
            if cmd.encrypted_private_key.is_some() {
                "included"
            } else {
                "omitted"
            }
        );

        // Parse the participant's public key
        let public_key = PublicKey::from_slice(&cmd.public_key)
            .map_err(|e| anyhow!("Invalid participant public key: {}", e))?;

        // If encrypted private key is provided, decrypt and store it
        if let Some(encrypted_private_key) = &cmd.encrypted_private_key {
            info!(
                "Decrypting and storing private key for participant {} in session {}",
                cmd.user_id, session_id
            );

            // Decrypt the private key using the enclave's private key
            let private_key_array: [u8; 32] = self.private_key[..32]
                .try_into()
                .map_err(|_| anyhow!("Private key must be exactly 32 bytes"))?;

            let secret_key = SecretKey::from_byte_array(private_key_array)
                .map_err(|e| anyhow!("Invalid enclave private key: {}", e))?;

            let decoded_bytes = hex::decode(encrypted_private_key)
                .map_err(|e| anyhow!("Hex decode failed: {}", e))?;

            let decrypted_private_key = SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes)
                .map_err(|e| anyhow!("Failed to decrypt participant private key: {}", e))?;

            // Store the decrypted private key securely
            let key_storage = SecurePrivateKey {
                key: decrypted_private_key.clone(),
            };

            let session_key = (session_id.clone(), cmd.user_id.clone());
            {
                let mut keys = self.private_keys.write().await;
                keys.insert(session_key, key_storage);
            }

            info!(
                "Successfully decrypted and stored private key for participant {} in session {}",
                cmd.user_id, session_id
            );
        }

        // Add participant to the MuSig session
        let mut processor = self.musig_processor.write().await;

        // Log current state before adding participant
        if let Some(session_meta) = processor.get_session_metadata_public(&session_id) {
            info!(
                "Before adding participant {}: session {} has {} participants, phase={:?}",
                cmd.user_id,
                session_id,
                session_meta.expected_participants.len(),
                session_meta.phase
            );
        }

        match processor.add_participant(&session_id, cmd.user_id.clone(), public_key) {
            Ok(()) => {
                // Log state after successful addition
                if let Some(session_meta) = processor.get_session_metadata_public(&session_id) {
                    info!(
                        "Successfully added participant {} to session {}: now has {} participants, phase={:?}",
                        cmd.user_id, session_id, session_meta.expected_participants.len(), session_meta.phase
                    );
                }
            }
            Err(MusigError::DuplicateParticipant(_)) => {
                info!(
                    "Participant {} already exists in session {} - ignoring duplicate",
                    cmd.user_id, session_id
                );
                // Return success for idempotent operation
                return Ok(EnclaveResponse::Success(SuccessResponse {
                    message: format!(
                        "Participant {} already exists in session {}",
                        cmd.user_id, session_id
                    ),
                }));
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to add participant to MuSig2 session: {}",
                    e
                ));
            }
        }

        // Also add participant to the session state (only if not already present)
        let mut operations = self.operations.write().await;
        if let Some(session_state) = operations.get_mut(&session_id) {
            match session_state {
                OperationState::Initialized(ref mut session) => {
                    // Check if participant key already exists to avoid duplicates
                    if !session.participant_keys.contains(&cmd.public_key) {
                        session.participant_keys.push(cmd.public_key.clone());

                        if let Some(_encrypted_private_key) = &cmd.encrypted_private_key {
                            info!(
                                "Validated encrypted private key for participant {} in session {}",
                                cmd.user_id, session_id
                            );
                        }
                    }
                }
                _ => {
                    warn!("Session {} is not in initialized state", session_id);
                }
            }
        } else {
            warn!("Session {} not found in session states", session_id);
        }

        info!(
            "Successfully added participant {} to session {}",
            cmd.user_id, session_id
        );

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: format!(
                "Participant {} added to session {}",
                cmd.user_id, session_id
            ),
        }))
    }

    async fn handle_generate_nonce(&self, cmd: GenerateNonceCommand) -> Result<EnclaveResponse> {
        info!(
            "Generating nonce for signing session {} (keygen: {}) user {} signer_index {}",
            cmd.signing_session_id, cmd.keygen_session_id, cmd.user_id, cmd.signer_index
        );

        // Check current session state in MuSig processor
        {
            let processor = self.musig_processor.read().await;
            if let Some(session_meta) =
                processor.get_session_metadata_public(&cmd.signing_session_id)
            {
                info!(
                    "Session {} MuSig state: phase={:?}, participant_count={}",
                    cmd.signing_session_id,
                    session_meta.phase,
                    session_meta.expected_participants.len()
                );
            } else {
                warn!(
                    "Session {} not found in MuSig processor",
                    cmd.signing_session_id
                );
            }
        }

        let private_key = if cmd.encrypted_private_key.is_none()
            || cmd
                .encrypted_private_key
                .as_ref()
                .map(|s| s.is_empty())
                .unwrap_or(true)
        {
            info!("Using coordinator private key for user {}", cmd.user_id);
            self.get_coordinator_private_key(&cmd.signing_session_id)
                .await
                .ok_or_else(|| anyhow!("No private key available"))?
        } else {
            info!(
                "Decrypting participant private key for user {}, enclave_id: {}",
                cmd.user_id, self.enclave_id
            );
            self.decrypt_private_key_from_coordinator(cmd.encrypted_private_key.as_ref().unwrap())
                .await
                .map_err(|e| {
                    error!(
                        "Failed to decrypt private key for user {}: {}",
                        cmd.user_id, e
                    );
                    anyhow!("Failed to decrypt private key: {}", e)
                })?
        };

        let key_material = KeyMaterial::new(private_key);
        let mut processor = self.musig_processor.write().await;

        let pub_nonce = processor
            .generate_nonce(
                &cmd.signing_session_id,
                &cmd.user_id,
                cmd.signer_index,
                &key_material,
            )
            .map_err(|e| anyhow!("Failed to generate nonce: {}", e))?;

        info!(
            "Successfully generated nonce for signing session {} user {} signer_index {}",
            cmd.signing_session_id, cmd.user_id, cmd.signer_index
        );
        Ok(EnclaveResponse::Nonce(NonceResponse {
            signing_session_id: cmd.signing_session_id,
            keygen_session_id: cmd.keygen_session_id,
            user_id: cmd.user_id,
            public_nonce: pub_nonce,
        }))
    }

    async fn handle_add_nonce(&self, cmd: AddNonceCommand) -> Result<EnclaveResponse> {
        let mut processor = self.musig_processor.write().await;

        processor
            .add_nonce(
                &cmd.signing_session_id,
                &cmd.user_id,
                cmd.signer_index,
                cmd.nonce,
            )
            .map_err(|e| anyhow!("Failed to add nonce: {}", e))?;

        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Nonce added".to_string(),
        }))
    }

    async fn handle_sign_partial_signature(
        &self,
        cmd: keymeld_core::enclave::ParitialSignatureCommand,
    ) -> Result<EnclaveResponse> {
        info!(
            "Signing partial signature for signing session {} (keygen: {}) user {}",
            cmd.signing_session_id, cmd.keygen_session_id, cmd.user_id
        );

        // Use the stored private key for this user and session
        let session_key = (cmd.keygen_session_id.clone(), cmd.user_id.clone());
        let private_key = {
            let keys = self.private_keys.read().await;
            keys.get(&session_key)
                .ok_or_else(|| {
                    anyhow!(
                        "Private key not found for user {} in session {}",
                        cmd.user_id,
                        cmd.keygen_session_id
                    )
                })?
                .key
                .clone()
        };

        let key_material = keymeld_core::KeyMaterial::new(private_key);
        let mut processor = self.musig_processor.write().await;

        let (partial_sig_bytes, pub_nonce_bytes) = processor
            .sign_for_aggregator(
                &cmd.signing_session_id,
                &cmd.user_id,
                &key_material,
                &cmd.aggregate_nonce.serialize(),
            )
            .map_err(|e| anyhow!("Failed to generate partial signature: {}", e))?;

        let partial_signature = PartialSignature::try_from(partial_sig_bytes.as_slice())
            .map_err(|e| anyhow!("Failed to parse partial signature: {}", e))?;
        let public_nonce = PubNonce::try_from(pub_nonce_bytes.as_slice())
            .map_err(|e| anyhow!("Failed to parse public nonce: {}", e))?;

        info!(
            "Successfully generated partial signature for signing session {} user {}",
            cmd.signing_session_id, cmd.user_id
        );

        Ok(EnclaveResponse::Signature(SignatureResponse {
            signing_session_id: cmd.signing_session_id,
            keygen_session_id: cmd.keygen_session_id,
            user_id: cmd.user_id,
            partial_signature,
            public_nonce,
        }))
    }

    async fn handle_add_partial_signature(
        &self,
        cmd: AddPartialSignatureCommand,
    ) -> Result<EnclaveResponse> {
        let mut processor = self.musig_processor.write().await;
        processor
            .add_partial_signature(&cmd.signing_session_id, cmd.signer_index, cmd.signature)
            .map_err(|e| anyhow!("Failed to add partial signature: {}", e))?;
        Ok(EnclaveResponse::Success(SuccessResponse {
            message: "Partial signature added".to_string(),
        }))
    }

    async fn handle_get_aggregate_public_key(
        &self,
        cmd: GetAggregatePublicKeyCommand,
    ) -> Result<EnclaveResponse> {
        info!(
            "Getting aggregate public key for keygen session {}",
            cmd.keygen_session_id
        );

        let processor = self.musig_processor.read().await;
        match processor.get_aggregate_pubkey(&cmd.keygen_session_id) {
            Ok(aggregate_key_bytes) => {
                let participant_count = processor
                    .get_session_metadata_public(&cmd.keygen_session_id)
                    .map(|meta| meta.expected_participants.len())
                    .unwrap_or(0);

                info!(
                    "Successfully retrieved aggregate public key for keygen session {} ({} participants)",
                    cmd.keygen_session_id, participant_count
                );

                // Create AggregatePublicKey from bytes
                let aggregate_public_key = AggregatePublicKey::new(
                    aggregate_key_bytes,
                    vec![], // participant_ids will be filled by the caller
                    vec![], // participant_keys_hash will be filled by the caller
                );

                Ok(EnclaveResponse::AggregatePublicKey(
                    AggregatePublicKeyResponse {
                        keygen_session_id: cmd.keygen_session_id,
                        aggregate_public_key: aggregate_public_key.key_bytes,
                        participant_count,
                    },
                ))
            }
            Err(e) => {
                warn!(
                    "Failed to get aggregate public key for keygen session {}: {}",
                    cmd.keygen_session_id, e
                );
                Err(anyhow!("Failed to get aggregate public key: {}", e))
            }
        }
    }

    async fn handle_finalize(&self, cmd: FinalizeCommand) -> Result<EnclaveResponse> {
        info!(
            "Finalizing signature for signing session {} (keygen: {})",
            cmd.signing_session_id, cmd.keygen_session_id
        );

        // Aggregate signatures using the MuSig processor
        let mut processor = self.musig_processor.write().await;
        let final_signature_bytes = processor
            .aggregate_signatures(&cmd.signing_session_id)
            .map_err(|e| anyhow!("Failed to aggregate signatures: {e}"))?;

        // Convert Vec<u8> to Signature
        let signature_array: [u8; 64] = final_signature_bytes
            .try_into()
            .map_err(|_| anyhow!("Final signature must be exactly 64 bytes"))?;
        let final_signature = Signature::from_byte_array(signature_array);

        let participant_count = processor
            .get_session_metadata_public(&cmd.signing_session_id)
            .map(|s| s.expected_participants.len())
            .unwrap_or(0);

        // Release the processor lock before accessing sessions
        drop(processor);

        // Get session for encryption - only need the session secret
        let operations = self.operations.read().await;
        let session_state = operations
            .get(&cmd.signing_session_id)
            .ok_or_else(|| anyhow!("Session {} not found", cmd.signing_session_id))?;

        // Extract session secret for encryption
        let session_secret = session_state
            .get_session_secret()
            .ok_or_else(|| {
                anyhow!(
                    "No session secret available for session {}",
                    cmd.signing_session_id
                )
            })?
            .clone();

        // Encrypt only the final signature (without the message)
        let final_signature_bytes = final_signature.to_byte_array();
        let encrypted_signed_message = session_secret
            .encrypt_signature(&final_signature_bytes)
            .map_err(|e| anyhow!("Failed to encrypt signature: {e:?}"))?
            .to_hex_json()
            .map_err(|e| anyhow!("Failed to serialize encrypted signature: {e:?}"))?;

        // Release read lock and update session to completed
        drop(operations);
        let mut operations = self.operations.write().await;

        let completed_session = OperationCompleted {
            session_id: cmd.signing_session_id.clone(),
            session_secret: Some(session_secret),
            encrypted_signed_message: encrypted_signed_message.clone().into_bytes(),
            participant_count: participant_count as u32,
        };

        operations.insert(
            cmd.signing_session_id.clone(),
            OperationState::Completed(completed_session),
        );

        info!(
            "Signing session {} finalized and encrypted signature stored",
            cmd.signing_session_id
        );

        Ok(EnclaveResponse::FinalSignature(FinalSignatureResponse {
            signing_session_id: cmd.signing_session_id,
            keygen_session_id: cmd.keygen_session_id,
            final_signature: encrypted_signed_message.into_bytes(),
            participant_count,
        }))
    }

    async fn handle_get_aggregate_nonce(
        &self,
        cmd: GetAggregateNonceCommand,
    ) -> Result<EnclaveResponse> {
        let processor = self.musig_processor.read().await;
        match processor.get_aggregate_nonce(&cmd.signing_session_id) {
            Ok(aggregated_nonce) => {
                let serialized = aggregated_nonce.serialize();
                let pubnonce = PubNonce::from_bytes(&serialized)
                    .map_err(|e| anyhow!("Failed to convert AggNonce to PubNonce: {}", e))?;
                Ok(EnclaveResponse::AggregateNonce(AggregateNonceResponse {
                    signing_session_id: cmd.signing_session_id,
                    keygen_session_id: cmd.keygen_session_id,
                    aggregate_nonce: pubnonce,
                }))
            }
            Err(e) => Ok(EnclaveResponse::Error(ErrorResponse {
                error: EnclaveError::MuSigError("Conversion error".to_string()),
                message: format!("Failed to get aggregate nonce: {}", e),
            })),
        }
    }

    pub async fn get_status(&self) -> (EnclaveId, bool, Vec<u8>, u32) {
        let operations = self.operations.read().await;
        let active_sessions = operations.len() as u32;
        let ready = true; // Always ready since we don't need KMS

        (
            self.enclave_id,
            ready,
            self.public_key.clone(),
            active_sessions,
        )
    }

    pub fn get_startup_time(&self) -> u64 {
        self.startup_time
    }

    pub fn get_key_generation_time(&self) -> u64 {
        self.key_generation_time
    }

    pub fn get_key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub fn get_uptime_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - self.startup_time
    }

    pub async fn get_active_sessions_count(&self) -> u32 {
        let operations = self.operations.read().await;
        operations.len() as u32
    }

    async fn handle_validate_session_hmac(
        &self,
        cmd: ValidateSessionHmacCommand,
    ) -> Result<EnclaveResponse> {
        let session_id = cmd
            .signing_session_id
            .or(cmd.keygen_session_id)
            .ok_or_else(|| {
                anyhow!("Either keygen_session_id or signing_session_id must be provided")
            })?;

        info!(
            "Validating session HMAC for session {} user {}",
            session_id, cmd.user_id
        );

        let session_secret = match self.decrypt_session_secret(&cmd.encrypted_session_secret) {
            Ok(secret) => secret,
            Err(e) => {
                warn!("Failed to decrypt session secret: {}", e);
                return Ok(EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::HmacInvalid,
                    message: "Failed to decrypt session secret".to_string(),
                }));
            }
        };

        let operations = self.operations.read().await;
        if let Some(_session) = operations.get(&session_id) {
            let validation_result = SecureCrypto::validate_signing_hmac(
                &session_id.as_string(),
                &cmd.user_id.as_str(),
                &cmd.session_hmac,
                &String::from_utf8_lossy(&session_secret),
                &cmd.message_hash,
            );

            match validation_result {
                Ok(()) => {
                    info!(
                        "HMAC validation SUCCESS - Session: {}, User: {}",
                        session_id, cmd.user_id
                    );
                    Ok(EnclaveResponse::Success(SuccessResponse {
                        message: "HMAC validation successful".to_string(),
                    }))
                }
                Err(e) => {
                    warn!(
                        "HMAC validation FAILED - Session: {}, User: {}, Error: {}",
                        session_id, cmd.user_id, e
                    );
                    Ok(EnclaveResponse::Error(ErrorResponse {
                        error: EnclaveError::HmacInvalid,
                        message: "HMAC validation failed".to_string(),
                    }))
                }
            }
        } else {
            warn!("Session {} not found for HMAC validation", session_id);
            Ok(EnclaveResponse::Error(ErrorResponse {
                error: EnclaveError::SessionNotFound,
                message: "Session not found".to_string(),
            }))
        }
    }

    fn decrypt_session_secret(
        &self,
        encrypted_session_secret: &str,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let private_key_array: [u8; 32] = self.private_key[..32]
            .try_into()
            .map_err(|_| anyhow!("Private key must be exactly 32 bytes"))?;

        let secret_key = SecretKey::from_byte_array(private_key_array)
            .map_err(|e| anyhow!("Invalid private key: {}", e))?;

        let decoded_bytes = hex::decode(encrypted_session_secret)
            .map_err(|e| anyhow!("Hex decode failed: {}", e))?;

        let decrypted_secret = SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes)
            .map_err(|e| anyhow!("Failed to decrypt session secret: {}", e))?;

        Ok(decrypted_secret)
    }

    async fn handle_validate_keygen_participant_hmac(
        &self,
        cmd: ValidateKeygenParticipantHmacCommand,
    ) -> Result<EnclaveResponse> {
        info!(
            "Validating keygen participant HMAC for keygen session {} user {}",
            cmd.keygen_session_id, cmd.user_id
        );

        let decrypted_secret = match self.decrypt_session_secret(&cmd.encrypted_session_secret) {
            Ok(secret) => secret,
            Err(e) => {
                warn!("Failed to decrypt session secret: {}", e);
                return Ok(EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::HmacInvalid,
                    message: "Failed to decrypt session secret".to_string(),
                }));
            }
        };

        // Parse the session_hmac to extract nonce and hmac (format: "nonce:hmac")
        let (nonce, provided_hmac) = match cmd.session_hmac.split_once(':') {
            Some((nonce, hmac)) => (nonce, hmac),
            None => {
                warn!("Invalid HMAC format, expected 'nonce:hmac'");
                return Ok(EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::HmacInvalid,
                    message: "Invalid HMAC format".to_string(),
                }));
            }
        };

        // For keygen participant validation, generate the message hash internally
        // using the pattern: "{}:{}:{}" with keygen_session_id, user_id, and nonce
        let message_data = format!(
            "{}:{}:{}",
            cmd.keygen_session_id.as_string(),
            cmd.user_id.as_str(),
            nonce
        );
        let message_hash = message_data.as_bytes();

        // Decode the hex session secret to get raw bytes for HMAC key
        let session_secret_str = String::from_utf8_lossy(&decrypted_secret);
        let secret_bytes = match hex::decode(session_secret_str.as_ref()) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Failed to decode hex session secret: {}", e);
                return Ok(EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::HmacInvalid,
                    message: "Failed to decrypt session secret".to_string(),
                }));
            }
        };

        // Create HMAC with the decoded session secret as the key
        let mut mac = match HmacSha256::new_from_slice(&secret_bytes) {
            Ok(mac) => mac,
            Err(e) => {
                warn!("Failed to create HMAC: {}", e);
                return Ok(EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::HmacInvalid,
                    message: "Failed to create HMAC".to_string(),
                }));
            }
        };

        mac.update(message_hash);
        let expected_hmac = hex::encode(mac.finalize().into_bytes());
        let is_valid = expected_hmac == provided_hmac;

        info!(
            "Keygen participant HMAC validation - Session: {}, User: {}, Nonce: {}, Message: {}, Expected: {}, Provided: {}, Valid: {}",
            cmd.keygen_session_id,
            cmd.user_id,
            nonce,
            message_data,
            expected_hmac,
            provided_hmac,
            is_valid
        );

        if is_valid {
            Ok(EnclaveResponse::Success(SuccessResponse {
                message: "Keygen participant HMAC validation successful".to_string(),
            }))
        } else {
            Ok(EnclaveResponse::Error(ErrorResponse {
                error: EnclaveError::HmacInvalid,
                message: "Keygen participant HMAC validation failed".to_string(),
            }))
        }
    }

    pub async fn clear_session(&self, session_id: SessionId) -> Result<(), EnclaveError> {
        info!("Clearing session {}", session_id);

        let mut operations = self.operations.write().await;
        operations.remove(&session_id);

        let mut processor = self.musig_processor.write().await;
        processor.clear_session(&session_id);

        // Clear stored private keys for this session
        let mut private_keys = self.private_keys.write().await;
        private_keys.retain(|(stored_session_id, _), _| stored_session_id != &session_id);

        info!(
            "Session {} cleared, including stored private keys",
            session_id
        );
        Ok(())
    }

    pub async fn decrypt_private_key_from_coordinator(
        &self,
        encrypted_data: &str,
    ) -> Result<Vec<u8>> {
        // Decrypt the private key using ECIES with our enclave private key
        let private_key_array: [u8; 32] = self.private_key[..32]
            .try_into()
            .map_err(|_| anyhow!("Private key must be exactly 32 bytes"))?;
        let secret_key = SecretKey::from_byte_array(private_key_array)
            .map_err(|e| anyhow!("Invalid private key: {}", e))?;

        let decoded_bytes =
            hex::decode(encrypted_data).map_err(|e| anyhow!("Hex decode failed: {}", e))?;

        let decrypted_bytes = SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes)
            .map_err(|e| anyhow!("Failed to decrypt private key: {}", e))?;

        Ok(decrypted_bytes)
    }

    pub async fn decrypt_private_key(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        info!(
            "Decrypting private key, input data length: {}",
            encrypted_data.len()
        );

        // Convert bytes back to string (they should be Base64 encoded ECIES data)
        let encrypted_string = String::from_utf8(encrypted_data.to_vec()).map_err(|e| {
            error!("Failed to convert encrypted data to UTF-8 string: {}", e);
            anyhow!("Failed to convert encrypted data to string: {}", e)
        })?;

        info!(
            "Converted to string, Base64 string length: {}",
            encrypted_string.len()
        );

        // Decrypt using ECIES with our enclave private key
        let private_key_array: [u8; 32] = self.private_key[..32].try_into().map_err(|_| {
            error!("Enclave private key is not exactly 32 bytes");
            anyhow!("Private key must be exactly 32 bytes")
        })?;
        let secret_key = SecretKey::from_byte_array(private_key_array).map_err(|e| {
            error!("Failed to create SecretKey from enclave private key: {}", e);
            anyhow!("Invalid private key: {}", e)
        })?;

        let decoded_bytes = hex::decode(&encrypted_string).map_err(|e| {
            error!("Hex decode failed for encrypted string: {}", e);
            anyhow!("Hex decode failed: {}", e)
        })?;

        info!("Hex decoded, ciphertext length: {}", decoded_bytes.len());

        let decrypted_bytes =
            SecureCrypto::ecies_decrypt(&secret_key, &decoded_bytes).map_err(|e| {
                error!("ECIES decryption failed: {}", e);
                anyhow!("Failed to decrypt private key: {}", e)
            })?;

        info!(
            "Successfully decrypted private key, length: {}",
            decrypted_bytes.len()
        );
        Ok(decrypted_bytes)
    }

    pub async fn get_coordinator_private_key(&self, session_id: &SessionId) -> Option<Vec<u8>> {
        let operations = self.operations.read().await;
        if let Some(operation_state) = operations.get(session_id) {
            match operation_state {
                OperationState::Initialized(s) => s.coordinator_private_key.clone(),
                OperationState::CollectingNonces(s) => s.coordinator_private_key.clone(),
                OperationState::GeneratingSignatures(s) => s.coordinator_private_key.clone(),
                OperationState::Completed(_) | OperationState::Failed(_) => None,
            }
        } else {
            None
        }
    }

    pub async fn is_session_coordinator(&self, session_id: &SessionId) -> bool {
        let operations = self.operations.read().await;
        if let Some(operation_state) = operations.get(session_id) {
            match operation_state {
                OperationState::Initialized(s) => s.is_coordinator,
                OperationState::CollectingNonces(s) => s.is_coordinator,
                OperationState::GeneratingSignatures(s) => s.is_coordinator,
                OperationState::Completed(_) | OperationState::Failed(_) => false,
            }
        } else {
            false
        }
    }

    pub async fn get_session_state(&self, session_id: &SessionId) -> Option<OperationState> {
        let operations = self.operations.read().await;
        operations.get(session_id).cloned()
    }

    pub async fn get_session_stats(&self) -> (u32, u32, u32, u32) {
        let operations = self.operations.read().await;
        let total = operations.len() as u32;
        let mut active = 0u32;
        let mut completed = 0u32;
        let mut failed = 0u32;

        for operation_state in operations.values() {
            match operation_state {
                OperationState::Completed(_) => completed += 1,
                OperationState::Failed(_) => failed += 1,
                _ => active += 1,
            }
        }

        (total, active, completed, failed)
    }
}

impl Drop for EnclaveOperator {
    fn drop(&mut self) {
        self.private_key.zeroize();
        info!(
            "EnclaveOperator dropped and zeroized for enclave {}",
            self.enclave_id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_operator_creation() {
        let enclave_id = EnclaveId::new(1);
        let operator = EnclaveOperator::new(enclave_id).unwrap();
        assert_eq!(operator.enclave_id, enclave_id);
        assert!(!operator.get_public_key().is_empty());
    }

    #[tokio::test]
    async fn test_enclave_status() {
        let enclave_id = EnclaveId::new(1);
        let operator = EnclaveOperator::new(enclave_id).unwrap();
        let (id, ready, pubkey, sessions) = operator.get_status().await;

        assert_eq!(id, enclave_id);
        assert!(ready); // Always ready in dev mode
        assert!(!pubkey.is_empty());
        assert_eq!(sessions, 0);
    }

    #[tokio::test]
    async fn test_session_management() {
        let enclave_id = EnclaveId::new(1);
        let operator = EnclaveOperator::new(enclave_id).unwrap();

        let active_sessions = operator.get_active_sessions_count().await;
        assert_eq!(active_sessions, 0);

        let (total, active, completed, failed) = operator.get_session_stats().await;
        assert_eq!((total, active, completed, failed), (0, 0, 0, 0));
    }

    #[tokio::test]
    async fn test_session_coordinator_check() {
        let enclave_id = EnclaveId::new(1);
        let operator = EnclaveOperator::new(enclave_id).unwrap();
        let session_id = SessionId::new_v7();

        assert!(!operator.is_session_coordinator(&session_id).await);
    }
}
