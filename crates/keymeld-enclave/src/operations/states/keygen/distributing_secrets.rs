use crate::musig::MusigProcessor;
use keymeld_core::{
    crypto::SecureCrypto,
    identifiers::{SessionId, UserId},
    protocol::{CryptoError, EnclaveError, EncryptedParticipantPublicKey, SessionError},
    KeyMaterial, SessionSecret,
};
use musig2::secp256k1::{PublicKey, SecretKey};
use std::time::SystemTime;
use tracing::{debug, error, info, warn};

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::KeygenSessionContext,
    states::{keygen::Completed, signing::CoordinatorData, KeygenStatus},
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct DistributingSecrets {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    // For batch responses: map of user_id -> encrypted public keys
    batch_encrypted_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
    musig_processor: MusigProcessor,
}

impl DistributingSecrets {
    pub(crate) fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        coordinator_data: Option<CoordinatorData>,
        created_at: SystemTime,
        encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
        musig_processor: MusigProcessor,
    ) -> Self {
        Self {
            session_id,
            created_at,
            session_secret,
            coordinator_data,
            encrypted_public_keys_for_response,
            batch_encrypted_keys: Vec::new(),
            musig_processor,
        }
    }

    pub fn from_keygen_context(
        keygen_ctx: &mut KeygenSessionContext,
    ) -> Result<Self, EnclaveError> {
        let session_secret = keygen_ctx
            .session_secret
            .clone()
            .ok_or(EnclaveError::Session(SessionError::SecretNotInitialized))?;

        let musig_processor = keygen_ctx
            .musig_processor
            .take()
            .ok_or(EnclaveError::Session(SessionError::MusigInitialization(
                "MusigProcessor not initialized".to_string(),
            )))?;

        Ok(Self::new(
            keygen_ctx.session_id.clone(),
            session_secret,
            keygen_ctx.coordinator_data.clone(),
            keygen_ctx.created_at,
            keygen_ctx.encrypted_public_keys_for_response.clone(),
            musig_processor,
        ))
    }

    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    pub fn coordinator_data(&self) -> &Option<CoordinatorData> {
        &self.coordinator_data
    }

    pub fn musig_processor(&self) -> &MusigProcessor {
        &self.musig_processor
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn encrypted_public_keys_for_response(&self) -> Vec<EncryptedParticipantPublicKey> {
        self.encrypted_public_keys_for_response.clone()
    }

    pub fn batch_encrypted_keys(&self) -> Vec<(UserId, Vec<EncryptedParticipantPublicKey>)> {
        self.batch_encrypted_keys.clone()
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }
}

impl From<DistributingSecrets> for Completed {
    fn from(distributing: DistributingSecrets) -> Self {
        Completed::new(
            distributing.session_id,
            distributing.session_secret,
            distributing.coordinator_data,
            distributing.created_at,
            distributing.encrypted_public_keys_for_response,
            distributing.batch_encrypted_keys,
            distributing.musig_processor,
        )
    }
}

impl DistributingSecrets {
    /// Process AddParticipantsBatch command.
    /// Returns: Distributing | Completed
    pub fn add_participants(
        self,
        add_batch_cmd: &keymeld_core::protocol::AddParticipantsBatchCommand,
        keygen_ctx: &mut KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<KeygenStatus, EnclaveError> {
        info!(
            "Adding batch of {} participants to keygen session {} in DistributingSecrets state",
            add_batch_cmd.participants.len(),
            self.session_id
        );

        let mut updated_state = self;
        let mut all_encrypted_public_keys = Vec::new();
        let mut processed_user_ids = Vec::new();

        // Process participants with auth info
        for participant in &add_batch_cmd.participants {
            info!(
                "Processing participant {} in batch for session {}",
                participant.user_id, updated_state.session_id
            );

            let encrypted_public_keys = updated_state.add_participant_and_generate_keys_for_user(
                &participant.user_id,
                &participant.enclave_encrypted_data,
                keygen_ctx,
                enclave_ctx,
                Some(participant.auth_pubkey.clone()),
                participant.require_signing_approval,
            )?;

            if !encrypted_public_keys.is_empty() {
                all_encrypted_public_keys
                    .push((participant.user_id.clone(), encrypted_public_keys));
            }
            processed_user_ids.push(participant.user_id.clone());

            // Check coordinator data
            if let Some(ref coordinator_data) = updated_state.coordinator_data {
                if coordinator_data.user_id == participant.user_id
                    && !participant.enclave_encrypted_data.is_empty()
                    && updated_state
                        .musig_processor
                        .get_private_key(&participant.user_id)
                        .is_some()
                {
                    debug!(
                        "Confirmed coordinator user {} in session {}",
                        participant.user_id, updated_state.session_id
                    );
                }
            }
        }

        // Store batch data for response
        updated_state.batch_encrypted_keys = all_encrypted_public_keys;
        updated_state.encrypted_public_keys_for_response = Vec::new();

        if updated_state.is_ready_to_complete() {
            updated_state.create_key_aggregation_context()?;

            match updated_state.musig_processor.get_aggregate_pubkey() {
                Ok(_) => {
                    let session_id = updated_state.session_id.clone();
                    let completed_state: Completed = updated_state.into();
                    info!("Keygen session {} completed", session_id);
                    Ok(KeygenStatus::Completed(completed_state))
                }
                Err(e) => {
                    warn!(
                        "Keygen session {} not ready to complete: {}",
                        updated_state.session_id, e
                    );
                    Ok(KeygenStatus::Distributing(updated_state))
                }
            }
        } else {
            Ok(KeygenStatus::Distributing(updated_state))
        }
    }

    /// Process DistributeParticipantPublicKeysBatch command.
    /// Returns: Distributing | Completed
    pub fn distribute_keys(
        mut self,
        distribute_batch_cmd: &keymeld_core::protocol::DistributeParticipantPublicKeysBatchCommand,
        _keygen_ctx: &mut KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<KeygenStatus, EnclaveError> {
        info!(
            "Processing distribute participant public keys batch command for {} participants in session {}",
            distribute_batch_cmd.participants_public_keys.len(),
            self.session_id
        );

        // Process each participant's public key in the batch
        for (user_id, encrypted_public_key) in &distribute_batch_cmd.participants_public_keys {
            info!(
                "Processing public key for participant {} in batch for session {}",
                user_id, self.session_id
            );

            let decrypted_public_key_bytes = {
                let enclave = enclave_ctx.read().unwrap();
                enclave.decrypt_with_ecies(encrypted_public_key, "participant public key")?
            };

            let public_key = PublicKey::from_slice(&decrypted_public_key_bytes).map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!("Invalid public key: {e}")))
            })?;

            // Check if participant already exists (idempotency for retries)
            let session_meta = self.musig_processor.get_session_metadata_public();
            let participant_already_exists =
                session_meta.participant_public_keys.contains_key(user_id);

            if !participant_already_exists {
                self.musig_processor
                    .add_participant(user_id.clone(), public_key)
                    .map_err(|e| {
                        EnclaveError::Session(SessionError::MusigInitialization(format!(
                            "Failed to add participant {}: {e}",
                            user_id
                        )))
                    })?;

                info!(
                    "Added participant {} public key to musig processor in session {}",
                    user_id, self.session_id
                );
            } else {
                info!(
                            "Participant {} already exists in session {}, skipping addition (idempotent retry)",
                            user_id, self.session_id
                        );
            }
        }

        info!(
            "Processed batch of {} public keys for session {}",
            distribute_batch_cmd.participants_public_keys.len(),
            self.session_id
        );

        if self.is_ready_to_complete() {
            self.create_key_aggregation_context()?;

            match self.musig_processor.get_aggregate_pubkey() {
                Ok(_) => {
                    info!(
                                "Keygen session {} transitioning to Completed after distributing batch of {} public keys",
                                self.session_id,
                                distribute_batch_cmd.participants_public_keys.len()
                            );

                    let completed_state: Completed = self.into();
                    Ok(KeygenStatus::Completed(completed_state))
                }
                Err(e) => {
                    warn!(
                                "Keygen session {} not ready to complete yet: {}. Staying in DistributingSecrets state.",
                                self.session_id, e
                            );
                    Ok(KeygenStatus::Distributing(self))
                }
            }
        } else {
            Ok(KeygenStatus::Distributing(self))
        }
    }
}

impl DistributingSecrets {
    pub fn is_ready_to_complete(&self) -> bool {
        let session_meta = self.musig_processor.get_session_metadata_public();
        let participant_count = session_meta.participant_public_keys.len();

        let expected_count = self.get_expected_participant_count().unwrap_or(0);
        participant_count >= expected_count
    }

    pub fn create_key_aggregation_context(&mut self) -> Result<(), EnclaveError> {
        if let Err(e) = self
            .musig_processor
            .create_key_aggregation_context(&self.session_id)
        {
            error!(
                "Failed to create key aggregation context for session {}: {}",
                self.session_id, e
            );
            return Err(EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to create key aggregation context: {e}"
            ))));
        }
        Ok(())
    }

    /// Helper method to process a single participant's data
    pub fn add_participant_and_generate_keys_for_user(
        &mut self,
        user_id: &UserId,
        enclave_encrypted_data: &str,
        keygen_ctx: &KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
        auth_pubkey: Option<Vec<u8>>,
        require_signing_approval: bool,
    ) -> Result<Vec<EncryptedParticipantPublicKey>, EnclaveError> {
        debug!(
            "Processing AddParticipant for user {} - enclave_encrypted_data length: {}",
            user_id,
            enclave_encrypted_data.len()
        );

        // Process enclave_encrypted_data if present (contains private key for this enclave)
        let public_key = if !enclave_encrypted_data.is_empty() {
            debug!(
                "Processing enclave_encrypted_data path for user {}",
                user_id
            );
            // Participant with enclave-specific encrypted data - decrypt with enclave private key
            // The enclave_encrypted_data contains the raw private key bytes directly
            let private_key_bytes = {
                let enclave = enclave_ctx.read().unwrap();
                enclave.decrypt_with_ecies(enclave_encrypted_data, "participant private key")
            }
            .map_err(|e| {
                error!(
                    "Failed to decrypt enclave_encrypted_data for user {}: {}",
                    user_id, e
                );
                e
            })?;

            debug!(
                "Decrypted private key for user {} (length: {} bytes)",
                user_id,
                private_key_bytes.len()
            );

            if private_key_bytes.len() != 32 {
                return Err(EnclaveError::Crypto(CryptoError::Other(format!(
                    "Invalid private key length: expected 32 bytes, got {}",
                    private_key_bytes.len()
                ))));
            }

            // Derive public key directly from the decrypted private key bytes
            debug!(
                "Deriving public key from decrypted private key for user {}",
                user_id
            );

            let secret_key =
                SecretKey::from_byte_array(private_key_bytes[..32].try_into().map_err(|_| {
                    EnclaveError::Crypto(CryptoError::Other(
                        "Failed to convert private key to array".to_string(),
                    ))
                })?)
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!("Invalid secret key: {e}")))
                })?;

            let public_key = secret_key.public_key(&musig2::secp256k1::Secp256k1::new());
            let public_key_bytes = public_key.serialize().to_vec();
            let public_key =
                musig2::secp256k1::PublicKey::from_slice(&public_key_bytes).map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!("Invalid public key: {e}")))
                })?;

            debug!(
                "Derived public key from private key for participant {} in session {}",
                user_id, self.session_id
            );

            // Store the private key in MusigProcessor for later use in signing sessions
            // Calculate signer index based on where this user will be in the EXPECTED participants list
            // Use expected_participants which contains ALL participants (sorted in descending order)
            // NOT get_all_participant_ids() which only returns participants added to THIS enclave
            let session_meta = self.musig_processor.get_session_metadata_public();
            let signer_index = session_meta
                .expected_participants
                .iter()
                .position(|id| id == user_id)
                .unwrap_or(0);

            let private_key = KeyMaterial::new(private_key_bytes.clone());

            // Check if this user is the coordinator
            let is_coordinator = self
                .coordinator_data
                .as_ref()
                .map(|cd| cd.user_id == *user_id)
                .unwrap_or(false);

            self.musig_processor
                .store_user_private_key(
                    user_id,
                    private_key,
                    signer_index,
                    is_coordinator,
                    auth_pubkey.clone(),
                    require_signing_approval,
                )
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!(
                        "Failed to store private key: {e}"
                    )))
                })?;

            debug!(
                "Stored private key for user {} in MusigProcessor for session {} with signer_index {}, require_approval={}",
                user_id, self.session_id, signer_index, require_signing_approval
            );

            public_key
        } else {
            // No enclave_encrypted_data means this enclave cannot decrypt this participant's private key
            // This is normal - only the enclave assigned to this participant can decrypt their private key
            debug!(
                "No enclave_encrypted_data for user {} - this enclave is not responsible for this participant",
                user_id
            );
            return Ok(Vec::new());
        };

        // Extract public key bytes for encryption
        let public_key_bytes = public_key.serialize().to_vec();

        // Check if participant already exists before adding
        let session_meta = self.musig_processor.get_session_metadata_public();
        let participant_already_exists = session_meta.participant_public_keys.contains_key(user_id);

        if !participant_already_exists {
            self.musig_processor
                .add_participant(user_id.clone(), public_key)
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to add participant: {e}"
                    )))
                })?;
        } else {
            info!(
                "Participant {} already exists in session {}, skipping addition",
                user_id, self.session_id
            );
        }

        info!(
            "Added participant {} to musig processor for keygen session {}",
            user_id, self.session_id
        );

        let mut encrypted_public_keys = Vec::new();
        debug!(
            "Starting public key encryption for participant {} - session enclave keys: {}",
            user_id,
            keygen_ctx.session_enclave_public_keys.len()
        );

        for (target_enclave_id, target_public_key_hex) in &keygen_ctx.session_enclave_public_keys {
            debug!(
                "Checking enclave {} for participant {} public key distribution",
                target_enclave_id, user_id
            );

            // Get enclave ID from context
            let enclave_id = {
                let enclave = enclave_ctx.read().unwrap();
                enclave.enclave_id
            };

            // Skip encrypting to our own enclave
            if *target_enclave_id == enclave_id {
                debug!(
                    "Skipping our own enclave {} for participant {} public key distribution",
                    *target_enclave_id, user_id
                );
                continue;
            }

            debug!(
                "Will encrypt participant {} public key for target enclave {}",
                user_id, target_enclave_id
            );

            let target_public_key_bytes = match hex::decode(target_public_key_hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(
                        "Failed to decode public key for enclave {}: {}",
                        target_enclave_id, e
                    );
                    continue;
                }
            };

            let target_public_key = match PublicKey::from_slice(&target_public_key_bytes) {
                Ok(pk) => pk,
                Err(e) => {
                    warn!(
                        "Failed to parse public key for enclave {}: {}",
                        target_enclave_id, e
                    );
                    continue;
                }
            };

            match SecureCrypto::ecies_encrypt(&target_public_key, &public_key_bytes) {
                Ok(encrypted_bytes) => {
                    encrypted_public_keys.push(EncryptedParticipantPublicKey {
                        target_enclave_id: *target_enclave_id,
                        encrypted_public_key: hex::encode(encrypted_bytes),
                    });
                    info!(
                        "Encrypted participant {} public key for enclave {}",
                        user_id, target_enclave_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to encrypt participant {} public key for enclave {}: {}",
                        user_id, target_enclave_id, e
                    );
                }
            }
        }

        info!(
            "Generated {} encrypted public keys for participant {} distribution",
            encrypted_public_keys.len(),
            user_id
        );

        Ok(encrypted_public_keys)
    }
}
