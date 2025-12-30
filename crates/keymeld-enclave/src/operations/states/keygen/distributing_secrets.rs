use keymeld_core::{
    crypto::SecureCrypto,
    enclave::{
        protocol::EncryptedParticipantPublicKey, AddParticipantCommand, CryptoError,
        EnclaveCommand, EnclaveError, SessionError,
    },
    KeyMaterial, SessionId, SessionSecret, UserId,
};
use musig2::secp256k1::{PublicKey, SecretKey};
use std::time::SystemTime;
use tracing::{debug, error, info, warn};

use crate::operations::{
    context::EnclaveContext,
    states::{
        keygen::{Completed, Initialized},
        signing::CoordinatorData,
        KeygenStatus, OperatorStatus,
    },
    EnclaveAdvanceable,
};

#[derive(Debug, Clone)]
pub struct DistributingSecrets {
    pub session_id: SessionId,
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub created_at: SystemTime,
    pub secrets_distributed: bool,
    pub encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    pub musig_processor: std::sync::Arc<keymeld_core::musig::MusigProcessor>,
}

impl DistributingSecrets {
    /// Get participant count from MuSig processor metadata
    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.participant_public_keys.len())
            .unwrap_or(0)
    }

    /// Get expected participant count from MuSig processor metadata
    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .and_then(|metadata| metadata.expected_participant_count)
    }

    /// Get participants list from MuSig processor metadata
    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public(&self.session_id)
            .map(|metadata| metadata.expected_participants.clone())
            .unwrap_or_default()
    }
}

impl TryFrom<Initialized> for DistributingSecrets {
    type Error = EnclaveError;

    fn try_from(initialized: Initialized) -> Result<Self, Self::Error> {
        let session_secret = initialized
            .session_secret
            .ok_or(EnclaveError::Session(SessionError::SecretNotInitialized))?;

        Ok(Self {
            session_id: initialized.session_id,
            session_secret,
            coordinator_data: initialized.coordinator_data,
            created_at: initialized.created_at,
            secrets_distributed: false,
            encrypted_public_keys_for_response: initialized.encrypted_public_keys_for_response,
            musig_processor: initialized.musig_processor,
        })
    }
}

impl EnclaveAdvanceable<OperatorStatus> for DistributingSecrets {
    fn process(
        self,
        ctx: &mut EnclaveContext,
        cmd: &EnclaveCommand,
    ) -> Result<OperatorStatus, EnclaveError> {
        info!(
            "Processing operation {} from keygen DistributingSecrets state",
            self.session_id
        );

        match cmd {
            EnclaveCommand::AddParticipant(add_participant_cmd) => {
                info!(
                    "Adding participant {} to keygen session {} in DistributingSecrets state",
                    add_participant_cmd.user_id, self.session_id
                );

                // Always try to add the participant and generate keys for assigned participants
                let encrypted_public_keys =
                    self.add_participant_and_generate_keys(add_participant_cmd, ctx)?;

                let mut updated_state = self.clone();
                updated_state.encrypted_public_keys_for_response = encrypted_public_keys;

                // If this enclave is the coordinator and we just processed the coordinator user,
                // update the coordinator data with the actual user ID
                if let Some(ref coordinator_data) = self.coordinator_data {
                    if coordinator_data.user_id == add_participant_cmd.user_id
                        && !add_participant_cmd.enclave_encrypted_data.is_empty()
                    {
                        // Verify we successfully stored a private key for this user
                        if self
                            .musig_processor
                            .get_private_key(&self.session_id, &add_participant_cmd.user_id)
                            .is_some()
                        {
                            debug!(
                                "Confirmed coordinator user {} in session {}",
                                add_participant_cmd.user_id, self.session_id
                            );
                        }
                    }
                }

                if self.is_ready_to_complete() {
                    self.create_key_aggregation_context()?;

                    info!(
                        "Keygen session {} transitioning to Completed after adding participant {}",
                        self.session_id, add_participant_cmd.user_id
                    );
                    Ok(OperatorStatus::Keygen(KeygenStatus::Completed(
                        Completed::from(updated_state),
                    )))
                } else {
                    Ok(OperatorStatus::Keygen(KeygenStatus::Distributing(
                        updated_state,
                    )))
                }
            }

            EnclaveCommand::DistributeParticipantPublicKey(distribute_cmd) => {
                info!(
                    "Processing distribute participant public key command for participant {} in session {}",
                    distribute_cmd.user_id, self.session_id
                );

                let decrypted_public_key_bytes = ctx.decrypt_with_ecies(
                    &distribute_cmd.encrypted_participant_public_key,
                    "participant public key",
                )?;

                let public_key =
                    PublicKey::from_slice(&decrypted_public_key_bytes).map_err(|e| {
                        EnclaveError::Crypto(CryptoError::Other(format!("Invalid public key: {e}")))
                    })?;

                // Check if participant already exists (idempotency for retries)
                let participant_already_exists = if let Some(session_meta) = self
                    .musig_processor
                    .get_session_metadata_public(&self.session_id)
                {
                    session_meta
                        .participant_public_keys
                        .contains_key(&distribute_cmd.user_id)
                } else {
                    false
                };

                if !participant_already_exists {
                    self.musig_processor
                        .add_participant(
                            &self.session_id,
                            distribute_cmd.user_id.clone(),
                            public_key,
                        )
                        .map_err(|e| {
                            EnclaveError::Crypto(CryptoError::Other(format!(
                                "Failed to add participant to musig processor: {e}"
                            )))
                        })?;

                    info!(
                        "Successfully added participant {} public key to musig processor in session {}",
                        distribute_cmd.user_id, self.session_id
                    );
                } else {
                    info!(
                        "Participant {} already exists in session {}, skipping addition (idempotent retry)",
                        distribute_cmd.user_id, self.session_id
                    );
                }

                if self.is_ready_to_complete() {
                    self.create_key_aggregation_context()?;

                    info!(
                        "Keygen session {} transitioning to Completed after distributing participant {} public key",
                        self.session_id, distribute_cmd.user_id
                    );
                    Ok(OperatorStatus::Keygen(KeygenStatus::Completed(
                        Completed::from(self),
                    )))
                } else {
                    Ok(OperatorStatus::Keygen(KeygenStatus::Distributing(self)))
                }
            }

            _ => {
                debug!(
                    "Command not applicable to keygen DistributingSecrets state for session {}, staying in current state",
                    self.session_id
                );
                Ok(OperatorStatus::Keygen(KeygenStatus::Distributing(self)))
            }
        }
    }
}

impl DistributingSecrets {
    pub fn is_ready_to_complete(&self) -> bool {
        let participant_count = if let Some(session_meta) = self
            .musig_processor
            .get_session_metadata_public(&self.session_id)
        {
            session_meta.participant_public_keys.len()
        } else {
            0
        };

        let expected_count = self.get_expected_participant_count().unwrap_or(0);
        participant_count >= expected_count
    }

    pub fn create_key_aggregation_context(&self) -> Result<(), EnclaveError> {
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

    pub fn add_participant_and_generate_keys(
        &self,
        add_participant_cmd: &AddParticipantCommand,
        ctx: &EnclaveContext,
    ) -> Result<Vec<EncryptedParticipantPublicKey>, EnclaveError> {
        debug!(
            "Processing AddParticipant for user {} - enclave_encrypted_data length: {}",
            add_participant_cmd.user_id,
            add_participant_cmd.enclave_encrypted_data.len()
        );

        // Process enclave_encrypted_data if present (contains private key for this enclave)
        let public_key = if !add_participant_cmd.enclave_encrypted_data.is_empty() {
            debug!(
                "Processing enclave_encrypted_data path for user {}",
                add_participant_cmd.user_id
            );
            // Participant with enclave-specific encrypted data - decrypt with enclave private key
            // The enclave_encrypted_data contains the raw private key bytes directly
            let private_key_bytes = ctx
                .decrypt_with_ecies(
                    &add_participant_cmd.enclave_encrypted_data,
                    "participant private key",
                )
                .map_err(|e| {
                    error!(
                        "Failed to decrypt enclave_encrypted_data for user {}: {}",
                        add_participant_cmd.user_id, e
                    );
                    e
                })?;

            debug!(
                "Decrypted private key for user {} (length: {} bytes)",
                add_participant_cmd.user_id,
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
                add_participant_cmd.user_id
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
                "Successfully derived public key from private key for participant {} in session {}",
                add_participant_cmd.user_id, self.session_id
            );

            // Store the private key in MusigProcessor for later use in signing sessions
            // Calculate signer index based on where this user will be in the EXPECTED participants list
            // Use expected_participants which contains ALL participants (sorted in descending order)
            // NOT get_all_participant_ids() which only returns participants added to THIS enclave
            let signer_index = if let Some(session_meta) = self
                .musig_processor
                .get_session_metadata_public(&self.session_id)
            {
                // Use expected_participants which has the full sorted list (descending: newest UUIDv7 first)
                session_meta
                    .expected_participants
                    .iter()
                    .position(|id| id == &add_participant_cmd.user_id)
                    .unwrap_or(0)
            } else {
                0
            };

            let private_key = KeyMaterial::new(private_key_bytes.clone());

            self.musig_processor
                .store_user_private_key(
                    &self.session_id,
                    &add_participant_cmd.user_id,
                    private_key,
                    signer_index,
                )
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to store private key: {e}"
                    )))
                })?;

            // Coordinator identification is now handled at initialization with the command's coordinator_user_id

            debug!(
                "Stored private key for user {} in MusigProcessor for session {} with signer_index {}",
                add_participant_cmd.user_id, self.session_id, signer_index
            );

            public_key
        } else {
            // No enclave_encrypted_data means this enclave cannot decrypt this participant's private key
            // This is normal - only the enclave assigned to this participant can decrypt their private key
            debug!(
                "No enclave_encrypted_data for user {} - this enclave is not responsible for this participant",
                add_participant_cmd.user_id
            );
            return Ok(self.encrypted_public_keys_for_response.clone());
        };

        // Extract public key bytes for encryption
        let public_key_bytes = public_key.serialize().to_vec();

        // Check if participant already exists before adding
        let participant_already_exists = if let Some(session_meta) = self
            .musig_processor
            .get_session_metadata_public(&self.session_id)
        {
            session_meta
                .participant_public_keys
                .contains_key(&add_participant_cmd.user_id)
        } else {
            false
        };

        if !participant_already_exists {
            self.musig_processor
                .add_participant(
                    &self.session_id,
                    add_participant_cmd.user_id.clone(),
                    public_key,
                )
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!(
                        "Failed to add participant to musig processor: {e}"
                    )))
                })?;
        } else {
            info!(
                "Participant {} already exists in session {}, skipping addition",
                add_participant_cmd.user_id, self.session_id
            );
        }

        info!(
            "Successfully added participant {} to musig processor for keygen session {}",
            add_participant_cmd.user_id, self.session_id
        );

        let mut encrypted_public_keys = Vec::new();
        debug!(
            "Starting public key encryption for participant {} - ctx.enclave_public_keys has {} entries, our enclave_id: {}",
            add_participant_cmd.user_id,
            ctx.enclave_public_keys.len(),
            ctx.enclave_id
        );

        for entry in ctx.enclave_public_keys.iter() {
            let target_enclave_id = *entry.key();
            let target_public_key_hex = entry.value();
            debug!(
                "Considering target enclave {} for participant {} public key distribution",
                target_enclave_id, add_participant_cmd.user_id
            );

            // Skip encrypting to our own enclave
            if target_enclave_id == ctx.enclave_id {
                debug!(
                    "Skipping our own enclave {} for participant {} public key distribution",
                    target_enclave_id, add_participant_cmd.user_id
                );
                continue;
            }

            debug!(
                "Will encrypt participant {} public key for target enclave {}",
                add_participant_cmd.user_id, target_enclave_id
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
                        target_enclave_id,
                        encrypted_public_key: hex::encode(encrypted_bytes),
                    });
                    info!(
                        "Encrypted participant {} public key for enclave {}",
                        add_participant_cmd.user_id, target_enclave_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to encrypt participant {} public key for enclave {}: {}",
                        add_participant_cmd.user_id, target_enclave_id, e
                    );
                }
            }
        }

        info!(
            "Generated {} encrypted public keys for participant {} distribution",
            encrypted_public_keys.len(),
            add_participant_cmd.user_id
        );

        Ok(encrypted_public_keys)
    }
}
