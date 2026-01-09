use crate::musig::MusigProcessor;
use keymeld_core::{
    hash_message,
    identifiers::SessionId,
    managed_vsock::TimeoutConfig,
    protocol::{CryptoError, EnclaveError, SessionError, SigningApproval, ValidationError},
    validation::decrypt_session_data,
    SessionSecret,
};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest, Sha256};

use std::time::SystemTime;
use tracing::{info, warn};

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::SigningSessionContext,
    states::{
        signing::{decrypt_adaptor_configs, CoordinatorData},
        SigningStatus,
    },
    GeneratingNonces,
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct Initialized {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    musig_processor: MusigProcessor,
}

impl Initialized {
    pub(crate) fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        coordinator_data: Option<CoordinatorData>,
        musig_processor: MusigProcessor,
    ) -> Self {
        info!(
            "Creating signing Initialized state from keygen - session: {}",
            session_id
        );

        Self {
            session_id,
            session_secret,
            coordinator_data,
            created_at: SystemTime::now(),
            musig_processor,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    pub fn coordinator_data(&self) -> &Option<CoordinatorData> {
        &self.coordinator_data
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    pub fn musig_processor(&self) -> &MusigProcessor {
        &self.musig_processor
    }

    pub fn get_participant_count(&self) -> usize {
        let metadata = self.musig_processor.get_session_metadata_public();
        metadata.participant_public_keys.len()
    }

    /// Verify approval signatures (validates command auth_pubkey matches stored).
    fn verify_approval_signatures(
        &self,
        message_hash: &[u8],
        signing_session_id: &SessionId,
        approval_signatures: &[SigningApproval],
        max_timestamp_age_secs: u64,
    ) -> Result<(), EnclaveError> {
        let secp = Secp256k1::verification_only();
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Check each user who requires approval
        for (user_id, user_session) in self.musig_processor.get_all_user_sessions() {
            if !user_session.require_signing_approval {
                continue;
            }

            // Find the approval signature for this user
            let approval = approval_signatures
                .iter()
                .find(|a| a.user_id == *user_id)
                .ok_or_else(|| {
                    EnclaveError::Validation(ValidationError::Other(format!(
                        "Missing approval signature for user {} who requires signing approval",
                        user_id
                    )))
                })?;

            // Cross-check: if we have a stored auth_pubkey, verify it matches the one in the command
            if let Some(stored_auth_pubkey) = &user_session.auth_pubkey {
                if stored_auth_pubkey != &approval.auth_pubkey {
                    return Err(EnclaveError::Validation(ValidationError::Other(format!(
                        "Auth pubkey mismatch for user {}: command auth_pubkey does not match stored auth_pubkey",
                        user_id
                    ))));
                }
            }

            // Verify timestamp is recent
            if current_time > approval.timestamp
                && current_time - approval.timestamp > max_timestamp_age_secs
            {
                return Err(EnclaveError::Validation(ValidationError::Other(format!(
                    "Approval signature for user {} has expired timestamp (age: {}s, max: {}s)",
                    user_id,
                    current_time - approval.timestamp,
                    max_timestamp_age_secs
                ))));
            }

            // Construct the message that should have been signed:
            // SHA256(message_hash || signing_session_id || timestamp)
            let mut hasher = Sha256::new();
            hasher.update(message_hash);
            hasher.update(signing_session_id.to_string().as_bytes());
            hasher.update(approval.timestamp.to_le_bytes());
            let approval_hash = hasher.finalize();

            // Parse the auth public key from the command (don't trust stored state)
            let pubkey = PublicKey::from_slice(&approval.auth_pubkey).map_err(|e| {
                EnclaveError::Validation(ValidationError::Other(format!(
                    "Invalid auth_pubkey in approval for user {}: {}",
                    user_id, e
                )))
            })?;

            // Parse the signature (session-level approval)
            // Note: For batch signing with per-item approvals, this would be None
            // and we'd verify per_item_approvals instead. For now, require session-level.
            let signature_bytes = approval.signature.as_ref().ok_or_else(|| {
                EnclaveError::Validation(ValidationError::Other(format!(
                    "Missing session-level approval signature for user {}",
                    user_id
                )))
            })?;
            let signature = Signature::from_compact(signature_bytes).map_err(|e| {
                EnclaveError::Validation(ValidationError::Other(format!(
                    "Invalid approval signature format for user {}: {}",
                    user_id, e
                )))
            })?;

            // Create the message for verification
            let approval_hash_array: [u8; 32] =
                approval_hash.as_slice().try_into().map_err(|_| {
                    EnclaveError::Validation(ValidationError::Other(
                        "Approval hash is not 32 bytes".to_string(),
                    ))
                })?;
            let msg = Message::from_digest(approval_hash_array);

            // Verify the signature against the auth_pubkey from the command
            secp.verify_ecdsa(msg, &signature, &pubkey).map_err(|e| {
                warn!(
                    "Approval signature verification failed for user {}: {}",
                    user_id, e
                );
                EnclaveError::Validation(ValidationError::Other(format!(
                    "Invalid approval signature for user {}: signature verification failed",
                    user_id
                )))
            })?;

            info!(
                "Verified approval signature for user {} in signing session {}",
                user_id, signing_session_id
            );
        }

        Ok(())
    }
}

impl TryFrom<Initialized> for GeneratingNonces {
    type Error = EnclaveError;

    fn try_from(initialized: Initialized) -> Result<Self, Self::Error> {
        initialized
            .musig_processor
            .get_aggregate_pubkey()
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Cannot start nonce generation, aggregate pubkey not ready: {}",
                    e
                )))
            })?;

        Ok(GeneratingNonces::new(
            initialized.session_id,
            initialized.session_secret,
            initialized.coordinator_data,
            initialized.created_at,
            initialized.musig_processor,
        ))
    }
}

impl Initialized {
    /// Process InitSession command.
    /// Returns: GeneratingNonces (chains to nonce generation immediately)
    pub fn init_session(
        self,
        init_cmd: &keymeld_core::protocol::InitSigningSessionCommand,
        signing_ctx: &mut SigningSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<SigningStatus, EnclaveError> {
        info!(
            "Processing initialize signing session command for session {}",
            self.session_id
        );

        if init_cmd.encrypted_message.is_empty() {
            return Err(EnclaveError::Validation(ValidationError::Other(
                "Encrypted message cannot be empty".to_string(),
            )));
        }

        if init_cmd.expected_participant_count == 0 {
            return Err(EnclaveError::Validation(ValidationError::Other(
                "Expected participant count must be greater than 0".to_string(),
            )));
        }

        let session_secret = self.session_secret.clone();

        let decrypted_message_hex = decrypt_session_data(
            &init_cmd.encrypted_message,
            &hex::encode(session_secret.as_bytes()),
        )
        .map_err(|e| {
            EnclaveError::Crypto(CryptoError::DecryptionFailed {
                context: "session_data".to_string(),
                error: format!("Failed to decrypt message: {e}"),
            })
        })?;

        let message = hex::decode(&decrypted_message_hex).map_err(|e| {
            EnclaveError::Crypto(CryptoError::DecryptionFailed {
                context: "session_data".to_string(),
                error: format!("Hex decode failed: {e}"),
            })
        })?;

        // Update session context with message
        signing_ctx.message = message.clone();
        signing_ctx.message_hash = hash_message(&signing_ctx.message);

        if message.is_empty() {
            return Err(EnclaveError::Validation(ValidationError::Other(
                "Decrypted message is empty".to_string(),
            )));
        }

        // Verify approval signatures for users who require signing approval
        // This MUST happen before any signing operations begin
        // Note: This is optional defense-in-depth. If no approval signatures are provided,
        // we trust that the gateway has already validated approvals. When approval signatures
        // ARE provided (e.g., single-signer flow), we verify them cryptographically.
        if !init_cmd.approval_signatures.is_empty() {
            let message_hash = keymeld_core::hash_message(&message);
            let max_approval_age_secs = 300; // 5 minutes max age for approval timestamps
            self.verify_approval_signatures(
                &message_hash,
                &init_cmd.signing_session_id,
                &init_cmd.approval_signatures,
                max_approval_age_secs,
            )?;
        }

        let max_size = enclave_ctx
            .read()
            .ok()
            .map(|ctx| ctx.config.max_message_size_bytes)
            .unwrap_or(TimeoutConfig::default().max_message_size_bytes);

        if message.len() > max_size {
            return Err(EnclaveError::Validation(ValidationError::Other(format!(
                "Message too large (>{} bytes)",
                max_size
            ))));
        }

        // Create a signing processor using our own musig_processor
        let mut signing_processor = self
            .musig_processor
            .into_signing_processor(init_cmd.signing_session_id.clone())
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to create signing session: {e}"
                )))
            })?;

        // Update the musig processor with the message
        signing_processor
            .update_session_message(message.clone())
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to update session message: {e}"
                )))
            })?;

        let adaptor_configs =
            if let Some(ref encrypted_adapator_configs) = init_cmd.encrypted_adaptor_configs {
                decrypt_adaptor_configs(encrypted_adapator_configs, &self.session_secret)?
            } else {
                vec![]
            };

        if !adaptor_configs.is_empty() {
            info!("Adaptor configs will be stored in SessionMetadata");

            // Store the adaptor configs in the session metadata
            signing_processor
                .set_adaptor_configs(adaptor_configs)
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to set adaptor configs: {e}"
                    )))
                })?;
        }

        signing_processor.get_aggregate_pubkey().map_err(|e| {
            EnclaveError::Session(SessionError::MusigInitialization(format!(
                "Failed to get aggregate public key: {e}"
            )))
        })?;

        let participant_count = self.get_participant_count();
        info!(
            "Signing session {} initialized successfully - participants: {} (from MuSig processor: {})",
            self.session_id,
            init_cmd.expected_participant_count,
            participant_count
        );

        // Transition to GeneratingNonces state and process nonce generation immediately
        info!(
            "Transitioning from Initialized -> GeneratingNonces for session {}",
            self.session_id
        );

        let generating_nonces =
            GeneratingNonces::from_signing_context(signing_ctx, signing_processor)?;

        // Immediately chain to nonce generation
        generating_nonces.generate_nonces(signing_ctx, enclave_ctx)
    }
}
