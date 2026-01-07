use crate::musig::MusigProcessor;
use keymeld_core::{
    hash_message,
    identifiers::SessionId,
    managed_vsock::TimeoutConfig,
    protocol::{CryptoError, EnclaveError, SessionError, ValidationError},
    validation::decrypt_session_data,
    SessionSecret,
};

use std::time::SystemTime;
use tracing::info;

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
