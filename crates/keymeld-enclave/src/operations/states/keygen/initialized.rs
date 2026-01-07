use crate::musig::MusigProcessor;
use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, EncryptedParticipantPublicKey, SessionError, ValidationError},
    SessionSecret,
};
use std::time::SystemTime;
use tracing::info;

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::{
        decrypt_coordinator_data_from_enclave, decrypt_session_secret_from_enclave,
        KeygenSessionContext,
    },
    states::{keygen::DistributingSecrets, signing::CoordinatorData, KeygenStatus},
};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub struct Initialized {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: Option<SessionSecret>,
    coordinator_data: Option<CoordinatorData>,
    encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    musig_processor: Option<MusigProcessor>,
}

impl TryFrom<Initialized> for DistributingSecrets {
    type Error = EnclaveError;

    fn try_from(initialized: Initialized) -> Result<Self, Self::Error> {
        let session_secret = initialized
            .session_secret
            .ok_or(EnclaveError::Session(SessionError::SecretNotInitialized))?;

        let musig_processor = initialized.musig_processor.ok_or(EnclaveError::Session(
            SessionError::MusigInitialization("MusigProcessor not initialized".to_string()),
        ))?;

        Ok(Self::new(
            initialized.session_id,
            session_secret,
            initialized.coordinator_data,
            initialized.created_at,
            initialized.encrypted_public_keys_for_response,
            musig_processor,
        ))
    }
}

impl Initialized {
    pub fn get_participant_count(&self) -> usize {
        self.musig_processor
            .as_ref()
            .map(|process| {
                process
                    .get_session_metadata_public()
                    .participant_public_keys
                    .len()
            })
            .unwrap_or(0)
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor.as_ref().and_then(|process| {
            process
                .get_session_metadata_public()
                .expected_participant_count
        })
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .as_ref()
            .map(|process| {
                process
                    .get_session_metadata_public()
                    .expected_participants
                    .clone()
            })
            .unwrap_or_default()
    }

    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id: session_id.clone(),
            created_at: SystemTime::now(),
            session_secret: None,
            coordinator_data: None,
            encrypted_public_keys_for_response: vec![],
            musig_processor: None,
        }
    }

    pub fn session_secret(&self) -> &Option<SessionSecret> {
        &self.session_secret
    }

    pub fn coordinator_data(&self) -> &Option<CoordinatorData> {
        &self.coordinator_data
    }

    pub fn musig_processor(&self) -> &Option<MusigProcessor> {
        &self.musig_processor
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn encrypted_public_keys_for_response(&self) -> Vec<EncryptedParticipantPublicKey> {
        self.encrypted_public_keys_for_response.clone()
    }
}
impl Initialized {
    /// Process InitSession command.
    /// Returns: Distributing (if coordinator) | Initialized (if non-coordinator)
    pub fn init_session(
        self,
        init_cmd: &keymeld_core::protocol::InitKeygenSessionCommand,
        keygen_ctx: &mut KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<KeygenStatus, EnclaveError> {
        info!(
            "Processing initialize keygen session command for session {}",
            self.session_id
        );

        // Decrypt session secret using enclave utility function
        if let Some(encrypted_secret) = &init_cmd.encrypted_session_secret {
            keygen_ctx.session_secret = Some(decrypt_session_secret_from_enclave(
                enclave_ctx,
                encrypted_secret,
            )?);
        }

        // Decrypt coordinator private key using enclave utility function
        if let Some(encrypted_key) = &init_cmd.coordinator_encrypted_private_key {
            if let Some(coordinator_user_id) = &init_cmd.coordinator_user_id {
                keygen_ctx.coordinator_data = Some(decrypt_coordinator_data_from_enclave(
                    enclave_ctx,
                    encrypted_key,
                    coordinator_user_id,
                )?);
            } else {
                return Err(EnclaveError::Validation(ValidationError::Other(
                    "Coordinator private key provided but coordinator user ID missing".to_string(),
                )));
            }
        }

        // Store session participant enclave public keys in session context
        for enclave_key_info in &init_cmd.enclave_public_keys {
            keygen_ctx.session_enclave_public_keys.insert(
                enclave_key_info.enclave_id,
                enclave_key_info.public_key.clone(),
            );
        }
        info!(
            "Stored {} session participant enclave public keys for session {}",
            init_cmd.enclave_public_keys.len(),
            self.session_id
        );

        // Decrypt taproot tweak if we have a session secret
        let taproot_tweak = if let Some(ref session_secret) = keygen_ctx.session_secret {
            use keymeld_core::crypto::EncryptedData;
            match EncryptedData::from_hex(&init_cmd.encrypted_taproot_tweak) {
                Ok(encrypted) => match session_secret.decrypt(&encrypted, "taproot_tweak") {
                    Ok(decrypted_bytes) => match serde_json::from_slice(&decrypted_bytes) {
                        Ok(tweak) => tweak,
                        Err(_) => keymeld_core::protocol::TaprootTweak::None,
                    },
                    Err(_) => keymeld_core::protocol::TaprootTweak::None,
                },
                Err(_) => keymeld_core::protocol::TaprootTweak::None,
            }
        } else {
            keymeld_core::protocol::TaprootTweak::None
        };

        // Initialize musig processor in session context
        keygen_ctx.musig_processor = Some(MusigProcessor::new(
            &self.session_id,
            vec![], // Empty message for keygen
            taproot_tweak,
            Some(init_cmd.expected_participant_count),
            init_cmd.expected_participants.clone(),
        ));

        info!(
            "Keygen session {} initialized successfully (coordinator: {})",
            self.session_id,
            keygen_ctx.coordinator_data.is_some()
        );

        // Transition logic based on session context state
        if keygen_ctx.session_secret.is_some() {
            info!(
                "Coordinator keygen session {} transitioning to DistributingSecrets after initialization",
                self.session_id
            );
            Ok(KeygenStatus::Distributing(
                DistributingSecrets::from_keygen_context(keygen_ctx)?,
            ))
        } else {
            info!(
                "Non-coordinator keygen session {} staying in Initialized state, waiting for session secret",
                self.session_id
            );
            Ok(KeygenStatus::Initialized(self))
        }
    }
}
