use crate::musig::MusigProcessor;
use keymeld_core::{
    crypto::{EncryptedData, SecureCrypto},
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, EncryptedParticipantPublicKey, SessionError, ValidationError},
    SessionSecret,
};
use std::time::SystemTime;
use tracing::info;

use crate::operations::{
    context::EnclaveSharedContext,
    session_context::{decrypt_session_secret_from_enclave, KeygenSessionContext},
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
        let invalid = |message: String| EnclaveError::Validation(ValidationError::Other(message));
        init_cmd
            .authorization_manifest
            .verify()
            .map_err(|e| invalid(e.to_string()))?;
        let manifest = &init_cmd.authorization_manifest.manifest;
        init_cmd
            .recipient_authorization
            .verify_recipient_keys(
                &init_cmd.authorization_manifest,
                &init_cmd.enclave_public_keys,
            )
            .map_err(|e| invalid(e.to_string()))?;
        {
            let enclave = enclave_ctx.read().unwrap();
            if init_cmd
                .recipient_authorization
                .recipient_public_keys
                .get(&enclave.enclave_id)
                != Some(&enclave.public_key)
                || init_cmd.coordinator_user_id.is_some()
                    != (init_cmd
                        .recipient_authorization
                        .user_enclave_assignments
                        .get(&manifest.coordinator_user_id)
                        == Some(&enclave.enclave_id))
            {
                return Err(invalid(
                    "Enclave identity or coordinator role does not match authorized recipient"
                        .into(),
                ));
            }
        }
        let expected: std::collections::BTreeSet<_> =
            init_cmd.expected_participants.iter().cloned().collect();
        let committed: std::collections::BTreeSet<_> =
            manifest.participant_verifiers.keys().cloned().collect();
        if manifest.keygen_session_id != self.session_id
            || init_cmd.keygen_session_id != self.session_id
            || expected != committed
            || expected.len() != init_cmd.expected_participants.len()
            || expected.len() != init_cmd.expected_participant_count
            || manifest.timeout_secs != init_cmd.timeout_secs
            || manifest.encrypted_taproot_tweak != init_cmd.encrypted_taproot_tweak
            || serde_json::to_vec(&manifest.subset_definitions)
                .map_err(|e| invalid(e.to_string()))?
                != serde_json::to_vec(&init_cmd.subset_definitions)
                    .map_err(|e| invalid(e.to_string()))?
            || init_cmd
                .coordinator_user_id
                .as_ref()
                .is_some_and(|id| id != &manifest.coordinator_user_id)
        {
            return Err(invalid(
                "Keygen command does not match signed session manifest".into(),
            ));
        }
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
            let public_key = SecureCrypto::derive_public_key_from_seed(
                keygen_ctx.session_secret.as_ref().unwrap().as_bytes(),
            )
            .map_err(|e| invalid(e.to_string()))?;
            if public_key.serialize().to_vec() != manifest.session_public_key {
                return Err(invalid(
                    "Session secret does not match signed session manifest".into(),
                ));
            }
        }
        // Keys enter custody only through an authorized participant registration.
        keygen_ctx.coordinator_data = None;
        keygen_ctx.coordinator_user_id = init_cmd.coordinator_user_id.clone();

        // Store session participant enclave public keys in session context
        keygen_ctx.recipient_authorization = Some(init_cmd.recipient_authorization.clone());
        keygen_ctx.session_enclave_public_keys.clear();
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

        // Encrypted policy must decode exactly; malformed policy cannot select defaults.
        let taproot_tweak = if let Some(ref session_secret) = keygen_ctx.session_secret {
            let encrypted = EncryptedData::from_hex(&init_cmd.encrypted_taproot_tweak)
                .map_err(|e| invalid(e.to_string()))?;
            let decrypted = session_secret
                .decrypt(&encrypted, "taproot_tweak")
                .map_err(|e| invalid(e.to_string()))?;
            serde_json::from_slice(&decrypted).map_err(|e| invalid(e.to_string()))?
        } else {
            keymeld_core::protocol::TaprootTweak::None
        };

        // Initialize musig processor in session context
        let mut musig_processor = MusigProcessor::new(
            &self.session_id,
            taproot_tweak,
            Some(init_cmd.expected_participant_count),
            init_cmd.expected_participants.clone(),
        );
        musig_processor.session_metadata.authorization_manifest =
            Some(init_cmd.authorization_manifest.as_ref().clone());

        // Set subset definitions if provided
        if !init_cmd.subset_definitions.is_empty() {
            musig_processor.set_subset_definitions(init_cmd.subset_definitions.clone());
        }

        keygen_ctx.musig_processor = Some(musig_processor);

        info!(
            "Keygen session {} initialized successfully (coordinator: {}, subsets: {})",
            self.session_id,
            keygen_ctx.coordinator_data.is_some(),
            init_cmd.subset_definitions.len()
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
