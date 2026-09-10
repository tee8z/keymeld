use crate::musig::types::BatchItemData;
use crate::musig::MusigProcessor;
use keymeld_core::{
    hash_message,
    identifiers::SessionId,
    managed_socket::TimeoutConfig,
    protocol::{CryptoError, EnclaveError, SessionError, TaprootTweak, ValidationError},
    validation::decrypt_session_data,
    SessionSecret,
};
use std::collections::BTreeMap;
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

    /// Verify all authorization before generating any nonce or signature.
    fn verify_authorization(
        &self,
        cmd: &keymeld_core::protocol::InitSigningSessionCommand,
    ) -> Result<(), EnclaveError> {
        let invalid = |message: String| EnclaveError::Validation(ValidationError::Other(message));
        let metadata = self.musig_processor.get_session_metadata_public();
        let manifest = metadata
            .authorization_manifest
            .as_ref()
            .ok_or_else(|| invalid("Missing session authorization manifest".into()))?;
        if cmd.keygen_session_id != manifest.manifest.keygen_session_id
            || cmd.expected_participant_count != metadata.participant_public_keys.len()
            || metadata.registrations.len() != metadata.participant_public_keys.len()
            || cmd
                .user_ids
                .iter()
                .any(|id| !metadata.registrations.contains_key(id))
        {
            return Err(invalid(
                "Signing command does not match the authorized keygen roster".into(),
            ));
        }
        cmd.signing_authorization
            .verify(
                &manifest.manifest.signing_pubkey,
                &cmd.keygen_session_id,
                &cmd.signing_session_id,
                &cmd.batch_items,
            )
            .map_err(|e| invalid(e.to_string()))?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| invalid(e.to_string()))?
            .as_secs();
        let mut approvals = std::collections::BTreeSet::new();
        for approval in &cmd.approval_signatures {
            if !approvals.insert(approval.user_id.clone()) {
                return Err(invalid("Duplicate participant approval".into()));
            }
            let registration = metadata
                .registrations
                .get(&approval.user_id)
                .ok_or_else(|| invalid("Approval from unknown participant".into()))?;
            approval
                .verify(
                    &registration.context.auth_pubkey,
                    &cmd.keygen_session_id,
                    &cmd.signing_session_id,
                    &cmd.batch_items,
                    now,
                )
                .map_err(|e| invalid(e.to_string()))?;
        }
        for (user_id, registration) in &metadata.registrations {
            if registration.context.require_signing_approval && !approvals.contains(user_id) {
                return Err(invalid(format!(
                    "Missing required signing approval for {user_id}"
                )));
            }
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

        if init_cmd.batch_items.is_empty() {
            return Err(EnclaveError::Validation(ValidationError::Other(
                "Batch items cannot be empty".to_string(),
            )));
        }

        if init_cmd.expected_participant_count == 0 {
            return Err(EnclaveError::Validation(ValidationError::Other(
                "Expected participant count must be greater than 0".to_string(),
            )));
        }

        // Get the first batch item (single message = batch of 1)
        let first_batch_item = &init_cmd.batch_items[0];

        let session_secret = self.session_secret.clone();

        let decrypted_message_hex = decrypt_session_data(
            &first_batch_item.encrypted_message,
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

        self.verify_authorization(init_cmd)?;

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

        // Store batch items in the session metadata with per-item decryption
        let mut batch_items_map = BTreeMap::new();
        let session_secret_hex = hex::encode(self.session_secret.as_bytes());

        for batch_item in &init_cmd.batch_items {
            // Decrypt per-item message
            let item_message =
                decrypt_session_data(&batch_item.encrypted_message, &session_secret_hex)
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::DecryptionFailed {
                            context: "batch_item_message".to_string(),
                            error: format!(
                                "Failed to decrypt message for batch item {}: {e}",
                                batch_item.batch_item_id
                            ),
                        })
                    })
                    .and_then(|hex_msg| {
                        hex::decode(&hex_msg).map_err(|e| {
                            EnclaveError::Crypto(CryptoError::DecryptionFailed {
                                context: "batch_item_message".to_string(),
                                error: format!("Hex decode failed: {e}"),
                            })
                        })
                    })?;

            // Decrypt per-item adaptor configs
            let item_adaptor_configs =
                if let Some(ref encrypted_adaptor_configs) = batch_item.encrypted_adaptor_configs {
                    let configs =
                        decrypt_adaptor_configs(encrypted_adaptor_configs, &self.session_secret)?;
                    if configs.is_empty() {
                        return Err(EnclaveError::Validation(ValidationError::Other(
                            "Adaptor signing requires at least one Single adaptor config".into(),
                        )));
                    }
                    configs
                } else {
                    vec![]
                };

            // Decrypt per-item taproot tweak
            let item_taproot_tweak =
                decrypt_session_data(&batch_item.encrypted_taproot_tweak, &session_secret_hex)
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::DecryptionFailed {
                            context: "batch_item_taproot_tweak".to_string(),
                            error: format!(
                                "Failed to decrypt taproot tweak for batch item {}: {e}",
                                batch_item.batch_item_id
                            ),
                        })
                    })
                    .and_then(|tweak_json| {
                        serde_json::from_str::<TaprootTweak>(&tweak_json).map_err(|e| {
                            EnclaveError::Crypto(CryptoError::DecryptionFailed {
                                context: "batch_item_taproot_tweak".to_string(),
                                error: format!("Failed to parse taproot tweak JSON: {e}"),
                            })
                        })
                    })?;

            if item_message.is_empty() || item_message.len() > max_size {
                return Err(EnclaveError::Validation(ValidationError::Other(
                    "Batch item message is empty or too large".into(),
                )));
            }
            if batch_items_map.contains_key(&batch_item.batch_item_id) {
                return Err(EnclaveError::Validation(ValidationError::Other(
                    "Duplicate batch item ID".into(),
                )));
            }
            if batch_item.subset_id.is_some_and(|id| {
                !signing_processor
                    .get_session_metadata_public()
                    .subset_key_agg_contexts
                    .contains_key(&id)
            }) {
                return Err(EnclaveError::Validation(ValidationError::Other(
                    "Batch item references an unauthorized subset".into(),
                )));
            }
            let batch_item_data = BatchItemData {
                batch_item_id: batch_item.batch_item_id,
                message: item_message,
                adaptor_configs: item_adaptor_configs,
                adaptor_final_signatures: BTreeMap::new(),
                taproot_tweak: item_taproot_tweak,
                subset_id: batch_item.subset_id,
            };
            batch_items_map.insert(batch_item.batch_item_id, batch_item_data);
        }
        signing_processor
            .set_batch_items(batch_items_map)
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to set batch items: {e}"
                )))
            })?;

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

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use crate::operations::registration::tests::fixture;
    use keymeld_core::{
        authorization::{ParticipantApproval, SigningAuthorization},
        crypto::SecureCrypto,
        protocol::{EnclaveBatchItem, InitSigningSessionCommand},
    };
    use uuid::Uuid;

    fn authorized_command() -> (Initialized, InitSigningSessionCommand) {
        let f = fixture();
        let keygen_id = f.manifest.manifest.keygen_session_id.clone();
        let user_id = f.participant.user_id.clone();
        let signing_id = SessionId::new_v7();
        let mut processor = MusigProcessor::new(
            &keygen_id,
            TaprootTweak::None,
            Some(1),
            vec![user_id.clone()],
        );
        processor
            .add_participant(
                user_id.clone(),
                secp256k1::PublicKey::from_slice(
                    &f.participant.registration_authorization.context.public_key,
                )
                .unwrap(),
            )
            .unwrap();
        processor.session_metadata.authorization_manifest = Some(f.manifest);
        processor
            .session_metadata
            .registrations
            .insert(user_id.clone(), f.participant.registration_authorization);
        let item = EnclaveBatchItem {
            batch_item_id: Uuid::now_v7(),
            encrypted_message: "reviewed-message-ciphertext".into(),
            encrypted_adaptor_configs: Some("reviewed-adaptor-ciphertext".into()),
            encrypted_taproot_tweak: "reviewed-tweak-ciphertext".into(),
            subset_id: None,
        };
        let items = vec![
            item.clone(),
            EnclaveBatchItem {
                batch_item_id: Uuid::now_v7(),
                ..item
            },
        ];
        let authority =
            SigningAuthorization::sign(&[12; 32], &keygen_id, &signing_id, 300, &items).unwrap();
        let (auth, _) =
            SecureCrypto::derive_session_auth_keypair(&[14; 32], &keygen_id.to_string()).unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let approval = ParticipantApproval::sign(
            &auth.secret_bytes(),
            user_id.clone(),
            &keygen_id,
            &signing_id,
            now,
            &items,
        )
        .unwrap();
        (
            Initialized::new(signing_id.clone(), f.session_secret, None, processor),
            InitSigningSessionCommand {
                keygen_session_id: keygen_id,
                signing_session_id: signing_id,
                signing_authorization: authority,
                user_ids: vec![user_id],
                encrypted_taproot_tweak: String::new(),
                expected_participant_count: 1,
                approval_signatures: vec![approval],
                batch_items: items,
            },
        )
    }

    #[test]
    fn required_approval_cannot_be_omitted_with_a_valid_batch_authority() {
        let (state, mut command) = authorized_command();
        assert!(state.verify_authorization(&command).is_ok());
        command.approval_signatures.clear();
        assert!(state.verify_authorization(&command).is_err());
    }

    #[test]
    fn every_batch_item_adaptor_tweak_subset_and_session_is_authorized() {
        let (state, command) = authorized_command();
        for mutation in 0..5 {
            let mut changed = command.clone();
            match mutation {
                0 => changed.batch_items[1].encrypted_message.push('x'),
                1 => changed.batch_items[1].encrypted_adaptor_configs = None,
                2 => changed.batch_items[1].encrypted_taproot_tweak.push('x'),
                3 => changed.batch_items[1].subset_id = Some(Uuid::now_v7()),
                _ => changed.signing_session_id = SessionId::new_v7(),
            }
            assert!(state.verify_authorization(&changed).is_err());
        }
        let mut reordered = command.clone();
        reordered.batch_items.reverse();
        assert!(state.verify_authorization(&reordered).is_err());
    }

    #[test]
    fn shared_secret_and_participant_approval_cannot_replace_batch_authority() {
        let (state, mut command) = authorized_command();
        command.signing_authorization = SigningAuthorization::sign(
            &[16; 32],
            &command.keygen_session_id,
            &command.signing_session_id,
            300,
            &command.batch_items,
        )
        .unwrap();
        assert!(state.verify_authorization(&command).is_err());
    }
}
