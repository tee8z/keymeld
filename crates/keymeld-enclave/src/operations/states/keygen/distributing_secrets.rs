use crate::musig::types::ParticipantSettings;
use crate::musig::MusigProcessor;
use keymeld_core::{
    authorization::RegistrationAuthorization,
    crypto::SecureCrypto,
    identifiers::{SessionId, UserId},
    protocol::{
        CryptoError, EnclaveError, EncryptedParticipantPublicKey, ParticipantRegistrationData,
        SessionError, ValidationError,
    },
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
                participant,
                keygen_ctx,
                enclave_ctx,
            )?;

            all_encrypted_public_keys.push((participant.user_id.clone(), encrypted_public_keys));
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
        keygen_ctx: &mut KeygenSessionContext,
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

            let decrypted = {
                let enclave = enclave_ctx.read().unwrap();
                enclave
                    .decrypt_with_ecies(encrypted_public_key, "participant registration receipt")?
            };
            let registration: RegistrationAuthorization = serde_json::from_slice(&decrypted)
                .map_err(|e| invalid_registration(e.to_string()))?;
            let metadata = self.musig_processor.get_session_metadata_public();
            let manifest = metadata
                .authorization_manifest
                .as_ref()
                .ok_or_else(|| invalid_registration("Missing session authorization manifest"))?;
            registration
                .verify_commitment(manifest)
                .map_err(|e| invalid_registration(e.to_string()))?;
            if registration.context.user_id != *user_id
                || registration.context.keygen_session_id != self.session_id
                || !metadata.expected_participants.contains(user_id)
                || keygen_ctx
                    .recipient_authorization
                    .as_ref()
                    .and_then(|authorization| authorization.user_enclave_assignments.get(user_id))
                    != Some(&registration.context.enclave_id)
            {
                return Err(invalid_registration(
                    "Distributed registration does not match participant slot",
                ));
            }
            if let Some(existing) = metadata.registrations.get(user_id) {
                if serde_json::to_vec(existing).map_err(|e| invalid_registration(e.to_string()))?
                    != serde_json::to_vec(&registration)
                        .map_err(|e| invalid_registration(e.to_string()))?
                {
                    return Err(invalid_registration(
                        "Conflicting participant registration receipt",
                    ));
                }
                continue;
            }
            let public_key = PublicKey::from_slice(&registration.context.public_key)
                .map_err(|e| invalid_registration(e.to_string()))?;
            self.musig_processor
                .add_participant(user_id.clone(), public_key)
                .map_err(|e| invalid_registration(e.to_string()))?;
            self.musig_processor
                .session_metadata
                .registrations
                .insert(user_id.clone(), registration);
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
        participant_count == expected_count && session_meta.registrations.len() == expected_count
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

        // Compute subset aggregates after main key aggregation
        if let Err(e) = self.musig_processor.compute_subset_aggregates() {
            error!(
                "Failed to compute subset aggregates for session {}: {}",
                self.session_id, e
            );
            return Err(EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to compute subset aggregates: {e}"
            ))));
        }

        Ok(())
    }

    /// Check every participant in a batch as [`Self::add_participants`] will, without changing
    /// anything, so that a batch can be refused whole before it is applied. A refused
    /// registration must not fail the session: while participants are still registering, it
    /// may be all a pool that never filled has left to refund them with.
    pub fn check_participants(
        &self,
        batch: &keymeld_core::protocol::AddParticipantsBatchCommand,
        keygen_ctx: &KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<(), EnclaveError> {
        let enclave = enclave_ctx.read().unwrap();
        let mut seen = std::collections::BTreeSet::new();
        for participant in &batch.participants {
            if !seen.insert(&participant.user_id) {
                return Err(invalid_registration(
                    "Participant slot is unknown or already registered",
                ));
            }
            self.check_participant(participant, keygen_ctx, &enclave)?;
        }
        Ok(())
    }

    /// Verify one participant's invitation and key proof against its slot, without importing
    /// it.
    fn check_participant(
        &self,
        participant: &ParticipantRegistrationData,
        keygen_ctx: &KeygenSessionContext,
        enclave: &EnclaveSharedContext,
    ) -> Result<CheckedParticipant, EnclaveError> {
        let user_id = &participant.user_id;
        let registration = &participant.registration_authorization;
        let metadata = self.musig_processor.get_session_metadata_public();
        let manifest = metadata
            .authorization_manifest
            .as_ref()
            .ok_or_else(|| invalid_registration("Missing session authorization manifest"))?;
        if !metadata.expected_participants.contains(user_id)
            || metadata.registrations.contains_key(user_id)
            || self.musig_processor.get_private_key(user_id).is_some()
        {
            return Err(invalid_registration(
                "Participant slot is unknown or already registered",
            ));
        }
        if keygen_ctx
            .recipient_authorization
            .as_ref()
            .and_then(|authorization| authorization.user_enclave_assignments.get(user_id))
            != Some(&enclave.enclave_id)
        {
            return Err(invalid_registration(
                "Participant is not authorized for this enclave",
            ));
        }
        let envelope = crate::operations::registration::validate_registration(
            manifest,
            participant,
            enclave,
            None,
        )?;
        let private_bytes = zeroize::Zeroizing::new(
            <[u8; 32]>::try_from(envelope.private_key.as_slice())
                .map_err(|_| invalid_registration("Invalid private key length"))?,
        );
        let (_, derived_auth) =
            SecureCrypto::derive_session_auth_keypair(&private_bytes, &self.session_id.to_string())
                .map_err(|e| invalid_registration(e.to_string()))?;
        if derived_auth.serialize().to_vec() != registration.context.auth_pubkey {
            return Err(invalid_registration(
                "Auth public key does not match decrypted participant key",
            ));
        }
        let private_key = SecretKey::from_byte_array(*private_bytes)
            .map_err(|e| invalid_registration(e.to_string()))?;
        let public_key = private_key.public_key(&musig2::secp256k1::Secp256k1::new());
        if public_key.serialize().to_vec() != registration.context.public_key {
            return Err(invalid_registration(
                "Public key does not match decrypted participant key",
            ));
        }
        let signer_index = metadata
            .expected_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or_else(|| invalid_registration("Participant is not expected"))?;
        let is_coordinator = keygen_ctx.coordinator_user_id.as_ref() == Some(user_id);
        if is_coordinator != (manifest.manifest.coordinator_user_id == *user_id) {
            return Err(invalid_registration(
                "Coordinator registration does not match this enclave's authorized role",
            ));
        }
        Ok(CheckedParticipant {
            envelope,
            auth_pubkey: derived_auth.serialize().to_vec(),
            public_key,
            signer_index,
            is_coordinator,
        })
    }

    /// Import one participant only after verifying its invitation and key proof.
    pub fn add_participant_and_generate_keys_for_user(
        &mut self,
        participant: &ParticipantRegistrationData,
        keygen_ctx: &mut KeygenSessionContext,
        enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    ) -> Result<Vec<EncryptedParticipantPublicKey>, EnclaveError> {
        let user_id = &participant.user_id;
        let registration = &participant.registration_authorization;
        let enclave = enclave_ctx.read().unwrap();
        let CheckedParticipant {
            envelope,
            auth_pubkey,
            public_key,
            signer_index,
            is_coordinator,
        } = self.check_participant(participant, keygen_ctx, &enclave)?;
        let mut encrypted_public_keys = Vec::new();
        let receipt =
            serde_json::to_vec(registration).map_err(|e| invalid_registration(e.to_string()))?;
        for (target_enclave_id, target_public_key_hex) in &keygen_ctx.session_enclave_public_keys {
            if *target_enclave_id == enclave.enclave_id {
                continue;
            }
            let target_bytes = hex::decode(target_public_key_hex)
                .map_err(|e| invalid_registration(e.to_string()))?;
            let target_key = PublicKey::from_slice(&target_bytes)
                .map_err(|e| invalid_registration(e.to_string()))?;
            let encrypted = SecureCrypto::ecies_encrypt(&target_key, &receipt)
                .map_err(|e| invalid_registration(e.to_string()))?;
            encrypted_public_keys.push(EncryptedParticipantPublicKey {
                target_enclave_id: *target_enclave_id,
                encrypted_public_key: hex::encode(encrypted),
            });
        }
        self.musig_processor
            .store_user_private_key(
                user_id,
                KeyMaterial::new(envelope.private_key.clone()),
                signer_index,
                is_coordinator,
                ParticipantSettings {
                    auth_pubkey: Some(auth_pubkey),
                    require_signing_approval: participant.require_signing_approval,
                    escrow: envelope.escrow.as_ref().map(|escrow| {
                        std::sync::Arc::new(keymeld_core::escrow::EscrowRegistration {
                            policy: escrow.policy.clone(),
                            secrets: escrow.secrets.clone(),
                        })
                    }),
                },
            )
            .map_err(|e| invalid_registration(e.to_string()))?;
        self.musig_processor
            .add_participant(user_id.clone(), public_key)
            .map_err(|e| invalid_registration(e.to_string()))?;
        self.musig_processor
            .session_metadata
            .registrations
            .insert(user_id.clone(), registration.clone());
        if is_coordinator {
            let coordinator_data = CoordinatorData {
                user_id: user_id.clone(),
                private_key: KeyMaterial::new(envelope.private_key.clone()),
            };
            self.coordinator_data = Some(coordinator_data.clone());
            keygen_ctx.coordinator_data = Some(coordinator_data);
        }
        Ok(encrypted_public_keys)
    }
}

/// A registration checked against its slot, ready to import.
struct CheckedParticipant {
    envelope: keymeld_core::authorization::RegistrationEnvelope,
    auth_pubkey: Vec<u8>,
    public_key: PublicKey,
    signer_index: usize,
    is_coordinator: bool,
}

fn invalid_registration(message: impl Into<String>) -> EnclaveError {
    EnclaveError::Validation(ValidationError::Other(message.into()))
}

#[cfg(test)]
mod registration_tests {
    use super::*;
    use crate::operations::{registration::tests::fixture, session_context::SessionContext};
    use keymeld_core::protocol::{AddParticipantsBatchCommand, InitKeygenSessionCommand};
    use std::collections::BTreeMap;

    #[tokio::test]
    async fn validated_slot_cannot_be_registered_twice_or_after_completion() {
        let f = fixture();
        let session_id = f.manifest.manifest.keygen_session_id.clone();
        let user_id = f.participant.user_id.clone();
        let encrypted_secret = hex::encode(
            SecureCrypto::ecies_encrypt(
                &PublicKey::from_slice(&f.enclave.public_key).unwrap(),
                f.session_secret.as_bytes(),
            )
            .unwrap(),
        );
        let enclave = Arc::new(RwLock::new(f.enclave));
        let mut context = match SessionContext::new_keygen(session_id.clone()) {
            SessionContext::Keygen(context) => context,
            _ => unreachable!(),
        };
        let initialized = super::super::Initialized::new(session_id.clone());
        let recipient_key = enclave.read().unwrap().public_key.clone();
        let enclave_id = enclave.read().unwrap().enclave_id;
        let recipient_authorization =
            keymeld_core::authorization::EnclaveRecipientAuthorization::sign(
                &f.manifest,
                BTreeMap::from([(user_id.clone(), enclave_id)]),
                BTreeMap::from([(enclave_id, recipient_key.clone())]),
                &[11; 32],
            )
            .unwrap();
        let command = InitKeygenSessionCommand {
            recipient_authorization: Box::new(recipient_authorization),
            keygen_session_id: session_id.clone(),
            authorization_manifest: Box::new(f.manifest.clone()),
            coordinator_encrypted_private_key: None,
            coordinator_user_id: Some(user_id.clone()),
            encrypted_session_secret: Some(encrypted_secret),
            timeout_secs: 300,
            expected_participant_count: 1,
            expected_participants: vec![user_id.clone()],
            enclave_public_keys: vec![keymeld_core::protocol::EnclavePublicKeyInfo {
                enclave_id,
                public_key: hex::encode(recipient_key),
            }],
            encrypted_taproot_tweak: f.manifest.manifest.encrypted_taproot_tweak.clone(),
            subset_definitions: Vec::new(),
        };
        let mut substituted = command.clone();
        substituted.enclave_public_keys[0].public_key = hex::encode(
            SecureCrypto::generate_enclave_keypair()
                .unwrap()
                .1
                .serialize(),
        );
        assert!(super::super::Initialized::new(session_id.clone())
            .init_session(&substituted, &mut context, &enclave)
            .is_err());
        assert!(context.session_secret.is_none());
        assert!(context.session_enclave_public_keys.is_empty());
        let mut state = match initialized
            .init_session(&command, &mut context, &enclave)
            .unwrap()
        {
            KeygenStatus::Distributing(state) => state,
            _ => panic!("expected distributing state"),
        };
        let p = &f.participant;
        assert!(state.coordinator_data().is_none());
        assert!(context.coordinator_data.is_none());
        let coordinator_user_id = context.coordinator_user_id.take();
        assert!(state
            .add_participant_and_generate_keys_for_user(p, &mut context, &enclave)
            .is_err());
        context.coordinator_user_id = coordinator_user_id;
        state
            .add_participant_and_generate_keys_for_user(p, &mut context, &enclave)
            .unwrap();
        assert_eq!(state.coordinator_data().as_ref().unwrap().user_id, user_id);
        assert_eq!(context.coordinator_data.as_ref().unwrap().user_id, user_id);
        assert!(state
            .add_participant_and_generate_keys_for_user(p, &mut context, &enclave)
            .is_err());
        state.create_key_aggregation_context().unwrap();
        let completed: Completed = state.into();
        let mut session = crate::operations::ContextAwareSession::new(
            crate::operations::OperatorStatus::Keygen(KeygenStatus::Completed(completed)),
            SessionContext::Keygen(context),
            enclave,
        );
        let registration = keymeld_core::protocol::EnclaveCommand::Musig(
            keymeld_core::protocol::MusigCommand::Keygen(
                keymeld_core::protocol::KeygenCommand::AddParticipantsBatch(
                    AddParticipantsBatchCommand {
                        keygen_session_id: session_id.clone(),
                        participants: vec![f.participant],
                    },
                ),
            ),
        );
        assert!(session.process(&registration).is_err());
        assert!(matches!(
            session.status,
            crate::operations::OperatorStatus::Keygen(KeygenStatus::Completed(_))
        ));

        // Exercise the real queue too: its error handling previously converted
        // this harmless rejection into a failed session and destroyed signing.
        let aggregate = session.extract_keygen_data().unwrap().aggregate_public_key;
        assert!(!aggregate.is_empty());
        let saved_command = keymeld_core::protocol::Command::new(registration.clone());
        session
            .session_context
            .add_processed_command(saved_command.clone());
        let sessions = Arc::new(dashmap::DashMap::new());
        sessions.insert(session_id.clone(), session);
        let queue = crate::queue::Queue::new(sessions.clone());
        for command in [
            saved_command,
            keymeld_core::protocol::Command::new(registration),
        ] {
            assert!(queue
                .process_command(session_id.clone(), command)
                .await
                .is_err());
            let preserved = sessions.get(&session_id).unwrap();
            let data = preserved
                .extract_keygen_data()
                .expect("late registration poisoned keygen");
            assert_eq!(data.aggregate_public_key, aggregate);
            assert_eq!(data.participants, vec![user_id.clone()]);
        }
    }

    type Sessions = Arc<dashmap::DashMap<SessionId, crate::operations::ContextAwareSession>>;

    /// A session on the real queue, started for `manifest` and waiting for its one participant,
    /// `user_id`, to register.
    fn registering_session(
        manifest: &keymeld_core::authorization::SignedSessionManifest,
        user_id: &UserId,
        enclave: EnclaveSharedContext,
        session_secret: &SessionSecret,
    ) -> (Sessions, crate::queue::Queue) {
        let session_id = manifest.manifest.keygen_session_id.clone();
        let encrypted_secret = hex::encode(
            SecureCrypto::ecies_encrypt(
                &PublicKey::from_slice(&enclave.public_key).unwrap(),
                session_secret.as_bytes(),
            )
            .unwrap(),
        );
        let enclave = Arc::new(RwLock::new(enclave));
        let mut context = match SessionContext::new_keygen(session_id.clone()) {
            SessionContext::Keygen(context) => context,
            _ => unreachable!(),
        };
        let recipient_key = enclave.read().unwrap().public_key.clone();
        let enclave_id = enclave.read().unwrap().enclave_id;
        let command = InitKeygenSessionCommand {
            recipient_authorization: Box::new(
                keymeld_core::authorization::EnclaveRecipientAuthorization::sign(
                    manifest,
                    BTreeMap::from([(user_id.clone(), enclave_id)]),
                    BTreeMap::from([(enclave_id, recipient_key.clone())]),
                    &[11; 32],
                )
                .unwrap(),
            ),
            keygen_session_id: session_id.clone(),
            authorization_manifest: Box::new(manifest.clone()),
            coordinator_encrypted_private_key: None,
            coordinator_user_id: Some(user_id.clone()),
            encrypted_session_secret: Some(encrypted_secret),
            timeout_secs: 300,
            expected_participant_count: 1,
            expected_participants: vec![user_id.clone()],
            enclave_public_keys: vec![keymeld_core::protocol::EnclavePublicKeyInfo {
                enclave_id,
                public_key: hex::encode(recipient_key),
            }],
            encrypted_taproot_tweak: manifest.manifest.encrypted_taproot_tweak.clone(),
            subset_definitions: Vec::new(),
        };
        let KeygenStatus::Distributing(state) = super::super::Initialized::new(session_id.clone())
            .init_session(&command, &mut context, &enclave)
            .unwrap()
        else {
            panic!("expected distributing state");
        };
        let sessions = Arc::new(dashmap::DashMap::new());
        sessions.insert(
            session_id,
            crate::operations::ContextAwareSession::new(
                crate::operations::OperatorStatus::Keygen(KeygenStatus::Distributing(state)),
                SessionContext::Keygen(context),
                enclave,
            ),
        );
        let queue = crate::queue::Queue::new(sessions.clone());
        (sessions, queue)
    }

    fn batch(
        session_id: &SessionId,
        participants: Vec<ParticipantRegistrationData>,
    ) -> keymeld_core::protocol::Command {
        keymeld_core::protocol::Command::new(keymeld_core::protocol::EnclaveCommand::Musig(
            keymeld_core::protocol::MusigCommand::Keygen(
                keymeld_core::protocol::KeygenCommand::AddParticipantsBatch(
                    AddParticipantsBatchCommand {
                        keygen_session_id: session_id.clone(),
                        participants,
                    },
                ),
            ),
        ))
    }

    fn is_registering(sessions: &Sessions, session_id: &SessionId) -> bool {
        matches!(
            sessions.get(session_id).unwrap().status,
            crate::operations::OperatorStatus::Keygen(KeygenStatus::Distributing(_))
        )
    }

    /// A registration batch is refused whole, and a refusal leaves a registering session as it
    /// was: for a pool that never filled, its registrations are what its refunds need.
    #[tokio::test]
    async fn a_refused_registration_batch_leaves_the_session_registering() {
        let f = fixture();
        let session_id = f.manifest.manifest.keygen_session_id.clone();
        let user_id = f.participant.user_id.clone();
        let (sessions, queue) =
            registering_session(&f.manifest, &user_id, f.enclave, &f.session_secret);

        let mut stranger = f.participant.clone();
        stranger.user_id = UserId::new_v7();
        let mut substituted = f.participant.clone();
        substituted.auth_pubkey = vec![2; 33];
        // A participant the manifest never named; a slot twice in one batch, whose first
        // copy alone would register; and a valid registration followed by a bad one.
        for participants in [
            vec![stranger],
            vec![f.participant.clone(), f.participant.clone()],
            vec![f.participant.clone(), substituted],
        ] {
            assert!(queue
                .process_command(session_id.clone(), batch(&session_id, participants))
                .await
                .is_err());
            assert!(is_registering(&sessions, &session_id));
        }

        // Nothing from them was applied: the session still takes the registration, and
        // completes with it.
        queue
            .process_command(session_id.clone(), batch(&session_id, vec![f.participant]))
            .await
            .unwrap();
        let data = sessions.get(&session_id).unwrap();
        assert_eq!(
            data.extract_keygen_data().unwrap().participants,
            vec![user_id]
        );
    }

    /// An escrow command can reach a session whose participants are still registering, as in
    /// a pool that never filled. Whether it may act is the escrow handler's decision. The state
    /// machine must pass it through rather than fail the session and lose its registrations.
    #[cfg(feature = "escrow")]
    #[tokio::test]
    async fn an_escrow_command_leaves_a_registering_session_registering() {
        use keymeld_core::escrow::{
            protocol::{EscrowCommand, Operation, Payload, RequestContext},
            ApplicationContext, EscrowContext,
        };
        use keymeld_core::protocol::{Command, EnclaveCommand, KeygenCommand, MusigCommand};

        let f = fixture();
        let session_id = f.manifest.manifest.keygen_session_id.clone();
        let user_id = f.participant.user_id.clone();
        let (sessions, queue) =
            registering_session(&f.manifest, &user_id, f.enclave, &f.session_secret);

        let escrow =
            EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(EscrowCommand {
                context: RequestContext {
                    schema_version: keymeld_core::escrow::SCHEMA_VERSION,
                    operation: Operation::Prepare,
                    escrow: EscrowContext {
                        keygen_session_id: session_id.clone(),
                        user_id: user_id.clone(),
                        escrow_id: uuid::Uuid::now_v7(),
                        manifest_digest: f.manifest.digest().unwrap().try_into().unwrap(),
                        application: ApplicationContext::commit("refund".into(), 1, b"policy")
                            .unwrap(),
                    },
                    policy_digest: [1; 32],
                    request_id: uuid::Uuid::now_v7(),
                    action_id: Some("refund".into()),
                    attempt: None,
                },
                encrypted_request: Payload::new(vec![1]).unwrap(),
                authorization: Vec::new(),
            })));
        queue
            .process_command(session_id.clone(), Command::new(escrow))
            .await
            .unwrap();
        assert!(matches!(
            sessions.get(&session_id).unwrap().status,
            crate::operations::OperatorStatus::Keygen(KeygenStatus::Distributing(_))
        ));

        // The session still takes its registration, and completes with it.
        let registration = EnclaveCommand::Musig(MusigCommand::Keygen(
            KeygenCommand::AddParticipantsBatch(AddParticipantsBatchCommand {
                keygen_session_id: session_id.clone(),
                participants: vec![f.participant],
            }),
        ));
        queue
            .process_command(session_id.clone(), Command::new(registration))
            .await
            .unwrap();
        assert!(matches!(
            sessions.get(&session_id).unwrap().status,
            crate::operations::OperatorStatus::Keygen(KeygenStatus::Completed(_))
        ));
    }
}
