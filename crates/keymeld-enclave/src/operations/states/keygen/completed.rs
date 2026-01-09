use crate::{
    musig::MusigProcessor,
    operations::states::{
        signing::{CoordinatorData, Initialized},
        KeygenStatus,
    },
};
use keymeld_core::{
    crypto::SessionSecret,
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, EncryptedParticipantPublicKey, SessionError},
};
use std::collections::BTreeMap;
use std::time::SystemTime;
use tracing::{debug, info};

#[derive(Debug)]
pub struct Completed {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    session_secret: SessionSecret,
    coordinator_data: Option<CoordinatorData>,
    encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    batch_encrypted_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
    musig_processor: MusigProcessor,
}

impl Completed {
    pub(crate) fn new(
        session_id: SessionId,
        session_secret: SessionSecret,
        coordinator_data: Option<CoordinatorData>,
        created_at: SystemTime,
        encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
        batch_encrypted_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
        musig_processor: MusigProcessor,
    ) -> Self {
        let participant_count = musig_processor.get_user_session_count() as u32;
        let completed_at = SystemTime::now();
        let duration = completed_at.duration_since(created_at).unwrap_or_default();

        info!(
            "Keygen session {} completed successfully in {:.2}s with {} participants",
            session_id,
            duration.as_secs_f64(),
            participant_count
        );

        Self {
            session_id,
            created_at,
            session_secret,
            coordinator_data,
            encrypted_public_keys_for_response,
            batch_encrypted_keys,
            musig_processor,
        }
    }

    pub fn get_participant_count(&self) -> usize {
        let session_meta = self.musig_processor.get_session_metadata_public();
        session_meta.participant_public_keys.len()
    }

    pub fn get_expected_participant_count(&self) -> Option<usize> {
        self.musig_processor
            .get_session_metadata_public()
            .expected_participant_count
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .get_session_metadata_public()
            .participant_public_keys
            .keys()
            .cloned()
            .collect()
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
}

impl TryFrom<Completed> for Initialized {
    type Error = EnclaveError;

    fn try_from(completed: Completed) -> Result<Self, Self::Error> {
        // Extract session metadata - this must exist for a completed keygen
        let session_metadata = completed.musig_processor.get_session_metadata_public();

        // Extract user private keys from the musig processor
        let users_in_session = completed.musig_processor.get_users_in_session();
        let mut user_private_keys = BTreeMap::new();

        for user_id in users_in_session {
            if let Some(user_session) = completed.musig_processor.get_user_session_data(&user_id) {
                if let Some(private_key) = user_session.private_key {
                    user_private_keys.insert(user_id, private_key);
                }
            }
        }

        // Create a new MusigProcessor for the signing session
        let mut musig_processor = MusigProcessor::new(
            &completed.session_id,
            Vec::new(), // Message will be set later during initialization
            session_metadata.taproot_tweak.clone(),
            Some(user_private_keys.len()),
            session_metadata.expected_participants.clone(),
        );

        // Insert session metadata
        musig_processor
            .insert_session_metadata(session_metadata.clone())
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to insert session metadata: {}",
                    e
                )))
            })?;

        // Store user private keys
        for (user_id, private_key) in user_private_keys {
            let signer_index = session_metadata
                .expected_participants
                .iter()
                .position(|id| id == &user_id)
                .unwrap_or(0);

            musig_processor
                .store_user_private_key(&user_id, private_key, signer_index, false, None, false)
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to store user private key: {}",
                        e
                    )))
                })?;
        }
        let key_iter = session_metadata.participant_public_keys.iter();

        // Add participants
        for (user_id, public_key) in key_iter {
            musig_processor
                .add_participant(user_id.to_owned(), public_key.to_owned())
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to add participant: {}",
                        e
                    )))
                })?;
        }

        Ok(Initialized::new(
            completed.session_id,
            completed.session_secret,
            completed.coordinator_data,
            musig_processor,
        ))
    }
}

impl TryFrom<&Completed> for Initialized {
    type Error = EnclaveError;

    fn try_from(completed: &Completed) -> Result<Self, Self::Error> {
        // Extract session metadata - this must exist for a completed keygen
        let session_metadata = completed.musig_processor.get_session_metadata_public();

        // Extract user private keys from the musig processor
        let users_in_session = completed.musig_processor.get_users_in_session();
        let mut user_private_keys = BTreeMap::new();

        for user_id in users_in_session {
            if let Some(user_session) = completed.musig_processor.get_user_session_data(&user_id) {
                if let Some(private_key) = user_session.private_key {
                    user_private_keys.insert(user_id, private_key);
                }
            }
        }

        // Create a new MusigProcessor for the signing session
        let mut musig_processor = MusigProcessor::new(
            &completed.session_id,
            Vec::new(), // Message will be set later during initialization
            session_metadata.taproot_tweak.clone(),
            Some(user_private_keys.len()),
            session_metadata.expected_participants.clone(),
        );

        // Insert session metadata
        musig_processor
            .insert_session_metadata(session_metadata.clone())
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to insert session metadata: {}",
                    e
                )))
            })?;

        // Store user private keys
        for (user_id, private_key) in user_private_keys {
            let signer_index = session_metadata
                .expected_participants
                .iter()
                .position(|id| id == &user_id)
                .unwrap_or(0);

            musig_processor
                .store_user_private_key(&user_id, private_key, signer_index, false, None, false)
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to store user private key: {}",
                        e
                    )))
                })?;
        }

        // Add participants
        for (user_id, public_key) in &session_metadata.participant_public_keys {
            musig_processor
                .add_participant(user_id.clone(), *public_key)
                .map_err(|e| {
                    EnclaveError::Session(SessionError::MusigInitialization(format!(
                        "Failed to add participant: {}",
                        e
                    )))
                })?;
        }

        Ok(Initialized::new(
            completed.session_id.clone(),
            completed.session_secret.clone(),
            completed.coordinator_data.clone(),
            musig_processor,
        ))
    }
}

impl Completed {
    /// Process GetAggregatePublicKey command.
    /// Returns: Completed (state unchanged, aggregate key available via musig_processor)
    pub fn get_aggregate_key(
        self,
        _cmd: &keymeld_core::protocol::GetAggregatePublicKeyCommand,
    ) -> Result<KeygenStatus, EnclaveError> {
        debug!(
            "Received GetAggregatePublicKey command for completed session {}, will be handled by caller",
            self.session_id
        );
        Ok(KeygenStatus::Completed(self))
    }
}
