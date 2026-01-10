use crate::musig::MusigProcessor;
use crate::operations::states::signing::CoordinatorData;
use keymeld_core::{
    crypto::SessionSecret,
    identifiers::UserId,
    protocol::{EnclaveError, InitSigningSessionCommand, SessionError},
};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug)]
pub struct KeygenSessionData<'a> {
    pub session_secret: SessionSecret,
    pub coordinator_data: Option<CoordinatorData>,
    pub musig_processor: &'a MusigProcessor,
    pub participants: Vec<UserId>,
    pub aggregate_public_key: Vec<u8>,
    /// Subset aggregate public keys (subset_id -> public key bytes)
    pub subset_aggregate_keys: BTreeMap<Uuid, Vec<u8>>,
}

pub fn create_signing_musig_from_keygen(
    keygen_data: &KeygenSessionData<'_>,
    init_cmd: &InitSigningSessionCommand,
) -> Result<MusigProcessor, EnclaveError> {
    let session_metadata = keygen_data.musig_processor.get_session_metadata_public();

    // Batch items are processed later in the initialized state
    // Here we just create the signing processor with the session-level taproot tweak
    let mut signing_processor = MusigProcessor::new(
        &init_cmd.signing_session_id,
        session_metadata.taproot_tweak.clone(),
        Some(keygen_data.participants.len()),
        keygen_data.participants.clone(),
    );

    // Insert session metadata
    signing_processor
        .insert_session_metadata(session_metadata.clone())
        .map_err(|e| {
            EnclaveError::Session(SessionError::MusigInitialization(format!(
                "Failed to insert session metadata: {}",
                e
            )))
        })?;

    // Transfer user private keys from keygen to signing
    let users_in_session = keygen_data.musig_processor.get_users_in_session();
    for user_id in users_in_session {
        if let Some(user_session) = keygen_data.musig_processor.get_user_session_data(&user_id) {
            if let Some(private_key) = user_session.private_key {
                let signer_index = session_metadata
                    .expected_participants
                    .iter()
                    .position(|id| id == &user_id)
                    .unwrap_or(0);

                signing_processor
                    .store_user_private_key(
                        &user_id,
                        private_key,
                        signer_index,
                        user_session.coordinator,
                        user_session.auth_pubkey.clone(),
                        user_session.require_signing_approval,
                    )
                    .map_err(|e| {
                        EnclaveError::Session(SessionError::MusigInitialization(format!(
                            "Failed to store user private key: {}",
                            e
                        )))
                    })?;
            }
        }
    }

    // Add participants to signing processor
    for (user_id, public_key) in &session_metadata.participant_public_keys {
        signing_processor
            .add_participant(user_id.clone(), *public_key)
            .map_err(|e| {
                EnclaveError::Session(SessionError::MusigInitialization(format!(
                    "Failed to add participant: {}",
                    e
                )))
            })?;
    }

    Ok(signing_processor)
}
