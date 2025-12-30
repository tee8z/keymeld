use dashmap::DashMap;
use musig2::KeyAggContext;
use std::collections::BTreeMap;
use tracing::{debug, info};

use crate::api::TaprootTweak;
use crate::enclave::{EnclaveError, SessionError};
use crate::identifiers::{SessionId, UserId};
use crate::musig::SessionPhase;

use super::{
    error::MusigError,
    types::{SessionMetadata, UserMusigSession},
};

#[derive(Debug)]
pub struct MusigProcessor {
    pub(crate) user_sessions: DashMap<SessionId, DashMap<UserId, UserMusigSession>>,
    pub(crate) session_metadata: DashMap<SessionId, SessionMetadata>,
}

impl MusigProcessor {
    pub fn new() -> Self {
        Self {
            user_sessions: DashMap::new(),
            session_metadata: DashMap::new(),
        }
    }

    pub fn init_session(
        &self,
        session_id: &SessionId,
        message: Vec<u8>,
        taproot_tweak: TaprootTweak,
        expected_participant_count: Option<usize>,
        expected_participants: Vec<UserId>,
    ) -> Result<(), MusigError> {
        let session_metadata = SessionMetadata::new(
            session_id.clone(),
            message,
            expected_participants, // Pass the full expected_participants list (sorted in descending order)
            expected_participant_count,
            taproot_tweak,
        );

        self.session_metadata
            .insert(session_id.clone(), session_metadata);

        info!("Initialized session {}", session_id);

        Ok(())
    }

    pub fn get_aggregate_pubkey(
        &self,
        session_id: &SessionId,
    ) -> Result<musig2::secp256k1::PublicKey, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        let Some(key_agg_ctx) = session_meta.key_agg_ctx else {
            return Err(MusigError::NotReady(
                "Key aggregation context not initialized".to_string(),
            ));
        };

        let aggregated_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();

        Ok(aggregated_pubkey)
    }

    pub fn get_private_key(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Option<crate::KeyMaterial> {
        self.user_sessions
            .get(session_id)
            .and_then(|session_users| {
                session_users
                    .get(user_id)
                    .and_then(|user_session| user_session.private_key.clone())
            })
    }

    pub fn set_adaptor_configs(
        &self,
        session_id: &SessionId,
        adaptor_configs: Vec<super::types::AdaptorConfig>,
    ) -> Result<(), MusigError> {
        match self.session_metadata.get_mut(session_id) {
            Some(mut session_meta) => {
                session_meta.adaptor_configs = adaptor_configs;
                info!(
                    "Successfully stored {} adaptor configs in session metadata for session {}",
                    session_meta.adaptor_configs.len(),
                    session_id
                );
                Ok(())
            }
            None => Err(MusigError::SessionNotFound(session_id.clone())),
        }
    }

    pub fn get_adaptor_signature_results(
        &self,
        session_id: &SessionId,
    ) -> Result<
        std::collections::BTreeMap<uuid::Uuid, super::types::AdaptorSignatureResult>,
        MusigError,
    > {
        let session_meta = self.get_session_metadata(session_id)?;
        Ok(session_meta.adaptor_final_signatures)
    }

    pub fn add_participant(
        &self,
        session_id: &SessionId,
        user_id: UserId,
        public_key: musig2::secp256k1::PublicKey,
    ) -> Result<(), MusigError> {
        match self.session_metadata.get_mut(session_id) {
            Some(mut session_meta) => {
                session_meta
                    .add_participant(user_id.clone(), public_key)
                    .map_err(MusigError::DuplicateParticipant)?;

                let participant_count = session_meta.participant_count();
                info!(
                    "Added participant to session {} ({}/{})",
                    session_id,
                    participant_count,
                    session_meta.expected_participant_count.unwrap_or(0)
                );

                Ok(())
            }
            None => Err(MusigError::SessionNotFound(session_id.clone())),
        }
    }

    pub fn create_key_aggregation_context(&self, session_id: &SessionId) -> Result<(), MusigError> {
        match self.session_metadata.get_mut(session_id) {
            Some(mut session_meta) => {
                if session_meta.has_all_participants() && session_meta.key_agg_ctx.is_none() {
                    let all_participants = session_meta.get_all_participants();

                    // Debug logging to verify participant order for KeyAggContext
                    debug!(
                        "Creating KeyAggContext for session {} with {} participants in this order:",
                        session_id,
                        all_participants.len()
                    );
                    for (i, pk) in all_participants.iter().enumerate() {
                        info!("  Index {}: {}", i, hex::encode(pk.serialize()));
                    }

                    let mut key_agg_ctx = KeyAggContext::new(all_participants)
                        .map_err(|e| MusigError::Musig2Error(e.into()))?;

                    key_agg_ctx = match &session_meta.taproot_tweak {
                        TaprootTweak::None => key_agg_ctx,
                        TaprootTweak::UnspendableTaproot => key_agg_ctx
                            .with_unspendable_taproot_tweak()
                            .map_err(|e| MusigError::Musig2Error(e.into()))?,
                        TaprootTweak::TaprootWithMerkleRoot { merkle_root } => key_agg_ctx
                            .with_taproot_tweak(merkle_root)
                            .map_err(|e| MusigError::Musig2Error(e.into()))?,
                        TaprootTweak::PlainTweak { tweak } => {
                            let scalar = musig2::secp256k1::Scalar::from_be_bytes(*tweak)
                                .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;
                            key_agg_ctx
                                .with_plain_tweak(scalar)
                                .map_err(|e| MusigError::Musig2Error(e.into()))?
                        }
                        TaprootTweak::XOnlyTweak { tweak } => {
                            let scalar = musig2::secp256k1::Scalar::from_be_bytes(*tweak)
                                .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;
                            key_agg_ctx
                                .with_xonly_tweak(scalar)
                                .map_err(|e| MusigError::Musig2Error(e.into()))?
                        }
                    };

                    session_meta.key_agg_ctx = Some(key_agg_ctx);
                    session_meta.set_phase(SessionPhase::NonceGeneration);

                    let participant_count = session_meta.participant_count();
                    info!(
                        "Session {} advanced to NonceGeneration phase with {} participants",
                        session_id, participant_count
                    );
                }

                Ok(())
            }
            None => Err(MusigError::SessionNotFound(session_id.clone())),
        }
    }

    pub fn get_user_session_count(&self, session_id: &SessionId) -> usize {
        self.user_sessions
            .get(session_id)
            .map(|session_users| session_users.len())
            .unwrap_or(0)
    }

    pub fn get_total_user_session_count(&self) -> usize {
        self.user_sessions
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    pub fn update_session_message(
        &self,
        session_id: &SessionId,
        message: Vec<u8>,
    ) -> Result<(), MusigError> {
        match self.session_metadata.get_mut(session_id) {
            Some(mut session_meta) => {
                session_meta.set_message(message);
                info!("Updated message for session {}", session_id);
                Ok(())
            }
            None => Err(MusigError::SessionNotFound(session_id.clone())),
        }
    }

    pub(crate) fn get_session_metadata(
        &self,
        session_id: &SessionId,
    ) -> Result<SessionMetadata, MusigError> {
        match self.session_metadata.get(session_id) {
            Some(metadata) => Ok(metadata.clone()),
            None => Err(MusigError::SessionNotFound(session_id.clone())),
        }
    }

    pub fn get_session_metadata_public(&self, session_id: &SessionId) -> Option<SessionMetadata> {
        self.session_metadata
            .get(session_id)
            .map(|entry| entry.clone())
    }

    pub fn metadata_count(&self) -> usize {
        self.session_metadata.len()
    }

    pub fn user_sessions_count(&self) -> usize {
        self.user_sessions
            .iter()
            .map(|entry| entry.value().len())
            .sum()
    }

    pub(crate) fn update_session_phase(
        &self,
        session_id: &SessionId,
        phase: super::types::SessionPhase,
    ) -> Result<(), MusigError> {
        match self.session_metadata.get_mut(session_id) {
            Some(mut session_meta) => {
                debug!(
                    "Updating session {} phase from {:?} to {:?}",
                    session_id, session_meta.phase, phase
                );
                session_meta.set_phase(phase);
                Ok(())
            }
            None => Err(MusigError::SessionNotFound(session_id.clone())),
        }
    }

    pub fn copy_for_signing(
        &self,
        signing_session_id: SessionId,
    ) -> Result<MusigProcessor, EnclaveError> {
        let new_processor = MusigProcessor::new();

        // Collect all metadata first without holding iteration locks
        let metadata_entries: Vec<_> = self
            .session_metadata
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        // Process collected metadata without holding locks
        for metadata in metadata_entries {
            let signing_metadata = metadata.copy_for_signing_session(signing_session_id.clone())?;
            debug!(
                "copy_for_signing - inserting session metadata for signing session {}",
                signing_session_id
            );
            new_processor
                .session_metadata
                .insert(signing_session_id.clone(), signing_metadata);
        }

        debug!(
            "copy_for_signing - new processor has {} session metadata entries",
            new_processor.session_metadata.len()
        );

        Ok(new_processor)
    }

    /// Copy session metadata from keygen session to signing session within the same processor
    /// This preserves all participant public keys and private keys in user_sessions
    pub fn copy_session_metadata_for_signing(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: SessionId,
    ) -> Result<(), EnclaveError> {
        info!(
            "Copying session metadata from keygen {} to signing {}",
            keygen_session_id, signing_session_id
        );

        let keygen_metadata =
            self.session_metadata
                .get(keygen_session_id)
                .ok_or(EnclaveError::Session(SessionError::NotFound(
                    keygen_session_id.clone(),
                )))?;

        let signing_metadata =
            keygen_metadata.copy_for_signing_session(signing_session_id.clone())?;

        info!(
            "Copied metadata has {} participant public keys",
            signing_metadata.participant_public_keys.len()
        );

        self.session_metadata
            .insert(signing_session_id.clone(), signing_metadata.clone());

        info!(
            "Successfully inserted session metadata for signing session {}",
            signing_session_id
        );

        // Copy private keys from keygen session to signing session
        // Private keys are stored per-user in the enclave and need to be accessible
        // under both keygen and signing session IDs

        // IMPORTANT: Collect private keys first, then release the read lock before acquiring write lock
        // DashMap issue: If keygen_session_id and signing_session_id hash to the same shard,
        // holding a read lock via .get() while trying to acquire a write lock via .entry()
        // will cause a deadlock. We must release the read lock first.
        let private_keys_to_copy: Vec<(UserId, crate::KeyMaterial)> =
            if let Some(keygen_users) = self.user_sessions.get(keygen_session_id) {
                keygen_users
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .value()
                            .private_key
                            .as_ref()
                            .map(|pk| (entry.key().clone(), pk.clone()))
                    })
                    .collect()
            } else {
                Vec::new()
            };
        // Read lock is automatically released here when the Ref guard goes out of scope

        info!(
            "Found {} private keys to copy from keygen to signing",
            private_keys_to_copy.len()
        );

        // Now we can safely acquire the write lock since the read lock has been released
        if !private_keys_to_copy.is_empty() {
            let signing_users = self
                .user_sessions
                .entry(signing_session_id.clone())
                .or_default();

            // Store private keys indexed by signing session ID with proper metadata
            for (user_id, private_key) in private_keys_to_copy {
                // CRITICAL: Preserve the exact signer index from the keygen session
                // DO NOT recalculate based on signing_metadata.expected_participants
                // as that might have different ordering
                let signer_index =
                    if let Some(keygen_users) = self.user_sessions.get(keygen_session_id) {
                        keygen_users
                            .get(&user_id)
                            .map(|user_session| user_session.signer_index)
                            .unwrap_or_else(|| {
                                // Fallback: calculate from expected_participants if keygen user session not found
                                signing_metadata
                                    .expected_participants
                                    .iter()
                                    .position(|id| id == &user_id)
                                    .unwrap_or(0)
                            })
                    } else {
                        // Fallback: calculate from expected_participants if no keygen session found
                        signing_metadata
                            .expected_participants
                            .iter()
                            .position(|id| id == &user_id)
                            .unwrap_or(0)
                    };

                // Create user session with proper data from signing session metadata
                let user_session = super::types::UserMusigSession {
                    user_id: user_id.clone(),
                    signer_index,
                    private_key: Some(private_key),
                    first_round: None,
                    second_round: None,
                    adaptor_first_rounds: std::collections::BTreeMap::new(),
                    adaptor_second_rounds: std::collections::BTreeMap::new(),
                };

                signing_users.insert(user_id.clone(), user_session);

                info!(
                    "Stored private key for user {} under signing session {} with preserved signer_index {} from keygen",
                    user_id, signing_session_id, signer_index
                );
            }
        }

        Ok(())
    }

    pub fn clear_session(&self, session_id: &SessionId) {
        self.session_metadata.remove(session_id);

        if let Some((_, removed_users)) = self.user_sessions.remove(session_id) {
            let removed_count = removed_users.len();
            if removed_count > 0 {
                info!(
                    "Cleaned up session {} with {} user sessions",
                    session_id, removed_count
                );
            }
        }
    }

    pub fn store_user_private_key(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: crate::KeyMaterial,
        signer_index: usize,
    ) -> Result<(), MusigError> {
        let user_session = UserMusigSession {
            user_id: user_id.clone(),
            signer_index,
            private_key: Some(private_key),
            first_round: None,
            second_round: None,
            adaptor_first_rounds: BTreeMap::new(),
            adaptor_second_rounds: BTreeMap::new(),
        };

        self.user_sessions
            .entry(session_id.clone())
            .or_default()
            .insert(user_id.clone(), user_session);

        info!(
            "Stored private key for user {} in session {} with signer_index {}",
            user_id, session_id, signer_index
        );

        Ok(())
    }
}

impl Default for MusigProcessor {
    fn default() -> Self {
        Self::new()
    }
}
