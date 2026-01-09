use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, PhaseError, TaprootTweak},
};
use musig2::secp256k1::PublicKey;
use std::collections::BTreeMap;

use super::types::{SessionMetadata, SessionPhase};

impl SessionMetadata {
    /// Get all participant public keys in descending order by UserId (newest UUIDv7 first).
    /// This order MUST be consistent across all operations for MuSig2 to work correctly.
    pub fn get_all_participants(&self) -> Vec<PublicKey> {
        let mut participants: Vec<(UserId, PublicKey)> = self
            .participant_public_keys
            .iter()
            .map(|(uid, pk)| (uid.clone(), *pk))
            .collect();
        participants.sort_by(|a, b| b.0.cmp(&a.0));
        participants.into_iter().map(|(_, pk)| pk).collect()
    }

    /// Get all participant user IDs in descending order (newest UUIDv7 first).
    /// This MUST match the order returned by get_all_participants() for signer indices to be correct.
    pub fn get_all_participant_ids(&self) -> Vec<UserId> {
        let mut participant_ids: Vec<UserId> =
            self.participant_public_keys.keys().cloned().collect();
        participant_ids.sort_by(|a, b| b.cmp(a));
        participant_ids
    }

    /// Create a new session metadata for signing based on a completed keygen session
    /// This preserves all participant information and adaptor configs while resetting
    /// signing-specific state
    pub fn copy_for_signing_session(
        &self,
        new_session_id: SessionId,
    ) -> Result<Self, EnclaveError> {
        let Some(initial_phase) = self
            .key_agg_ctx
            .as_ref()
            .map(|_| SessionPhase::NonceGeneration)
        else {
            return Err(EnclaveError::Phase(PhaseError::KeygenNotCompleted));
        };

        // Use the expected_participants from keygen to preserve the exact order
        // that was used for the KeyAggContext. We must NOT re-sort here because that
        // would change signer indices and break MuSig2 signatures.
        let expected_participants = self.expected_participants.clone();

        Ok(SessionMetadata {
            session_id: new_session_id,
            message: Vec::new(), // Will be set during signing initialization
            expected_participants,
            participant_public_keys: self.participant_public_keys.clone(),
            expected_participant_count: self.expected_participant_count,
            key_agg_ctx: self.key_agg_ctx.clone(), // Preserve key aggregation context

            phase: initial_phase,
            taproot_tweak: self.taproot_tweak.clone(), // Preserve taproot configuration
            adaptor_configs: self.adaptor_configs.clone(), // Preserve adaptor configurations
            adaptor_final_signatures: BTreeMap::new(), // Reset final adaptor signatures
            batch_items: BTreeMap::new(), // Will be set during signing initialization if batch
        })
    }

    /// Create a new empty session metadata
    pub fn new(
        session_id: SessionId,
        message: Vec<u8>,
        mut expected_participants: Vec<UserId>,
        expected_participant_count: Option<usize>,
        taproot_tweak: TaprootTweak,
    ) -> Self {
        // Log BEFORE sorting
        tracing::debug!(
            "SessionMetadata::new BEFORE sort for session {}: {:?}",
            session_id,
            expected_participants
        );
        // Ensure expected_participants is always in descending order (newest UUIDv7 first)
        // to match get_all_participants() ordering for consistent signer indices
        expected_participants.sort_by(|a, b| b.cmp(a));
        // Log AFTER sorting
        tracing::debug!(
            "SessionMetadata::new AFTER sort for session {}: {:?}",
            session_id,
            expected_participants
        );

        SessionMetadata {
            session_id,
            message,
            expected_participants,
            participant_public_keys: BTreeMap::new(),
            expected_participant_count,
            key_agg_ctx: None,
            phase: SessionPhase::CollectingParticipants,
            taproot_tweak,
            adaptor_configs: Vec::new(),
            adaptor_final_signatures: BTreeMap::new(),
            batch_items: BTreeMap::new(),
        }
    }

    pub fn has_all_participants(&self) -> bool {
        if let Some(expected_count) = self.expected_participant_count {
            self.participant_public_keys.len() >= expected_count
        } else {
            self.participant_public_keys.len() >= self.expected_participants.len()
        }
    }

    pub fn has_adaptor_configs(&self) -> bool {
        !self.adaptor_configs.is_empty()
    }

    pub fn participant_count(&self) -> usize {
        self.participant_public_keys.len()
    }

    pub fn add_participant(
        &mut self,
        user_id: UserId,
        public_key: PublicKey,
    ) -> Result<(), UserId> {
        if self.participant_public_keys.contains_key(&user_id) {
            return Err(user_id);
        }

        self.participant_public_keys.insert(user_id, public_key);
        Ok(())
    }

    pub fn set_phase(&mut self, phase: SessionPhase) {
        self.phase = phase;
    }

    pub fn set_message(&mut self, message: Vec<u8>) {
        self.message = message;
    }

    /// Update expected_participants to match the actual participants in descending order.
    /// This should be called after all participants have been added to ensure signer
    /// indices are calculated correctly.
    pub fn update_expected_participants_from_actual(&mut self) {
        self.expected_participants = self.get_all_participant_ids();
    }
}
