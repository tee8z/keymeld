use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, PhaseError, TaprootTweak},
};
use musig2::secp256k1::PublicKey;
use std::collections::BTreeMap;

use super::types::{SessionMetadata, SessionPhase};

impl SessionMetadata {
    /// Get all participant public keys sorted by compressed public key bytes (BIP327 compatible).
    /// This order MUST be consistent across all operations for MuSig2 to work correctly.
    /// BIP327 specifies lexicographic sorting by compressed public key for interoperability
    /// with other MuSig2 implementations.
    pub fn get_all_participants(&self) -> Vec<PublicKey> {
        let mut participants: Vec<PublicKey> =
            self.participant_public_keys.values().copied().collect();
        // Sort by compressed public key bytes (BIP327)
        participants.sort_by_key(|a| a.serialize());
        participants
    }

    /// Get all participant user IDs sorted by their corresponding public keys (BIP327 order).
    /// This MUST match the order returned by get_all_participants() for signer indices to be correct.
    pub fn get_all_participant_ids(&self) -> Vec<UserId> {
        let mut participants: Vec<(UserId, PublicKey)> = self
            .participant_public_keys
            .iter()
            .map(|(uid, pk)| (uid.clone(), *pk))
            .collect();
        // Sort by compressed public key bytes (BIP327) to match get_all_participants()
        participants.sort_by(|a, b| a.1.serialize().cmp(&b.1.serialize()));
        participants.into_iter().map(|(uid, _)| uid).collect()
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
            expected_participants,
            participant_public_keys: self.participant_public_keys.clone(),
            expected_participant_count: self.expected_participant_count,
            key_agg_ctx: self.key_agg_ctx.clone(), // Preserve key aggregation context
            phase: initial_phase,
            taproot_tweak: self.taproot_tweak.clone(), // Preserve taproot configuration
            batch_items: BTreeMap::new(),              // Will be set during signing initialization
            subset_definitions: self.subset_definitions.clone(), // Preserve subset definitions
            subset_key_agg_contexts: self.subset_key_agg_contexts.clone(), // Preserve subset contexts
        })
    }

    /// Create a new empty session metadata
    pub fn new(
        session_id: SessionId,
        expected_participants: Vec<UserId>,
        expected_participant_count: Option<usize>,
        taproot_tweak: TaprootTweak,
    ) -> Self {
        // Note: expected_participants order doesn't matter for key aggregation.
        // The actual key ordering is determined by get_all_participants() which
        // sorts by compressed public key bytes (BIP327) after all participants register.
        SessionMetadata {
            session_id,
            expected_participants,
            participant_public_keys: BTreeMap::new(),
            expected_participant_count,
            key_agg_ctx: None,
            phase: SessionPhase::CollectingParticipants,
            taproot_tweak,
            batch_items: BTreeMap::new(),
            subset_definitions: Vec::new(),
            subset_key_agg_contexts: BTreeMap::new(),
        }
    }

    pub fn has_all_participants(&self) -> bool {
        if let Some(expected_count) = self.expected_participant_count {
            self.participant_public_keys.len() >= expected_count
        } else {
            self.participant_public_keys.len() >= self.expected_participants.len()
        }
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

    /// Update expected_participants to match the actual participants in descending order.
    /// This should be called after all participants have been added to ensure signer
    /// indices are calculated correctly.
    pub fn update_expected_participants_from_actual(&mut self) {
        self.expected_participants = self.get_all_participant_ids();
    }
}
