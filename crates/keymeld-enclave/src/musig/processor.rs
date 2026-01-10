use musig2::secp256k1::PublicKey;
use musig2::KeyAggContext;
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, info, warn};
use uuid::Uuid;

use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{EnclaveError, SubsetDefinition, TaprootTweak},
    KeyMaterial,
};

use crate::musig::types::BatchItemData;

use super::types::SessionPhase;

use super::{
    error::MusigError,
    types::{SessionMetadata, UserMusigSession},
};

#[derive(Debug)]
pub struct MusigProcessor {
    pub(crate) session_metadata: SessionMetadata,
    pub(crate) user_sessions: HashMap<UserId, UserMusigSession>,
}

impl MusigProcessor {
    pub fn new(
        session_id: &SessionId,
        taproot_tweak: TaprootTweak,
        expected_participant_count: Option<usize>,
        expected_participants: Vec<UserId>,
    ) -> Self {
        let session_metadata = SessionMetadata::new(
            session_id.clone(),
            expected_participants,
            expected_participant_count,
            taproot_tweak,
        );

        Self {
            session_metadata,
            user_sessions: HashMap::new(),
        }
    }

    pub fn get_aggregate_pubkey(&self) -> Result<musig2::secp256k1::PublicKey, MusigError> {
        let Some(key_agg_ctx) = self.session_metadata.key_agg_ctx.clone() else {
            return Err(MusigError::NotReady(
                "Key aggregation context not initialized".to_string(),
            ));
        };

        let aggregated_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();

        Ok(aggregated_pubkey)
    }

    pub fn get_private_key(&self, user_id: &UserId) -> Option<keymeld_core::KeyMaterial> {
        self.user_sessions
            .get(user_id)
            .and_then(|user_session| user_session.private_key.clone())
    }

    /// Set batch items for batch signing
    pub fn set_batch_items(
        &mut self,
        batch_items: BTreeMap<Uuid, BatchItemData>,
    ) -> Result<(), MusigError> {
        info!(
            "Storing {} batch items for session {}",
            batch_items.len(),
            self.session_metadata.session_id
        );
        self.session_metadata.batch_items = batch_items;
        Ok(())
    }

    pub fn add_participant(
        &mut self,
        user_id: UserId,
        public_key: PublicKey,
    ) -> Result<(), MusigError> {
        if self
            .session_metadata
            .participant_public_keys
            .contains_key(&user_id)
        {
            info!(
                "Participant {} already exists in session {}, skipping duplicate addition",
                user_id, self.session_metadata.session_id
            );
            return Ok(());
        }

        self.session_metadata
            .add_participant(user_id.clone(), public_key)
            .map_err(MusigError::DuplicateParticipant)?;

        let participant_count = self.session_metadata.participant_count();
        info!(
            "Added participant to session {} ({}/{})",
            self.session_metadata.session_id,
            participant_count,
            self.session_metadata
                .expected_participant_count
                .unwrap_or(0)
        );

        Ok(())
    }

    pub fn create_key_aggregation_context(
        &mut self,
        session_id: &SessionId,
    ) -> Result<(), MusigError> {
        if self.session_metadata.has_all_participants()
            && self.session_metadata.key_agg_ctx.is_none()
        {
            let all_participants = self.session_metadata.get_all_participants();

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

            key_agg_ctx = match &self.session_metadata.taproot_tweak {
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

            self.session_metadata.key_agg_ctx = Some(key_agg_ctx);
            self.session_metadata
                .set_phase(SessionPhase::NonceGeneration);

            let participant_count = self.session_metadata.participant_count();
            info!(
                "Session {} advanced to NonceGeneration phase with {} participants",
                session_id, participant_count
            );
        }

        Ok(())
    }

    /// Create a KeyAggContext with the specified tweak applied.
    /// Uses the session's participant public keys.
    pub fn create_key_agg_ctx_with_tweak(
        &self,
        tweak: &TaprootTweak,
    ) -> Result<KeyAggContext, MusigError> {
        let all_participants = self.session_metadata.get_all_participants();

        let mut key_agg_ctx =
            KeyAggContext::new(all_participants).map_err(|e| MusigError::Musig2Error(e.into()))?;

        key_agg_ctx = match tweak {
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

        Ok(key_agg_ctx)
    }

    /// Get the KeyAggContext for a specific batch item.
    /// If the item specifies a subset_id, returns the subset's KeyAggContext.
    /// Otherwise, returns an item-specific context based on the item's tweak.
    pub fn get_key_agg_ctx_for_batch_item(
        &self,
        batch_item_id: &Uuid,
    ) -> Result<KeyAggContext, MusigError> {
        // Get the batch item
        let batch_item = self
            .session_metadata
            .batch_items
            .get(batch_item_id)
            .ok_or_else(|| {
                MusigError::NotReady(format!("Batch item {} not found", batch_item_id))
            })?;

        // If subset_id is specified, use the subset's KeyAggContext
        if let Some(subset_id) = batch_item.subset_id {
            if let Some(subset_ctx) = self
                .session_metadata
                .subset_key_agg_contexts
                .get(&subset_id)
            {
                debug!(
                    "Using subset {} KeyAggContext for batch item {}",
                    subset_id, batch_item_id
                );
                return Ok(subset_ctx.clone());
            } else {
                return Err(MusigError::NotReady(format!(
                    "Subset {} not found for batch item {}",
                    subset_id, batch_item_id
                )));
            }
        }

        // Otherwise, create KeyAggContext with the item's specific tweak
        self.create_key_agg_ctx_with_tweak(&batch_item.taproot_tweak)
    }

    /// Set subset definitions for computing additional aggregate keys
    pub fn set_subset_definitions(&mut self, subset_definitions: Vec<SubsetDefinition>) {
        info!(
            "Storing {} subset definitions for session {}",
            subset_definitions.len(),
            self.session_metadata.session_id
        );
        self.session_metadata.subset_definitions = subset_definitions;
    }

    /// Compute subset aggregate keys after all participants have been added.
    /// Each subset produces a KeyAggContext from its participant subset.
    /// Returns the computed subset aggregate public keys (subset_id -> aggregate pubkey bytes).
    pub fn compute_subset_aggregates(&mut self) -> Result<BTreeMap<Uuid, Vec<u8>>, MusigError> {
        if self.session_metadata.subset_definitions.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut subset_aggregates = BTreeMap::new();

        for subset_def in &self.session_metadata.subset_definitions {
            // Collect public keys for this subset's participants
            let mut subset_pubkeys: Vec<PublicKey> = Vec::new();

            for user_id in &subset_def.participants {
                if let Some(pubkey) = self.session_metadata.participant_public_keys.get(user_id) {
                    subset_pubkeys.push(*pubkey);
                } else {
                    warn!(
                        "Subset {} references unknown participant {}, skipping subset",
                        subset_def.subset_id, user_id
                    );
                    continue;
                }
            }

            if subset_pubkeys.len() < 2 {
                warn!(
                    "Subset {} has fewer than 2 valid participants ({}), skipping",
                    subset_def.subset_id,
                    subset_pubkeys.len()
                );
                continue;
            }

            // Sort by compressed public key bytes (BIP327) for consistent ordering
            subset_pubkeys.sort_by_key(|a| a.serialize());

            debug!(
                "Creating KeyAggContext for subset {} with {} participants",
                subset_def.subset_id,
                subset_pubkeys.len()
            );

            // Create KeyAggContext for this subset with the session's taproot tweak
            let mut key_agg_ctx = KeyAggContext::new(subset_pubkeys)
                .map_err(|e| MusigError::Musig2Error(e.into()))?;

            key_agg_ctx = match &self.session_metadata.taproot_tweak {
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

            // Get the aggregate public key
            let aggregate_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();
            let pubkey_bytes = aggregate_pubkey.serialize().to_vec();

            info!(
                "Computed subset {} aggregate key: {}",
                subset_def.subset_id,
                hex::encode(&pubkey_bytes)
            );

            // Store the context for signing
            self.session_metadata
                .subset_key_agg_contexts
                .insert(subset_def.subset_id, key_agg_ctx);

            // Return the public key bytes
            subset_aggregates.insert(subset_def.subset_id, pubkey_bytes);
        }

        info!(
            "Computed {} subset aggregates for session {}",
            subset_aggregates.len(),
            self.session_metadata.session_id
        );

        Ok(subset_aggregates)
    }

    /// Get the KeyAggContext for a specific subset.
    pub fn get_subset_key_agg_ctx(&self, subset_id: &Uuid) -> Option<&KeyAggContext> {
        self.session_metadata.subset_key_agg_contexts.get(subset_id)
    }

    pub fn get_user_session_count(&self) -> usize {
        self.user_sessions.len()
    }

    pub fn get_users_in_session(&self) -> Vec<UserId> {
        self.user_sessions.keys().cloned().collect()
    }

    pub fn get_user_session_data(&self, user_id: &UserId) -> Option<UserMusigSession> {
        self.user_sessions.get(user_id).map(|session| {
            // Create a new session with cleared crypto state for safety
            UserMusigSession {
                user_id: session.user_id.clone(),
                coordinator: session.coordinator,
                signer_index: session.signer_index,
                private_key: session.private_key.clone(),
                auth_pubkey: session.auth_pubkey.clone(),
                require_signing_approval: session.require_signing_approval,
                batch_first_rounds: BTreeMap::new(),
                batch_second_rounds: BTreeMap::new(),
                batch_adaptor_first_rounds: BTreeMap::new(),
                batch_adaptor_second_rounds: BTreeMap::new(),
            }
        })
    }

    pub fn insert_session_metadata(&mut self, metadata: SessionMetadata) -> Result<(), MusigError> {
        self.session_metadata = metadata;
        Ok(())
    }

    pub fn insert_user_session(&mut self, user_id: UserId, user_session: UserMusigSession) {
        self.user_sessions.insert(user_id, user_session);
    }

    pub(crate) fn get_session_metadata(&self) -> &SessionMetadata {
        &self.session_metadata
    }

    pub fn get_session_metadata_public(&self) -> &SessionMetadata {
        &self.session_metadata
    }

    pub fn user_sessions_count(&self) -> usize {
        self.user_sessions.len()
    }

    /// Get an iterator over all user sessions for approval verification
    pub fn get_all_user_sessions(&self) -> impl Iterator<Item = (&UserId, &UserMusigSession)> {
        self.user_sessions.iter()
    }

    pub(crate) fn update_session_phase(&mut self, phase: SessionPhase) -> Result<(), MusigError> {
        debug!(
            "Updating session {} phase from {:?} to {:?}",
            self.session_metadata.session_id, self.session_metadata.phase, phase
        );
        self.session_metadata.set_phase(phase);
        Ok(())
    }

    pub fn into_signing_processor(
        &self,
        signing_session_id: SessionId,
    ) -> Result<MusigProcessor, EnclaveError> {
        let signing_metadata = self
            .session_metadata
            .copy_for_signing_session(signing_session_id.clone())?;

        // Create new user_sessions for the signing session, copying private keys,
        // signer_index, and auth info. Nonce rounds must NOT be copied to prevent nonce reuse
        // across multiple signing sessions from the same keygen session.
        let mut signing_user_sessions = HashMap::new();
        for (user_id, user_session) in &self.user_sessions {
            // Only copy private key, signer_index, and auth info - no nonce rounds
            if let Some(private_key) = &user_session.private_key {
                signing_user_sessions.insert(
                    user_id.clone(),
                    UserMusigSession {
                        user_id: user_id.clone(),
                        signer_index: user_session.signer_index,
                        private_key: Some(private_key.clone()),
                        coordinator: user_session.coordinator,
                        auth_pubkey: user_session.auth_pubkey.clone(),
                        require_signing_approval: user_session.require_signing_approval,
                        batch_first_rounds: BTreeMap::new(),
                        batch_second_rounds: BTreeMap::new(),
                        batch_adaptor_first_rounds: BTreeMap::new(),
                        batch_adaptor_second_rounds: BTreeMap::new(),
                    },
                );
            }
        }

        Ok(Self {
            session_metadata: signing_metadata,
            user_sessions: signing_user_sessions,
        })
    }

    pub fn store_user_private_key(
        &mut self,
        user_id: &UserId,
        private_key: KeyMaterial,
        signer_index: usize,
        coordinator: bool,
        auth_pubkey: Option<Vec<u8>>,
        require_signing_approval: bool,
    ) -> Result<(), MusigError> {
        let user_session = UserMusigSession {
            user_id: user_id.clone(),
            signer_index,
            private_key: Some(private_key),
            coordinator,
            auth_pubkey,
            require_signing_approval,
            batch_first_rounds: BTreeMap::new(),
            batch_second_rounds: BTreeMap::new(),
            batch_adaptor_first_rounds: BTreeMap::new(),
            batch_adaptor_second_rounds: BTreeMap::new(),
        };

        self.user_sessions.insert(user_id.clone(), user_session);

        info!(
            "Stored private key for user {} with signer_index {}, require_approval={}",
            user_id, signer_index, require_signing_approval
        );

        Ok(())
    }

    pub fn is_coordinator(&mut self) -> bool {
        self.user_sessions
            .values()
            .any(|session| session.coordinator)
    }
}
