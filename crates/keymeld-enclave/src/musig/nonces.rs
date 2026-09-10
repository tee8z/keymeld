use musig2::{secp256k1::SecretKey, FirstRound, PubNonce, SecNonceSpices};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use keymeld_core::{crypto::SecureCrypto, identifiers::UserId, protocol::NonceData, KeyMaterial};

use super::{
    error::MusigError,
    types::{SessionPhase, UserMusigSession},
    MusigProcessor,
};

impl MusigProcessor {
    /// Compute the signer index for a user within a subset.
    /// The subset's KeyAggContext is built from public keys sorted by BIP327 order,
    /// so we need to find the user's position in that sorted order.
    fn compute_subset_signer_index(
        &self,
        user_id: &UserId,
        subset_id: &Uuid,
    ) -> Result<usize, MusigError> {
        // Find the subset definition
        let subset_def = self
            .session_metadata
            .subset_definitions
            .iter()
            .find(|def| def.subset_id == *subset_id)
            .ok_or_else(|| {
                MusigError::NotReady(format!("Subset definition {} not found", subset_id))
            })?;

        // Check if user is in this subset
        if !subset_def.participants.contains(user_id) {
            return Err(MusigError::NotReady(format!(
                "User {} is not a member of subset {}",
                user_id, subset_id
            )));
        }

        // Collect and sort public keys for subset participants (same as compute_subset_aggregates)
        let mut subset_pubkeys_with_ids: Vec<(UserId, musig2::secp256k1::PublicKey)> = Vec::new();
        for uid in &subset_def.participants {
            if let Some(pubkey) = self.session_metadata.participant_public_keys.get(uid) {
                subset_pubkeys_with_ids.push((uid.clone(), *pubkey));
            }
        }

        // Sort by compressed public key bytes (BIP327) - same order as KeyAggContext
        subset_pubkeys_with_ids.sort_by_key(|a| a.1.serialize());

        // Find user's position in sorted order
        subset_pubkeys_with_ids
            .iter()
            .position(|(uid, _)| uid == user_id)
            .ok_or_else(|| {
                MusigError::NotReady(format!(
                    "User {} not found in sorted subset {} participants",
                    user_id, subset_id
                ))
            })
    }

    /// Generate nonces for all batch items for a user.
    /// Each batch item gets its own FirstRound with a unique nonce seed.
    /// Returns a map of batch_item_id -> NonceData (Regular or Adaptor depending on config)
    pub fn generate_batch_nonces(
        &mut self,
        user_id: &UserId,
        signer_index: usize,
        private_key: &KeyMaterial,
    ) -> Result<BTreeMap<Uuid, NonceData>, MusigError> {
        let session_metadata = &self.session_metadata;
        let session_id = &session_metadata.session_id;

        if session_metadata.phase != SessionPhase::NonceGeneration
            && session_metadata.phase != SessionPhase::NonceAggregation
        {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceGeneration,
                actual: session_metadata.phase.clone(),
            });
        }

        if session_metadata.batch_items.is_empty() {
            return Err(MusigError::NotReady(
                "No batch items in session".to_string(),
            ));
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        // Verify key aggregation is ready (we get per-item context in the loop)
        if session_metadata.key_agg_ctx.is_none() {
            return Err(MusigError::NotReady(
                "Session not ready for nonce generation".to_string(),
            ));
        }

        // Generate base nonce seed
        let base_nonce_seed = zeroize::Zeroizing::new(
            SecureCrypto::generate_secure_nonce(&session_id.to_string(), &user_id.to_string())
                .map_err(|e| {
                    MusigError::Musig2Error(format!("Secure nonce generation failed: {e}").into())
                })?,
        );

        let mut batch_first_rounds: BTreeMap<Uuid, FirstRound> = BTreeMap::new();
        let mut batch_adaptor_first_rounds: BTreeMap<Uuid, BTreeMap<Uuid, FirstRound>> =
            BTreeMap::new();
        let mut batch_nonces: BTreeMap<Uuid, NonceData> = BTreeMap::new();

        // Clone batch_items to avoid borrow issues
        let batch_items: Vec<_> = session_metadata.batch_items.iter().collect();

        for (batch_item_id, batch_item) in batch_items {
            keymeld_core::validation::validate_decrypted_adaptor_configs(
                &batch_item.adaptor_configs,
            )
            .map_err(|e| MusigError::InvalidAdaptorConfig(e.to_string()))?;

            let message = &batch_item.message;

            // Get the KeyAggContext for this specific batch item (with its own tweak)
            let item_key_agg_ctx = self.get_key_agg_ctx_for_batch_item(batch_item_id)?;

            // Determine the correct signer index for this batch item
            // If the batch item uses a subset, compute the index within that subset
            let item_signer_index = if let Some(subset_id) = batch_item.subset_id {
                match self.compute_subset_signer_index(user_id, &subset_id) {
                    Ok(subset_idx) => {
                        debug!(
                            "User {} has subset signer index {} (full group index {}) for batch_item {} with subset {}",
                            user_id, subset_idx, signer_index, batch_item_id, subset_id
                        );
                        subset_idx
                    }
                    Err(e) => {
                        // User is not in this subset - skip this batch item
                        warn!(
                            "Skipping batch_item {} for user {}: {}",
                            batch_item_id, user_id, e
                        );
                        continue;
                    }
                }
            } else {
                // No subset - use the full group signer index
                signer_index
            };

            if batch_item.adaptor_configs.is_empty() {
                // Regular signing for this batch item
                let batch_nonce_seed = SecureCrypto::derive_signing_nonce_seed(
                    &base_nonce_seed,
                    session_id,
                    user_id,
                    batch_item_id,
                    None,
                )
                .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;
                let first_round = FirstRound::new(
                    item_key_agg_ctx,
                    batch_nonce_seed,
                    item_signer_index,
                    SecNonceSpices::new()
                        .with_seckey(secret_key)
                        .with_message(message),
                )
                .map_err(|e| MusigError::Musig2Error(e.into()))?;

                let pub_nonce = first_round.our_public_nonce();
                batch_first_rounds.insert(*batch_item_id, first_round);
                batch_nonces.insert(*batch_item_id, NonceData::Regular(pub_nonce));

                debug!(
                    "Generated batch nonce for user {} batch_item {} (regular, signer_index={})",
                    user_id, batch_item_id, item_signer_index
                );
            } else {
                // Adaptor signing for this batch item - one FirstRound per adaptor config
                let mut adaptor_first_rounds_for_item: BTreeMap<Uuid, FirstRound> = BTreeMap::new();
                let mut adaptor_nonces: Vec<(Uuid, PubNonce)> = Vec::new();

                for adaptor_config in &batch_item.adaptor_configs {
                    let adaptor_nonce_seed = SecureCrypto::derive_signing_nonce_seed(
                        &base_nonce_seed,
                        session_id,
                        user_id,
                        batch_item_id,
                        Some(&adaptor_config.adaptor_id),
                    )
                    .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;

                    let first_round = FirstRound::new(
                        item_key_agg_ctx.clone(),
                        adaptor_nonce_seed,
                        item_signer_index,
                        SecNonceSpices::new()
                            .with_seckey(secret_key)
                            .with_message(message),
                    )
                    .map_err(|e| MusigError::Musig2Error(e.into()))?;

                    let pub_nonce = first_round.our_public_nonce();
                    adaptor_nonces.push((adaptor_config.adaptor_id, pub_nonce));
                    adaptor_first_rounds_for_item.insert(adaptor_config.adaptor_id, first_round);

                    debug!(
                        "Generated batch adaptor nonce for user {} batch_item {} adaptor_id {} (signer_index={})",
                        user_id, batch_item_id, adaptor_config.adaptor_id, item_signer_index
                    );
                }

                batch_adaptor_first_rounds.insert(*batch_item_id, adaptor_first_rounds_for_item);
                batch_nonces.insert(*batch_item_id, NonceData::Adaptor(adaptor_nonces));
            }
        }

        info!(
            "Generated batch nonces for user {} in session {}: {} regular, {} adaptor batch items",
            user_id,
            session_id,
            batch_first_rounds.len(),
            batch_adaptor_first_rounds.len()
        );

        // Store in user session
        if let Some(existing_session) = self.user_sessions.get_mut(user_id) {
            existing_session.batch_first_rounds = batch_first_rounds;
            existing_session.batch_adaptor_first_rounds = batch_adaptor_first_rounds;
            existing_session.private_key = Some(private_key.clone());
            existing_session.signer_index = signer_index;
        } else {
            let user_session = UserMusigSession {
                user_id: user_id.clone(),
                coordinator: false,
                signer_index,
                private_key: Some(private_key.clone()),
                auth_pubkey: None,
                require_signing_approval: false,
                batch_first_rounds,
                batch_second_rounds: BTreeMap::new(),
                batch_adaptor_first_rounds,
                batch_adaptor_second_rounds: BTreeMap::new(),
            };
            self.user_sessions.insert(user_id.clone(), user_session);
        }

        Ok(batch_nonces)
    }

    /// Store batch nonces from a remote participant into local participants' FirstRounds.
    /// batch_nonces is a map of batch_item_id -> NonceData
    pub fn store_batch_nonces(
        &mut self,
        user_id: &UserId,
        batch_nonces: BTreeMap<Uuid, NonceData>,
    ) -> Result<(), MusigError> {
        let session_metadata = &self.session_metadata;
        let session_id = &session_metadata.session_id;

        // Calculate the full group signer index for the user who sent these nonces using BIP327-sorted order
        let sorted_participants = session_metadata.get_all_participant_ids();
        let full_group_signer_index = sorted_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or(MusigError::InvalidParticipant(user_id.clone()))?;

        debug!(
            "store_batch_nonces - user {} has full_group_signer_index {} in session {}",
            user_id, full_group_signer_index, session_id
        );

        // Get all user IDs that need updating
        let user_ids_with_private_keys: Vec<UserId> = self
            .user_sessions
            .iter()
            .filter_map(|(uid, session)| {
                if session.private_key.is_some() {
                    Some(uid.clone())
                } else {
                    None
                }
            })
            .collect();

        // Clone batch_items to check subset_id for each batch item
        let batch_items = self.session_metadata.batch_items.clone();

        // Pre-compute signer indices for all batch items to avoid borrow conflicts
        let mut batch_item_signer_indices: BTreeMap<Uuid, Option<usize>> = BTreeMap::new();
        for (batch_item_id, batch_item) in &batch_items {
            let signer_index = if let Some(subset_id) = batch_item.subset_id {
                match self.compute_subset_signer_index(user_id, &subset_id) {
                    Ok(idx) => {
                        debug!(
                            "store_batch_nonces: User {} has subset signer index {} for batch_item {} with subset {}",
                            user_id, idx, batch_item_id, subset_id
                        );
                        Some(idx)
                    }
                    Err(_) => {
                        // User is not in this subset - will skip this nonce
                        debug!(
                            "store_batch_nonces: User {} is not in subset {} for batch_item {}, will skip",
                            user_id, subset_id, batch_item_id
                        );
                        None
                    }
                }
            } else {
                Some(full_group_signer_index)
            };
            batch_item_signer_indices.insert(*batch_item_id, signer_index);
        }

        // Update each local user session
        for session_user_id in user_ids_with_private_keys {
            if let Some(user_session) = self.user_sessions.get_mut(&session_user_id) {
                for (batch_item_id, nonce_data) in &batch_nonces {
                    // Get the pre-computed signer index for this batch item
                    let signer_index = match batch_item_signer_indices.get(batch_item_id) {
                        Some(Some(idx)) => *idx,
                        _ => {
                            // User is not in this subset or batch item not found - skip
                            continue;
                        }
                    };

                    match nonce_data {
                        NonceData::Regular(nonce) => {
                            if let Some(first_round) =
                                user_session.batch_first_rounds.get_mut(batch_item_id)
                            {
                                if let Err(e) =
                                    first_round.receive_nonce(signer_index, nonce.clone())
                                {
                                    debug!(
                                        "Failed to add batch nonce for user {} batch_item {}: {}",
                                        session_user_id, batch_item_id, e
                                    );
                                }
                            }
                        }
                        NonceData::Adaptor(adaptor_nonces) => {
                            if let Some(adaptor_rounds) = user_session
                                .batch_adaptor_first_rounds
                                .get_mut(batch_item_id)
                            {
                                for (adaptor_id, nonce) in adaptor_nonces {
                                    if let Some(first_round) = adaptor_rounds.get_mut(adaptor_id) {
                                        if let Err(e) =
                                            first_round.receive_nonce(signer_index, nonce.clone())
                                        {
                                            debug!(
                                                "Failed to add batch adaptor nonce for user {} batch_item {} adaptor {}: {}",
                                                session_user_id, batch_item_id, adaptor_id, e
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        NonceData::Batch(_) => {
                            // Nested batch is not supported - this shouldn't happen
                            debug!(
                                "Unexpected nested Batch nonce data for batch_item {}",
                                batch_item_id
                            );
                        }
                    }
                }
            }
        }

        info!(
            "Stored batch nonces from user {} (full_group_index {}) in session {}",
            user_id, full_group_signer_index, session_id
        );

        Ok(())
    }

    /// Get batch nonce data for a user (for distribution to other participants)
    pub fn get_user_batch_nonce_data(&self, user_id: &UserId) -> Option<BTreeMap<Uuid, NonceData>> {
        let user_session = self.user_sessions.get(user_id)?;

        let mut batch_nonces: BTreeMap<Uuid, NonceData> = BTreeMap::new();

        // Collect regular batch nonces
        for (batch_item_id, first_round) in &user_session.batch_first_rounds {
            let pub_nonce = first_round.our_public_nonce();
            batch_nonces.insert(*batch_item_id, NonceData::Regular(pub_nonce));
        }

        // Collect adaptor batch nonces
        for (batch_item_id, adaptor_rounds) in &user_session.batch_adaptor_first_rounds {
            let mut adaptor_nonces: Vec<(Uuid, PubNonce)> = Vec::new();
            for (adaptor_id, first_round) in adaptor_rounds {
                let pub_nonce = first_round.our_public_nonce();
                adaptor_nonces.push((*adaptor_id, pub_nonce));
            }
            if !adaptor_nonces.is_empty() {
                batch_nonces.insert(*batch_item_id, NonceData::Adaptor(adaptor_nonces));
            }
        }

        if batch_nonces.is_empty() {
            None
        } else {
            Some(batch_nonces)
        }
    }

    /// Check if all batch nonces have been collected for all batch items
    pub fn all_batch_nonces_complete(&self) -> bool {
        let batch_item_count = self.session_metadata.batch_items.len();
        if batch_item_count == 0 {
            return false;
        }

        // Check all user sessions that have private keys (local participants)
        for user_session in self.user_sessions.values() {
            if user_session.private_key.is_none() {
                continue;
            }

            // Check regular batch first rounds
            for (batch_item_id, first_round) in &user_session.batch_first_rounds {
                if !first_round.is_complete() {
                    debug!(
                        "Batch item {} regular nonce round not complete for user {}",
                        batch_item_id, user_session.user_id
                    );
                    return false;
                }
            }

            // Check adaptor batch first rounds
            for (batch_item_id, adaptor_rounds) in &user_session.batch_adaptor_first_rounds {
                for (adaptor_id, first_round) in adaptor_rounds {
                    if !first_round.is_complete() {
                        debug!(
                            "Batch item {} adaptor {} nonce round not complete for user {}",
                            batch_item_id, adaptor_id, user_session.user_id
                        );
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Check nonce completion and advance phase if ready
    pub fn check_nonce_completion(&mut self) -> Result<(), MusigError> {
        if self.all_batch_nonces_complete() {
            let session_id = self.session_metadata.session_id.clone();
            self.update_session_phase(SessionPhase::NonceAggregation)?;
            info!("Session {} advanced to NonceAggregation phase", session_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod nonce_security_tests {
    use super::*;
    use crate::musig::types::BatchItemData;
    use keymeld_core::{
        protocol::{AdaptorConfig, TaprootTweak},
        SessionId,
    };
    use std::collections::BTreeSet;

    fn processor() -> (MusigProcessor, UserId, KeyMaterial) {
        let session_id = SessionId::new_v7();
        let user_id = UserId::new_v7();
        let secret = SecretKey::from_byte_array([21; 32]).unwrap();
        let mut processor = MusigProcessor::new(
            &session_id,
            TaprootTweak::None,
            Some(1),
            vec![user_id.clone()],
        );
        processor
            .add_participant(user_id.clone(), secret.public_key(secp256k1::SECP256K1))
            .unwrap();
        processor
            .create_key_aggregation_context(&session_id)
            .unwrap();
        (
            processor,
            user_id,
            KeyMaterial::new(secret.secret_bytes().to_vec()),
        )
    }

    fn item(id: Uuid, configs: Vec<AdaptorConfig>) -> BatchItemData {
        BatchItemData {
            batch_item_id: id,
            message: vec![22; 32],
            adaptor_configs: configs,
            adaptor_final_signatures: BTreeMap::new(),
            taproot_tweak: TaprootTweak::None,
            subset_id: None,
        }
    }

    fn point() -> String {
        hex::encode(
            SecretKey::from_byte_array([23; 32])
                .unwrap()
                .public_key(secp256k1::SECP256K1)
                .serialize(),
        )
    }

    #[test]
    fn more_than_256_adaptors_and_batch_items_have_distinct_public_nonces() {
        let (mut processor, user, key) = processor();
        let adaptor_item_id = Uuid::from_u128(1_000);
        let configs = (0..257)
            .map(|index| {
                let mut config = AdaptorConfig::single(point());
                config.adaptor_id = Uuid::from_u128(index);
                config
            })
            .collect();
        let mut items: BTreeMap<_, _> = (0..257)
            .map(|index| {
                let id = Uuid::from_u128(index);
                (id, item(id, vec![]))
            })
            .collect();
        items.insert(adaptor_item_id, item(adaptor_item_id, configs));
        processor.set_batch_items(items).unwrap();
        let nonces = processor.generate_batch_nonces(&user, 0, &key).unwrap();
        let mut unique = BTreeSet::new();
        for nonce in nonces.values() {
            match nonce {
                NonceData::Regular(nonce) => assert!(unique.insert(nonce.serialize())),
                NonceData::Adaptor(nonces) => {
                    assert_eq!(nonces.len(), 257);
                    for (_, nonce) in nonces {
                        assert!(
                            unique.insert(nonce.serialize()),
                            "reused adaptor public nonce"
                        );
                    }
                }
                NonceData::Batch(_) => panic!("unexpected nested batch"),
            }
        }
        assert_eq!(unique.len(), 514);
    }

    #[test]
    fn nonce_generation_rejects_unsupported_or_ambiguous_adaptor_configs() {
        for configs in [
            vec![AdaptorConfig::and(vec![point(), point()])],
            vec![AdaptorConfig::or(vec![point(), point()])],
            {
                let config = AdaptorConfig::single(point());
                vec![config.clone(), config]
            },
        ] {
            let (mut processor, user, key) = processor();
            let id = Uuid::now_v7();
            processor
                .set_batch_items(BTreeMap::from([(id, item(id, configs))]))
                .unwrap();
            assert!(processor.generate_batch_nonces(&user, 0, &key).is_err());
            assert!(processor.user_sessions.is_empty());
        }
    }
}
