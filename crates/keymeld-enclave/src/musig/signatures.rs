use musig2::{BinaryEncoding, PartialSignature, SecondRound};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use keymeld_core::{identifiers::UserId, protocol::FinalizedData};

use super::{error::MusigError, MusigProcessor};

impl MusigProcessor {
    // ========== BATCH SIGNING SIGNATURE METHODS ==========
    // All signing now goes through batch paths. Single messages are treated as a batch of 1.

    /// Finalize batch nonce rounds for a user - converts FirstRounds to SecondRounds
    /// for all batch items, producing partial signatures.
    pub fn finalize_batch_nonce_rounds(&mut self, user_id: &UserId) -> Result<(), MusigError> {
        let session_id = self.session_metadata.session_id.clone();

        let user_session = self.user_sessions.get_mut(user_id).ok_or_else(|| {
            MusigError::NotReady(format!("No user session found for user {user_id}"))
        })?;

        let private_key = user_session.private_key.clone().ok_or_else(|| {
            MusigError::NotReady(format!("No private key found for user {user_id}"))
        })?;

        let secret_key = musig2::secp256k1::SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        // Clone batch_items to avoid borrow issues
        let batch_items: BTreeMap<_, _> = self.session_metadata.batch_items.clone();

        // Re-borrow user_session
        let user_session = self.user_sessions.get_mut(user_id).unwrap();

        // Finalize regular batch first rounds
        let batch_item_ids: Vec<_> = user_session.batch_first_rounds.keys().cloned().collect();
        for batch_item_id in batch_item_ids {
            if user_session
                .batch_second_rounds
                .contains_key(&batch_item_id)
            {
                continue; // Already finalized
            }

            let first_round = match user_session.batch_first_rounds.remove(&batch_item_id) {
                Some(round) => round,
                None => continue,
            };

            if !first_round.is_complete() {
                return Err(MusigError::NotReady(format!(
                    "Batch item {} first round not complete",
                    batch_item_id
                )));
            }

            let message = batch_items
                .get(&batch_item_id)
                .map(|item| item.message.clone())
                .unwrap_or_default();

            let second_round = first_round
                .finalize(secret_key, message)
                .map_err(|e| MusigError::Musig2Error(e.into()))?;

            user_session
                .batch_second_rounds
                .insert(batch_item_id, second_round);

            info!(
                "Finalized batch second round for user {} batch_item {} in session {}",
                user_id, batch_item_id, session_id
            );
        }

        // Finalize adaptor batch first rounds
        let adaptor_batch_ids: Vec<_> = user_session
            .batch_adaptor_first_rounds
            .keys()
            .cloned()
            .collect();
        for batch_item_id in adaptor_batch_ids {
            let batch_item = match batch_items.get(&batch_item_id) {
                Some(item) => item,
                None => continue,
            };

            let adaptor_rounds = match user_session
                .batch_adaptor_first_rounds
                .remove(&batch_item_id)
            {
                Some(rounds) => rounds,
                None => continue,
            };

            let mut second_rounds: BTreeMap<Uuid, SecondRound<Vec<u8>>> = BTreeMap::new();

            // Build lookup of adaptor configs by id for easy access
            let adaptor_configs: BTreeMap<_, _> = batch_item
                .adaptor_configs
                .iter()
                .map(|c| (c.adaptor_id, c))
                .collect();

            // Iterate over owned adaptor rounds
            for (adaptor_id, first_round) in adaptor_rounds {
                let adaptor_config = match adaptor_configs.get(&adaptor_id) {
                    Some(config) => *config,
                    None => continue,
                };

                if !first_round.is_complete() {
                    return Err(MusigError::NotReady(format!(
                        "Batch item {} adaptor {} first round not complete",
                        batch_item_id, adaptor_id
                    )));
                }

                // Parse adaptor point
                let adaptor_point_hex = adaptor_config.adaptor_points.first().ok_or_else(|| {
                    MusigError::InvalidAdaptorConfig(format!(
                        "No adaptor points in config {}",
                        adaptor_id
                    ))
                })?;

                let adaptor_point_bytes = hex::decode(adaptor_point_hex).map_err(|e| {
                    MusigError::InvalidAdaptorConfig(format!("Invalid adaptor point hex: {}", e))
                })?;

                let adaptor_point = musig2::secp256k1::PublicKey::from_slice(&adaptor_point_bytes)
                    .map_err(|e| {
                        MusigError::InvalidAdaptorConfig(format!("Invalid adaptor point: {}", e))
                    })?;

                let second_round = first_round
                    .finalize_adaptor(secret_key, adaptor_point, batch_item.message.clone())
                    .map_err(|e| MusigError::Musig2Error(e.into()))?;

                second_rounds.insert(adaptor_id, second_round);

                info!(
                    "Finalized batch adaptor second round for user {} batch_item {} adaptor {} in session {}",
                    user_id, batch_item_id, adaptor_id, session_id
                );
            }

            user_session
                .batch_adaptor_second_rounds
                .insert(batch_item_id, second_rounds);
        }

        Ok(())
    }

    /// Get batch partial signatures for a user.
    /// Returns map of batch_item_id -> BatchPartialSigData
    pub fn get_user_batch_partial_signatures(
        &self,
        user_id: &UserId,
    ) -> Result<BTreeMap<Uuid, BatchPartialSigData>, MusigError> {
        let user_session = self
            .user_sessions
            .get(user_id)
            .ok_or_else(|| MusigError::UserNotFound(user_id.clone()))?;

        let mut results: BTreeMap<Uuid, BatchPartialSigData> = BTreeMap::new();

        // Get regular batch signatures
        for (batch_item_id, second_round) in &user_session.batch_second_rounds {
            let partial_sig: PartialSignature = second_round.our_signature();
            let aggregated_nonce = second_round.aggregated_nonce();
            results.insert(
                *batch_item_id,
                BatchPartialSigData::Regular {
                    signature: partial_sig.serialize().to_vec(),
                    nonce: aggregated_nonce.serialize().to_vec(),
                },
            );
        }

        // Get adaptor batch signatures
        for (batch_item_id, adaptor_rounds) in &user_session.batch_adaptor_second_rounds {
            let mut adaptor_sigs: Vec<(Uuid, Vec<u8>, Vec<u8>)> = Vec::new();
            for (adaptor_id, second_round) in adaptor_rounds {
                let partial_sig: PartialSignature = second_round.our_signature();
                let aggregated_nonce = second_round.aggregated_nonce();
                adaptor_sigs.push((
                    *adaptor_id,
                    partial_sig.serialize().to_vec(),
                    aggregated_nonce.serialize().to_vec(),
                ));
            }
            if !adaptor_sigs.is_empty() {
                results.insert(*batch_item_id, BatchPartialSigData::Adaptor(adaptor_sigs));
            }
        }

        Ok(results)
    }

    /// Compute the signer index for a user within a subset (for signature verification).
    /// The subset's KeyAggContext is built from public keys sorted by BIP327 order.
    fn compute_subset_signer_index_for_sigs(
        &self,
        user_id: &UserId,
        subset_id: &Uuid,
    ) -> Option<usize> {
        // Find the subset definition
        let subset_def = self
            .session_metadata
            .subset_definitions
            .iter()
            .find(|def| def.subset_id == *subset_id)?;

        // Check if user is in this subset
        if !subset_def.participants.contains(user_id) {
            return None;
        }

        // Collect and sort public keys for subset participants (same as compute_subset_aggregates)
        let mut subset_pubkeys_with_ids: Vec<(UserId, musig2::secp256k1::PublicKey)> = Vec::new();
        for uid in &subset_def.participants {
            if let Some(pubkey) = self.session_metadata.participant_public_keys.get(uid) {
                subset_pubkeys_with_ids.push((uid.clone(), *pubkey));
            }
        }

        // Sort by compressed public key bytes (BIP327) - same order as KeyAggContext
        subset_pubkeys_with_ids.sort_by(|a, b| a.1.serialize().cmp(&b.1.serialize()));

        // Find user's position in sorted order
        subset_pubkeys_with_ids
            .iter()
            .position(|(uid, _)| uid == user_id)
    }

    /// Add batch partial signatures from a remote participant.
    pub fn add_batch_partial_signatures(
        &mut self,
        user_id: &UserId,
        batch_signatures: BTreeMap<Uuid, BatchPartialSigData>,
    ) -> Result<(), MusigError> {
        let sorted_participants = self.session_metadata.get_all_participant_ids();
        let full_group_signer_index = sorted_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or(MusigError::InvalidParticipant(user_id.clone()))?;

        // Get all user IDs that need updating
        let user_ids_with_private_keys: Vec<_> = self
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
        let mut batch_item_signer_indices: std::collections::BTreeMap<Uuid, Option<usize>> =
            std::collections::BTreeMap::new();
        for (batch_item_id, batch_item) in &batch_items {
            let signer_index = if let Some(subset_id) = batch_item.subset_id {
                match self.compute_subset_signer_index_for_sigs(user_id, &subset_id) {
                    Some(idx) => {
                        debug!(
                            "User {} has subset signer index {} for batch_item {} with subset {}",
                            user_id, idx, batch_item_id, subset_id
                        );
                        Some(idx)
                    }
                    None => {
                        // User is not in this subset - will skip
                        warn!(
                            "User {} is not in subset {} for batch_item {}, will skip signature",
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

        for session_user_id in user_ids_with_private_keys {
            if let Some(user_session) = self.user_sessions.get_mut(&session_user_id) {
                for (batch_item_id, sig_data) in &batch_signatures {
                    // Get the pre-computed signer index for this batch item
                    let signer_index = match batch_item_signer_indices.get(batch_item_id) {
                        Some(Some(idx)) => *idx,
                        _ => {
                            // User is not in this subset or batch item not found - skip
                            continue;
                        }
                    };

                    match sig_data {
                        BatchPartialSigData::Regular { signature, .. } => {
                            if let Some(second_round) =
                                user_session.batch_second_rounds.get_mut(batch_item_id)
                            {
                                let partial_sig =
                                    PartialSignature::from_slice(signature).map_err(|e| {
                                        MusigError::SigningError(format!(
                                            "Invalid partial signature: {:?}",
                                            e
                                        ))
                                    })?;
                                second_round
                                    .receive_signature(signer_index, partial_sig)
                                    .map_err(|e| {
                                        MusigError::SigningError(format!(
                                            "Failed to add batch signature: {:?}",
                                            e
                                        ))
                                    })?;
                            }
                        }
                        BatchPartialSigData::Adaptor(adaptor_sigs) => {
                            if let Some(adaptor_rounds) = user_session
                                .batch_adaptor_second_rounds
                                .get_mut(batch_item_id)
                            {
                                for (adaptor_id, sig_bytes, _) in adaptor_sigs {
                                    if let Some(second_round) = adaptor_rounds.get_mut(adaptor_id) {
                                        let partial_sig = PartialSignature::from_slice(sig_bytes)
                                            .map_err(|e| {
                                            MusigError::SigningError(format!(
                                                "Invalid adaptor partial signature: {:?}",
                                                e
                                            ))
                                        })?;
                                        second_round
                                            .receive_signature(signer_index, partial_sig)
                                            .map_err(|e| {
                                            MusigError::SigningError(format!(
                                                "Failed to add batch adaptor signature: {:?}",
                                                e
                                            ))
                                        })?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        info!(
            "Added batch partial signatures from user {} (full_group_index {}) in session {}",
            user_id, full_group_signer_index, self.session_metadata.session_id
        );

        Ok(())
    }

    /// Finalize all batch signatures (coordinator only).
    /// Returns map of batch_item_id -> FinalizedData
    pub fn finalize_batch(
        &mut self,
        coordinator_user_id: &UserId,
    ) -> Result<BTreeMap<Uuid, FinalizedData>, MusigError> {
        let session_id = self.session_metadata.session_id.clone();
        let batch_items = self.session_metadata.batch_items.clone();

        let user_session = self
            .user_sessions
            .get_mut(coordinator_user_id)
            .ok_or_else(|| MusigError::UserNotFound(coordinator_user_id.clone()))?;

        let mut results: BTreeMap<Uuid, FinalizedData> = BTreeMap::new();

        // Finalize regular batch second rounds
        let batch_item_ids: Vec<_> = user_session.batch_second_rounds.keys().cloned().collect();
        for batch_item_id in batch_item_ids {
            if let Some(second_round) = user_session.batch_second_rounds.remove(&batch_item_id) {
                if !second_round.holdouts().is_empty() {
                    return Err(MusigError::NotReady(format!(
                        "Batch item {} second round not complete - missing signatures",
                        batch_item_id
                    )));
                }

                let final_sig: [u8; 64] = second_round.finalize::<[u8; 64]>().map_err(|e| {
                    MusigError::SigningError(format!("Failed to finalize batch signature: {:?}", e))
                })?;

                results.insert(
                    batch_item_id,
                    FinalizedData::FinalSignature(final_sig.to_vec()),
                );

                info!(
                    "Finalized batch signature for batch_item {} in session {}",
                    batch_item_id, session_id
                );
            }
        }

        // Finalize adaptor batch second rounds
        let adaptor_batch_ids: Vec<_> = user_session
            .batch_adaptor_second_rounds
            .keys()
            .cloned()
            .collect();
        for batch_item_id in adaptor_batch_ids {
            let batch_item = match batch_items.get(&batch_item_id) {
                Some(item) => item,
                None => continue,
            };

            if let Some(mut adaptor_rounds) = user_session
                .batch_adaptor_second_rounds
                .remove(&batch_item_id)
            {
                let mut adaptor_results: Vec<(Uuid, Vec<u8>)> = Vec::new();

                for adaptor_config in &batch_item.adaptor_configs {
                    let adaptor_id = adaptor_config.adaptor_id;

                    if let Some(second_round) = adaptor_rounds.remove(&adaptor_id) {
                        if !second_round.holdouts().is_empty() {
                            return Err(MusigError::NotReady(format!(
                                "Batch item {} adaptor {} not complete",
                                batch_item_id, adaptor_id
                            )));
                        }

                        // Get aggregated nonce before finalize consumes the round
                        let aggregated_nonce = second_round.aggregated_nonce();
                        let nonce_bytes = aggregated_nonce.serialize().to_vec();

                        let adaptor_sig = second_round
                            .finalize_adaptor::<musig2::AdaptorSignature>()
                            .map_err(|e| {
                                MusigError::SigningError(format!(
                                    "Failed to finalize batch adaptor signature: {:?}",
                                    e
                                ))
                            })?;

                        let sig_bytes = adaptor_sig.to_bytes().to_vec();

                        // Store adaptor signature result in batch_item metadata
                        if let Some(item) =
                            self.session_metadata.batch_items.get_mut(&batch_item_id)
                        {
                            item.adaptor_final_signatures.insert(
                                adaptor_id,
                                keymeld_core::protocol::AdaptorSignatureResult {
                                    adaptor_id,
                                    adaptor_type: adaptor_config.adaptor_type.clone(),
                                    signature_scalar: sig_bytes.clone(),
                                    nonce_point: nonce_bytes,
                                    adaptor_points: adaptor_config
                                        .adaptor_points
                                        .iter()
                                        .filter_map(|hex| hex::decode(hex).ok())
                                        .collect(),
                                    hints: adaptor_config.hints.clone(),
                                    aggregate_adaptor_point: adaptor_config
                                        .adaptor_points
                                        .first()
                                        .and_then(|hex| hex::decode(hex).ok())
                                        .unwrap_or_default(),
                                },
                            );
                        }

                        adaptor_results.push((adaptor_id, sig_bytes));

                        info!(
                            "Finalized batch adaptor signature for batch_item {} adaptor {} in session {}",
                            batch_item_id, adaptor_id, session_id
                        );
                    }
                }

                if !adaptor_results.is_empty() {
                    results.insert(
                        batch_item_id,
                        FinalizedData::AdaptorSignatures(adaptor_results),
                    );
                }
            }
        }

        info!(
            "Finalized {} batch signatures in session {}",
            results.len(),
            session_id
        );

        Ok(results)
    }

    /// Check if all batch signatures are complete and ready for finalization
    pub fn all_batch_signatures_complete(&self) -> bool {
        for user_session in self.user_sessions.values() {
            if user_session.private_key.is_none() {
                continue;
            }

            // Check regular batch second rounds
            for second_round in user_session.batch_second_rounds.values() {
                if !second_round.holdouts().is_empty() {
                    return false;
                }
            }

            // Check adaptor batch second rounds
            for adaptor_rounds in user_session.batch_adaptor_second_rounds.values() {
                for second_round in adaptor_rounds.values() {
                    if !second_round.holdouts().is_empty() {
                        return false;
                    }
                }
            }
        }

        true
    }

    /// Get the count of batch items that have finalized signatures
    pub fn get_batch_signature_count(&self) -> usize {
        let mut count = 0;
        for user_session in self.user_sessions.values() {
            if user_session.private_key.is_some() {
                count = count.max(user_session.batch_second_rounds.len());
                count = count.max(user_session.batch_adaptor_second_rounds.len());
            }
        }
        count
    }
}

/// Data for batch partial signatures - can be regular or adaptor
#[derive(Debug, Clone)]
pub enum BatchPartialSigData {
    Regular { signature: Vec<u8>, nonce: Vec<u8> },
    Adaptor(Vec<(Uuid, Vec<u8>, Vec<u8>)>), // Vec of (adaptor_id, sig_bytes, nonce_bytes)
}
