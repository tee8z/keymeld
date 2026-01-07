use musig2::{BinaryEncoding, PartialSignature};
use std::collections::BTreeMap;
use tracing::info;

use keymeld_core::{identifiers::UserId, protocol::FinalizedData, KeyMaterial};

use super::{error::MusigError, MusigProcessor};

/// Type alias for adaptor signature result: (uuid, signature_bytes, adaptor_bytes)
type AdaptorSignatureResult = Vec<(uuid::Uuid, Vec<u8>, Vec<u8>)>;

impl MusigProcessor {
    pub fn sign(
        &self,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        let session_meta = self.get_session_metadata();

        if session_meta.has_adaptor_configs() {
            let adaptor_results = self.sign_adaptor_for_user(user_id, private_key)?;
            adaptor_results
                .first()
                .map(|(_, sig, nonce)| (sig.clone(), nonce.clone()))
                .ok_or(MusigError::InvalidAdaptorConfig(
                    "No adaptor results generated".to_string(),
                ))
        } else {
            self.sign_regular_for_user(user_id, private_key)
        }
    }

    fn sign_regular_for_user(
        &self,
        user_id: &UserId,
        _private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        let session_meta = self.get_session_metadata();

        info!(
            "sign_regular_for_user called for user {} in session {} (phase: {:?})",
            user_id, session_meta.session_id, session_meta.phase
        );

        // Get user session data
        let user_session = self
            .user_sessions
            .get(user_id)
            .ok_or_else(|| MusigError::UserNotFound(user_id.clone()))?;

        match &user_session.second_round {
            Some(second_round) => {
                let signature: PartialSignature = second_round.our_signature();
                let aggregated_nonce = second_round.aggregated_nonce();

                // Return signature bytes and actual aggregated nonce
                Ok((
                    signature.serialize().to_vec(),
                    aggregated_nonce.serialize().to_vec(),
                ))
            }
            None => Err(MusigError::SessionNotReady(
                "Second round not initialized".to_string(),
            )),
        }
    }

    pub fn add_partial_signature(
        &mut self,
        signer_index: usize,
        partial_signature: PartialSignature,
    ) -> Result<(), MusigError> {
        // Add the signature to ALL local user sessions that have SecondRound active
        // This is how MuSig2 works - each participant collects signatures from all other participants
        let mut signatures_added = 0;
        for (session_user_id, user_session) in self.user_sessions.iter_mut() {
            if let Some(second_round) = &mut user_session.second_round {
                second_round
                    .receive_signature(signer_index, partial_signature)
                    .map_err(|e| {
                        MusigError::SigningError(format!(
                            "Failed to add partial signature: {:?}",
                            e
                        ))
                    })?;
                signatures_added += 1;
                info!(
                    "Added partial signature (index {}) to user session {} in session {}",
                    signer_index, session_user_id, self.session_metadata.session_id
                );
            }
        }

        if signatures_added == 0 {
            return Err(MusigError::SigningError(
                "No active SecondRound sessions to receive signature".to_string(),
            ));
        }

        Ok(())
    }

    pub fn add_adaptor_partial_signatures(
        &mut self,
        signer_index: usize,
        adaptor_signatures: Vec<(uuid::Uuid, Vec<u8>)>,
    ) -> Result<(), MusigError> {
        // Add the signatures to ALL local user sessions that have adaptor SecondRounds active
        // This is how MuSig2 works - each participant collects signatures from all other participants
        let mut signatures_added = 0;
        for (session_user_id, user_session) in self.user_sessions.iter_mut() {
            // Process each adaptor signature for the configs available in this session
            for (config_id, signature_bytes) in &adaptor_signatures {
                if let Some(adaptor_second_round) =
                    user_session.adaptor_second_rounds.get_mut(config_id)
                {
                    // Convert bytes to PartialSignature
                    let partial_sig =
                        PartialSignature::from_slice(signature_bytes).map_err(|e| {
                            MusigError::SigningError(format!(
                                "Invalid partial signature format: {:?}",
                                e
                            ))
                        })?;

                    adaptor_second_round
                        .receive_signature(signer_index, partial_sig)
                        .map_err(|e| {
                            MusigError::SigningError(format!(
                                "Failed to add adaptor signature: {:?}",
                                e
                            ))
                        })?;
                    signatures_added += 1;
                    info!(
                        "Added adaptor partial signature (index {}, config {}) to user session {} in session {}",
                        signer_index, config_id, session_user_id, self.session_metadata.session_id
                    );
                }
            }
        }

        if signatures_added == 0 {
            return Err(MusigError::SigningError(
                "No active adaptor SecondRound sessions to receive signature".to_string(),
            ));
        }

        Ok(())
    }

    pub fn finalize(&mut self, coordinator_user_id: &UserId) -> Result<[u8; 64], MusigError> {
        let has_adaptor_configs = self.session_metadata.has_adaptor_configs();

        if has_adaptor_configs {
            // For adaptor signatures, use aggregate_adaptor_signatures
            // This also stores the results in session_metadata.adaptor_final_signatures
            let finalized_data = self.aggregate_adaptor_signatures()?;
            match finalized_data {
                FinalizedData::AdaptorSignatures(adaptor_sigs) => {
                    // Return the first adaptor signature as the "main" signature
                    // The full adaptor signatures are available via get_adaptor_signature_results()
                    if let Some((_, sig)) = adaptor_sigs.first() {
                        if sig.len() >= 64 {
                            let mut result = [0u8; 64];
                            result.copy_from_slice(&sig[..64]);
                            Ok(result)
                        } else {
                            Err(MusigError::SigningError(
                                "Adaptor signature too short".to_string(),
                            ))
                        }
                    } else {
                        Err(MusigError::SigningError(
                            "No adaptor signatures produced".to_string(),
                        ))
                    }
                }
                FinalizedData::FinalSignature(sig) => {
                    if sig.len() >= 64 {
                        let mut result = [0u8; 64];
                        result.copy_from_slice(&sig[..64]);
                        Ok(result)
                    } else {
                        Err(MusigError::SigningError("Signature too short".to_string()))
                    }
                }
            }
        } else {
            // Regular signing: use second_round.finalize()
            let coordinator_session = self
                .user_sessions
                .get_mut(coordinator_user_id)
                .ok_or_else(|| MusigError::UserNotFound(coordinator_user_id.clone()))?;

            if let Some(second_round) = coordinator_session.second_round.take() {
                let final_signature: [u8; 64] =
                    second_round.finalize::<[u8; 64]>().map_err(|e| {
                        MusigError::SigningError(format!("Finalization failed: {:?}", e))
                    })?;

                Ok(final_signature)
            } else {
                Err(MusigError::SessionNotReady(
                    "Second round not initialized for coordinator".to_string(),
                ))
            }
        }
    }

    pub fn can_aggregate_signatures(&self) -> bool {
        let session_metadata = &self.session_metadata;

        if session_metadata.has_adaptor_configs() {
            // Check adaptor signature completion
            for entry in &self.user_sessions {
                let user_session = entry.1;

                for adaptor_second_round in user_session.adaptor_second_rounds.values() {
                    let holdouts_count = adaptor_second_round.holdouts().len();
                    if holdouts_count > 0 {
                        return false;
                    }
                }
            }
            true
        } else {
            // Check regular signature completion
            for entry in &self.user_sessions {
                let user_session = entry.1;

                if let Some(second_round) = &user_session.second_round {
                    let holdouts_count = second_round.holdouts().len();
                    if holdouts_count > 0 {
                        return false;
                    }
                }
            }
            true
        }
    }

    pub fn aggregate_signatures(&mut self) -> Result<FinalizedData, MusigError> {
        let session_metadata = &self.session_metadata;

        if session_metadata.has_adaptor_configs() {
            self.aggregate_adaptor_signatures()
        } else {
            self.aggregate_regular_signatures()
        }
    }

    fn aggregate_regular_signatures(&mut self) -> Result<FinalizedData, MusigError> {
        // Find any user with a complete second round for aggregation
        for entry in self.user_sessions.iter_mut() {
            let (user_id, user_session) = entry;

            if let Some(second_round) = &mut user_session.second_round {
                // Check if this round is ready for finalization
                let holdouts_count = second_round.holdouts().len();
                if holdouts_count == 0 {
                    if let Some(second_round) = user_session.second_round.take() {
                        let signature: [u8; 64] =
                            second_round.finalize::<[u8; 64]>().map_err(|e| {
                                MusigError::SigningError(format!(
                                    "Aggregation failed for user {}: {:?}",
                                    user_id, e
                                ))
                            })?;
                        return Ok(FinalizedData::FinalSignature(signature.to_vec()));
                    }
                }
            }
        }

        Err(MusigError::SessionNotReady(
            "No complete signature rounds available for aggregation".to_string(),
        ))
    }

    pub fn get_partial_signature_count(&self) -> usize {
        let session_metadata = &self.session_metadata;

        if session_metadata.has_adaptor_configs() {
            // Count adaptor partial signatures
            let mut total_count = 0;
            for entry in &self.user_sessions {
                let user_session = entry.1;

                for adaptor_second_round in user_session.adaptor_second_rounds.values() {
                    let holdouts_count = adaptor_second_round.holdouts().len();
                    total_count += session_metadata.expected_participants.len() - holdouts_count;
                }
            }
            total_count
        } else {
            // Count regular partial signatures
            let mut total_count = 0;
            for entry in &self.user_sessions {
                let user_session = entry.1;

                if let Some(second_round) = &user_session.second_round {
                    let holdouts_count = second_round.holdouts().len();
                    total_count += session_metadata.expected_participants.len() - holdouts_count;
                }
            }
            total_count
        }
    }

    pub fn get_adaptor_signature_completion_count(&self) -> BTreeMap<uuid::Uuid, usize> {
        let session_metadata = &self.session_metadata;
        let mut completion_counts = BTreeMap::new();

        if session_metadata.has_adaptor_configs() {
            for entry in &self.user_sessions {
                let user_session = entry.1;

                for (config_id, adaptor_second_round) in &user_session.adaptor_second_rounds {
                    let holdouts_count = adaptor_second_round.holdouts().len();
                    let completed_count =
                        session_metadata.expected_participants.len() - holdouts_count;

                    completion_counts.insert(*config_id, completed_count);
                }
            }
        }

        completion_counts
    }

    pub fn has_all_adaptor_signatures(&self) -> bool {
        let session_metadata = &self.session_metadata;

        if !session_metadata.has_adaptor_configs() {
            return true; // No adaptor signatures needed
        }

        for entry in &self.user_sessions {
            let user_session = entry.1;

            for adaptor_second_round in user_session.adaptor_second_rounds.values() {
                let holdouts_count = adaptor_second_round.holdouts().len();
                if holdouts_count > 0 {
                    return false;
                }
            }
        }

        true
    }

    pub fn get_user_partial_signature(&self, user_id: &UserId) -> Result<Vec<u8>, MusigError> {
        let user_session = self
            .user_sessions
            .get(user_id)
            .ok_or_else(|| MusigError::UserNotFound(user_id.clone()))?;

        if let Some(second_round) = &user_session.second_round {
            // Get the actual partial signature from the second round
            let partial_sig: PartialSignature = second_round.our_signature();
            Ok(partial_sig.serialize().to_vec())
        } else {
            Err(MusigError::SessionNotReady(
                "Second round not initialized".to_string(),
            ))
        }
    }

    pub fn get_user_adaptor_signatures(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<(uuid::Uuid, Vec<u8>)>, MusigError> {
        let user_session = self
            .user_sessions
            .get(user_id)
            .ok_or_else(|| MusigError::UserNotFound(user_id.clone()))?;

        let mut signatures = Vec::new();

        for (config_id, adaptor_second_round) in &user_session.adaptor_second_rounds {
            // Get the actual adaptor signature from the second round
            let partial_sig: PartialSignature = adaptor_second_round.our_signature();
            signatures.push((*config_id, partial_sig.serialize().to_vec()));
        }

        Ok(signatures)
    }

    pub fn user_has_all_adaptor_signatures(&self, user_id: &UserId) -> bool {
        if let Some(user_session) = self.user_sessions.get(user_id) {
            !user_session.adaptor_second_rounds.is_empty()
        } else {
            false
        }
    }

    pub fn get_session_partial_signatures(&self) -> BTreeMap<UserId, Vec<u8>> {
        let mut signatures = BTreeMap::new();

        for (user_id, user_session) in &self.user_sessions {
            if let Some(second_round) = &user_session.second_round {
                // Get the actual partial signature
                let partial_sig: PartialSignature = second_round.our_signature();
                signatures.insert(user_id.clone(), partial_sig.serialize().to_vec());
            }
        }

        signatures
    }

    fn sign_adaptor_for_user(
        &self,
        user_id: &UserId,
        _private_key: &KeyMaterial,
    ) -> Result<AdaptorSignatureResult, MusigError> {
        let session_meta = self.get_session_metadata();

        info!(
            "sign_adaptor_for_user called for user {} in session {} (phase: {:?})",
            user_id, session_meta.session_id, session_meta.phase
        );

        let user_session = self
            .user_sessions
            .get(user_id)
            .ok_or_else(|| MusigError::UserNotFound(user_id.clone()))?;

        let mut results = Vec::new();

        for config in &session_meta.adaptor_configs {
            if let Some(adaptor_second_round) =
                user_session.adaptor_second_rounds.get(&config.adaptor_id)
            {
                // Get the actual adaptor signature and nonce from the second round
                let partial_sig: PartialSignature = adaptor_second_round.our_signature();
                let aggregated_nonce = adaptor_second_round.aggregated_nonce();
                results.push((
                    config.adaptor_id,
                    partial_sig.serialize().to_vec(),
                    aggregated_nonce.serialize().to_vec(),
                ));
            }
        }

        if results.is_empty() {
            Err(MusigError::SessionNotReady(
                "No adaptor second rounds initialized".to_string(),
            ))
        } else {
            Ok(results)
        }
    }

    fn aggregate_adaptor_signatures(&mut self) -> Result<FinalizedData, MusigError> {
        // We need to finalize ALL adaptor configs, not just the first one
        let adaptor_configs = self.session_metadata.adaptor_configs.clone();

        // Find any user session that has adaptor_second_rounds (coordinator's session)
        let user_id_with_rounds = self
            .user_sessions
            .iter()
            .find(|(_, session)| !session.adaptor_second_rounds.is_empty())
            .map(|(user_id, _)| user_id.clone());

        let Some(user_id) = user_id_with_rounds else {
            return Err(MusigError::SessionNotReady(
                "No user session with adaptor second rounds found".to_string(),
            ));
        };

        // First pass: finalize all rounds and collect results (without storing yet)
        // Tuple: (config_id, signature_bytes, config_index, nonce_bytes)
        let mut pending_results: Vec<(uuid::Uuid, Vec<u8>, usize, Vec<u8>)> = Vec::new();

        {
            let user_session = self
                .user_sessions
                .get_mut(&user_id)
                .ok_or_else(|| MusigError::SessionNotReady("User session not found".to_string()))?;

            for (idx, adaptor_config) in adaptor_configs.iter().enumerate() {
                let config_id = adaptor_config.adaptor_id;

                // Check if this config's round is ready
                let round_ready = user_session
                    .adaptor_second_rounds
                    .get(&config_id)
                    .map(|round| round.holdouts().is_empty())
                    .unwrap_or(false);

                if !round_ready {
                    return Err(MusigError::SessionNotReady(format!(
                        "Adaptor second round for config {} is not ready",
                        config_id
                    )));
                }

                // Remove and finalize the round
                if let Some(adaptor_second_round) =
                    user_session.adaptor_second_rounds.remove(&config_id)
                {
                    // Get the aggregated nonce BEFORE finalize_adaptor consumes the round
                    let aggregated_nonce = adaptor_second_round.aggregated_nonce();
                    let nonce_bytes = aggregated_nonce.serialize().to_vec();

                    let adaptor_signature = adaptor_second_round
                        .finalize_adaptor::<musig2::AdaptorSignature>()
                        .map_err(|e| {
                            MusigError::SigningError(format!(
                                "Adaptor aggregation failed for config {}: {:?}",
                                config_id, e
                            ))
                        })?;

                    let serialized = adaptor_signature.to_bytes().to_vec();

                    info!(
                        "Finalized adaptor signature for config {} ({} bytes)",
                        config_id,
                        serialized.len()
                    );

                    pending_results.push((config_id, serialized, idx, nonce_bytes));
                }
            }
        }

        if pending_results.is_empty() {
            return Err(MusigError::SessionNotReady(
                "No adaptor signatures were finalized".to_string(),
            ));
        }

        // Second pass: store all results in session metadata
        let mut all_results: Vec<(uuid::Uuid, Vec<u8>)> = Vec::new();
        for (config_id, serialized, idx, nonce_bytes) in pending_results {
            let adaptor_config = &adaptor_configs[idx];
            self.store_adaptor_signature_result(
                config_id,
                serialized.clone(),
                adaptor_config,
                Some(nonce_bytes),
            )?;
            all_results.push((config_id, serialized));
        }

        info!("Finalized {} adaptor signatures", all_results.len());

        Ok(FinalizedData::AdaptorSignatures(all_results))
    }
}
