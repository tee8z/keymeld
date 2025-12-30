use musig2::{secp256k1::SecretKey, PartialSignature};
use std::collections::BTreeMap;
use tracing::{debug, error, info};

use crate::{
    identifiers::{SessionId, UserId},
    KeyMaterial,
};

use super::{
    error::MusigError,
    types::{SessionMetadata, SessionPhase},
    MusigProcessor,
};

/// Type alias for adaptor signature result: (uuid, signature_bytes, adaptor_bytes)
type AdaptorSignatureResult = Vec<(uuid::Uuid, Vec<u8>, Vec<u8>)>;

impl MusigProcessor {
    pub fn sign(
        &mut self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        self.sign_for_user(session_id, user_id, private_key)
    }

    pub fn sign_for_user(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.has_adaptor_configs() {
            let adaptor_results = self.sign_adaptor_for_user(session_id, user_id, private_key)?;
            adaptor_results
                .first()
                .map(|(_, sig, nonce)| (sig.clone(), nonce.clone()))
                .ok_or(MusigError::InvalidAdaptorConfig(
                    "No adaptor results generated".to_string(),
                ))
        } else {
            self.sign_regular_for_user(session_id, user_id, private_key)
        }
    }

    fn sign_regular_for_user(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        let session_users = self
            .user_sessions
            .get(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        let mut user_session = session_users
            .get_mut(user_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        if session_meta.phase == SessionPhase::Signing {
            if let Some(ref second_round) = user_session.second_round {
                let partial_signature: PartialSignature = second_round.our_signature();
                let signature_bytes = partial_signature.serialize().to_vec();
                let nonce_bytes = session_meta
                    .nonces
                    .get(user_id)
                    .map(|n: &musig2::PubNonce| n.serialize().to_vec())
                    .unwrap_or_else(Vec::new);
                return Ok((signature_bytes, nonce_bytes));
            }
        }

        if session_meta.phase != SessionPhase::NonceAggregation {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceAggregation,
                actual: session_meta.phase.clone(),
            });
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        if let Some(first_round_ref) = &user_session.first_round {
            if !first_round_ref.is_complete() {
                return Err(MusigError::NotReady("Not all nonces received".to_string()));
            }
        }

        let first_round = user_session.first_round.take().ok_or(MusigError::NotReady(
            "No first round found - signature may have already been generated".to_string(),
        ))?;

        info!(
            "🔍 Finalizing first_round for user {} (signer_index={}) in session {}",
            user_id, user_session.signer_index, session_id
        );

        let second_round = first_round
            .finalize(secret_key, session_meta.message.clone())
            .map_err(|e| {
                error!(
                    "Failed to finalize first_round for user {} (signer_index={}): {}",
                    user_id, user_session.signer_index, e
                );
                MusigError::Musig2Error(e.into())
            })?;

        let partial_signature: PartialSignature = second_round.our_signature();

        info!(
            "🔍 Generated partial signature for user {} (signer_index={}): {}",
            user_id,
            user_session.signer_index,
            hex::encode(partial_signature.serialize())
        );

        user_session.second_round = Some(second_round);

        self.update_session_phase(session_id, SessionPhase::Signing)?;

        let signature_bytes = partial_signature.serialize().to_vec();
        let nonce_bytes = session_meta
            .nonces
            .get(user_id)
            .map(|n: &musig2::PubNonce| n.serialize().to_vec())
            .unwrap_or_else(Vec::new);

        debug!(
            "Generated regular partial signature for user {} in session {}",
            user_id, session_id
        );

        Ok((signature_bytes, nonce_bytes))
    }

    pub fn add_partial_signature(
        &self,
        session_id: &SessionId,
        signer_index: usize,
        partial_signature: PartialSignature,
    ) -> Result<(), MusigError> {
        debug!(
            "Adding partial signature for session {} signer_index {}",
            session_id, signer_index
        );

        let mut all_complete = false;

        if let Some(session_users) = self.user_sessions.get(session_id) {
            for mut user_session in session_users.iter_mut() {
                if let Some(ref mut second_round) = user_session.second_round {
                    second_round
                        .receive_signature(signer_index, partial_signature)
                        .map_err(|e| MusigError::Musig2Error(e.into()))?;

                    // Check if all signatures received
                    if second_round.holdouts().is_empty() {
                        all_complete = true;
                    }
                }
            }
        }

        if all_complete {
            self.update_session_phase(session_id, SessionPhase::Aggregation)?;
        }

        Ok(())
    }

    pub fn add_adaptor_partial_signatures(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        adaptor_signatures: Vec<(uuid::Uuid, PartialSignature)>,
    ) -> Result<(), MusigError> {
        debug!(
            "Adding {} adaptor partial signatures for user {} in session {}",
            adaptor_signatures.len(),
            user_id,
            session_id
        );

        // Store adaptor signatures in session metadata
        if let Some(mut session_meta_ref) = self.session_metadata.get_mut(session_id) {
            for (config_id, partial_signature) in adaptor_signatures {
                let partial_sig_map = session_meta_ref
                    .adaptor_partial_signatures
                    .entry(config_id)
                    .or_insert_with(std::collections::BTreeMap::new);

                partial_sig_map.insert(user_id.to_owned(), partial_signature);
            }
        } else {
            return Err(MusigError::SessionNotFound(session_id.clone()));
        }

        Ok(())
    }

    pub fn finalize(&self, session_id: &SessionId) -> Result<Vec<u8>, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.phase != SessionPhase::Aggregation {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::Aggregation,
                actual: session_meta.phase.clone(),
            });
        }

        if let Some(first_user_id) = session_meta.expected_participants.first() {
            let session_users = self
                .user_sessions
                .get(session_id)
                .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

            let mut user_session = session_users
                .get_mut(first_user_id)
                .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

            if let Some(second_round_ref) = &user_session.second_round {
                if !second_round_ref.is_complete() {
                    return Err(MusigError::NotReady(
                        "Expected second round to be complete".to_string(),
                    ));
                }
            }

            let second_round = user_session
                .second_round
                .take()
                .ok_or(MusigError::NotReady(
                    "Expected second round to exist".to_string(),
                ))?;

            let final_signature: [u8; 64] = second_round
                .finalize()
                .map_err(|e| MusigError::Musig2Error(e.into()))?;

            self.update_session_phase(session_id, SessionPhase::Complete)?;

            info!(
                "Successfully finalized MuSig2 signature for session {}",
                session_id
            );

            return Ok(final_signature.to_vec());
        }

        Err(MusigError::SessionNotFound(session_id.clone()))
    }

    pub fn can_aggregate_signatures(
        &self,
        session_id: &SessionId,
        coordinator_user_id: &UserId,
    ) -> Result<bool, MusigError> {
        // Check if this session uses adaptor signatures
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.has_adaptor_configs() {
            // For adaptor signatures, check if all participants have completed all adaptor signatures
            Ok(self.has_all_adaptor_signatures(session_id))
        } else {
            // For regular signatures, use the existing logic
            if let Some(session_users) = self.user_sessions.get(session_id) {
                if let Some(user_session) = session_users.get(coordinator_user_id) {
                    if let Some(ref second_round) = user_session.second_round {
                        return Ok(second_round.holdouts().is_empty());
                    }
                }
            }
            Ok(false)
        }
    }

    pub fn aggregate_signatures(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<Vec<u8>, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.has_adaptor_configs() {
            self.aggregate_adaptor_signatures(session_id, user_id)
        } else {
            self.aggregate_regular_signatures(session_id, user_id)
        }
    }

    fn aggregate_regular_signatures(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<Vec<u8>, MusigError> {
        let session_users = self
            .user_sessions
            .get(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        let mut user_session = session_users
            .get_mut(user_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        if let Some(second_round_ref) = &user_session.second_round {
            if !second_round_ref.is_complete() {
                let session_meta = self.get_session_metadata(session_id)?;
                let expected = session_meta
                    .expected_participant_count
                    .unwrap_or(session_meta.expected_participants.len());
                let actual = expected - second_round_ref.holdouts().len();
                return Err(MusigError::InsufficientParticipants { expected, actual });
            }
        }

        let second_round = user_session
            .second_round
            .take()
            .ok_or(MusigError::NotReady("Second round missing".to_string()))?;

        let final_signature: [u8; 64] = second_round
            .finalize()
            .map_err(|e| MusigError::Musig2Error(e.into()))?;

        self.update_session_phase(session_id, SessionPhase::Complete)?;

        info!(
            "Successfully aggregated regular signatures for session {}",
            session_id
        );

        Ok(final_signature.to_vec())
    }

    pub fn get_partial_signature_count(&self, session_id: &SessionId) -> usize {
        if let Some(session_meta) = self.session_metadata.get(session_id) {
            // Check if this is an adaptor signatures session
            if !session_meta.adaptor_configs.is_empty() {
                return self.get_adaptor_signature_completion_count(session_id);
            }

            // Regular signature counting logic
            if let Some(session_users) = self.user_sessions.get(session_id) {
                if let Some(first_user) = session_users.iter().next() {
                    let user_session = first_user.value();
                    if let Some(ref second_round) = user_session.second_round {
                        let expected_count = session_meta
                            .expected_participant_count
                            .unwrap_or(session_meta.expected_participants.len());
                        let holdouts_count = second_round.holdouts().len();
                        return expected_count - holdouts_count;
                    }
                }
            }
        }
        0
    }

    /// For adaptor signatures, check how many users have completed ALL their adaptor signatures
    pub fn get_adaptor_signature_completion_count(&self, session_id: &SessionId) -> usize {
        if let Some(session_meta) = self.session_metadata.get(session_id) {
            if session_meta.adaptor_configs.is_empty() {
                return 0;
            }

            let expected_participants = &session_meta.expected_participants;
            let adaptor_config_count = session_meta.adaptor_configs.len();

            info!(
                "Computing adaptor signature completion for session {}: {} configs, {} participants",
                session_id, adaptor_config_count, expected_participants.len()
            );

            let mut completed_users = 0;

            for user_id in expected_participants {
                let mut user_config_count = 0;

                // Count how many adaptor configs this user has signed
                for (config_id, partial_sigs) in &session_meta.adaptor_partial_signatures {
                    if partial_sigs.contains_key(user_id) {
                        user_config_count += 1;
                        info!("  User {} has signature for config {}", user_id, config_id);
                    }
                }

                info!(
                    "  User {}: {}/{} configs signed",
                    user_id, user_config_count, adaptor_config_count
                );

                // User is complete if they've signed for all adaptor configs
                if user_config_count >= adaptor_config_count {
                    completed_users += 1;
                    info!("  User {} is COMPLETE", user_id);
                } else {
                    info!("  User {} is INCOMPLETE", user_id);
                }
            }

            info!(
                "Total completion count for session {}: {}/{}",
                session_id,
                completed_users,
                expected_participants.len()
            );

            completed_users
        } else {
            0
        }
    }

    /// Check if all users have completed all adaptor signatures
    pub fn has_all_adaptor_signatures(&self, session_id: &SessionId) -> bool {
        if let Some(session_meta) = self.session_metadata.get(session_id) {
            let expected_count = session_meta
                .expected_participant_count
                .unwrap_or(session_meta.expected_participants.len());
            let completed_count = self.get_adaptor_signature_completion_count(session_id);

            info!(
                "Checking adaptor signature completion for session {}: {}/{} completed",
                session_id, completed_count, expected_count
            );

            // Debug: check each user individually
            for user_id in &session_meta.expected_participants {
                let user_completed = self.user_has_all_adaptor_signatures(session_id, user_id);
                let user_sig_count = self.get_user_adaptor_signatures(session_id, user_id).len();
                let config_count = session_meta.adaptor_configs.len();
                info!(
                    "  User {}: {} signatures/{} configs = completed: {}",
                    user_id, user_sig_count, config_count, user_completed
                );
            }

            completed_count >= expected_count
        } else {
            false
        }
    }

    pub fn get_user_partial_signature(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Option<PartialSignature> {
        if let Some(session_meta) = self.session_metadata.get(session_id) {
            // Check if this is an adaptor signatures session
            if !session_meta.adaptor_configs.is_empty() {
                // For adaptor signatures, this method doesn't make sense since there are multiple signatures per user
                // Return the first one found just for compatibility, but use get_user_adaptor_signatures for real work
                for partial_sigs in session_meta.adaptor_partial_signatures.values() {
                    if let Some(partial_sig) = partial_sigs.get(&user_id.to_owned()) {
                        return Some(*partial_sig);
                    }
                }
                return None;
            }
        }

        // Regular signature lookup
        self.user_sessions
            .get(session_id)
            .and_then(|session_users| {
                session_users.get(user_id).and_then(|user_session| {
                    user_session
                        .second_round
                        .as_ref()
                        .map(|second_round| second_round.our_signature())
                })
            })
    }

    /// Get all adaptor signatures for a specific user
    pub fn get_user_adaptor_signatures(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Vec<(uuid::Uuid, PartialSignature)> {
        if let Some(session_meta) = self.session_metadata.get(session_id) {
            let mut signatures = Vec::new();
            for (config_id, partial_sigs) in &session_meta.adaptor_partial_signatures {
                if let Some(partial_sig) = partial_sigs.get(&user_id.to_owned()) {
                    signatures.push((*config_id, *partial_sig));
                }
            }
            signatures
        } else {
            Vec::new()
        }
    }

    /// Check if a specific user has completed all their adaptor signatures
    pub fn user_has_all_adaptor_signatures(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> bool {
        if let Some(session_meta) = self.session_metadata.get(session_id) {
            let adaptor_config_count = session_meta.adaptor_configs.len();
            let user_signature_count = self.get_user_adaptor_signatures(session_id, user_id).len();
            user_signature_count >= adaptor_config_count
        } else {
            false
        }
    }

    pub fn get_session_partial_signatures(
        &self,
        session_id: &SessionId,
    ) -> BTreeMap<UserId, PartialSignature> {
        let mut signatures = BTreeMap::new();

        if let Some(session_users) = self.user_sessions.get(session_id) {
            for entry in session_users.iter() {
                let user_id = entry.key();
                let user_session = entry.value();
                if let Some(ref second_round) = user_session.second_round {
                    signatures.insert(user_id.clone(), second_round.our_signature());
                }
            }
        }

        signatures
    }

    fn sign_adaptor_for_user(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<AdaptorSignatureResult, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        debug!(
            "sign_adaptor_for_user - user {} in session {} with {} adaptor configs (expected_participants: {:?})",
            user_id, session_id, session_meta.adaptor_configs.len(), session_meta.expected_participants
        );

        if !session_meta.has_adaptor_configs() {
            return Err(MusigError::InvalidAdaptorConfig(
                "No adaptor configs found".to_string(),
            ));
        }

        if session_meta.phase == SessionPhase::Signing {
            return self.get_existing_adaptor_signatures(user_id, &session_meta);
        }

        if session_meta.phase != SessionPhase::NonceAggregation {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceAggregation,
                actual: session_meta.phase.clone(),
            });
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let adaptor_signature_results = self.generate_adaptor_signatures_for_configs(
            session_id,
            user_id,
            &session_meta,
            secret_key,
        )?;

        self.update_session_phase(session_id, SessionPhase::Signing)?;

        self.store_adaptor_signature_results(session_id, user_id, &adaptor_signature_results)?;

        debug!(
            "Generated {} adaptor partial signatures for user {} in session {}",
            adaptor_signature_results.len(),
            user_id,
            session_id
        );

        Ok(adaptor_signature_results)
    }

    fn get_existing_adaptor_signatures(
        &self,
        user_id: &UserId,
        session_meta: &SessionMetadata,
    ) -> Result<AdaptorSignatureResult, MusigError> {
        let mut results = Vec::new();
        let user_nonce = session_meta
            .nonces
            .get(user_id)
            .map(|n: &musig2::PubNonce| n.serialize().to_vec())
            .unwrap_or_default();

        for (config_id, partial_sigs) in &session_meta.adaptor_partial_signatures {
            if let Some(partial_sig) = partial_sigs.get(&user_id.to_owned()) {
                results.push((
                    *config_id,
                    partial_sig.serialize().to_vec(),
                    user_nonce.clone(),
                ));
            }
        }

        if results.is_empty() {
            return Err(MusigError::NotReady(
                "No existing adaptor signatures found".to_string(),
            ));
        }

        Ok(results)
    }

    fn generate_adaptor_signatures_for_configs(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        session_meta: &SessionMetadata,
        secret_key: SecretKey,
    ) -> Result<AdaptorSignatureResult, MusigError> {
        let session_users = self
            .user_sessions
            .get(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        let mut user_session = session_users
            .get_mut(user_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        let mut adaptor_signature_results = Vec::new();

        debug!(
            "User {} has signer_index {} in user session",
            user_id, user_session.signer_index
        );

        for config in &session_meta.adaptor_configs {
            debug!(
                "Processing adaptor config {} for user {}",
                config.adaptor_id, user_id
            );

            if let Some(second_round) = user_session.adaptor_second_rounds.get(&config.adaptor_id) {
                let partial_sig: PartialSignature = second_round.our_signature();
                let adaptor_first_round = user_session
                    .adaptor_first_rounds
                    .get(&config.adaptor_id)
                    .ok_or(MusigError::NotReady(format!(
                        "No adaptor first round found for config {}",
                        config.adaptor_id
                    )))?;
                let user_nonce = adaptor_first_round.our_public_nonce();
                adaptor_signature_results.push((
                    config.adaptor_id,
                    partial_sig.serialize().to_vec(),
                    user_nonce.serialize().to_vec(),
                ));
                continue;
            }

            let adaptor_first_round = user_session
                .adaptor_first_rounds
                .remove(&config.adaptor_id)
                .ok_or(MusigError::NotReady(format!(
                    "No adaptor first round found for config {}",
                    config.adaptor_id
                )))?;

            if !adaptor_first_round.is_complete() {
                return Err(MusigError::NotReady(format!(
                    "Not all nonces received for adaptor config {}",
                    config.adaptor_id
                )));
            }

            let user_nonce = adaptor_first_round.our_public_nonce();

            let adaptor_point = match config.adaptor_type {
                super::types::AdaptorType::Single => config
                    .adaptor_points
                    .first()
                    .ok_or(MusigError::InvalidAdaptorConfig(
                        "No adaptor point for Single type".to_string(),
                    ))?
                    .clone(),
                super::types::AdaptorType::And => {
                    if config.adaptor_points.is_empty() {
                        return Err(MusigError::InvalidAdaptorConfig(
                            "AND adaptor requires at least one point".to_string(),
                        ));
                    }
                    let combined = Self::combine_adaptor_points_and(&config.adaptor_points)?;
                    hex::encode(combined.serialize())
                }
                super::types::AdaptorType::Or => config
                    .adaptor_points
                    .first()
                    .ok_or(MusigError::InvalidAdaptorConfig(
                        "No adaptor point for Or type".to_string(),
                    ))?
                    .clone(),
            };

            let adaptor_point_parsed = Self::parse_adaptor_point(&adaptor_point)?;

            let second_round = adaptor_first_round
                .finalize_adaptor(
                    secret_key,
                    adaptor_point_parsed,
                    session_meta.message.clone(),
                )
                .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;

            let partial_sig: PartialSignature = second_round.our_signature();

            adaptor_signature_results.push((
                config.adaptor_id,
                partial_sig.serialize().to_vec(),
                user_nonce.serialize().to_vec(),
            ));

            user_session
                .adaptor_second_rounds
                .insert(config.adaptor_id, second_round);
        }

        Ok(adaptor_signature_results)
    }

    fn store_adaptor_signature_results(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        adaptor_signature_results: &AdaptorSignatureResult,
    ) -> Result<(), MusigError> {
        if let Some(mut session_meta_ref) = self.session_metadata.get_mut(session_id) {
            for (config_id, signature_bytes, _) in adaptor_signature_results {
                let partial_sig_map = session_meta_ref
                    .adaptor_partial_signatures
                    .entry(*config_id)
                    .or_insert_with(BTreeMap::new);

                partial_sig_map.insert(
                    user_id.to_owned(),
                    PartialSignature::from_slice(signature_bytes)
                        .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?,
                );

                debug!(
                    "Stored partial signature for user {} in config {} (total signatures for this config: {})",
                    user_id, config_id, partial_sig_map.len()
                );
            }
        }
        Ok(())
    }

    /// Parse a hex-encoded adaptor point into a secp256k1 PublicKey
    fn parse_adaptor_point(
        adaptor_point_hex: &str,
    ) -> Result<musig2::secp256k1::PublicKey, MusigError> {
        let adaptor_point_bytes = hex::decode(adaptor_point_hex).map_err(|_| {
            MusigError::InvalidAdaptorConfig("Invalid hex in adaptor point".to_string())
        })?;
        musig2::secp256k1::PublicKey::from_slice(&adaptor_point_bytes)
            .map_err(|_| MusigError::InvalidAdaptorConfig("Invalid adaptor point".to_string()))
    }

    /// Combine multiple adaptor points using elliptic curve point addition (AND logic)
    fn combine_adaptor_points_and(
        adaptor_points: &[String],
    ) -> Result<musig2::secp256k1::PublicKey, MusigError> {
        if adaptor_points.is_empty() {
            return Err(MusigError::InvalidAdaptorConfig(
                "Cannot combine empty adaptor points".to_string(),
            ));
        }

        let mut combined_point = Self::parse_adaptor_point(&adaptor_points[0])?;

        for adaptor_point_hex in adaptor_points.iter().skip(1) {
            let point = Self::parse_adaptor_point(adaptor_point_hex)?;
            combined_point = combined_point.combine(&point).map_err(|_| {
                MusigError::InvalidAdaptorConfig("Failed to combine adaptor points".to_string())
            })?;
        }

        Ok(combined_point)
    }

    fn aggregate_adaptor_signatures(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<Vec<u8>, MusigError> {
        info!(
            "Starting adaptor signature aggregation for session {}",
            session_id
        );

        if !self.can_aggregate_signatures(session_id, user_id)? {
            let session_meta = self.get_session_metadata(session_id)?;
            let expected = session_meta
                .expected_participant_count
                .unwrap_or(session_meta.expected_participants.len());
            let completed = self.get_adaptor_signature_completion_count(session_id);
            info!(
                "Cannot aggregate - insufficient participants: {}/{} completed",
                completed, expected
            );
            return Err(MusigError::InsufficientParticipants {
                expected,
                actual: completed,
            });
        }

        let session_meta = self.get_session_metadata(session_id)?;
        info!(
            "Session has {} adaptor configs to aggregate",
            session_meta.adaptor_configs.len()
        );

        let mut final_adaptor_results = std::collections::BTreeMap::new();
        let mut first_signature = None;

        // First collect all needed data to avoid holding locks too long
        let session_meta = self.get_session_metadata(session_id)?;

        // Process each adaptor config
        for config in &session_meta.adaptor_configs {
            let config_id = config.adaptor_id;
            info!("Processing adaptor config {}", config_id);

            if let Some(partial_sigs_map) = session_meta.adaptor_partial_signatures.get(&config_id)
            {
                info!(
                    "Found {} partial signatures for config {}",
                    partial_sigs_map.len(),
                    config_id
                );

                if partial_sigs_map.is_empty() {
                    info!("No partial signatures found for config {}", config_id);
                    continue;
                }

                // Get the adaptor point for this config
                let adaptor_point = if let Some(adaptor_point_hex) = config.adaptor_points.first() {
                    Self::parse_adaptor_point(adaptor_point_hex)?
                } else {
                    info!("No adaptor points for config {}, skipping", config_id);
                    continue;
                };

                // Find any user that has a SecondRound for this config to use for aggregation
                let mut aggregation_result = None;

                // Get session users with a scoped lock to avoid deadlocks
                {
                    let session_users = self
                        .user_sessions
                        .get(session_id)
                        .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

                    for mut user_session_ref in session_users.iter_mut() {
                        let user_session = user_session_ref.value_mut();

                        if let Some(mut second_round) =
                            user_session.adaptor_second_rounds.remove(&config_id)
                        {
                            info!(
                                "Using SecondRound from user {} for config {} aggregation",
                                user_session.user_id, config_id
                            );

                            // Get the aggregated nonce before we start modifying the round
                            let aggregated_nonce =
                                second_round.aggregated_nonce().serialize().to_vec();

                            // Feed all partial signatures to this SecondRound using state machine API
                            // Sort partial signatures by user_id to ensure consistent ordering
                            let mut sorted_partial_sigs: Vec<(UserId, musig2::PartialSignature)> =
                                partial_sigs_map
                                    .iter()
                                    .map(|(k, v)| (k.clone(), *v))
                                    .collect();
                            sorted_partial_sigs.sort_by(|a, b| a.0.cmp(&b.0));

                            info!(
                                "Feeding {} partial signatures to SecondRound for config {}",
                                sorted_partial_sigs.len(),
                                config_id
                            );

                            // Map user_id strings to signer indices using expected_participants order
                            for (user_id, partial_sig) in sorted_partial_sigs {
                                // Find the signer index for this user_id
                                if let Some(signer_index) = session_meta
                                    .expected_participants
                                    .iter()
                                    .position(|expected_user| *expected_user == user_id)
                                {
                                    debug!(
                                        "Receiving signature from signer {} (user {}) for config {}",
                                        signer_index, user_id, config_id
                                    );

                                    second_round
                                        .receive_signature(signer_index, partial_sig)
                                        .map_err(|e| {
                                            MusigError::Musig2Error(
                                                format!(
                                                    "Failed to receive signature from signer {signer_index} (user {user_id}): {e}"
                                                )
                                                .into(),
                                            )
                                        })?;
                                } else {
                                    debug!(
                                        "Could not find signer index for user {} in expected_participants: {:?}",
                                        user_id, session_meta.expected_participants
                                    );
                                    return Err(MusigError::InvalidParticipant(user_id));
                                }
                            }

                            // Now finalize the adaptor signature using state machine API
                            debug!(
                                "Finalizing adaptor signature for config {} using state machine API",
                                config_id
                            );

                            let adaptor_signature: musig2::AdaptorSignature =
                                second_round.finalize_adaptor::<&[u8]>().map_err(|e| {
                                    MusigError::Musig2Error(
                                        format!(
                                            "Failed to finalize adaptor signature for config {config_id}: {e}"
                                        )
                                        .into(),
                                    )
                                })?;

                            debug!(
                                "Successfully finalized adaptor signature for config {}",
                                config_id
                            );

                            aggregation_result = Some((adaptor_signature, aggregated_nonce));
                            break; // Found a working round, no need to check others
                        }
                    }
                } // session_users lock released here

                // Store the result if we successfully aggregated
                if let Some((adaptor_signature, agg_nonce_bytes)) = aggregation_result {
                    let adaptor_result = super::types::AdaptorSignatureResult {
                        adaptor_id: config_id,
                        adaptor_type: config.adaptor_type.clone(),
                        signature_scalar: adaptor_signature.serialize().to_vec(),
                        nonce_point: agg_nonce_bytes,
                        adaptor_points: config
                            .adaptor_points
                            .iter()
                            .map(|s| hex::decode(s).unwrap_or_default())
                            .collect(),
                        hints: config.hints.clone(),
                        aggregate_adaptor_point: adaptor_point.serialize().to_vec(),
                    };

                    final_adaptor_results.insert(config_id, adaptor_result);

                    // Note: This is NOT a valid Bitcoin signature until adapted with the secret
                    if first_signature.is_none() {
                        first_signature = Some(adaptor_signature.serialize().to_vec());
                    }
                } else {
                    return Err(MusigError::NotReady(format!(
                        "No SecondRound available for config {config_id} aggregation"
                    )));
                }
            } else {
                info!("Config {} not found in partial signatures map", config_id);
            }
        }

        // Store final results in session metadata
        if let Some(mut session_metadata) = self.session_metadata.get_mut(session_id) {
            for (config_id, result) in &final_adaptor_results {
                session_metadata
                    .adaptor_final_signatures
                    .insert(*config_id, result.clone());
            }
        }

        self.update_session_phase(session_id, SessionPhase::Complete)?;

        let signature_count = final_adaptor_results.len();
        info!(
            "Successfully aggregated {} adaptor signatures for session {} using state machine API",
            signature_count, session_id
        );

        first_signature.ok_or(MusigError::InvalidAdaptorConfig(
            "No adaptor signatures were aggregated".to_string(),
        ))
    }
}
