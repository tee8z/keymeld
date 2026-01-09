use musig2::{secp256k1::SecretKey, FirstRound, PubNonce, SecNonceSpices};
use std::collections::BTreeMap;
use tracing::{debug, info};
use uuid::Uuid;

use keymeld_core::{crypto::SecureCrypto, identifiers::UserId, protocol::NonceData, KeyMaterial};

use super::{
    error::MusigError,
    types::{SessionPhase, UserMusigSession},
    MusigProcessor,
};

impl MusigProcessor {
    pub fn generate_nonce(
        &mut self,
        user_id: &UserId,
        signer_index: usize,
        private_key: &KeyMaterial,
    ) -> Result<NonceData, MusigError> {
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

        if session_metadata.has_adaptor_configs() {
            let adaptor_nonces =
                self.generate_adaptor_nonces(user_id, signer_index, private_key)?;
            return Ok(NonceData::Adaptor(adaptor_nonces));
        }

        // Check if user session already exists and has a nonce
        if let Some(user_session) = self.user_sessions.get(user_id) {
            if let Some(ref first_round) = user_session.first_round {
                let existing_nonce = first_round.our_public_nonce();
                return Ok(NonceData::Regular(existing_nonce));
            }
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let key_agg_ctx = session_metadata
            .key_agg_ctx
            .as_ref()
            .ok_or(MusigError::NotReady(
                "Session not ready for nonce generation".to_string(),
            ))?;

        let nonce_seed =
            SecureCrypto::generate_secure_nonce(&session_id.to_string(), &user_id.to_string())
                .map_err(|e| {
                    MusigError::Musig2Error(format!("Secure nonce generation failed: {e}").into())
                })?;

        let first_round = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            signer_index,
            SecNonceSpices::new()
                .with_seckey(secret_key)
                .with_message(&session_metadata.message),
        )
        .map_err(|e| MusigError::Musig2Error(e.into()))?;

        let pub_nonce = first_round.our_public_nonce();

        info!(
            "generate_nonce: Storing nonce for user {} in session {}",
            user_id, session_id
        );

        // Store nonce only in user_sessions to eliminate race condition
        if let Some(existing_session) = self.user_sessions.get_mut(user_id) {
            info!(
                "generate_nonce: Found existing session for user {} - updating with first_round (existing: first_round={}, second_round={})",
                user_id, existing_session.first_round.is_some(), existing_session.second_round.is_some()
            );
            // Update existing session with first_round data
            existing_session.first_round = Some(first_round);
            // Ensure private key and signer_index are set correctly
            existing_session.private_key = Some(private_key.clone());
            existing_session.signer_index = signer_index;
            info!(
                "generate_nonce: Updated existing session for user {} (now: first_round={}, second_round={})",
                user_id, existing_session.first_round.is_some(), existing_session.second_round.is_some()
            );
        } else {
            info!(
                "generate_nonce: No existing session for user {} - creating new one",
                user_id
            );
            // Create new session if none exists
            let user_session = UserMusigSession {
                user_id: user_id.clone(),
                coordinator: false, // Default to false for nonce generation
                signer_index,
                private_key: Some(private_key.clone()),
                auth_pubkey: None,
                require_signing_approval: false,
                first_round: Some(first_round),
                second_round: None,
                adaptor_first_rounds: BTreeMap::new(),
                adaptor_second_rounds: BTreeMap::new(),
            };

            self.user_sessions.insert(user_id.clone(), user_session);
            info!("generate_nonce: Created new session for user {}", user_id);
        }

        // Final verification - both storage locations should be consistent now
        if let Some(verification_session) = self.user_sessions.get(user_id) {
            info!(
                "generate_nonce: Final verification - user {} has first_round={}, second_round={}",
                user_id,
                verification_session.first_round.is_some(),
                verification_session.second_round.is_some()
            );
        } else {
            // This should never happen after our atomic update above
            return Err(MusigError::FailedLock(format!(
                "Nonce generation inconsistency: user session not found for user {} after creation",
                user_id
            )));
        }

        Ok(NonceData::Regular(pub_nonce))
    }

    pub fn add_nonce(&mut self, signer_index: usize, nonce: PubNonce) -> Result<(), MusigError> {
        let session_metadata = &self.session_metadata;

        if session_metadata.phase != SessionPhase::NonceGeneration
            && session_metadata.phase != SessionPhase::NonceAggregation
        {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceGeneration,
                actual: session_metadata.phase.clone(),
            });
        }

        let current_phase = session_metadata.phase.clone();

        // Update first round for all user sessions if in nonce generation or aggregation phase
        // We need to allow nonce addition during aggregation phase because the phase can transition
        // during this same add_nonce call when the last nonce is added
        if current_phase == SessionPhase::NonceGeneration
            || current_phase == SessionPhase::NonceAggregation
        {
            // Get all user IDs that need updating to avoid concurrent iteration issues
            let user_ids: Vec<UserId> = self.user_sessions.keys().cloned().collect();

            // Update each user session
            for session_user_id in user_ids {
                if let Some(user_session) = self.user_sessions.get_mut(&session_user_id) {
                    if let Some(ref mut first_round) = user_session.first_round {
                        if let Err(e) = first_round.receive_nonce(signer_index, nonce.clone()) {
                            debug!("Failed to add nonce for user {}: {}", session_user_id, e);
                        }
                    }
                }
            }
        }

        self.check_nonce_completion()?;

        Ok(())
    }

    pub fn get_nonce_count(&self) -> usize {
        let session_meta = &self.session_metadata;
        let expected_count = session_meta
            .expected_participant_count
            .unwrap_or(session_meta.expected_participants.len());

        // Check if this is an adaptor signature session
        if !session_meta.adaptor_configs.is_empty() {
            // For adaptor sessions, check all user sessions and return the maximum nonce count
            let mut max_total_nonces = 0;

            for user_session in self.user_sessions.values() {
                let mut session_nonces = 0;

                // Count nonces across all adaptor configs for this user session
                for config in &session_meta.adaptor_configs {
                    if let Some(first_round) =
                        user_session.adaptor_first_rounds.get(&config.adaptor_id)
                    {
                        let holdouts_count = first_round.holdouts().len();
                        session_nonces += expected_count - holdouts_count;
                    }
                }

                max_total_nonces = max_total_nonces.max(session_nonces);
            }
            max_total_nonces
        } else {
            // Regular session logic - check all user sessions and return the maximum nonce count
            let mut max_nonce_count = 0;

            for user_session in self.user_sessions.values() {
                // If we have a first_round, use holdouts to determine total nonces received
                if let Some(ref first_round) = user_session.first_round {
                    let holdouts_count = first_round.holdouts().len();
                    let nonce_count = expected_count - holdouts_count;
                    max_nonce_count = max_nonce_count.max(nonce_count);
                }

                // If first_round is consumed (finalized), but we have second_round,
                // it means all nonces were collected
                if user_session.second_round.is_some() {
                    max_nonce_count = max_nonce_count.max(expected_count);
                }
            }

            max_nonce_count
        }
    }

    pub fn get_user_nonce(&self, user_id: &UserId) -> Option<PubNonce> {
        // Get nonce from user session first_round instead of session metadata
        self.user_sessions.get(user_id).and_then(|user_session| {
            user_session
                .first_round
                .as_ref()
                .map(|first_round| first_round.our_public_nonce())
        })
    }

    pub fn get_user_nonce_data(&self, user_id: &UserId) -> Option<NonceData> {
        if self.session_metadata.has_adaptor_configs() {
            // For adaptor sessions, collect adaptor nonces from user session
            let user_session = self.user_sessions.get(user_id)?;

            let mut adaptor_nonces = Vec::new();
            for (config_id, first_round) in &user_session.adaptor_first_rounds {
                let pub_nonce = first_round.our_public_nonce();
                adaptor_nonces.push((*config_id, pub_nonce));
            }

            if !adaptor_nonces.is_empty() {
                Some(NonceData::Adaptor(adaptor_nonces))
            } else {
                None
            }
        } else {
            // For regular sessions, get nonce from user session first_round
            let user_session = self.user_sessions.get(user_id)?;
            let first_round = user_session.first_round.as_ref()?;
            let pub_nonce = first_round.our_public_nonce();
            Some(NonceData::Regular(pub_nonce))
        }
    }

    pub fn get_session_nonces(&self) -> BTreeMap<UserId, PubNonce> {
        // Collect nonces from user_sessions where first_round is present
        let mut nonces = BTreeMap::new();
        for (user_id, user_session) in &self.user_sessions {
            if let Some(ref first_round) = user_session.first_round {
                nonces.insert(user_id.clone(), first_round.our_public_nonce());
            }
        }
        nonces
    }

    pub fn check_nonce_completion(&mut self) -> Result<(), MusigError> {
        let expected_count = self
            .session_metadata
            .expected_participant_count
            .unwrap_or(self.session_metadata.expected_participants.len());

        let current_nonce_count = self.get_nonce_count();
        let session_id = self.session_metadata.session_id.clone();

        // If all nonces are collected, transition to aggregation phase
        if current_nonce_count == expected_count {
            self.update_session_phase(SessionPhase::NonceAggregation)?;
            info!("Session {} advanced to NonceAggregation phase", session_id);
        }

        Ok(())
    }

    pub fn finalize_nonce_rounds(&mut self, user_id: &UserId) -> Result<(), MusigError> {
        let session_id = self.session_metadata.session_id.clone();
        let current_phase = self.session_metadata.phase.clone();
        let has_adaptor_configs = self.session_metadata.has_adaptor_configs();

        info!(
            "finalize_nonce_rounds called for user {} in session {} (phase: {:?}, adaptor: {})",
            user_id, session_id, current_phase, has_adaptor_configs
        );

        if current_phase != SessionPhase::NonceAggregation && current_phase != SessionPhase::Signing
        {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceAggregation,
                actual: current_phase,
            });
        }

        let user_session = self.user_sessions.get_mut(user_id).ok_or_else(|| {
            info!(
                "No user session found for user {} in session {}",
                user_id, session_id
            );
            MusigError::NotReady(format!("No user session found for user {user_id}"))
        })?;

        let private_key = user_session.private_key.clone().ok_or_else(|| {
            info!(
                "No private key found for user {} in session {}",
                user_id, session_id
            );
            MusigError::NotReady(format!("No private key found for user {user_id}"))
        })?;

        let secret_key = musig2::secp256k1::SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        if has_adaptor_configs {
            // Adaptor signing: finalize adaptor_first_rounds -> adaptor_second_rounds
            info!(
                "Finalizing {} adaptor first rounds for user {} in session {}",
                user_session.adaptor_first_rounds.len(),
                user_id,
                session_id
            );

            // Get adaptor configs to iterate over
            let adaptor_configs = self.session_metadata.adaptor_configs.clone();

            // Re-borrow user_session mutably after cloning configs
            let user_session = self.user_sessions.get_mut(user_id).unwrap();

            for config in &adaptor_configs {
                let config_id = config.adaptor_id;

                // Skip if already finalized
                if user_session.adaptor_second_rounds.contains_key(&config_id) {
                    info!(
                        "Adaptor second round already exists for config {} - skipping",
                        config_id
                    );
                    continue;
                }

                let first_round = match user_session.adaptor_first_rounds.remove(&config_id) {
                    Some(round) => round,
                    None => {
                        info!(
                            "No adaptor first round found for config {} - skipping",
                            config_id
                        );
                        continue;
                    }
                };

                if !first_round.is_complete() {
                    info!(
                        "Adaptor first round not complete for config {} - not all nonces received",
                        config_id
                    );
                    return Err(MusigError::NotReady(format!(
                        "Adaptor first round not complete for config {} - not all nonces received",
                        config_id
                    )));
                }

                // Parse adaptor point from config
                let adaptor_point_hex = config.adaptor_points.first().ok_or_else(|| {
                    MusigError::InvalidAdaptorConfig(format!(
                        "No adaptor points in config {}",
                        config_id
                    ))
                })?;

                let adaptor_point_bytes = hex::decode(adaptor_point_hex).map_err(|e| {
                    MusigError::InvalidAdaptorConfig(format!(
                        "Invalid adaptor point hex for config {}: {}",
                        config_id, e
                    ))
                })?;

                let adaptor_point = musig2::secp256k1::PublicKey::from_slice(&adaptor_point_bytes)
                    .map_err(|e| {
                        MusigError::InvalidAdaptorConfig(format!(
                            "Invalid adaptor point for config {}: {}",
                            config_id, e
                        ))
                    })?;

                // Finalize with adaptor point
                let second_round = first_round
                    .finalize_adaptor(
                        secret_key,
                        adaptor_point,
                        self.session_metadata.message.clone(),
                    )
                    .map_err(|e| MusigError::Musig2Error(e.into()))?;

                user_session
                    .adaptor_second_rounds
                    .insert(config_id, second_round);

                info!(
                    "Finalized adaptor round for config {} for user {} in session {}",
                    config_id, user_id, session_id
                );
            }

            info!(
                "Finalized {} adaptor second rounds for user {} in session {}",
                user_session.adaptor_second_rounds.len(),
                user_id,
                session_id
            );
        } else {
            // Regular signing: finalize first_round -> second_round
            info!(
                "User session found for {}: first_round={}, second_round={}, signer_index={}",
                user_id,
                user_session.first_round.is_some(),
                user_session.second_round.is_some(),
                user_session.signer_index
            );

            // Only finalize if we have a first_round and no second_round yet
            if user_session.first_round.is_some() && user_session.second_round.is_none() {
                // Check if first_round is complete before taking it
                if let Some(ref first_round) = user_session.first_round {
                    if !first_round.is_complete() {
                        info!(
                            "First round not complete for user {} - not all nonces received",
                            user_id
                        );
                        return Err(MusigError::NotReady(format!(
                            "First round not complete for user {} - not all nonces received",
                            user_id
                        )));
                    }
                }

                info!(
                    "About to take first_round and finalize for user {} in session {}",
                    user_id, session_id
                );

                // Only take first_round after validation
                let first_round = user_session.first_round.take().unwrap();

                // Finalize first round to get second round
                let second_round = first_round
                    .finalize(secret_key, self.session_metadata.message.clone())
                    .map_err(|e: musig2::errors::RoundFinalizeError| {
                        MusigError::Musig2Error(e.into())
                    })?;

                // Store the second round
                user_session.second_round = Some(second_round);

                info!(
                    "Finalized second_round for user {} in session {} (signer_index={})",
                    user_id, session_id, user_session.signer_index
                );
            } else if user_session.second_round.is_some() {
                info!(
                    "second_round already exists for user {} in session {} - skipping finalization",
                    user_id, session_id
                );
            } else {
                info!(
                    "No first_round found for user {} in session {} - cannot finalize",
                    user_id, session_id
                );
            }
        }

        // Update session phase to indicate we're ready for signature generation
        // Only update if we're not already in Signing phase
        if self.session_metadata.phase != SessionPhase::Signing {
            self.update_session_phase(SessionPhase::Signing)?;
            info!(
                "Session {} advanced to Signing phase for user {}",
                session_id, user_id
            );
        } else {
            info!(
                "Session {} already in Signing phase, finalized nonce round for user {}",
                session_id, user_id
            );
        }

        Ok(())
    }

    /// Generate adaptor nonces for a user (one per adaptor config)
    pub fn generate_adaptor_nonces(
        &mut self,
        user_id: &UserId,
        signer_index: usize,
        private_key: &KeyMaterial,
    ) -> Result<Vec<(Uuid, PubNonce)>, MusigError> {
        let session_metadata = &self.session_metadata;
        let session_id = &session_metadata.session_id;

        // Parse private key
        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let key_agg_ctx = session_metadata
            .key_agg_ctx
            .as_ref()
            .ok_or(MusigError::NotReady(
                "Session not ready for nonce generation".to_string(),
            ))?;

        // Generate base nonce seed
        let base_nonce_seed =
            SecureCrypto::generate_secure_nonce(&session_id.to_string(), &user_id.to_string())
                .map_err(|e| {
                    MusigError::Musig2Error(format!("Secure nonce generation failed: {e}").into())
                })?;

        let mut adaptor_first_rounds = BTreeMap::new();
        let mut adaptor_nonces = Vec::new();

        // Generate one FirstRound per adaptor config
        for (config_index, config) in session_metadata.adaptor_configs.iter().enumerate() {
            // Create deterministic but unique nonce seed for each config
            let mut adaptor_nonce_seed = base_nonce_seed;
            adaptor_nonce_seed[0] = adaptor_nonce_seed[0].wrapping_add(config_index as u8 + 1);

            let first_round = FirstRound::new(
                key_agg_ctx.clone(),
                adaptor_nonce_seed,
                signer_index,
                SecNonceSpices::new()
                    .with_seckey(secret_key)
                    .with_message(&session_metadata.message),
            )
            .map_err(|e| MusigError::Musig2Error(e.into()))?;

            let pub_nonce = first_round.our_public_nonce();
            adaptor_nonces.push((config.adaptor_id, pub_nonce));
            adaptor_first_rounds.insert(config.adaptor_id, first_round);
        }

        // Create user session with adaptor first rounds
        let user_session = UserMusigSession {
            user_id: user_id.clone(),
            coordinator: false, // Default to false for adaptor nonce generation
            signer_index,
            private_key: Some(private_key.clone()),
            auth_pubkey: None,
            require_signing_approval: false,
            first_round: None,
            second_round: None,
            adaptor_first_rounds,
            adaptor_second_rounds: BTreeMap::new(),
        };

        self.user_sessions.insert(user_id.clone(), user_session);

        Ok(adaptor_nonces)
    }

    /// Add adaptor nonces from a remote participant to local participants' FirstRounds
    pub fn store_adaptor_nonces(
        &mut self,
        user_id: &UserId,
        adaptor_nonces: Vec<(uuid::Uuid, PubNonce)>,
    ) -> Result<(), MusigError> {
        let session_metadata = &self.session_metadata;
        let session_id = &session_metadata.session_id;

        // Calculate the signer index for the user who sent these nonces
        let signer_index = session_metadata
            .expected_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or(MusigError::InvalidParticipant(user_id.clone()))?;

        debug!(
            "add_adaptor_nonces - user {} has signer_index {} in session {} (expected_participants: {:?})",
            user_id,
            signer_index,
            session_id,
            session_metadata.expected_participants
        );

        // Get all user IDs that need updating to avoid concurrent iteration issues
        let user_ids_with_private_keys: Vec<UserId> = self
            .user_sessions
            .iter()
            .filter_map(|(user_id, user_session)| {
                if user_session.private_key.is_some() {
                    Some(user_id.clone())
                } else {
                    None
                }
            })
            .collect();

        // Update each user session
        for session_user_id in user_ids_with_private_keys {
            if let Some(user_session) = self.user_sessions.get_mut(&session_user_id) {
                debug!(
                    "Distributing nonces to local participant {} (stored signer_index: {})",
                    user_session.user_id, user_session.signer_index
                );

                for (config_id, nonce) in &adaptor_nonces {
                    if let Some(first_round) = user_session.adaptor_first_rounds.get_mut(config_id)
                    {
                        debug!(
                            "Receiving nonce for config {} at signer_index {} into FirstRound of user {}",
                            config_id, signer_index, user_session.user_id
                        );

                        if let Err(e) = first_round.receive_nonce(signer_index, nonce.clone()) {
                            debug!(
                                "Failed to add adaptor nonce for user {} config {}: {}",
                                user_session.user_id, config_id, e
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if all local participants have received all adaptor nonces
    pub fn all_adaptor_first_rounds_complete(&self) -> Result<bool, MusigError> {
        if !self.session_metadata.has_adaptor_configs() {
            return Ok(false);
        }

        let expected_participant_count = self.session_metadata.expected_participants.len();
        let current_phase = self.session_metadata.phase.clone();
        let adaptor_config_count = self.session_metadata.adaptor_configs.len();

        // Check all user sessions
        for user_session in self.user_sessions.values() {
            if user_session.private_key.is_none() {
                continue;
            }

            let actual_rounds = user_session.adaptor_first_rounds.len();

            if actual_rounds < adaptor_config_count {
                debug!(
                    "User {} has {} adaptor rounds, expected {} (session has {} configs). Not complete.",
                    user_session.user_id, actual_rounds, adaptor_config_count, adaptor_config_count
                );
                return Ok(false);
            }

            for (config_id, first_round) in &user_session.adaptor_first_rounds {
                if !first_round.is_complete() {
                    debug!(
                        "User {} config {} adaptor round not complete (expected {} nonces)",
                        user_session.user_id, config_id, expected_participant_count
                    );
                    return Ok(false);
                }
            }
        }

        // Note: Session phase updates should be handled by callers, not by this read-only query method
        if current_phase == SessionPhase::NonceGeneration {
            tracing::info!("Session ready to advance to NonceAggregation phase (adaptor)");
        }

        Ok(true)
    }
}
