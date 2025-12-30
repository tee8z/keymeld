use musig2::{secp256k1::SecretKey, FirstRound, PubNonce, SecNonceSpices};
use std::collections::BTreeMap;
use tracing::{debug, info};

use crate::{
    crypto::SecureCrypto,
    enclave::protocol::NonceData,
    identifiers::{SessionId, UserId},
    KeyMaterial,
};

use super::{
    error::MusigError,
    types::{SessionPhase, UserMusigSession},
    MusigProcessor,
};

impl MusigProcessor {
    pub fn generate_nonce(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        signer_index: usize,
        private_key: &KeyMaterial,
    ) -> Result<NonceData, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.phase != SessionPhase::NonceGeneration
            && session_meta.phase != SessionPhase::NonceAggregation
        {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceGeneration,
                actual: session_meta.phase.clone(),
            });
        }

        if session_meta.has_adaptor_configs() {
            let adaptor_nonces =
                self.generate_adaptor_nonces(session_id, user_id, signer_index, private_key)?;
            return Ok(NonceData::Adaptor(adaptor_nonces));
        }

        if let Some(existing_nonce) = session_meta.nonces.get(user_id) {
            return Ok(NonceData::Regular(existing_nonce.clone()));
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let key_agg_ctx = session_meta
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
                .with_message(&session_meta.message),
        )
        .map_err(|e| MusigError::Musig2Error(e.into()))?;

        let pub_nonce = first_round.our_public_nonce();

        self.session_metadata
            .get_mut(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?
            .nonces
            .insert(user_id.clone(), pub_nonce.clone());

        let user_session = UserMusigSession {
            user_id: user_id.clone(),
            signer_index,
            private_key: Some(private_key.clone()),
            first_round: Some(first_round),
            second_round: None,
            adaptor_first_rounds: BTreeMap::new(),
            adaptor_second_rounds: BTreeMap::new(),
        };

        self.user_sessions
            .entry(session_id.clone())
            .or_default()
            .insert(user_id.clone(), user_session);

        Ok(NonceData::Regular(pub_nonce))
    }

    pub fn add_nonce(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        signer_index: usize,
        nonce: PubNonce,
    ) -> Result<(), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.phase != SessionPhase::NonceGeneration
            && session_meta.phase != SessionPhase::NonceAggregation
        {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceGeneration,
                actual: session_meta.phase.clone(),
            });
        }

        let current_phase = session_meta.phase.clone();

        if let Some(existing_nonce) = session_meta.nonces.get(user_id) {
            if existing_nonce.serialize() == nonce.serialize() {
                return Ok(());
            }
        }

        self.session_metadata
            .get_mut(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?
            .nonces
            .insert(user_id.clone(), nonce.clone());

        if let Some(session_users) = self.user_sessions.get(session_id) {
            for mut user_session in session_users.iter_mut() {
                // If we're in nonce generation phase, add to first round
                if current_phase == SessionPhase::NonceGeneration {
                    if let Some(ref mut first_round) = user_session.first_round {
                        first_round
                            .receive_nonce(signer_index, nonce.clone())
                            .map_err(|e| MusigError::Musig2Error(e.into()))?;
                    }
                }
            }
        }

        self.check_nonce_completion(session_id)?;

        Ok(())
    }

    pub fn get_nonce_count(&self, session_id: &SessionId) -> usize {
        self.session_metadata
            .get(session_id)
            .map(|meta| meta.nonces.len())
            .unwrap_or(0)
    }

    pub fn get_user_nonce(&self, session_id: &SessionId, user_id: &UserId) -> Option<PubNonce> {
        self.session_metadata
            .get(session_id)
            .and_then(|meta| meta.nonces.get(user_id).cloned())
    }

    pub fn get_user_nonce_data(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Option<NonceData> {
        let session_meta = self.session_metadata.get(session_id)?;

        if session_meta.has_adaptor_configs() {
            // For adaptor sessions, collect adaptor nonces from user session
            let user_sessions = self.user_sessions.get(session_id)?;
            let user_session = user_sessions.get(user_id)?;

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
            // For regular sessions, return regular nonce from session metadata
            let pub_nonce = session_meta.nonces.get(user_id)?;
            Some(NonceData::Regular(pub_nonce.clone()))
        }
    }

    pub fn get_session_nonces(&self, session_id: &SessionId) -> BTreeMap<UserId, PubNonce> {
        self.session_metadata
            .get(session_id)
            .map(|meta| meta.nonces.clone())
            .unwrap_or_default()
    }

    fn check_nonce_completion(&self, session_id: &SessionId) -> Result<(), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;
        let expected_count = session_meta
            .expected_participant_count
            .unwrap_or(session_meta.expected_participants.len());

        let current_nonce_count = session_meta.nonces.len();

        // If all nonces are collected, transition to aggregation phase
        if current_nonce_count == expected_count {
            self.update_session_phase(session_id, SessionPhase::NonceAggregation)?;
            info!("Session {} advanced to NonceAggregation phase", session_id);
        }

        Ok(())
    }

    pub fn finalize_nonce_rounds(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<(), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.phase != SessionPhase::NonceAggregation
            && session_meta.phase != SessionPhase::Signing
        {
            return Err(MusigError::WrongPhase {
                expected: SessionPhase::NonceAggregation,
                actual: session_meta.phase.clone(),
            });
        }

        if let Some(session_users) = self.user_sessions.get(session_id) {
            if let Some(mut user_session_ref) = session_users.get_mut(user_id) {
                let user_session = user_session_ref.value_mut();

                // Only finalize if we have a first_round and no second_round yet
                if let Some(first_round) = user_session.first_round.take() {
                    if user_session.second_round.is_none() {
                        if let Some(private_key) = &user_session.private_key {
                            let secret_key = musig2::secp256k1::SecretKey::from_byte_array(
                                private_key
                                    .as_bytes()
                                    .try_into()
                                    .map_err(|_| MusigError::InvalidPrivateKey)?,
                            )
                            .map_err(|_| MusigError::InvalidPrivateKey)?;

                            // Finalize first round to get second round
                            let second_round = first_round
                                .finalize(secret_key, session_meta.message.clone())
                                .map_err(|e| MusigError::Musig2Error(e.into()))?;

                            // Store the second round
                            user_session.second_round = Some(second_round);

                            info!(
                                "Finalized first round for user {} in session {}",
                                user_id, session_id
                            );
                        } else {
                            return Err(MusigError::NotReady(format!(
                                "No private key found for user {user_id}"
                            )));
                        }
                    }
                }
            } else {
                return Err(MusigError::NotReady(format!(
                    "No user session found for user {user_id}"
                )));
            }
        }

        // Update session phase to indicate we're ready for signature generation
        // Only update if we're not already in Signing phase
        if session_meta.phase != SessionPhase::Signing {
            self.update_session_phase(session_id, SessionPhase::Signing)?;
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
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        signer_index: usize,
        private_key: &KeyMaterial,
    ) -> Result<Vec<(uuid::Uuid, PubNonce)>, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        // Parse private key
        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let key_agg_ctx = session_meta
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
        for (config_index, config) in session_meta.adaptor_configs.iter().enumerate() {
            // Create deterministic but unique nonce seed for each config
            let mut adaptor_nonce_seed = base_nonce_seed;
            adaptor_nonce_seed[0] = adaptor_nonce_seed[0].wrapping_add(config_index as u8 + 1);

            let first_round = FirstRound::new(
                key_agg_ctx.clone(),
                adaptor_nonce_seed,
                signer_index,
                SecNonceSpices::new()
                    .with_seckey(secret_key)
                    .with_message(&session_meta.message),
            )
            .map_err(|e| MusigError::Musig2Error(e.into()))?;

            let pub_nonce = first_round.our_public_nonce();
            adaptor_nonces.push((config.adaptor_id, pub_nonce));
            adaptor_first_rounds.insert(config.adaptor_id, first_round);
        }

        // Create user session with adaptor first rounds
        let user_session = UserMusigSession {
            user_id: user_id.clone(),
            signer_index,
            private_key: Some(private_key.clone()),
            first_round: None, // No regular first round for adaptor sessions
            second_round: None,
            adaptor_first_rounds,
            adaptor_second_rounds: BTreeMap::new(),
        };

        self.user_sessions
            .entry(session_id.clone())
            .or_default()
            .insert(user_id.clone(), user_session);

        Ok(adaptor_nonces)
    }

    /// Add adaptor nonces from a remote participant to local participants' FirstRounds
    pub fn add_adaptor_nonces(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        adaptor_nonces: Vec<(uuid::Uuid, PubNonce)>,
    ) -> Result<(), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        // Calculate the signer index for the user who sent these nonces
        let signer_index = session_meta
            .expected_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or(MusigError::InvalidParticipant(user_id.clone()))?;

        debug!(
            "add_adaptor_nonces - user {} has signer_index {} in session {} (expected_participants: {:?})",
            user_id,
            signer_index,
            session_id,
            session_meta.expected_participants
        );

        let session_users = self
            .user_sessions
            .get(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        // Add the nonces to ALL local participants' FirstRounds (those with private keys)
        for mut user_session in session_users.iter_mut() {
            // Only distribute to local participants (those with private keys)
            if user_session.private_key.is_some() {
                debug!(
                    "Distributing nonces to local participant {} (stored signer_index: {})",
                    user_session.user_id, user_session.signer_index
                );
                let user_id = user_session.user_id.clone();

                for (config_id, nonce) in &adaptor_nonces {
                    if let Some(first_round) = user_session.adaptor_first_rounds.get_mut(config_id)
                    {
                        debug!(
                            "Receiving nonce for config {} at signer_index {} into FirstRound of user {}",
                            config_id, signer_index, user_id
                        );

                        first_round
                            .receive_nonce(signer_index, nonce.clone())
                            .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if all local participants have received all adaptor nonces
    pub fn all_adaptor_first_rounds_complete(
        &self,
        session_id: &SessionId,
    ) -> Result<bool, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if !session_meta.has_adaptor_configs() {
            return Ok(false);
        }

        let adaptor_config_count = session_meta.adaptor_configs.len();
        let expected_participant_count = session_meta.expected_participants.len();
        let current_phase = session_meta.phase.clone();

        drop(session_meta);

        let session_users = self
            .user_sessions
            .get(session_id)
            .ok_or(MusigError::SessionNotFound(session_id.clone()))?;

        for user_session in session_users.iter() {
            if user_session.private_key.is_none() {
                continue;
            }

            let actual_rounds = user_session.adaptor_first_rounds.len();

            if actual_rounds != adaptor_config_count {
                tracing::debug!(
                    "Local participant {} has {}/{} adaptor first rounds",
                    user_session.user_id,
                    actual_rounds,
                    adaptor_config_count
                );
                return Ok(false);
            }

            for (config_id, first_round) in &user_session.adaptor_first_rounds {
                if !first_round.is_complete() {
                    tracing::debug!(
                        "Local participant {} config {} not complete (expected {} nonces)",
                        user_session.user_id,
                        config_id,
                        expected_participant_count
                    );
                    return Ok(false);
                }
            }
        }

        if current_phase == SessionPhase::NonceGeneration {
            self.update_session_phase(session_id, SessionPhase::NonceAggregation)?;
            tracing::info!(
                "Session {} advanced to NonceAggregation phase (adaptor)",
                session_id
            );
        }

        Ok(true)
    }
}
