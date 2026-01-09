use hex;
use musig2::secp256k1::{PublicKey, SecretKey};
use musig2::{FirstRound, KeyAggContext, PartialSignature, PubNonce, SecNonceSpices};
use std::collections::{BTreeMap, HashMap};
use tracing::{debug, info};

use keymeld_core::{
    crypto::SecureCrypto,
    identifiers::{SessionId, UserId},
    protocol::{AdaptorConfig, AdaptorSignatureResult, EnclaveError, TaprootTweak},
    KeyMaterial,
};

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
        message: Vec<u8>,
        taproot_tweak: TaprootTweak,
        expected_participant_count: Option<usize>,
        expected_participants: Vec<UserId>,
    ) -> Self {
        let session_metadata = SessionMetadata::new(
            session_id.clone(),
            message,
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

    pub fn set_adaptor_configs(
        &mut self,
        adaptor_configs: Vec<AdaptorConfig>,
    ) -> Result<(), MusigError> {
        self.session_metadata.adaptor_configs = adaptor_configs;
        info!(
            "Stored {} adaptor configs for session {}",
            self.session_metadata.adaptor_configs.len(),
            self.session_metadata.session_id
        );
        Ok(())
    }

    pub fn get_adaptor_signature_results(
        &self,
    ) -> Result<BTreeMap<uuid::Uuid, AdaptorSignatureResult>, MusigError> {
        Ok(self.session_metadata.adaptor_final_signatures.clone())
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
                first_round: None,
                second_round: None,
                adaptor_first_rounds: BTreeMap::new(),
                adaptor_second_rounds: BTreeMap::new(),
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

    pub fn update_session_message(&mut self, message: Vec<u8>) -> Result<(), MusigError> {
        self.session_metadata.set_message(message);
        info!("Updated session message");
        Ok(())
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
                        first_round: None, // Must be None - will be generated fresh for this signing session
                        second_round: None,
                        adaptor_first_rounds: BTreeMap::new(),
                        adaptor_second_rounds: BTreeMap::new(),
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
            first_round: None,
            second_round: None,
            adaptor_first_rounds: BTreeMap::new(),
            adaptor_second_rounds: BTreeMap::new(),
        };

        self.user_sessions.insert(user_id.clone(), user_session);

        info!(
            "Stored private key for user {} with signer_index {}, require_approval={}",
            user_id, signer_index, require_signing_approval
        );

        Ok(())
    }

    pub fn generate_nonce_for_user(&mut self, user_id: &UserId) -> Result<PubNonce, MusigError> {
        let user_session = self.user_sessions.get_mut(user_id).ok_or_else(|| {
            MusigError::NotReady(format!("User session not found for user {}", user_id))
        })?;

        let private_key = user_session.private_key.as_ref().ok_or_else(|| {
            MusigError::NotReady(format!("Private key not found for user {}", user_id))
        })?;

        let key_agg_ctx = self.session_metadata.key_agg_ctx.as_ref().ok_or_else(|| {
            MusigError::NotReady("Key aggregation context not initialized".to_string())
        })?;

        // Convert private key to SecretKey
        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        // Generate secure nonce seed
        let nonce_seed = SecureCrypto::generate_secure_nonce(
            &self.session_metadata.session_id.to_string(),
            &user_id.to_string(),
        )
        .map_err(|e| {
            MusigError::Musig2Error(format!("Secure nonce generation failed: {e}").into())
        })?;

        let first_round = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            user_session.signer_index,
            SecNonceSpices::new()
                .with_seckey(secret_key)
                .with_message(&self.session_metadata.message),
        )
        .map_err(|e| MusigError::Musig2Error(e.into()))?;

        let pub_nonce = first_round.our_public_nonce();
        user_session.first_round = Some(first_round);

        debug!(
            "Generated nonce for user {} in session {}",
            user_id, self.session_metadata.session_id
        );
        Ok(pub_nonce)
    }

    pub fn add_participant_nonce(
        &mut self,
        user_id: &UserId,
        nonce: PubNonce,
    ) -> Result<(), MusigError> {
        if !self
            .session_metadata
            .expected_participants
            .contains(user_id)
        {
            return Err(MusigError::NotReady(format!(
                "Unexpected participant {} not in expected participants list",
                user_id
            )));
        }

        // Get the signer index for this user
        let signer_index = self
            .session_metadata
            .expected_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or_else(|| {
                MusigError::NotReady(format!(
                    "User {} not found in expected participants",
                    user_id
                ))
            })?;

        // Add the nonce to all user sessions that have FirstRound active
        // receive_nonce returns error if we already have a nonce for that signer index
        // This is expected when distributing nonces - local users already have their own nonces
        let mut nonces_added = 0;
        let mut nonces_skipped = 0;
        for (session_user_id, user_session) in self.user_sessions.iter_mut() {
            if let Some(first_round) = &mut user_session.first_round {
                match first_round.receive_nonce(signer_index, nonce.clone()) {
                    Ok(_) => {
                        nonces_added += 1;
                        info!(
                            "Added nonce from {} (index {}) to user session {} in session {}",
                            user_id,
                            signer_index,
                            session_user_id,
                            self.session_metadata.session_id
                        );
                    }
                    Err(_) => {
                        // Nonce already exists for this signer index - expected for local users
                        nonces_skipped += 1;
                    }
                }
            }
        }

        if nonces_added == 0 && nonces_skipped == 0 {
            return Err(MusigError::NotReady(
                "No active FirstRound sessions to receive nonce".to_string(),
            ));
        }

        info!(
            "Added nonce from participant {} to {} user sessions in session {}",
            user_id, nonces_added, self.session_metadata.session_id
        );

        // Check if all nonces are collected and advance phase if needed
        self.check_nonce_completion()?;

        Ok(())
    }

    pub fn generate_partial_signature_for_user(
        &mut self,
        user_id: &UserId,
    ) -> Result<PartialSignature, MusigError> {
        let user_session = self.user_sessions.get_mut(user_id).ok_or_else(|| {
            MusigError::NotReady(format!("User session not found for user {}", user_id))
        })?;

        let private_key = user_session.private_key.as_ref().ok_or_else(|| {
            MusigError::NotReady(format!("Private key not found for user {}", user_id))
        })?;

        let first_round = user_session.first_round.take().ok_or_else(|| {
            MusigError::NotReady(format!("First round not found for user {}", user_id))
        })?;

        if self.session_metadata.key_agg_ctx.is_none() {
            return Err(MusigError::NotReady(
                "Key aggregation context not initialized".to_string(),
            ));
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let message = &self.session_metadata.message;

        // Check if first round is complete (has all nonces)
        if !first_round.is_complete() {
            return Err(MusigError::NotReady(
                "First round not complete - missing nonces from some participants".to_string(),
            ));
        }

        let second_round = first_round
            .finalize(secret_key, message.clone())
            .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;

        let partial_sig = second_round.our_signature();
        user_session.second_round = Some(second_round);

        info!(
            "Generated partial signature for user {} in session {}",
            user_id, self.session_metadata.session_id
        );

        Ok(partial_sig)
    }

    pub fn add_participant_partial_signature(
        &mut self,
        user_id: &UserId,
        signature: PartialSignature,
    ) -> Result<(), MusigError> {
        if !self
            .session_metadata
            .expected_participants
            .contains(user_id)
        {
            return Err(MusigError::NotReady(format!(
                "Unexpected participant {} not in expected participants list",
                user_id
            )));
        }

        let signer_index = self
            .session_metadata
            .expected_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or_else(|| {
                MusigError::NotReady(format!(
                    "User {} not found in expected participants",
                    user_id
                ))
            })?;

        // Add the signature to all user sessions that have SecondRound active
        let mut signatures_added = 0;
        for (session_user_id, user_session) in self.user_sessions.iter_mut() {
            if let Some(second_round) = &mut user_session.second_round {
                second_round
                    .receive_signature(signer_index, signature)
                    .map_err(|e| {
                        MusigError::Musig2Error(format!("Failed to add signature: {}", e).into())
                    })?;
                signatures_added += 1;
                info!(
                    "Added partial signature from {} (index {}) to user session {} in session {}",
                    user_id, signer_index, session_user_id, self.session_metadata.session_id
                );
            }
        }

        if signatures_added == 0 {
            return Err(MusigError::NotReady(
                "No active SecondRound sessions to receive signature".to_string(),
            ));
        }

        info!(
            "Added partial signature from participant {} to {} user sessions in session {}",
            user_id, signatures_added, self.session_metadata.session_id
        );

        Ok(())
    }

    /// Finalize signature (coordinator only)
    pub fn finalize_signature(&mut self) -> Result<Vec<u8>, MusigError> {
        if !self.is_coordinator() {
            return Err(MusigError::NotReady(
                "Only coordinator can finalize signature".to_string(),
            ));
        }

        info!(
            "Finalizing signature for session {} (coordinator enclave)",
            self.session_metadata.session_id
        );

        // Check if we have all required partial signatures
        let expected_count = self.session_metadata.expected_participants.len();
        let mut collected_signatures = 0;

        // Count available signatures from our local user sessions
        for user_id in &self.session_metadata.expected_participants {
            if let Some(user_session) = self.user_sessions.get(user_id) {
                if user_session.second_round.is_some() {
                    collected_signatures += 1;
                }
            }
        }

        if collected_signatures < expected_count {
            return Err(MusigError::NotReady(format!(
                "Insufficient partial signatures: {}/{} collected",
                collected_signatures, expected_count
            )));
        }

        // Find any user session with a complete second round to use for aggregation
        let mut final_signature_bytes = None;

        for user_id in &self.session_metadata.expected_participants {
            if let Some(user_session) = self.user_sessions.get_mut(user_id) {
                if let Some(second_round) = user_session.second_round.take() {
                    // Check if this second round has all signatures and is ready to finalize
                    if second_round.holdouts().is_empty() {
                        match second_round.finalize::<[u8; 64]>() {
                            Ok(signature) => {
                                final_signature_bytes = Some(signature.to_vec());
                                break;
                            }
                            Err(e) => {
                                info!("Failed to finalize signature for user {}: {}", user_id, e);
                                continue;
                            }
                        }
                    } else {
                        // Put the second round back if it's not ready
                        user_session.second_round = Some(second_round);
                    }
                }
            }
        }

        match final_signature_bytes {
            Some(signature) => {
                info!(
                    "Finalized signature for session {} ({} bytes)",
                    self.session_metadata.session_id,
                    signature.len()
                );
                Ok(signature)
            }
            None => Err(MusigError::NotReady(
                "No complete second round available for signature finalization".to_string(),
            )),
        }
    }

    pub fn is_coordinator(&mut self) -> bool {
        self.user_sessions
            .values()
            .any(|session| session.coordinator)
    }

    /// Check if user has FirstRound available (adaptor signatures reuse regular FirstRound)
    pub fn has_first_round_for_user(&self, user_id: &UserId) -> bool {
        self.user_sessions
            .get(user_id)
            .map(|session| session.first_round.is_some())
            .unwrap_or(false)
    }

    /// Get user's public nonce from their FirstRound (same for regular and adaptor)
    pub fn get_user_public_nonce(&self, user_id: &UserId) -> Option<PubNonce> {
        self.user_sessions
            .get(user_id)?
            .first_round
            .as_ref()
            .map(|round| round.our_public_nonce())
    }

    /// Add participant nonce - same method used for both regular and adaptor signatures
    /// (adaptor signatures reuse the regular FirstRound nonce collection)
    pub fn add_participant_nonce_for_adaptor(
        &mut self,
        user_id: &UserId,
        nonce: PubNonce,
    ) -> Result<(), MusigError> {
        // Reuse the existing add_participant_nonce method since adaptor signatures
        // use the same FirstRound instances as regular signatures
        self.add_participant_nonce(user_id, nonce)
    }

    /// Generate adaptor partial signature using finalize_adaptor() state-machine API
    /// This consumes the regular FirstRound and produces an adaptor SecondRound
    pub fn generate_adaptor_partial_signature_for_user(
        &mut self,
        user_id: &UserId,
        adaptor_config: &AdaptorConfig,
    ) -> Result<PartialSignature, MusigError> {
        let user_session = self.user_sessions.get_mut(user_id).ok_or_else(|| {
            MusigError::NotReady(format!("User session not found for user {}", user_id))
        })?;

        let private_key = user_session.private_key.as_ref().ok_or_else(|| {
            MusigError::NotReady(format!("Private key not found for user {}", user_id))
        })?;

        // Take the regular FirstRound (shared between regular and adaptor signatures)
        let first_round = user_session.first_round.take().ok_or_else(|| {
            MusigError::NotReady(format!(
                "FirstRound not found for user {} - ensure nonce generation completed",
                user_id
            ))
        })?;

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        // Check if first round is complete (has all nonces)
        if !first_round.is_complete() {
            // Put the first round back if not complete
            user_session.first_round = Some(first_round);
            return Err(MusigError::NotReady(
                "FirstRound not complete - missing nonces from some participants".to_string(),
            ));
        }

        // Parse adaptor point from the first adaptor point in config
        if adaptor_config.adaptor_points.is_empty() {
            user_session.first_round = Some(first_round);
            return Err(MusigError::NotReady(
                "No adaptor points provided in adaptor config".to_string(),
            ));
        }

        let adaptor_point_hex = &adaptor_config.adaptor_points[0];
        let adaptor_point_bytes = match hex::decode(adaptor_point_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                user_session.first_round = Some(first_round);
                return Err(MusigError::NotReady(format!(
                    "Invalid adaptor point hex: {}",
                    e
                )));
            }
        };

        let adaptor_point = match PublicKey::from_slice(&adaptor_point_bytes) {
            Ok(point) => point,
            Err(e) => {
                user_session.first_round = Some(first_round);
                return Err(MusigError::NotReady(format!(
                    "Invalid adaptor point: {}",
                    e
                )));
            }
        };

        let message = &self.session_metadata.message;

        // Use finalize_adaptor() to create SecondRound for adaptor signatures
        let second_round = first_round
            .finalize_adaptor(secret_key, adaptor_point, message.clone())
            .map_err(|e| MusigError::Musig2Error(e.to_string().into()))?;

        let partial_sig = second_round.our_signature();

        // Store the adaptor SecondRound for later aggregation
        user_session
            .adaptor_second_rounds
            .insert(adaptor_config.adaptor_id, second_round);

        info!(
            "Generated adaptor partial signature for user {} in session {} (adaptor_id: {})",
            user_id, self.session_metadata.session_id, adaptor_config.adaptor_id
        );

        Ok(partial_sig)
    }

    /// Store adaptor signature result in session metadata with complete metadata
    pub fn store_adaptor_signature_result(
        &mut self,
        adaptor_id: uuid::Uuid,
        adaptor_signature_bytes: Vec<u8>,
        adaptor_config: &AdaptorConfig,
        aggregated_nonce: Option<Vec<u8>>,
    ) -> Result<(), MusigError> {
        // Parse all adaptor points and compute aggregate if needed
        let mut adaptor_point_bytes_vec = Vec::new();
        let mut adaptor_public_keys = Vec::new();

        for adaptor_point_hex in &adaptor_config.adaptor_points {
            let point_bytes = hex::decode(adaptor_point_hex)
                .map_err(|e| MusigError::NotReady(format!("Invalid adaptor point hex: {}", e)))?;

            let public_key = secp256k1::PublicKey::from_slice(&point_bytes)
                .map_err(|e| MusigError::NotReady(format!("Invalid adaptor point: {}", e)))?;

            adaptor_point_bytes_vec.push(point_bytes);
            adaptor_public_keys.push(public_key);
        }

        // Calculate aggregate adaptor point if we have multiple points
        let aggregate_adaptor_point = if adaptor_public_keys.len() > 1 {
            let key_refs: Vec<&secp256k1::PublicKey> = adaptor_public_keys.iter().collect();
            let combined = secp256k1::PublicKey::combine_keys(&key_refs).map_err(|e| {
                MusigError::NotReady(format!("Failed to combine adaptor points: {}", e))
            })?;
            combined.serialize().to_vec()
        } else {
            // Single point case - use the point itself as the aggregate
            adaptor_point_bytes_vec.first().cloned().unwrap_or_default()
        };

        let result = AdaptorSignatureResult {
            adaptor_id,
            adaptor_type: adaptor_config.adaptor_type.clone(),
            signature_scalar: adaptor_signature_bytes,
            nonce_point: aggregated_nonce.unwrap_or_default(),
            adaptor_points: adaptor_point_bytes_vec,
            hints: adaptor_config.hints.clone(),
            aggregate_adaptor_point,
        };

        self.session_metadata
            .adaptor_final_signatures
            .insert(adaptor_id, result);

        info!(
            "Stored adaptor signature result for session {} (adaptor_id: {}, {} adaptor points)",
            self.session_metadata.session_id,
            adaptor_id,
            adaptor_config.adaptor_points.len()
        );

        Ok(())
    }

    /// Add participant adaptor partial signature to all relevant SecondRound instances
    pub fn add_participant_adaptor_partial_signature(
        &mut self,
        user_id: &UserId,
        adaptor_id: uuid::Uuid,
        signature: PartialSignature,
    ) -> Result<(), MusigError> {
        if !self
            .session_metadata
            .expected_participants
            .contains(user_id)
        {
            return Err(MusigError::NotReady(format!(
                "Unexpected participant {} not in expected participants list",
                user_id
            )));
        }

        let signer_index = self
            .session_metadata
            .expected_participants
            .iter()
            .position(|id| id == user_id)
            .ok_or_else(|| {
                MusigError::NotReady(format!(
                    "User {} not found in expected participants",
                    user_id
                ))
            })?;

        // Add the adaptor signature to all user sessions that have this adaptor SecondRound active
        let mut signatures_added = 0;
        for (session_user_id, user_session) in self.user_sessions.iter_mut() {
            if let Some(second_round) = user_session.adaptor_second_rounds.get_mut(&adaptor_id) {
                second_round
                    .receive_signature(signer_index, signature)
                    .map_err(|e| {
                        MusigError::Musig2Error(
                            format!("Failed to add adaptor partial signature: {}", e).into(),
                        )
                    })?;
                signatures_added += 1;
                info!(
                    "Added adaptor partial signature from {} (index {}) to user session {} in session {} (adaptor_id: {})",
                    user_id, signer_index, session_user_id, self.session_metadata.session_id, adaptor_id
                );
            }
        }

        if signatures_added == 0 {
            return Err(MusigError::NotReady(format!(
                "No active adaptor SecondRound sessions found for adaptor_id {}",
                adaptor_id
            )));
        }

        info!(
            "Added adaptor partial signature from participant {} to {} user sessions in session {} (adaptor_id: {})",
            user_id, signatures_added, self.session_metadata.session_id, adaptor_id
        );

        Ok(())
    }

    /// Finalize adaptor signature using finalize_adaptor() state-machine API
    pub fn finalize_adaptor_signature(
        &mut self,
        adaptor_id: uuid::Uuid,
    ) -> Result<Vec<u8>, MusigError> {
        if !self.is_coordinator() {
            return Err(MusigError::NotReady(
                "Only coordinator can finalize adaptor signature".to_string(),
            ));
        }

        info!(
            "Finalizing adaptor signature for session {} (coordinator enclave, adaptor_id: {})",
            self.session_metadata.session_id, adaptor_id
        );

        // Check if we have all required partial signatures for this adaptor
        let expected_count = self.session_metadata.expected_participants.len();
        let mut collected_signatures = 0;

        // Count available adaptor signatures from our local user sessions
        for user_id in &self.session_metadata.expected_participants {
            if let Some(user_session) = self.user_sessions.get(user_id) {
                if user_session.adaptor_second_rounds.contains_key(&adaptor_id) {
                    collected_signatures += 1;
                }
            }
        }

        if collected_signatures < expected_count {
            return Err(MusigError::NotReady(format!(
                "Insufficient adaptor partial signatures: {}/{} collected (adaptor_id: {})",
                collected_signatures, expected_count, adaptor_id
            )));
        }

        // Find any user session with a complete adaptor second round to use for aggregation
        let mut adaptor_signature_bytes: Option<(Vec<u8>, Vec<u8>)> = None;

        for user_id in &self.session_metadata.expected_participants {
            if let Some(user_session) = self.user_sessions.get_mut(user_id) {
                if let Some(second_round) = user_session.adaptor_second_rounds.remove(&adaptor_id) {
                    // Check if this second round has all signatures and is ready to finalize
                    if second_round.holdouts().is_empty() {
                        // Extract aggregated nonce before consuming second_round
                        let aggregated_nonce = second_round.aggregated_nonce();
                        let nonce_bytes = aggregated_nonce.serialize().to_vec();

                        // Use finalize_adaptor() to produce AdaptorSignature
                        match second_round.finalize_adaptor::<musig2::AdaptorSignature>() {
                            Ok(adaptor_signature) => {
                                // Convert AdaptorSignature to bytes for storage
                                let signature_bytes = adaptor_signature.serialize().to_vec();
                                adaptor_signature_bytes = Some((signature_bytes, nonce_bytes));
                                break;
                            }
                            Err(e) => {
                                info!(
                                    "Failed to finalize adaptor signature for user {}: {}",
                                    user_id, e
                                );
                                continue;
                            }
                        }
                    } else {
                        // Put the second round back if it's not ready
                        user_session
                            .adaptor_second_rounds
                            .insert(adaptor_id, second_round);
                    }
                }
            }
        }

        match adaptor_signature_bytes {
            Some((signature, _nonce)) => {
                info!(
                    "Finalized adaptor signature for session {} ({} bytes, adaptor_id: {})",
                    self.session_metadata.session_id,
                    signature.len(),
                    adaptor_id
                );
                Ok(signature)
            }
            None => Err(MusigError::NotReady(format!(
                "No complete adaptor second round available for signature finalization (adaptor_id: {})",
                adaptor_id
            ))),
        }
    }

    /// Check if regular signature is ready for adaptor finalization
    pub fn can_finalize_adaptor_signature(&self, adaptor_id: uuid::Uuid) -> bool {
        // Check if any user session has a complete adaptor SecondRound for this adaptor_id
        self.user_sessions.values().any(|session| {
            session
                .adaptor_second_rounds
                .get(&adaptor_id)
                .map(|second_round| second_round.is_complete())
                .unwrap_or(false)
        })
    }
}
