use musig2::{
    secp256k1::{PublicKey, Scalar, SecretKey},
    AggNonce, FirstRound, KeyAggContext, PartialSignature, PubNonce, SecNonceSpices, SecondRound,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    string::ToString,
    vec::Vec,
};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::{
    api::TaprootTweak,
    crypto::SecureCrypto,
    identifiers::{SessionId, UserId},
    KeyMaterial,
};

#[derive(Error, Debug)]
pub enum MusigError {
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Invalid partial signature")]
    InvalidPartialSignature,
    #[error("Session not found: {0}")]
    SessionNotFound(SessionId),
    #[error("Wrong session phase: {0}")]
    WrongPhase(String),
    #[error("MuSig2 error: {0}")]
    Musig2Error(String),
    #[error("Insufficient participants: {0}")]
    InsufficientParticipants(String),
    #[error("Nonce already exists for user: {0}")]
    NonceAlreadyExists(String),
    #[error("Signature already exists for user: {0}")]
    SignatureAlreadyExists(String),
    #[error("Duplicate participant: {0}")]
    DuplicateParticipant(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SessionPhase {
    CollectingParticipants,
    NonceGeneration,
    NonceAggregation,
    Signing,
    Aggregation,
    Complete,
    Failed(String),
}

type UserSessionKey = (SessionId, UserId);

#[derive(Debug, Clone)]
pub struct UserMusigSession {
    pub user_id: UserId,
    pub signer_index: usize,
    pub musig_session: MusigSession,
}

#[derive(Debug, Clone)]
pub struct SessionMetadata {
    pub session_id: SessionId,
    pub message: Vec<u8>,
    pub expected_participants: Vec<UserId>,
    pub participant_public_keys: BTreeMap<UserId, PublicKey>,
    pub expected_participant_count: Option<usize>,
    pub key_agg_ctx: Option<KeyAggContext>,
    pub aggregate_nonce: Option<AggNonce>,
    pub phase: SessionPhase,
    pub participants_ready: BTreeSet<UserId>,
    pub taproot_tweak: TaprootTweak,
}

impl SessionMetadata {
    pub fn get_all_participants(&self) -> Vec<PublicKey> {
        // Ensure consistent ordering by sorting participants by user_id
        let mut participants: Vec<(UserId, PublicKey)> = self
            .participant_public_keys
            .iter()
            .map(|(uid, pk)| (uid.clone(), *pk))
            .collect();
        participants.sort_by(|a, b| a.0.cmp(&b.0));
        participants.into_iter().map(|(_, pk)| pk).collect()
    }
}

pub struct MusigProcessor {
    // Each user gets their own MuSig2 session
    user_sessions: BTreeMap<UserSessionKey, UserMusigSession>,
    // Session-level coordination metadata
    session_metadata: BTreeMap<SessionId, SessionMetadata>,
}

impl MusigProcessor {
    pub fn new() -> Self {
        Self {
            user_sessions: BTreeMap::new(),
            session_metadata: BTreeMap::new(),
        }
    }

    fn get_session_metadata(&self, session_id: &SessionId) -> Result<&SessionMetadata, MusigError> {
        self.session_metadata
            .get(session_id)
            .ok_or_else(|| MusigError::SessionNotFound(session_id.clone()))
    }

    fn get_session_metadata_mut(
        &mut self,
        session_id: &SessionId,
    ) -> Result<&mut SessionMetadata, MusigError> {
        self.session_metadata
            .get_mut(session_id)
            .ok_or_else(|| MusigError::SessionNotFound(session_id.clone()))
    }

    pub fn init_session(
        &mut self,
        session_id: &SessionId,
        message: Vec<u8>,
        taproot_tweak: TaprootTweak,
        participants: Vec<PublicKey>,
        expected_participant_count: Option<usize>,
    ) -> Result<(), MusigError> {
        let key_agg_ctx = if participants.len() >= 2 {
            let mut key_agg_ctx = KeyAggContext::new(participants.clone()).map_err(|e| {
                MusigError::Musig2Error(format!("Failed to create key agg context: {e}"))
            })?;

            key_agg_ctx = Self::apply_taproot_tweak(key_agg_ctx, &taproot_tweak)?;

            Some(key_agg_ctx)
        } else {
            None
        };

        let has_key_agg_ctx = key_agg_ctx.is_some();
        let phase = if has_key_agg_ctx {
            SessionPhase::NonceGeneration
        } else {
            SessionPhase::CollectingParticipants
        };

        // Create new session metadata
        let session_metadata = SessionMetadata {
            session_id: session_id.clone(),
            message: message.clone(),
            expected_participants: vec![], // Will be populated when users are added
            participant_public_keys: BTreeMap::new(), // Will be populated when participants are added
            expected_participant_count,
            key_agg_ctx: key_agg_ctx.clone(),
            aggregate_nonce: None,
            phase: phase.clone(),
            participants_ready: BTreeSet::new(),
            taproot_tweak,
        };

        self.session_metadata
            .insert(session_id.clone(), session_metadata);
        Ok(())
    }

    pub fn add_participant(
        &mut self,
        session_id: &SessionId,
        user_id: UserId,
        public_key: PublicKey,
    ) -> Result<(), MusigError> {
        let taproot_tweak_config = TaprootTweak::UnspendableTaproot; // Default for Bitcoin compatibility
                                                                     // Check session metadata first
        {
            let session_meta = self.get_session_metadata(session_id)?;
            if session_meta.expected_participants.contains(&user_id) {
                return Err(MusigError::DuplicateParticipant(format!(
                    "Participant {} already exists in session {}",
                    user_id, session_id
                )));
            }
        }

        // Update session metadata - store both user ID and public key
        {
            let session_meta = self.get_session_metadata_mut(session_id)?;
            session_meta.expected_participants.push(user_id.clone());
            session_meta
                .participant_public_keys
                .insert(user_id.clone(), public_key);
        }

        // Check if we can create key aggregation context with current participants
        let session_meta = self.get_session_metadata(session_id)?;
        let participant_count = session_meta.participant_public_keys.len();

        // Determine expected count - either from session metadata or minimum 2
        let expected_count = session_meta.expected_participant_count.unwrap_or(2);

        debug!(
            "Session {} add_participant: current={}, expected={}, has_key_agg_ctx={}",
            session_id,
            participant_count,
            expected_count,
            session_meta.key_agg_ctx.is_some()
        );

        // Create key aggregation context only when we have ALL expected participants
        if participant_count >= expected_count
            && participant_count >= 2
            && session_meta.key_agg_ctx.is_none()
        {
            let all_public_keys: Vec<PublicKey> = session_meta.get_all_participants();
            debug!(
                "Session {} creating KeyAggContext with {} participants: {:?}",
                session_id,
                all_public_keys.len(),
                all_public_keys
                    .iter()
                    .map(|pk| hex::encode(pk.serialize()))
                    .collect::<Vec<_>>()
            );

            let mut key_agg_ctx = KeyAggContext::new(all_public_keys).map_err(|e| {
                MusigError::Musig2Error(format!("Failed to create key agg context: {e}"))
            })?;

            key_agg_ctx = Self::apply_taproot_tweak(key_agg_ctx, &taproot_tweak_config)?;

            let session_meta = self.get_session_metadata_mut(session_id)?;
            let current_phase = session_meta.phase.clone();
            session_meta.key_agg_ctx = Some(key_agg_ctx);
            session_meta.phase = SessionPhase::NonceGeneration;

            info!(
                "🔄 Session {} transitioned from {:?} to NonceGeneration phase with {} participants",
                session_id, current_phase, participant_count
            );
        } else if expected_count == 0 {
            warn!(
                "Session {} has no expected participant count set, cannot transition to NonceGeneration",
                session_id
            );
        } else {
            let session_meta = self.get_session_metadata(session_id)?;
            debug!(
                "Session {} waiting for more participants: {}/{} (phase: {:?})",
                session_id, participant_count, expected_count, session_meta.phase
            );
        }

        Ok(())
    }

    /// Check if session should transition to NonceGeneration phase and force transition if needed
    pub fn check_and_force_phase_transition(
        &mut self,
        session_id: &SessionId,
    ) -> Result<bool, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;
        let participant_count = session_meta.participant_public_keys.len();
        let expected_count = session_meta.expected_participant_count.unwrap_or(0);

        if session_meta.phase == SessionPhase::CollectingParticipants
            && participant_count >= expected_count
            && participant_count >= 2
            && session_meta.key_agg_ctx.is_none()
        {
            info!(
                "🔄 Force transitioning session {} to NonceGeneration phase ({} participants ready)",
                session_id, participant_count
            );

            let all_public_keys: Vec<PublicKey> = session_meta.get_all_participants();
            let mut key_agg_ctx = KeyAggContext::new(all_public_keys).map_err(|e| {
                MusigError::Musig2Error(format!("Failed to create key agg context: {e}"))
            })?;

            // Apply taproot tweak using the stored configuration
            key_agg_ctx = Self::apply_taproot_tweak(key_agg_ctx, &session_meta.taproot_tweak)?;

            let session_meta = self.get_session_metadata_mut(session_id)?;
            session_meta.key_agg_ctx = Some(key_agg_ctx);
            session_meta.phase = SessionPhase::NonceGeneration;

            return Ok(true);
        }

        Ok(false)
    }

    pub fn generate_nonce(
        &mut self,
        session_id: &SessionId,
        user_id: &UserId,
        signer_index: usize,
        private_key: &KeyMaterial,
    ) -> Result<PubNonce, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        debug!(
            "Session {} generate_nonce: user={}, signer_index={}, participants={}, key_agg_ctx={}",
            session_id,
            user_id,
            signer_index,
            session_meta
                .expected_participant_count
                .unwrap_or(session_meta.expected_participants.len()),
            session_meta.key_agg_ctx.is_some()
        );

        let user_key = (session_id.clone(), user_id.clone());

        // Allow nonce generation in both NonceGeneration and NonceAggregation phases
        // This handles retry scenarios where session may have advanced but user hasn't generated nonce
        if session_meta.phase != SessionPhase::NonceGeneration
            && session_meta.phase != SessionPhase::NonceAggregation
        {
            return Err(MusigError::WrongPhase(format!(
                "Expected NonceGeneration or NonceAggregation, got {:?}",
                session_meta.phase
            )));
        }

        // Check if user already has a session with a nonce - if so, return the existing nonce
        if let Some(user_session) = self.user_sessions.get(&user_key) {
            if let Some(existing_nonce) = user_session.musig_session.nonces.get(user_id) {
                debug!(
                    "User {} already has nonce for session {}, returning existing",
                    user_id, session_id
                );
                return Ok(existing_nonce.clone());
            }
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        let key_agg_ctx = session_meta.key_agg_ctx.as_ref().ok_or_else(|| {
            MusigError::WrongPhase("Session not ready for nonce generation".to_string())
        })?;

        debug!(
            "Session {} creating FirstRound with signer_index={} for group of {} signers",
            session_id,
            signer_index,
            session_meta
                .expected_participant_count
                .unwrap_or(session_meta.expected_participants.len())
        );

        // Create individual MuSig2 session for this user
        let nonce_seed =
            SecureCrypto::generate_secure_nonce(&session_id.to_string(), &user_id.to_string())
                .map_err(|e| {
                    MusigError::Musig2Error(format!("Secure nonce generation failed: {}", e))
                })?;

        let first_round = FirstRound::new(
            key_agg_ctx.clone(),
            nonce_seed,
            signer_index,
            SecNonceSpices::new()
                .with_seckey(secret_key)
                .with_message(&session_meta.message),
        )
        .map_err(|e| MusigError::Musig2Error(format!("Failed to create first round: {e}")))?;

        let pub_nonce = first_round.our_public_nonce();

        // Create user's individual session
        let mut nonces = BTreeMap::new();
        nonces.insert(user_id.clone(), pub_nonce.clone());

        let user_session = UserMusigSession {
            user_id: user_id.clone(),
            signer_index,
            musig_session: MusigSession {
                session_id: session_id.clone(),
                message: session_meta.message.clone(),
                key_agg_ctx: session_meta.key_agg_ctx.clone(),
                participants: session_meta.get_all_participants(),
                nonces,
                phase: SessionPhase::NonceGeneration,
                first_round: Some(first_round),
                second_round: None,
                expected_participant_count: session_meta
                    .expected_participant_count
                    .or(Some(session_meta.expected_participants.len())),
            },
        };

        self.user_sessions.insert(user_key, user_session);

        Ok(pub_nonce)
    }

    pub fn add_nonce(
        &mut self,
        session_id: &SessionId,
        user_id: &UserId,
        signer_index: usize,
        nonce: PubNonce,
    ) -> Result<(), MusigError> {
        debug!(
            "Adding nonce for session {} user {} signer_index {}",
            session_id, user_id, signer_index
        );

        let session_meta = self.get_session_metadata(session_id)?;

        // Allow nonce addition in both NonceGeneration and NonceAggregation phases
        // This handles retry scenarios where session may have advanced but we're still receiving nonces
        if session_meta.phase != SessionPhase::NonceGeneration
            && session_meta.phase != SessionPhase::NonceAggregation
        {
            return Err(MusigError::WrongPhase(format!(
                "Expected NonceGeneration or NonceAggregation, got {:?}",
                session_meta.phase
            )));
        }

        // Clone the phase to avoid borrowing issues
        let current_phase = session_meta.phase.clone();

        trace!(
            "Before adding nonce - expected participants: {}",
            session_meta
                .expected_participant_count
                .unwrap_or(session_meta.expected_participants.len())
        );

        // Check if this nonce already exists to avoid duplicates
        for ((sid, _uid), user_session) in self.user_sessions.iter() {
            if sid == session_id {
                if let Some(existing_nonce) = user_session.musig_session.nonces.get(user_id) {
                    if existing_nonce.serialize() == nonce.serialize() {
                        debug!(
                            "Nonce for user {} already exists in session {}, skipping duplicate",
                            user_id, session_id
                        );
                        return Ok(());
                    }
                }
                break;
            }
        }

        // Add nonce to ALL user sessions in this session
        // This ensures all users have the complete nonce set
        let mut updated_sessions = 0;
        for ((sid, uid), user_session) in self.user_sessions.iter_mut() {
            if sid == session_id {
                if current_phase == SessionPhase::NonceGeneration {
                    if let Some(ref mut first_round) = user_session.musig_session.first_round {
                        first_round
                            .receive_nonce(signer_index, nonce.clone())
                            .map_err(|e| {
                                MusigError::Musig2Error(format!("Failed to receive nonce: {e}"))
                            })?;
                    }
                }
                user_session
                    .musig_session
                    .nonces
                    .insert(user_id.clone(), nonce.clone());
                updated_sessions += 1;
                trace!(
                    "Added nonce to user {} session, now has {} nonces",
                    uid,
                    user_session.musig_session.nonces.len()
                );
            }
        }

        trace!(
            "Updated {} user sessions with nonce for session {}",
            updated_sessions,
            session_id
        );

        // Check if all nonces are collected for session-level phase transition
        self.check_nonce_completion(session_id)?;

        Ok(())
    }

    fn check_nonce_completion(&mut self, session_id: &SessionId) -> Result<(), MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;
        let expected_count = session_meta
            .expected_participant_count
            .unwrap_or(session_meta.expected_participants.len());

        trace!(
            "Checking nonce completion for session {} - expected {} participants",
            session_id,
            expected_count
        );

        // Find ANY user session for this signing session to check nonce completion
        let mut found_user_session = None;
        for ((sid, uid), user_session) in self.user_sessions.iter() {
            if sid == session_id {
                found_user_session = Some((uid.clone(), user_session));
                break;
            }
        }

        if let Some((user_id, user_session)) = found_user_session {
            let current_nonce_count = user_session.musig_session.nonces.len();
            tracing::trace!(
                "Checking user {} session: has {} nonces, need {}",
                user_id,
                current_nonce_count,
                expected_count
            );

            if current_nonce_count == expected_count {
                debug!(
                    "All nonces collected! Transitioning session {} to NonceAggregation phase",
                    session_id
                );

                // All nonces collected, update session metadata phase
                let session_meta = self.get_session_metadata_mut(session_id)?;
                session_meta.phase = SessionPhase::NonceAggregation;

                // Update ALL user sessions to NonceAggregation phase
                let mut updated_user_sessions = 0;
                for ((sid, uid), user_session) in self.user_sessions.iter_mut() {
                    if sid == session_id {
                        user_session.musig_session.phase = SessionPhase::NonceAggregation;
                        updated_user_sessions += 1;
                        debug!("Updated user {} session to NonceAggregation phase", uid);
                    }
                }

                info!(
                    "✅ Session {} transitioned to NonceAggregation phase - all {} nonces collected, updated {} user sessions",
                    session_id, expected_count, updated_user_sessions
                );
            } else {
                info!(
                    "⏳ Not all nonces collected yet for session {} ({}/{})",
                    session_id, current_nonce_count, expected_count
                );
            }
        } else {
            info!(
                "⏳ No user sessions found yet for signing session {} - waiting for nonce generation to start",
                session_id
            );
        }

        Ok(())
    }

    pub fn sign(
        &mut self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        // Delegate to the new per-user signing method
        self.sign_for_user(session_id, user_id, private_key)
    }

    pub fn sign_for_user(
        &mut self,
        session_id: &SessionId,
        user_id: &UserId,
        private_key: &KeyMaterial,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        let user_key = (session_id.clone(), user_id.clone());
        let user_session = self
            .user_sessions
            .get_mut(&user_key)
            .ok_or_else(|| MusigError::SessionNotFound(session_id.clone()))?;

        info!(
            "Session {} sign_for_user: user={}, phase={:?}, nonce_count={}, has_first_round={}",
            session_id,
            user_id,
            user_session.musig_session.phase,
            user_session.musig_session.nonces.len(),
            user_session.musig_session.first_round.is_some()
        );

        // Check if signature already exists (from previous attempt) - return existing signature
        if user_session.musig_session.phase == SessionPhase::Signing {
            if let Some(ref second_round) = user_session.musig_session.second_round {
                debug!(
                    "User {} already has a signature for session {}, returning existing signature",
                    user_id, session_id
                );
                let partial_signature: PartialSignature = second_round.our_signature();
                let signature_bytes = partial_signature.serialize().to_vec();
                let nonce_bytes = user_session
                    .musig_session
                    .nonces
                    .get(user_id)
                    .map(|n| n.serialize().to_vec())
                    .unwrap_or_else(Vec::new);
                return Ok((signature_bytes, nonce_bytes));
            }
        }

        if user_session.musig_session.phase != SessionPhase::NonceAggregation {
            return Err(MusigError::WrongPhase(format!(
                "Expected NonceAggregation, got {:?}",
                user_session.musig_session.phase
            )));
        }

        let secret_key = SecretKey::from_byte_array(
            private_key
                .as_bytes()
                .try_into()
                .map_err(|_| MusigError::InvalidPrivateKey)?,
        )
        .map_err(|_| MusigError::InvalidPrivateKey)?;

        // Each user has their own FirstRound - can finalize independently
        // Handle case where first_round was already taken in a previous attempt
        let first_round = if let Some(first_round) = user_session.musig_session.first_round.take() {
            first_round
        } else {
            return Err(MusigError::Musig2Error(
                "No first round found - signature may have already been generated".to_string(),
            ));
        };

        if !first_round.is_complete() {
            return Err(MusigError::Musig2Error(
                "Not all nonces received".to_string(),
            ));
        }

        // Finalize this user's FirstRound with their private key
        let second_round = first_round
            .finalize(secret_key, user_session.musig_session.message.clone())
            .map_err(|e| MusigError::Musig2Error(format!("Failed to finalize first round: {e}")))?;

        let partial_signature: PartialSignature = second_round.our_signature();

        // Store the SecondRound for this user
        user_session.musig_session.second_round = Some(second_round);
        user_session.musig_session.phase = SessionPhase::Signing;

        let signature_bytes = partial_signature.serialize().to_vec();
        let nonce_bytes = user_session
            .musig_session
            .nonces
            .get(user_id)
            .map(|n| n.serialize().to_vec())
            .unwrap_or_else(Vec::new);

        Ok((signature_bytes, nonce_bytes))
    }

    pub fn add_partial_signature(
        &mut self,
        session_id: &SessionId,
        signer_index: usize,
        partial_signature: PartialSignature,
    ) -> Result<(), MusigError> {
        // Add signature to ALL user sessions in this session
        for ((sid, _uid), user_session) in self.user_sessions.iter_mut() {
            if sid == session_id {
                if let Some(ref mut second_round) = user_session.musig_session.second_round {
                    second_round
                        .receive_signature(signer_index, partial_signature)
                        .map_err(|e| {
                            MusigError::Musig2Error(format!("Failed to receive signature: {e}"))
                        })?;

                    if second_round.holdouts().is_empty() {
                        user_session.musig_session.phase = SessionPhase::Aggregation;
                    }
                }
            }
        }

        Ok(())
    }

    pub fn add_partial_signature_for_user(
        &mut self,
        session_id: &SessionId,
        _from_user_id: &UserId,
        target_user_id: &UserId,
        signer_index: usize,
        partial_signature: PartialSignature,
    ) -> Result<(), MusigError> {
        // Add signature to the target user's session
        let user_key = (session_id.clone(), target_user_id.clone());
        let user_session = self
            .user_sessions
            .get_mut(&user_key)
            .ok_or_else(|| MusigError::SessionNotFound(session_id.clone()))?;

        if let Some(ref mut second_round) = user_session.musig_session.second_round {
            second_round
                .receive_signature(signer_index, partial_signature)
                .map_err(|e| {
                    MusigError::Musig2Error(format!("Failed to receive signature: {e}"))
                })?;

            if second_round.holdouts().is_empty() {
                user_session.musig_session.phase = SessionPhase::Aggregation;
            }
        }

        Ok(())
    }

    pub fn finalize(&mut self, session_id: &SessionId) -> Result<Vec<u8>, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        if session_meta.phase != SessionPhase::Aggregation {
            return Err(MusigError::WrongPhase(format!(
                "Expected Aggregation, got {:?}",
                session_meta.phase
            )));
        }

        // Get any user's second round to finalize (they all have the same state)
        if let Some(first_user_id) = session_meta.expected_participants.first() {
            let user_key = (session_id.clone(), first_user_id.clone());
            let user_session = self
                .user_sessions
                .get_mut(&user_key)
                .ok_or_else(|| MusigError::SessionNotFound(session_id.clone()))?;

            let Some(second_round) = user_session.musig_session.second_round.take() else {
                return Err(MusigError::WrongPhase(
                    "Expected second round to exist".to_string(),
                ));
            };
            if !second_round.is_complete() {
                return Err(MusigError::WrongPhase(
                    "Expected second round to be complete".to_string(),
                ));
            };

            let final_signature: [u8; 64] = second_round
                .finalize()
                .map_err(|e| MusigError::Musig2Error(format!("Failed to finalize: {e}")))?;

            // Update session metadata phase
            let session_meta = self.get_session_metadata_mut(session_id)?;
            session_meta.phase = SessionPhase::Complete;

            info!(
                "Successfully finalized MuSig2 signature for session {}",
                session_id
            );

            return Ok(final_signature.to_vec());
        }

        Err(MusigError::SessionNotFound(session_id.clone()))
    }

    pub fn get_session_metadata_public(&self, session_id: &SessionId) -> Option<&SessionMetadata> {
        self.session_metadata.get(session_id)
    }

    pub fn clear_session(&mut self, session_id: &SessionId) {
        // Count sessions before clearing
        let user_sessions_before = self.user_sessions.len();
        let has_metadata_before = self.session_metadata.contains_key(session_id);

        // Remove all user sessions for this session
        self.user_sessions.retain(|(sid, _), _| sid != session_id);

        // Remove session metadata
        let metadata_removed = self.session_metadata.remove(session_id).is_some();

        let user_sessions_after = self.user_sessions.len();
        let removed_user_sessions = user_sessions_before - user_sessions_after;

        info!(
            "🧹 MuSig clear_session {}: removed {} user sessions, metadata_existed={}, metadata_removed={}",
            session_id, removed_user_sessions, has_metadata_before, metadata_removed
        );
    }

    pub fn get_aggregate_pubkey(&self, session_id: &SessionId) -> Result<Vec<u8>, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        let key_agg_ctx = session_meta.key_agg_ctx.as_ref().ok_or_else(|| {
            MusigError::WrongPhase("Session not ready - no key aggregation context".to_string())
        })?;

        // With taproot tweak applied, aggregated_pubkey() returns the tweaked key
        // This is the output key that should be used directly for taproot addresses
        let agg_pubkey: musig2::secp256k1::PublicKey = key_agg_ctx.aggregated_pubkey();
        Ok(agg_pubkey.serialize().to_vec())
    }

    /// Apply the specified taproot tweak configuration to a KeyAggContext
    fn apply_taproot_tweak(
        key_agg_ctx: KeyAggContext,
        config: &TaprootTweak,
    ) -> Result<KeyAggContext, MusigError> {
        match config {
            TaprootTweak::None => Ok(key_agg_ctx),
            TaprootTweak::UnspendableTaproot => {
                key_agg_ctx.with_unspendable_taproot_tweak().map_err(|e| {
                    MusigError::Musig2Error(format!(
                        "Failed to apply unspendable taproot tweak: {e}"
                    ))
                })
            }
            TaprootTweak::TaprootWithMerkleRoot { merkle_root } => {
                key_agg_ctx.with_taproot_tweak(merkle_root).map_err(|e| {
                    MusigError::Musig2Error(format!(
                        "Failed to apply taproot tweak with merkle root: {e}"
                    ))
                })
            }
            TaprootTweak::PlainTweak { tweak } => {
                let scalar = Scalar::from_be_bytes(*tweak).map_err(|e| {
                    MusigError::Musig2Error(format!("Invalid plain tweak scalar: {e}"))
                })?;
                key_agg_ctx.with_plain_tweak(scalar).map_err(|e| {
                    MusigError::Musig2Error(format!("Failed to apply plain tweak: {e}"))
                })
            }
            TaprootTweak::XOnlyTweak { tweak } => {
                let scalar = Scalar::from_be_bytes(*tweak).map_err(|e| {
                    MusigError::Musig2Error(format!("Invalid x-only tweak scalar: {e}"))
                })?;
                key_agg_ctx.with_xonly_tweak(scalar).map_err(|e| {
                    MusigError::Musig2Error(format!("Failed to apply x-only tweak: {e}"))
                })
            }
        }
    }

    pub fn initiate_signing_ceremony(
        &mut self,
        session_id: &SessionId,
        message: &[u8],
    ) -> Result<(), MusigError> {
        {
            let session_meta = self.get_session_metadata_mut(session_id)?;
            session_meta.message = message.to_vec();
            session_meta.phase = SessionPhase::NonceGeneration;
        }

        // Clear all user sessions for this session to restart
        self.user_sessions.retain(|(sid, _), _| sid != session_id);

        let session_meta = self.get_session_metadata(session_id)?;
        info!(
            "Initiated MuSig2 signing ceremony for session {} with {} participants",
            session_id,
            session_meta
                .expected_participant_count
                .unwrap_or(session_meta.expected_participants.len())
        );

        Ok(())
    }

    pub fn can_proceed_to_signing(&self, session_id: &SessionId) -> Result<bool, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        // Check if any user has all nonces collected
        if let Some(first_user_id) = session_meta.expected_participants.first() {
            let user_key = (session_id.clone(), first_user_id.clone());
            if let Some(user_session) = self.user_sessions.get(&user_key) {
                return Ok(user_session.musig_session.nonces.len()
                    == session_meta
                        .expected_participant_count
                        .unwrap_or(session_meta.expected_participants.len()));
            }
        }

        Ok(false)
    }

    pub fn can_aggregate_signatures(&self, session_id: &SessionId) -> Result<bool, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        // Check if any user has all partial signatures
        if let Some(first_user_id) = session_meta.expected_participants.first() {
            let user_key = (session_id.clone(), first_user_id.clone());
            if let Some(user_session) = self.user_sessions.get(&user_key) {
                if let Some(ref second_round) = user_session.musig_session.second_round {
                    return Ok(second_round.holdouts().is_empty());
                }
            }
        }

        Ok(false)
    }

    pub fn aggregate_signatures(&mut self, session_id: &SessionId) -> Result<Vec<u8>, MusigError> {
        if !self.can_aggregate_signatures(session_id)? {
            let session_meta = self.get_session_metadata(session_id)?;
            return Err(MusigError::InsufficientParticipants(format!(
                "Need {} partial signatures, not all collected yet",
                session_meta
                    .expected_participant_count
                    .unwrap_or(session_meta.expected_participants.len())
            )));
        }

        let session_meta = self.get_session_metadata(session_id)?;

        // Get any user's second round to finalize (they all have the same state)
        if let Some(first_user_id) = session_meta.expected_participants.first() {
            let user_key = (session_id.clone(), first_user_id.clone());
            let user_session = self
                .user_sessions
                .get_mut(&user_key)
                .ok_or_else(|| MusigError::SessionNotFound(session_id.clone()))?;

            let Some(second_round) = user_session.musig_session.second_round.take() else {
                return Err(MusigError::WrongPhase(String::from("second round missing")));
            };

            let final_signature: [u8; 64] = second_round
                .finalize()
                .map_err(|e| MusigError::Musig2Error(e.to_string()))?;

            // Update session metadata phase
            let session_meta = self.get_session_metadata_mut(session_id)?;
            session_meta.phase = SessionPhase::Complete;

            info!(
                "Successfully aggregated MuSig2 signature for session {}",
                session_id
            );

            return Ok(final_signature.to_vec());
        }

        Err(MusigError::SessionNotFound(session_id.clone()))
    }

    pub fn get_aggregate_nonce(&self, session_id: &SessionId) -> Result<AggNonce, MusigError> {
        let session_meta = self.get_session_metadata(session_id)?;

        // Get nonces from any user session (they all have the same nonces)
        if let Some(first_user_id) = session_meta.expected_participants.first() {
            let user_key = (session_id.clone(), first_user_id.clone());
            if let Some(user_session) = self.user_sessions.get(&user_key) {
                if user_session.musig_session.nonces.len()
                    != session_meta
                        .expected_participant_count
                        .unwrap_or(session_meta.expected_participants.len())
                {
                    return Err(MusigError::InsufficientParticipants(format!(
                        "Need {} nonces, got {}",
                        session_meta
                            .expected_participant_count
                            .unwrap_or(session_meta.expected_participants.len()),
                        user_session.musig_session.nonces.len()
                    )));
                }

                let public_nonces: Vec<PubNonce> = user_session
                    .musig_session
                    .nonces
                    .values()
                    .cloned()
                    .collect();
                let agg_nonce = AggNonce::sum(&public_nonces);
                return Ok(agg_nonce);
            }
        }
        Err(MusigError::SessionNotFound(session_id.clone()))
    }

    pub fn cleanup_sessions(&mut self, _older_than_secs: u64) {
        // Get completed session IDs
        let completed_sessions: Vec<SessionId> = self
            .session_metadata
            .iter()
            .filter_map(|(session_id, meta)| {
                if matches!(meta.phase, SessionPhase::Complete | SessionPhase::Failed(_)) {
                    Some(session_id.clone())
                } else {
                    None
                }
            })
            .collect();

        // Remove completed sessions
        for session_id in completed_sessions {
            self.clear_session(&session_id);
        }
    }

    #[cfg(test)]
    pub fn sign_simple(
        &mut self,
        key_material: &KeyMaterial,
        message: &[u8],
        participant_pubkeys: Vec<PublicKey>,
        session_id: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Vec<u8>), MusigError> {
        let sid = if let Some(id) = session_id {
            SessionId::new(String::from_utf8_lossy(id).to_string())
        } else {
            SessionId::new_v7()
        };

        self.init_session(
            &sid,
            message.to_vec(),
            TaprootTweak::None,
            participant_pubkeys,
            None,
        )?;

        let user_id = UserId::new_v7();
        let signer_index = 0;

        let _pub_nonce = self.generate_nonce(&sid, &user_id, signer_index, key_material)?;

        // Update session metadata phase to allow signing
        let session_meta = self.get_session_metadata_mut(&sid)?;
        session_meta.phase = SessionPhase::NonceAggregation;

        self.sign(&sid, &user_id, key_material)
    }
}

impl Default for MusigProcessor {
    fn default() -> Self {
        Self::new()
    }
}

pub struct MusigSession {
    pub session_id: SessionId,
    pub message: Vec<u8>,
    pub key_agg_ctx: Option<KeyAggContext>,
    pub participants: Vec<PublicKey>,
    pub nonces: BTreeMap<UserId, PubNonce>,
    pub phase: SessionPhase,
    pub first_round: Option<FirstRound>,
    pub second_round: Option<SecondRound<Vec<u8>>>,
    pub expected_participant_count: Option<usize>,
}

impl std::fmt::Debug for MusigSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MusigSession")
            .field("session_id", &self.session_id)
            .field("message", &self.message)
            .field("key_agg_ctx", &self.key_agg_ctx.is_some())
            .field("participants", &self.participants)
            .field("nonces", &self.nonces)
            .field("phase", &self.phase)
            .field("first_round", &self.first_round.is_some())
            .field("second_round", &self.second_round.is_some())
            .field(
                "expected_participant_count",
                &self.expected_participant_count,
            )
            .finish()
    }
}

impl Clone for MusigSession {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            message: self.message.clone(),
            key_agg_ctx: self.key_agg_ctx.clone(),
            participants: self.participants.clone(),
            nonces: self.nonces.clone(),
            phase: self.phase.clone(),
            first_round: None,  // Cannot clone FirstRound, reset to None
            second_round: None, // Cannot clone SecondRound, reset to None
            expected_participant_count: self.expected_participant_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use musig2::secp256k1::Secp256k1;
    use rand::rng;
    #[test]
    fn test_musig_session_creation() {
        let mut processor = MusigProcessor::new();

        let secp = Secp256k1::new();
        let (_secret_key, public_key) = secp.generate_keypair(&mut rng());

        let participants = vec![public_key];

        let session_id = SessionId::new("test_session");
        let result = processor.init_session(
            &session_id,
            vec![1, 2, 3],
            TaprootTweak::None,
            participants,
            Some(2),
        );

        // Session creation should succeed with 1 participant, but be in CollectingParticipants phase
        assert!(result.is_ok());

        let session_meta = processor.get_session_metadata_public(&session_id).unwrap();
        assert!(matches!(
            session_meta.phase,
            SessionPhase::CollectingParticipants
        ));
    }

    #[test]
    fn test_nonce_generation() {
        let mut processor = MusigProcessor::new();

        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng());
        let (_secret_key2, public_key2) = secp.generate_keypair(&mut rng());

        let participants = std::vec![public_key, public_key2];

        let session_id = SessionId::new("test_session");
        processor
            .init_session(
                &session_id,
                std::vec![1, 2, 3, 4],
                TaprootTweak::None,
                participants,
                Some(2),
            )
            .unwrap();

        let key_material = KeyMaterial::new(secret_key.secret_bytes().to_vec());
        let user_id = UserId::new_v7();

        let result = processor.generate_nonce(&session_id, &user_id, 0, &key_material);
        assert!(result.is_ok());

        // Check that the user session was created with the nonce
        let user_key = (session_id.clone(), user_id.clone());
        let user_session = processor.user_sessions.get(&user_key).unwrap();
        assert!(user_session.musig_session.nonces.contains_key(&user_id));
    }
}
