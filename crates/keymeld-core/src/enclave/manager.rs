use crate::{
    api::TaprootTweak,
    enclave::{
        protocol::EnclavePublicKeyInfo, AddNonceCommand, AddPartialSignatureCommand,
        GenerateNonceCommand, InitKeygenSessionCommand, InitSigningSessionCommand,
        ParitialSignatureCommand,
    },
    identifiers::{EnclaveId, SessionId, UserId},
    resilience::{RetryConfig, TimeoutConfig},
    AggregatePublicKey, KeyMeldError, ParticipantData,
};
use governor::{clock::DefaultClock, Quota, RateLimiter};
use musig2::PubNonce;
use std::num::NonZeroU32;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::{
    client::VsockClient,
    distribution::{EnclaveAssignmentManager, SessionAssignment},
    protocol::{
        AddParticipantCommand, AttestationResponse, DistributeSessionSecretCommand, EnclaveCommand,
        EnclaveResponse, FinalizeCommand, GetAggregateNonceCommand, GetAggregatePublicKeyCommand,
        ValidateKeygenParticipantHmacCommand, ValidateSessionHmacCommand,
    },
};

#[derive(Debug, Clone)]
pub struct SessionHmacValidationParams {
    pub enclave_id: EnclaveId,
    pub signing_session_id: Option<SessionId>,
    pub keygen_session_id: Option<SessionId>,
    pub user_id: UserId,
    pub message_hash: Vec<u8>,
    pub session_hmac: String,
    pub encrypted_session_secret: String,
}

#[derive(Debug, Clone)]
pub struct SigningSessionInitParams {
    pub keygen_session_id: SessionId,
    pub signing_session_id: SessionId,
    pub encrypted_message: String,
    pub participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub taproot_tweak: TaprootTweak,
}

#[derive(Debug, Clone)]
pub struct EnclaveConfig {
    pub id: u32,
    pub cid: u32,
    pub port: u32,
}

#[derive(Debug, Clone)]
pub struct EnclaveInfo {
    pub cid: u32,
    pub port: u32,
    pub startup_time: SystemTime,
    pub key_epoch: u64,
    pub public_key: Option<Vec<u8>>,
    pub key_generation_time: SystemTime,
    pub attestation_document: Option<String>,
}

pub struct EnclaveManager {
    clients: BTreeMap<EnclaveId, VsockClient>,
    enclave_info: Arc<Mutex<BTreeMap<EnclaveId, EnclaveInfo>>>,
    is_configured: bool,
    assignment_manager: RwLock<EnclaveAssignmentManager>,
    timeout_config: TimeoutConfig,
    retry_config: RetryConfig,
    rate_limiters: BTreeMap<
        EnclaveId,
        Arc<
            RateLimiter<
                governor::state::direct::NotKeyed,
                governor::state::InMemoryState,
                DefaultClock,
                governor::middleware::NoOpMiddleware,
            >,
        >,
    >,
}

impl EnclaveManager {
    pub fn new(enclave_configs: Vec<EnclaveConfig>) -> Result<Self, KeyMeldError> {
        Self::new_with_config(
            enclave_configs,
            TimeoutConfig::default(),
            RetryConfig::default(),
            50, // Default max connections per enclave
        )
    }

    async fn collect_enclave_public_keys(
        &self,
        enclave_ids: &[EnclaveId],
    ) -> Result<Vec<EnclavePublicKeyInfo>, KeyMeldError> {
        let mut keys = Vec::new();
        for enclave_id in enclave_ids {
            let public_key = self.get_enclave_public_key(enclave_id).await?;
            keys.push(EnclavePublicKeyInfo {
                enclave_id: *enclave_id,
                public_key,
            });
        }
        Ok(keys)
    }

    pub fn new_with_config(
        enclave_configs: Vec<EnclaveConfig>,
        timeout_config: TimeoutConfig,
        retry_config: RetryConfig,
        max_connections_per_enclave: usize,
    ) -> Result<Self, KeyMeldError> {
        let mut clients = BTreeMap::new();
        let mut enclave_info = BTreeMap::new();
        let mut rate_limiters = BTreeMap::new();

        let now = SystemTime::now();
        let quota = Quota::per_second(
            NonZeroU32::new(max_connections_per_enclave as u32).ok_or_else(|| {
                KeyMeldError::InvalidConfiguration(
                    "max_connections_per_enclave must be greater than 0".to_string(),
                )
            })?,
        );

        for config in enclave_configs {
            let enclave_id = EnclaveId::from(config.id);
            let client = VsockClient::with_config(config.cid, config.port, &timeout_config);

            let info = EnclaveInfo {
                cid: config.cid,
                port: config.port,
                startup_time: now,
                key_epoch: 1,
                public_key: None,
                key_generation_time: now,
                attestation_document: None,
            };

            let rate_limiter = Arc::new(RateLimiter::direct(quota));

            clients.insert(enclave_id, client);
            enclave_info.insert(enclave_id, info);
            rate_limiters.insert(enclave_id, rate_limiter);
        }

        let available_enclaves: Vec<EnclaveId> = clients.keys().cloned().collect();
        let assignment_manager = EnclaveAssignmentManager::new(available_enclaves);

        Ok(Self {
            clients,
            enclave_info: Arc::new(Mutex::new(enclave_info)),
            is_configured: false,
            assignment_manager: RwLock::new(assignment_manager),
            timeout_config,
            retry_config,
            rate_limiters,
        })
    }

    pub async fn configure_all(&mut self, region: String) -> Result<(), KeyMeldError> {
        for (enclave_id, client) in &self.clients {
            client.configure(region.clone(), *enclave_id).await?;
        }
        self.is_configured = true;
        Ok(())
    }

    pub fn get_enclave_client(&self, enclave_id: &EnclaveId) -> Option<&VsockClient> {
        self.clients.get(enclave_id)
    }

    pub fn handle_enclave_restart(&self, enclave_id: &EnclaveId) -> Result<(), KeyMeldError> {
        let mut info_map = self
            .enclave_info
            .lock()
            .map_err(|_| KeyMeldError::EnclaveError("Failed to lock enclave info".to_string()))?;

        if let Some(info) = info_map.get_mut(enclave_id) {
            let is_restart = info
                .key_generation_time
                .elapsed()
                .unwrap_or_default()
                .as_secs()
                > 300;

            if is_restart {
                debug!(
                    "Enclave {} restart detected, incrementing key epoch",
                    enclave_id
                );
                info.key_epoch += 1;
                info.key_generation_time = SystemTime::now();
                info.attestation_document = None;
            }
        }

        Ok(())
    }

    pub fn get_enclave_key_epoch(&self, enclave_id: &EnclaveId) -> Option<u64> {
        self.enclave_info
            .lock()
            .ok()?
            .get(enclave_id)
            .map(|info| info.key_epoch)
    }

    pub fn update_enclave_attestation(&self, enclave_id: &EnclaveId, attestation: String) {
        if let Ok(mut info_map) = self.enclave_info.lock() {
            if let Some(info) = info_map.get_mut(enclave_id) {
                info.attestation_document = Some(attestation);
            }
        }
    }

    pub fn clients(&self) -> &BTreeMap<EnclaveId, VsockClient> {
        &self.clients
    }

    pub fn create_session_assignment(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
    ) -> Result<SessionAssignment, KeyMeldError> {
        self.assignment_manager
            .write()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {}", e))
            })?
            .assign_enclaves_for_session(session_id, user_ids)
    }

    pub fn create_session_assignment_with_coordinator(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_enclave_id: EnclaveId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        self.assignment_manager
            .write()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {}", e))
            })?
            .assign_enclaves_for_session_with_coordinator(
                session_id,
                user_ids,
                coordinator_enclave_id,
            )
    }

    pub fn copy_session_assignment_for_signing(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: SessionId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        self.assignment_manager
            .write()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {}", e))
            })?
            .copy_session_assignment_for_signing(keygen_session_id, signing_session_id)
    }

    pub fn get_session_assignment(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionAssignment>, KeyMeldError> {
        Ok(self
            .assignment_manager
            .read()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {}", e))
            })?
            .get_session_assignment(session_id))
    }

    pub fn remove_session_assignment(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionAssignment>, KeyMeldError> {
        Ok(self
            .assignment_manager
            .write()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {}", e))
            })?
            .remove_session(session_id))
    }

    pub fn restore_session_assignment(
        &self,
        assignment: SessionAssignment,
    ) -> Result<(), KeyMeldError> {
        self.assignment_manager
            .write()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {}", e))
            })?
            .restore_session_assignment(assignment);
        Ok(())
    }

    pub fn enclave_info(&self) -> Result<BTreeMap<EnclaveId, EnclaveInfo>, KeyMeldError> {
        self.enclave_info
            .lock()
            .map(|guard| guard.clone())
            .map_err(|_| KeyMeldError::EnclaveError("Failed to lock enclave info".to_string()))
    }

    pub async fn health_check(&self) -> BTreeMap<EnclaveId, bool> {
        let mut results = BTreeMap::new();
        for (enclave_id, client) in &self.clients {
            let healthy = client.health_check().await.unwrap_or(false);
            results.insert(*enclave_id, healthy);
        }
        results
    }

    pub fn get_enclave_info(&self, enclave_id: &EnclaveId) -> Option<EnclaveInfo> {
        self.enclave_info.lock().ok()?.get(enclave_id).cloned()
    }

    pub fn is_configured(&self) -> bool {
        self.is_configured
    }

    pub fn list_enclaves(&self) -> Vec<EnclaveId> {
        self.clients.keys().cloned().collect()
    }

    pub async fn send_command_to_enclave(
        &self,
        enclave_id: &EnclaveId,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        let start_time = std::time::Instant::now();

        // Check rate limiter before proceeding - clone the Arc for thread safety
        let rate_limiter = self
            .rate_limiters
            .get(enclave_id)
            .ok_or_else(|| {
                error!("Rate limiter not found for enclave {}", enclave_id);
                KeyMeldError::EnclaveError(format!(
                    "Rate limiter not found for enclave {}",
                    enclave_id
                ))
            })?
            .clone();

        // Check if we can proceed (non-blocking check)
        match rate_limiter.check() {
            Ok(_) => {}
            Err(_) => {
                error!("Rate limit exceeded for enclave {}", enclave_id);
                return Err(KeyMeldError::EnclaveError(format!(
                    "Rate limit exceeded for enclave {}",
                    enclave_id
                )));
            }
        }

        let client = self.clients.get(enclave_id).ok_or_else(|| {
            error!("Client not found for enclave {}", enclave_id);
            KeyMeldError::EnclaveError(format!("Enclave {} not found", enclave_id))
        })?;

        match client.send_command(command).await {
            Ok(response) => {
                let elapsed = start_time.elapsed();
                debug!(
                    "Command successful to enclave {} in {:?}, response type: {:?}",
                    enclave_id,
                    elapsed,
                    std::mem::discriminant(&response)
                );
                Ok(response)
            }
            Err(e) => {
                let elapsed = start_time.elapsed();
                error!(
                    "Command failed to enclave {} after {:?}: {}",
                    enclave_id, elapsed, e
                );
                Err(e)
            }
        }
    }

    pub async fn execute_with_retry<F, T, R>(
        &self,
        enclave_id: &EnclaveId,
        command_fn: F,
        response_mapper: R,
    ) -> Result<T, KeyMeldError>
    where
        F: Fn() -> EnclaveCommand + Send + Sync,
        R: Fn(EnclaveResponse) -> Result<T, KeyMeldError> + Send + Sync,
        T: Send,
    {
        let mut last_error = None;

        for attempt in 0..self.retry_config.max_attempts {
            if attempt > 0 {
                let delay = self.retry_config.delay_for_attempt(attempt - 1);
                debug!(
                    "Retrying command to enclave {} after delay {:?} (attempt {}/{})",
                    enclave_id,
                    delay,
                    attempt + 1,
                    self.retry_config.max_attempts
                );
                sleep(delay).await;
            }

            match self.send_command_to_enclave(enclave_id, command_fn()).await {
                Ok(response) => match response_mapper(response) {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        warn!(
                            "Response mapping failed for enclave {} (attempt {}/{}): {}",
                            enclave_id,
                            attempt + 1,
                            self.retry_config.max_attempts,
                            e
                        );
                        last_error = Some(e);
                        continue;
                    }
                },
                Err(e) => {
                    warn!(
                        "Command failed for enclave {} (attempt {}/{}): {}",
                        enclave_id,
                        attempt + 1,
                        self.retry_config.max_attempts,
                        e
                    );
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            KeyMeldError::EnclaveError(format!(
                "All retry attempts failed for enclave {}",
                enclave_id
            ))
        }))
    }

    pub async fn get_aggregate_public_key(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let command = GetAggregatePublicKeyCommand {
            keygen_session_id: keygen_session_id.clone(),
        };

        let Some(session_assignment) = self.get_session_assignment(keygen_session_id)? else {
            return Err(KeyMeldError::EnclaveError(format!(
                "missing keygen session {}",
                keygen_session_id
            )));
        };

        match self
            .send_command_to_enclave(
                &session_assignment.coordinator_enclave,
                EnclaveCommand::GetAggregatePublicKey(command),
            )
            .await?
        {
            EnclaveResponse::AggregatePublicKey(response) => Ok(response.aggregate_public_key),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response for aggregate public key request: {:?}",
                response
            ))),
        }
    }

    pub async fn get_enclave_public_info(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<(String, Option<AttestationResponse>, u32, u64, u64, u64), KeyMeldError> {
        use super::protocol::{EnclaveCommand, EnclaveResponse};

        match self
            .send_command_to_enclave(enclave_id, EnclaveCommand::GetPublicInfo)
            .await?
        {
            EnclaveResponse::PublicInfo(response) => Ok((
                response.public_key,
                response.attestation_document,
                response.active_sessions,
                response.uptime_seconds,
                response.key_epoch,
                response.key_generation_time,
            )),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(format!(
                "Enclave {} returned error: {}",
                enclave_id, err
            ))),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from enclave {}: {:?}",
                enclave_id, response
            ))),
        }
    }

    pub async fn get_enclave_public_key(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<String, KeyMeldError> {
        let (public_key, _, _, _, _, _) = self.get_enclave_public_info(enclave_id).await?;
        Ok(public_key)
    }

    pub async fn add_participant(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        enclave_id: &EnclaveId,
        session_encrypted_data: String,
        enclave_encrypted_data: String,
    ) -> Result<(), KeyMeldError> {
        let add_participant_cmd = AddParticipantCommand {
            keygen_session_id: Some(session_id.clone()),
            signing_session_id: None,
            user_id: user_id.clone(),
            session_encrypted_data,
            enclave_encrypted_data,
        };

        let response = self
            .send_command_to_enclave(
                enclave_id,
                EnclaveCommand::AddParticipant(add_participant_cmd),
            )
            .await?;

        match response {
            EnclaveResponse::Success(_) => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(format!(
                "Failed to add participant to enclave {}: {}",
                enclave_id, err
            ))),
            _ => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from enclave {} when adding participant",
                enclave_id
            ))),
        }
    }

    pub async fn validate_session_hmac(
        &self,
        params: SessionHmacValidationParams,
    ) -> Result<(), KeyMeldError> {
        let cmd = ValidateSessionHmacCommand {
            signing_session_id: params.signing_session_id,
            keygen_session_id: params.keygen_session_id,
            user_id: params.user_id,
            message_hash: params.message_hash,
            session_hmac: params.session_hmac,
            encrypted_session_secret: params.encrypted_session_secret,
        };

        match self
            .send_command_to_enclave(&params.enclave_id, EnclaveCommand::ValidateSessionHmac(cmd))
            .await?
        {
            EnclaveResponse::Success(_) => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(format!(
                "HMAC validation failed in enclave {}: {}",
                params.enclave_id, err
            ))),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from enclave {} for HMAC validation: {:?}",
                params.enclave_id, response
            ))),
        }
    }

    pub async fn validate_keygen_participant_hmac(
        &self,
        enclave_id: &EnclaveId,
        keygen_session_id: &SessionId,
        user_id: &UserId,
        session_hmac: &str,
        encrypted_session_secret: &str,
    ) -> Result<(), KeyMeldError> {
        let validate_cmd = ValidateKeygenParticipantHmacCommand {
            keygen_session_id: keygen_session_id.clone(),
            user_id: user_id.clone(),
            session_hmac: session_hmac.to_string(),
            encrypted_session_secret: encrypted_session_secret.to_string(),
        };

        match self
            .send_command_to_enclave(
                enclave_id,
                EnclaveCommand::ValidateKeygenParticipantHmac(validate_cmd),
            )
            .await?
        {
            EnclaveResponse::Success(_) => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(format!(
                "Keygen participant HMAC validation failed in enclave {}: {}",
                enclave_id, err
            ))),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from enclave {} for keygen participant HMAC validation: {:?}",
                enclave_id, response
            ))),
        }
    }

    fn calculate_signer_index(
        &self,
        user_id: &UserId,
        participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<usize, KeyMeldError> {
        let mut sorted_participants: Vec<_> = participants.keys().collect();
        sorted_participants.sort();

        sorted_participants
            .iter()
            .position(|&uid| uid == user_id)
            .ok_or_else(|| {
                KeyMeldError::EnclaveError(format!("User {} not found in participants", user_id))
            })
    }

    pub async fn orchestrate_nonce_generation(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
        participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<BTreeMap<UserId, PubNonce>, KeyMeldError> {
        info!(
            "Orchestrating nonce generation for signing session {} with {} participants",
            signing_session_id,
            participants.len()
        );

        let mut generated_nonces = BTreeMap::new();

        for (user_id, participant) in participants {
            let nonce_cmd = GenerateNonceCommand {
                signing_session_id: signing_session_id.clone(),
                keygen_session_id: keygen_session_id.clone(),
                user_id: user_id.clone(),
                signer_index: self.calculate_signer_index(user_id, participants)?,
            };

            // Use standardized retry logic with exponential backoff
            let public_nonce = self
                .execute_with_retry(
                    &participant.enclave_id,
                    || EnclaveCommand::GenerateNonce(nonce_cmd.clone()),
                    |response| match response {
                        EnclaveResponse::Nonce(nonce_response) => Ok(nonce_response.public_nonce),
                        other => Err(KeyMeldError::EnclaveError(format!(
                            "Invalid nonce response: {:?}",
                            other
                        ))),
                    },
                )
                .await?;

            generated_nonces.insert(user_id.clone(), public_nonce);
        }

        let all_enclaves: BTreeSet<EnclaveId> =
            participants.values().map(|p| p.enclave_id).collect();

        info!(
            "Starting nonce distribution phase for {} nonces to {} enclaves",
            generated_nonces.len(),
            all_enclaves.len()
        );

        for (nonce_user_id, nonce) in &generated_nonces {
            let signer_index = self.calculate_signer_index(nonce_user_id, participants)?;

            for enclave_id in &all_enclaves {
                let add_nonce_cmd = AddNonceCommand {
                    signing_session_id: signing_session_id.clone(),
                    keygen_session_id: keygen_session_id.clone(),
                    user_id: nonce_user_id.clone(),
                    signer_index,
                    nonce: nonce.clone(),
                };

                match self
                    .send_command_to_enclave(
                        enclave_id,
                        EnclaveCommand::AddNonce(add_nonce_cmd.clone()),
                    )
                    .await
                {
                    Ok(EnclaveResponse::Success(_)) => {}
                    Ok(response) => {
                        error!(
                            "Unexpected nonce distribution response for user {} to enclave {}: {:?}",
                            nonce_user_id, enclave_id, response
                        );
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Unexpected nonce distribution response for user {} to enclave {}: {:?}",
                            nonce_user_id, enclave_id, response
                        )));
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to distribute nonce for user {} (signer_index={}) to enclave {}: {}",
                            nonce_user_id, signer_index, enclave_id, e
                        );
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to distribute nonce for user {} to enclave {}: {}",
                            nonce_user_id, enclave_id, e
                        )));
                    }
                }
            }
        }

        Ok(generated_nonces)
    }

    pub async fn get_aggregate_nonce(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
    ) -> Result<musig2::AggNonce, KeyMeldError> {
        // Get the session assignment to find the coordinator enclave
        let session_assignment =
            self.get_session_assignment(keygen_session_id)?
                .ok_or_else(|| {
                    KeyMeldError::EnclaveError(format!(
                        "No session assignment found for keygen session {}",
                        keygen_session_id
                    ))
                })?;

        let coordinator_enclave = session_assignment.coordinator_enclave;

        let cmd = GetAggregateNonceCommand {
            signing_session_id: signing_session_id.clone(),
            keygen_session_id: keygen_session_id.clone(),
        };

        // Use the coordinator enclave where the aggregate nonce is stored
        match self
            .send_command_to_enclave(&coordinator_enclave, EnclaveCommand::GetAggregateNonce(cmd))
            .await
        {
            Ok(EnclaveResponse::AggregateNonce(resp)) => {
                // Convert PubNonce back to AggNonce
                let serialized = resp.aggregate_nonce.serialize();
                let agg_nonce = musig2::AggNonce::from_bytes(&serialized).map_err(|e| {
                    KeyMeldError::CryptoError(format!("Invalid aggregate nonce: {}", e))
                })?;
                Ok(agg_nonce)
            }
            Ok(_) => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from coordinator enclave {} for aggregate nonce",
                coordinator_enclave.as_u32()
            ))),
            Err(e) => Err(KeyMeldError::EnclaveError(format!(
                "Failed to get aggregate nonce from coordinator enclave {}: {}",
                coordinator_enclave.as_u32(),
                e
            ))),
        }
    }

    pub async fn finalize_signature(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
    ) -> Result<Vec<u8>, KeyMeldError> {
        // Get the session assignment to find the coordinator enclave
        let session_assignment =
            self.get_session_assignment(keygen_session_id)?
                .ok_or_else(|| {
                    KeyMeldError::EnclaveError(format!(
                        "No session assignment found for keygen session {}",
                        keygen_session_id
                    ))
                })?;

        let coordinator_enclave = session_assignment.coordinator_enclave;

        let cmd = FinalizeCommand {
            signing_session_id: signing_session_id.clone(),
            keygen_session_id: keygen_session_id.clone(),
        };

        // Use the coordinator enclave where the final signature aggregation happens
        match self
            .send_command_to_enclave(&coordinator_enclave, EnclaveCommand::Finalize(cmd))
            .await
        {
            Ok(EnclaveResponse::FinalSignature(resp)) => Ok(resp.final_signature),
            Ok(_) => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from coordinator enclave {} for signature finalization",
                coordinator_enclave.as_u32()
            ))),
            Err(e) => Err(KeyMeldError::EnclaveError(format!(
                "Failed to finalize signature with coordinator enclave {}: {}",
                coordinator_enclave.as_u32(),
                e
            ))),
        }
    }

    pub async fn orchestrate_partial_signatures(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
        participants: &BTreeMap<UserId, ParticipantData>,
        aggregate_nonce: &musig2::PubNonce,
    ) -> Result<BTreeMap<UserId, musig2::PartialSignature>, KeyMeldError> {
        let mut partial_signatures = BTreeMap::new();

        info!(
            "Starting partial signature generation for signing session {} with {} participants",
            signing_session_id,
            participants.len()
        );

        let mut successful_signatures = 0;

        for (user_id, participant) in participants {
            // Check if participant already has a signature
            if participant.partial_signature.is_some() {
                debug!(
                    "✅ User {} already has partial signature, skipping generation",
                    user_id
                );
                if let Some(existing_sig) = &participant.partial_signature {
                    partial_signatures.insert(user_id.clone(), *existing_sig);
                    successful_signatures += 1;
                    continue;
                }
            }
            let sig_cmd = ParitialSignatureCommand {
                signing_session_id: signing_session_id.clone(),
                keygen_session_id: keygen_session_id.clone(),
                user_id: user_id.clone(),
                aggregate_nonce: aggregate_nonce.clone(),
            };

            match self
                .send_command_to_enclave(
                    &participant.enclave_id,
                    EnclaveCommand::SignPartialSignature(sig_cmd),
                )
                .await
            {
                Ok(response) => {
                    if let EnclaveResponse::Signature(sig_resp) = response {
                        partial_signatures.insert(user_id.clone(), sig_resp.partial_signature);
                        successful_signatures += 1;
                        debug!(
                            "✅ Generated partial signature for user {} ({}/{})",
                            user_id,
                            successful_signatures,
                            participants.len()
                        );
                    } else {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Invalid signature response from enclave for user {}",
                            user_id
                        )));
                    }
                }
                Err(e) => {
                    warn!(
                        "⚠️ Failed to generate partial signature for user {}: {}",
                        user_id, e
                    );
                    return Err(e);
                }
            }
        }

        info!(
            "Completed partial signature generation: {}/{} successful",
            successful_signatures,
            participants.len()
        );

        let all_enclaves: BTreeSet<EnclaveId> =
            participants.values().map(|p| p.enclave_id).collect();

        for (sig_user_id, partial_signature) in &partial_signatures {
            let signer_index = self.calculate_signer_index(sig_user_id, participants)?;

            for enclave_id in &all_enclaves {
                let add_signature_cmd = AddPartialSignatureCommand {
                    signing_session_id: signing_session_id.clone(),
                    keygen_session_id: keygen_session_id.clone(),
                    user_id: sig_user_id.clone(),
                    signer_index,
                    signature: *partial_signature,
                };

                match self
                    .send_command_to_enclave(
                        enclave_id,
                        EnclaveCommand::AddPartialSignature(add_signature_cmd),
                    )
                    .await
                {
                    Ok(EnclaveResponse::Success(_)) => {}
                    Ok(response) => {
                        warn!(
                            "Unexpected partial signature distribution response: {:?}",
                            response
                        );
                    }
                    Err(e) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to distribute partial signature: {}",
                            e
                        )));
                    }
                }
            }
        }

        Ok(partial_signatures)
    }

    pub async fn orchestrate_signing_session_initialization(
        &self,
        params: SigningSessionInitParams,
    ) -> Result<(), KeyMeldError> {
        info!(
            "🚀 Starting optimized signing session initialization for session {} with {} participants",
            params.signing_session_id,
            params.participants.len()
        );

        for (user_id, participant_data) in &params.participants {
            debug!(
                "📋 Participant {} assigned to enclave {} with enclave_data_len={}",
                user_id,
                participant_data.enclave_id,
                participant_data.enclave_encrypted_data.len()
            );
        }
        let session_assignment = self
            .get_session_assignment(&params.keygen_session_id)?
            .ok_or_else(|| {
                KeyMeldError::EnclaveError(format!(
                    "No session assignment found for keygen session {}",
                    params.keygen_session_id
                ))
            })?;

        let coordinator_enclave_id = session_assignment.coordinator_enclave;

        let mut enclave_participants: BTreeMap<EnclaveId, Vec<(&UserId, &ParticipantData)>> =
            BTreeMap::new();
        let mut all_required_enclaves = std::collections::BTreeSet::new();

        for (user_id, participant_data) in &params.participants {
            enclave_participants
                .entry(participant_data.enclave_id)
                .or_default()
                .push((user_id, participant_data));
            all_required_enclaves.insert(participant_data.enclave_id);
        }

        // Initialize sessions in all enclaves that have participants
        let mut successfully_initialized_enclaves = std::collections::BTreeSet::new();
        for enclave_id in enclave_participants.keys() {
            let init_cmd = InitSigningSessionCommand {
                keygen_session_id: params.keygen_session_id.clone(),
                signing_session_id: params.signing_session_id.clone(),
                encrypted_message: params.encrypted_message.clone(),
                coordinator_encrypted_private_key: if *enclave_id == coordinator_enclave_id {
                    params.coordinator_encrypted_private_key.clone()
                } else {
                    None
                },
                encrypted_session_secret: if *enclave_id == coordinator_enclave_id {
                    params.encrypted_session_secret.clone()
                } else {
                    None
                },
                timeout_secs: self.timeout_config.session_init_timeout_secs,
                taproot_tweak: params.taproot_tweak.clone(),
                expected_participant_count: params.participants.len(),
            };

            match self
                .send_command_to_enclave(enclave_id, EnclaveCommand::InitSigningSession(init_cmd))
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully initialized signing session on enclave {}",
                        enclave_id
                    );
                    successfully_initialized_enclaves.insert(*enclave_id);
                }
                Err(e) => {
                    error!(
                        "❌ CRITICAL: Failed to initialize signing session on enclave {}: {}",
                        enclave_id, e
                    );
                    // DO NOT skip this enclave - we need all enclaves to work
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Failed to initialize signing session on required enclave {}: {}. Cannot proceed without all enclaves.",
                        enclave_id, e
                    )));
                }
            }
        }

        // Add participants only to their assigned enclaves for optimal distribution
        debug!(
            "🔄 Adding participants to their assigned enclaves for signing session {}",
            params.signing_session_id
        );
        let mut successful_additions = 0;
        let mut failed_enclaves = Vec::new();
        let total_additions = params.participants.len();

        for (user_id, participant) in &params.participants {
            let assigned_enclave_id = participant.enclave_id;

            // Only process if this enclave was successfully initialized
            if !successfully_initialized_enclaves.contains(&assigned_enclave_id) {
                error!(
                    "❌ Skipping participant {} - assigned enclave {} was not successfully initialized",
                    user_id, assigned_enclave_id
                );
                failed_enclaves.push((
                    assigned_enclave_id,
                    user_id.clone(),
                    KeyMeldError::EnclaveError("Assigned enclave not initialized".to_string()),
                ));
                continue;
            }

            debug!(
                "Processing AddParticipant for user {} on their assigned enclave {}",
                user_id, assigned_enclave_id
            );

            let add_participant_cmd = AddParticipantCommand {
                keygen_session_id: Some(params.keygen_session_id.clone()),
                signing_session_id: Some(params.signing_session_id.clone()),
                user_id: user_id.clone(),
                session_encrypted_data: participant.session_encrypted_data.clone(),
                enclave_encrypted_data: participant.enclave_encrypted_data.clone(),
            };

            let mut attempts = 0;
            //TODO(@tee8z): make configurable
            const MAX_ATTEMPTS: u32 = 3;

            loop {
                attempts += 1;
                debug!(
                    "Sending AddParticipant command for user {} to enclave {} (attempt {})",
                    user_id, assigned_enclave_id, attempts
                );

                match self
                    .send_command_to_enclave(
                        &assigned_enclave_id,
                        EnclaveCommand::AddParticipant(add_participant_cmd.clone()),
                    )
                    .await
                {
                    Ok(_) => {
                        successful_additions += 1;
                        info!(
                            "Successfully added participant {} to enclave {} ({}/{})",
                            user_id, assigned_enclave_id, successful_additions, total_additions
                        );
                        break;
                    }
                    Err(e) => {
                        if attempts >= MAX_ATTEMPTS {
                            error!("❌ Failed to add participant {} to enclave {} after {} attempts: {}",
                                user_id, assigned_enclave_id, MAX_ATTEMPTS, e);
                            failed_enclaves.push((assigned_enclave_id, user_id.clone(), e));
                            break; // Exit retry loop for this participant
                        } else {
                            warn!("⚠️ Failed to add participant {} to enclave {} (attempt {}), retrying: {}",
                                user_id, assigned_enclave_id, attempts, e);
                            sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }

        info!(
            "🎉 Completed signing session initialization for session {} - added {} participants to their assigned enclaves",
            params.signing_session_id, successful_additions
        );

        if !failed_enclaves.is_empty() {
            warn!(
                "⚠️ Some participant additions failed: {} failures",
                failed_enclaves.len()
            );
            for (enclave_id, user_id, error) in &failed_enclaves {
                debug!(
                    "Failed to add participant {} to enclave {}: {}",
                    user_id, enclave_id, error
                );
            }

            // If any participants failed to be added, the session cannot proceed
            return Err(KeyMeldError::EnclaveError(format!(
                "Signing session initialization failed: {} participants could not be added to their assigned enclaves",
                failed_enclaves.len()
            )));
        }

        if successfully_initialized_enclaves.is_empty() {
            return Err(KeyMeldError::EnclaveError(
                "Signing session initialization failed: no enclaves were successfully initialized"
                    .to_string(),
            ));
        }

        // Verify all participants were successfully added to their assigned enclaves
        if successful_additions != params.participants.len() {
            error!(
                "🚨 Participant distribution incomplete: {}/{} participants successfully added",
                successful_additions,
                params.participants.len()
            );
            return Err(KeyMeldError::EnclaveError(format!(
                "Signing session initialization partially failed: only {}/{} participants were successfully added to their assigned enclaves",
                successful_additions,
                params.participants.len()
            )));
        }

        info!(
            "✅ All {} participants successfully added to their assigned enclaves",
            params.participants.len()
        );

        Ok(())
    }

    pub async fn orchestrate_keygen_session_initialization(
        &self,
        keygen_session_id: &SessionId,
        coordinator_enclave_id: &EnclaveId,
        coordinator_encrypted_private_key: &str,
        encrypted_session_secret: &str,
        participants: &BTreeMap<UserId, ParticipantData>,
        taproot_tweak_config: &TaprootTweak,
    ) -> Result<AggregatePublicKey, KeyMeldError> {
        debug!(
            "Participants count: {}, details: {:?}",
            participants.len(),
            participants.keys().collect::<Vec<_>>()
        );

        let session_assignment =
            self.get_session_assignment(keygen_session_id)?
                .ok_or_else(|| {
                    error!(
                        "No session assignment found for session {}",
                        keygen_session_id
                    );
                    KeyMeldError::EnclaveError(format!(
                        "No session assignment found for session {}",
                        keygen_session_id
                    ))
                })?;

        debug!(
            "Found session assignment for session {} with {} enclaves",
            keygen_session_id,
            session_assignment.get_all_assigned_enclaves().len()
        );

        let enclaves_with_participants = session_assignment.get_all_assigned_enclaves();

        debug!(
            "Starting enclave initialization phase for {} enclaves",
            enclaves_with_participants.len()
        );

        let all_enclave_public_keys = self
            .collect_enclave_public_keys(&enclaves_with_participants)
            .await?;

        // Phase 1: Initialize keygen sessions on all enclaves
        let mut coordinator_encrypted_secrets = Vec::new();
        for enclave_id in &enclaves_with_participants {
            let init_cmd = InitKeygenSessionCommand {
                keygen_session_id: keygen_session_id.clone(),
                coordinator_encrypted_private_key: if *enclave_id == *coordinator_enclave_id {
                    Some(coordinator_encrypted_private_key.to_string())
                } else {
                    None
                },
                encrypted_session_secret: if *enclave_id == *coordinator_enclave_id {
                    Some(encrypted_session_secret.to_string())
                } else {
                    None
                },
                timeout_secs: 1800,
                taproot_tweak: taproot_tweak_config.clone(),
                expected_participant_count: participants.len(),
                enclave_public_keys: if *enclave_id == *coordinator_enclave_id {
                    all_enclave_public_keys.clone()
                } else {
                    vec![] // Non-coordinator enclaves don't need other enclave keys
                },
            };

            match self
                .send_command_to_enclave(enclave_id, EnclaveCommand::InitKeygenSession(init_cmd))
                .await?
            {
                EnclaveResponse::KeygenInitialized(response)
                    if *enclave_id == *coordinator_enclave_id =>
                {
                    info!(
                        "✅ Coordinator enclave {} initialized and encrypted session secret for {} other enclaves",
                        enclave_id, response.encrypted_session_secrets.len()
                    );
                    coordinator_encrypted_secrets = response.encrypted_session_secrets;
                }
                EnclaveResponse::Success(_) => {
                    debug!(
                        "Successfully initialized keygen session {} in enclave {}",
                        keygen_session_id, enclave_id
                    );
                }
                response => {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response from enclave {} during keygen initialization: {:?}",
                        enclave_id, response
                    )));
                }
            }
        }

        // Phase 2: Distribute session secrets to non-coordinator enclaves
        for encrypted_secret in coordinator_encrypted_secrets {
            let command = DistributeSessionSecretCommand {
                keygen_session_id: keygen_session_id.clone(),
                encrypted_session_secret: encrypted_secret.encrypted_session_secret,
            };

            match self
                .send_command_to_enclave(
                    &encrypted_secret.target_enclave_id,
                    EnclaveCommand::DistributeSessionSecret(command),
                )
                .await?
            {
                EnclaveResponse::Success(_) => {
                    info!(
                        "✅ Distributed session secret to enclave {} after initialization",
                        encrypted_secret.target_enclave_id
                    );
                }
                response => {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response from enclave {} during session secret distribution: {:?}",
                        encrypted_secret.target_enclave_id, response
                    )));
                }
            }
        }

        // Add participant data to all involved enclaves for aggregate key computation
        // NOTE: In MuSig2 keygen, involved enclaves need participant public keys
        // for aggregate key computation. Private keys are only sent to assigned enclaves.
        info!(
            "Adding {} participants to {} enclaves for keygen session {} (MuSig2 aggregate key computation)",
            participants.len(),
            enclaves_with_participants.len(),
            keygen_session_id
        );
        for enclave_id in &enclaves_with_participants {
            info!("Processing participants for enclave {}", enclave_id);
            debug!(
                "Starting participant loop for enclave {}, total participants: {}",
                enclave_id,
                participants.len()
            );
            for (user_id, participant) in participants {
                info!(
                    "Adding participant {} to enclave {} (participant's assigned enclave: {})",
                    user_id, enclave_id, participant.enclave_id
                );
                // Only provide private key material to the participant's assigned enclave
                // Public key data is shared as needed for MuSig2 operations
                let enclave_encrypted_data = if *enclave_id == participant.enclave_id {
                    debug!(
                        "✅ Providing private key data for user {} to their assigned enclave {}",
                        user_id, enclave_id
                    );
                    participant.enclave_encrypted_data.clone()
                } else {
                    debug!(
                        "🔐 Only providing public key data for user {} to non-assigned enclave {}",
                        user_id, enclave_id
                    );
                    String::new()
                };

                let add_participant_cmd = AddParticipantCommand {
                    keygen_session_id: Some(keygen_session_id.clone()),
                    signing_session_id: None,
                    user_id: user_id.clone(),
                    session_encrypted_data: participant.session_encrypted_data.clone(),
                    enclave_encrypted_data,
                };

                debug!(
                    "About to send AddParticipant command for user {} to enclave {}",
                    user_id, enclave_id
                );

                match self
                    .send_command_to_enclave(
                        enclave_id,
                        EnclaveCommand::AddParticipant(add_participant_cmd),
                    )
                    .await
                {
                    Ok(_response) => {
                        info!(
                            "Successfully added participant {} to enclave {}",
                            user_id, enclave_id,
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to add participant {} to enclave {}: {}",
                            user_id, enclave_id, e
                        );
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to add participant {} to enclave {}: {}",
                            user_id, enclave_id, e
                        )));
                    }
                }

                debug!(
                    "Completed AddParticipant command for user {} to enclave {}",
                    user_id, enclave_id
                );
            }

            info!(
                "Completed adding all participants to enclave {}",
                enclave_id
            );
        }

        info!(
            "Participant addition phase completed for session {}, getting aggregate public key",
            keygen_session_id
        );

        let aggregate_public_key_bytes = self.get_aggregate_public_key(keygen_session_id).await?;

        info!(
            "Keygen session initialization completed successfully for session {}",
            keygen_session_id
        );

        Ok(aggregate_public_key_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::TaprootTweak,
        enclave::distribution::EnclaveAssignmentManager,
        identifiers::{EnclaveId, SessionId, UserId},
        ParticipantData,
    };
    use std::collections::{BTreeMap, HashSet};
    use std::sync::{Arc, RwLock};

    fn create_test_manager() -> EnclaveManager {
        let assignment_manager = RwLock::new(EnclaveAssignmentManager::new(vec![
            EnclaveId::from(0),
            EnclaveId::from(1),
            EnclaveId::from(2),
        ]));

        EnclaveManager {
            clients: BTreeMap::new(),
            enclave_info: Arc::new(Mutex::new(BTreeMap::new())),
            is_configured: false,
            assignment_manager,
            timeout_config: TimeoutConfig::default(),
            retry_config: RetryConfig::default(),
            rate_limiters: BTreeMap::new(),
        }
    }

    fn create_test_participants() -> BTreeMap<UserId, ParticipantData> {
        let mut participants = BTreeMap::new();

        for i in 0..3 {
            let user_id = UserId::new_v7();
            let participant = ParticipantData {
                user_id: user_id.clone(),
                enclave_id: EnclaveId::from(i),
                enclave_key_epoch: 1,
                public_nonces: None,
                partial_signature: None,
                session_encrypted_data: format!("session_data_{}", i),
                enclave_encrypted_data: format!("enclave_data_{}", i),
            };
            participants.insert(user_id, participant);
        }

        participants
    }

    #[test]
    fn test_participant_assignment_optimization() {
        let participants = create_test_participants();

        let assigned_enclaves: HashSet<_> = participants.values().map(|p| p.enclave_id).collect();

        assert_eq!(
            assigned_enclaves.len(),
            3,
            "Each participant should be on a different enclave"
        );
        assert!(assigned_enclaves.contains(&EnclaveId::from(0)));
        assert!(assigned_enclaves.contains(&EnclaveId::from(1)));
        assert!(assigned_enclaves.contains(&EnclaveId::from(2)));
    }

    #[test]
    fn test_signing_session_init_params_structure() {
        let keygen_session_id = SessionId::new_v7();
        let signing_session_id = SessionId::new_v7();
        let participants = create_test_participants();

        let params = SigningSessionInitParams {
            keygen_session_id: keygen_session_id.clone(),
            signing_session_id: signing_session_id.clone(),
            encrypted_message: "test_message".to_string(),
            participants: participants.clone(),
            coordinator_encrypted_private_key: Some("coordinator_key".to_string()),
            encrypted_session_secret: Some("session_secret".to_string()),
            taproot_tweak: TaprootTweak::UnspendableTaproot,
        };

        assert_eq!(params.participants.len(), 3);
        assert!(params.coordinator_encrypted_private_key.is_some());
        assert!(params.encrypted_session_secret.is_some());
    }

    #[test]
    fn test_enclave_participant_mapping() {
        let participants = create_test_participants();
        let mut enclave_participants: BTreeMap<EnclaveId, Vec<(&UserId, &ParticipantData)>> =
            BTreeMap::new();

        for (user_id, participant_data) in &participants {
            enclave_participants
                .entry(participant_data.enclave_id)
                .or_default()
                .push((user_id, participant_data));
        }

        assert!(
            enclave_participants.len() <= 3,
            "Should have at most 3 enclaves with participants"
        );
        assert!(
            !enclave_participants.is_empty(),
            "Should have at least one enclave with participants"
        );

        let total_participants_assigned: usize =
            enclave_participants.values().map(|v| v.len()).sum();
        assert_eq!(
            total_participants_assigned,
            participants.len(),
            "All participants should be assigned to enclaves"
        );
    }

    #[test]
    fn test_session_assignment_inheritance() {
        let manager = create_test_manager();
        let keygen_session_id = SessionId::new_v7();
        let signing_session_id = SessionId::new_v7();
        let user_ids: Vec<UserId> = (0..3).map(|_| UserId::new_v7()).collect();

        let keygen_assignment = manager
            .assignment_manager
            .write()
            .unwrap()
            .assign_enclaves_for_session(keygen_session_id.clone(), &user_ids)
            .unwrap();

        let signing_assignment = manager
            .assignment_manager
            .write()
            .unwrap()
            .copy_session_assignment_for_signing(&keygen_session_id, signing_session_id.clone())
            .unwrap();

        assert_eq!(
            keygen_assignment.coordinator_enclave,
            signing_assignment.coordinator_enclave
        );
        assert_eq!(
            keygen_assignment.user_enclave_assignments,
            signing_assignment.user_enclave_assignments
        );

        assert_ne!(keygen_assignment.session_id, signing_assignment.session_id);
    }
}
