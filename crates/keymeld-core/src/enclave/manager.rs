use crate::{
    api::TaprootTweak,
    enclave::{
        protocol::{EnclavePublicKeyInfo, EncryptedSessionSecret, SignatureData},
        AddNonceCommand, AddPartialSignatureCommand, ConfigureCommand, GenerateNonceCommand,
        InitKeygenSessionCommand, InitSigningSessionCommand, ParitialSignatureCommand,
    },
    identifiers::{EnclaveId, SessionId, UserId},
    resilience::{RetryConfig, TimeoutConfig},
    AggregatePublicKey, AttestationDocument, KeyMeldError, ParticipantData,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime},
};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::{
    client::VsockClient,
    distribution::{EnclaveAssignmentManager, SessionAssignment},
    protocol::{
        AddParticipantCommand, DistributeParticipantPublicKeyCommand,
        DistributeSessionSecretCommand, EnclaveCommand, EnclaveResponse, FinalizeCommand,
        GetAggregatePublicKeyCommand,
    },
};

#[derive(Debug, Clone)]
pub struct SigningSessionInitParams {
    pub keygen_session_id: SessionId,
    pub signing_session_id: SessionId,
    pub encrypted_message: String,
    pub participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub taproot_tweak: TaprootTweak,
    pub encrypted_adaptor_configs: String,
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
    pub public_key: Option<String>,
    pub key_generation_time: SystemTime,
    pub attestation_document: Option<AttestationDocument>,
}

pub struct EnclaveManager {
    clients: BTreeMap<EnclaveId, VsockClient>,
    enclave_info: Arc<RwLock<BTreeMap<EnclaveId, EnclaveInfo>>>,
    is_configured: bool,
    assignment_manager: RwLock<EnclaveAssignmentManager>,
    timeout_config: TimeoutConfig,
    retry_config: RetryConfig,
}

impl EnclaveManager {
    pub async fn orchestrate_participant_registration(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        assigned_enclave_id: &EnclaveId,
        enclave_encrypted_data: String,
    ) -> Result<(), KeyMeldError> {
        info!(
            "Orchestrating registration of participant {} to assigned enclave {} for session {}",
            user_id, assigned_enclave_id, session_id
        );

        let add_participant_cmd = AddParticipantCommand {
            keygen_session_id: Some(session_id.clone()),
            signing_session_id: None,
            user_id: user_id.clone(),
            enclave_encrypted_data,
        };

        let response = self
            .send_command_to_enclave(
                assigned_enclave_id,
                EnclaveCommand::AddParticipant(add_participant_cmd),
            )
            .await?;

        let encrypted_public_keys = match response {
            EnclaveResponse::ParticipantAdded(participant_response) => {
                info!(
                    "Successfully added participant {} to assigned enclave {} with {} encrypted public keys",
                    user_id, assigned_enclave_id, participant_response.encrypted_public_keys.len()
                );
                participant_response.encrypted_public_keys
            }
            EnclaveResponse::Success => {
                info!(
                    "Participant {} added to assigned enclave {} (no encrypted keys returned)",
                    user_id, assigned_enclave_id
                );
                return Ok(());
            }
            _ => {
                return Err(KeyMeldError::EnclaveError(format!(
                    "Unexpected response from enclave {assigned_enclave_id} when adding participant: {response:?}"
                )));
            }
        };

        if encrypted_public_keys.is_empty() {
            info!(
                "No encrypted public keys to distribute for participant {}",
                user_id
            );
            return Ok(());
        }

        info!(
            "Distributing participant {} encrypted public keys to {} target enclaves",
            user_id,
            encrypted_public_keys.len()
        );

        for encrypted_key in &encrypted_public_keys {
            let distribute_cmd = DistributeParticipantPublicKeyCommand {
                keygen_session_id: session_id.clone(),
                user_id: user_id.clone(),
                encrypted_participant_public_key: encrypted_key.encrypted_public_key.clone(),
            };

            match self
                .send_command_to_enclave(
                    &encrypted_key.target_enclave_id,
                    EnclaveCommand::DistributeParticipantPublicKey(distribute_cmd),
                )
                .await
            {
                Ok(EnclaveResponse::Success) => {
                    info!(
                        "Successfully distributed participant {} encrypted public key to enclave {}",
                        user_id, encrypted_key.target_enclave_id
                    );
                }
                Ok(response) => {
                    return Err(KeyMeldError::EnclaveError(format!(
                    "Unexpected response from enclave {} when distributing participant public key: {:?}",
                    encrypted_key.target_enclave_id, response
                )));
                }
                Err(e) => {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Failed to distribute participant {} public key to enclave {}: {}",
                        user_id, encrypted_key.target_enclave_id, e
                    )));
                }
            }
        }

        info!(
            "Successfully orchestrated registration of participant {} across all enclaves",
            user_id
        );

        Ok(())
    }

    async fn collect_enclave_public_keys(
        &self,
        enclave_ids: &[EnclaveId],
    ) -> Result<Vec<EnclavePublicKeyInfo>, KeyMeldError> {
        let mut keys = Vec::new();
        info!("Collecting public keys for {} enclaves", enclave_ids.len());

        for enclave_id in enclave_ids {
            match self.get_enclave_public_key(enclave_id).await {
                Ok(public_key) => {
                    keys.push(EnclavePublicKeyInfo {
                        enclave_id: *enclave_id,
                        public_key,
                    });
                }
                Err(e) => {
                    error!(
                        "Failed to collect public key for enclave {}: {}",
                        enclave_id, e
                    );
                    return Err(e);
                }
            }
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

        let now = SystemTime::now();

        for config in enclave_configs {
            let enclave_id = EnclaveId::from(config.id);
            let client = VsockClient::with_config_and_pool_size(
                config.cid,
                config.port,
                &timeout_config,
                max_connections_per_enclave,
            );

            let info = EnclaveInfo {
                cid: config.cid,
                port: config.port,
                startup_time: now,
                key_epoch: 1,
                public_key: None,
                key_generation_time: now,
                attestation_document: None,
            };

            clients.insert(enclave_id, client);
            enclave_info.insert(enclave_id, info);
        }

        let available_enclaves: Vec<EnclaveId> = clients.keys().cloned().collect();
        let assignment_manager = EnclaveAssignmentManager::new(available_enclaves);

        Ok(Self {
            clients,
            enclave_info: Arc::new(RwLock::new(enclave_info)),
            is_configured: false,
            assignment_manager: RwLock::new(assignment_manager),
            timeout_config,
            retry_config,
        })
    }

    pub async fn configure_all(&mut self) -> Result<(), KeyMeldError> {
        for (enclave_id, client) in &self.clients {
            client.configure(*enclave_id, None).await?;
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
            .write()
            .map_err(|_| KeyMeldError::EnclaveError("Failed to lock enclave info".to_string()))?;

        if let Some(info) = info_map.get_mut(enclave_id) {
            let is_restart = info
                .key_generation_time
                .elapsed()
                .unwrap_or_default()
                .as_secs()
                > 300;

            if is_restart {
                info!("Enclave {} restart detected", enclave_id);
                info.key_epoch += 1;
                info.key_generation_time = SystemTime::now();
                info.attestation_document = None;
            }
        }

        Ok(())
    }

    pub fn get_enclave_key_epoch(&self, enclave_id: &EnclaveId) -> Option<u64> {
        self.enclave_info
            .read()
            .ok()?
            .get(enclave_id)
            .map(|info| info.key_epoch)
    }

    pub fn update_enclave_attestation(
        &self,
        enclave_id: &EnclaveId,
        attestation: AttestationDocument,
    ) {
        if let Ok(mut info_map) = self.enclave_info.write() {
            if let Some(info) = info_map.get_mut(enclave_id) {
                info.attestation_document = Some(attestation);
            }
        }
    }

    pub fn clients(&self) -> &BTreeMap<EnclaveId, VsockClient> {
        &self.clients
    }

    pub fn create_session_assignment_with_coordinator(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_user_id: &UserId,
        coordinator_enclave_id: EnclaveId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        self.assignment_manager
            .write()
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {e}"))
            })?
            .assign_enclaves_for_session_with_coordinator(
                session_id,
                user_ids,
                coordinator_user_id,
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
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {e}"))
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
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {e}"))
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
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {e}"))
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
                KeyMeldError::EnclaveError(format!("Assignment manager lock poisoned: {e}"))
            })?
            .restore_session_assignment(assignment);
        Ok(())
    }

    pub fn enclave_info(&self) -> Result<BTreeMap<EnclaveId, EnclaveInfo>, KeyMeldError> {
        self.enclave_info
            .read()
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
        self.enclave_info.read().ok()?.get(enclave_id).cloned()
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
        let start_time = Instant::now();

        let client = self
            .clients
            .get(enclave_id)
            .ok_or(KeyMeldError::EnclaveError(format!(
                "Enclave {enclave_id} not found"
            )))
            .inspect_err(|err| error!("{err}"))?;

        match client.send_command(command).await {
            Ok(response) => Ok(response),
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
                "All retry attempts failed for enclave {enclave_id}"
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
                "missing keygen session {keygen_session_id}"
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
                "Unexpected response for aggregate public key request: {response:?}"
            ))),
        }
    }

    pub async fn get_enclave_public_info(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<(String, Option<AttestationDocument>, u32, u64, u64, u64), KeyMeldError> {
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
                "Enclave {enclave_id} returned error: {err}"
            ))),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from enclave {enclave_id}: {response:?}"
            ))),
        }
    }

    pub async fn initialize_enclave_public_keys(&self) -> Result<usize, KeyMeldError> {
        let enclave_ids: Vec<EnclaveId> =
            self.enclave_info.read().unwrap().keys().cloned().collect();
        let mut successful_count = 0;

        for enclave_id in &enclave_ids {
            match self.get_enclave_public_info(enclave_id).await {
                Ok((public_key, attestation_response, _, _, key_epoch, key_generation_time)) => {
                    if let Some(info) = self.enclave_info.write().unwrap().get_mut(enclave_id) {
                        info.public_key = Some(public_key.clone());
                        info.key_epoch = key_epoch;
                        info.key_generation_time =
                            SystemTime::UNIX_EPOCH + Duration::from_secs(key_generation_time);
                        info.attestation_document = attestation_response;
                    }
                    successful_count += 1;
                    info!("Initialized public key for enclave {}", enclave_id);
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize public key for enclave {}: {}",
                        enclave_id, e
                    );
                }
            }
        }

        if successful_count == 0 {
            return Err(KeyMeldError::EnclaveError(
                "Failed to initialize any enclave public keys".to_string(),
            ));
        }

        Ok(successful_count)
    }

    pub async fn validate_and_sync_enclave_epochs(&self) -> Result<bool, KeyMeldError> {
        let enclave_ids: Vec<EnclaveId> =
            self.enclave_info.read().unwrap().keys().cloned().collect();
        let mut any_epoch_mismatch = false;

        for enclave_id in &enclave_ids {
            match self.validate_enclave_epoch(enclave_id).await {
                Ok(had_mismatch) => {
                    if had_mismatch {
                        any_epoch_mismatch = true;
                        info!("Detected restart for enclave {}, epoch synced", enclave_id);
                    }
                }
                Err(e) => {
                    warn!("Failed to validate epoch for enclave {}: {}", enclave_id, e);
                }
            }
        }

        Ok(any_epoch_mismatch)
    }

    pub async fn validate_enclave_epoch(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<bool, KeyMeldError> {
        let (current_public_key, _, _, _, current_epoch, _) =
            self.get_enclave_public_info(enclave_id).await?;

        let cached_info = self.get_cached_enclave_info(enclave_id);

        if let Some(cached) = cached_info {
            let cached_public_key = cached.public_key.as_deref().unwrap_or("");
            let cached_epoch = cached.key_epoch;

            if current_public_key != cached_public_key || current_epoch != cached_epoch {
                warn!(
                    "Enclave {} restart detected - public key or epoch changed. Old epoch: {}, new epoch: {}",
                    enclave_id, cached_epoch, current_epoch
                );

                let new_epoch = cached_epoch + 1;

                let configure_cmd = ConfigureCommand {
                    enclave_id: *enclave_id,
                    key_epoch: Some(new_epoch),
                };

                match self
                    .send_command_to_enclave(
                        enclave_id,
                        super::protocol::EnclaveCommand::Configure(configure_cmd),
                    )
                    .await
                {
                    Ok(super::protocol::EnclaveResponse::Success) => {
                        info!(
                            "Successfully synced epoch {} for enclave {}",
                            new_epoch, enclave_id
                        );

                        if let Some(info) = self.enclave_info.write().unwrap().get_mut(enclave_id) {
                            info.public_key = Some(current_public_key);
                            info.key_epoch = new_epoch;
                            info.key_generation_time = SystemTime::now();
                        }

                        return Ok(true);
                    }
                    Ok(response) => {
                        warn!(
                            "Unexpected response from configure command for enclave {}: {:?}",
                            enclave_id, response
                        );
                    }
                    Err(e) => {
                        error!(
                            "Failed to send configure command to enclave {}: {}",
                            enclave_id, e
                        );
                        return Err(e);
                    }
                }
            }
        } else {
            info!(
                "No cached info for enclave {}, treating as first contact",
                enclave_id
            );
        }

        Ok(false)
    }

    pub fn are_enclave_keys_fresh(&self, enclave_id: &EnclaveId) -> bool {
        if let Some(info) = self.enclave_info.read().unwrap().get(enclave_id) {
            if info.public_key.is_some() {
                let epoch_age = SystemTime::now()
                    .duration_since(info.key_generation_time)
                    .unwrap_or(Duration::from_secs(0));

                return epoch_age < Duration::from_secs(300);
            }
        }
        false
    }

    fn get_cached_enclave_info(&self, enclave_id: &EnclaveId) -> Option<EnclaveInfo> {
        let info_lock = self.enclave_info.read().unwrap();
        info_lock.get(enclave_id).cloned()
    }

    pub async fn get_enclave_public_key_safe(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<String, KeyMeldError> {
        let had_restart = self.validate_enclave_epoch(enclave_id).await?;

        if had_restart {
            info!(
                "Enclave {} restart detected during key request, using fresh keys",
                enclave_id
            );
        }

        let (public_key, _, _, _, _, _) = self.get_enclave_public_info(enclave_id).await?;
        Ok(public_key)
    }

    pub async fn get_enclave_public_key(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<String, KeyMeldError> {
        let (public_key, _, _, _, _, _) = self.get_enclave_public_info(enclave_id).await?;
        Ok(public_key)
    }

    pub fn get_enclave_ids(&self) -> Vec<EnclaveId> {
        self.enclave_info.read().unwrap().keys().cloned().collect()
    }

    pub async fn add_participant(
        &self,
        session_id: &SessionId,
        user_id: &UserId,
        enclave_id: &EnclaveId,
        enclave_encrypted_data: String,
    ) -> Result<(), KeyMeldError> {
        let add_participant_cmd = AddParticipantCommand {
            keygen_session_id: Some(session_id.clone()),
            signing_session_id: None,
            user_id: user_id.clone(),
            enclave_encrypted_data,
        };

        let response = self
            .send_command_to_enclave(
                enclave_id,
                EnclaveCommand::AddParticipant(add_participant_cmd),
            )
            .await?;

        match response {
            EnclaveResponse::Success => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(format!(
                "Failed to add participant to enclave {enclave_id}: {err}"
            ))),
            _ => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response from enclave {enclave_id} when adding participant"
            ))),
        }
    }

    fn calculate_signer_index(
        &self,
        user_id: &UserId,
        participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<usize, KeyMeldError> {
        let mut sorted_participants: Vec<_> = participants.keys().collect();
        sorted_participants.sort_by(|a, b| b.cmp(a));

        let signer_index = sorted_participants
            .iter()
            .position(|&uid| uid == user_id)
            .ok_or(KeyMeldError::EnclaveError(format!(
                "User {user_id} not found in participants"
            )))?;

        debug!(
            "Calculated signer_index={} for user {} from {} participants (descending order)",
            signer_index,
            user_id,
            participants.len()
        );

        Ok(signer_index)
    }

    pub async fn orchestrate_nonce_generation(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
        participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<BTreeMap<UserId, crate::enclave::protocol::NonceData>, KeyMeldError> {
        info!(
            "Orchestrating nonce generation for signing session {} with {} participants",
            signing_session_id,
            participants.len()
        );

        let mut generated_nonces: BTreeMap<UserId, crate::enclave::protocol::NonceData> =
            BTreeMap::new();

        for (user_id, participant) in participants {
            let nonce_cmd = GenerateNonceCommand {
                signing_session_id: signing_session_id.clone(),
                keygen_session_id: keygen_session_id.clone(),
                user_id: user_id.clone(),
                signer_index: self.calculate_signer_index(user_id, participants)?,
            };

            let nonce_data = self
                .execute_with_retry(
                    &participant.enclave_id,
                    || EnclaveCommand::GenerateNonce(nonce_cmd.clone()),
                    |response| match response {
                        EnclaveResponse::Nonce(nonce_response) => Ok(nonce_response.nonce_data),
                        other => {
                            error!(
                                "Failed to get nonce from enclave {} for user {}: {:?}",
                                participant.enclave_id, user_id, other
                            );
                            Err(KeyMeldError::EnclaveError(format!(
                                "Invalid nonce response: {other:?}"
                            )))
                        }
                    },
                )
                .await?;

            generated_nonces.insert(user_id.clone(), nonce_data);
        }

        let all_enclaves: BTreeSet<EnclaveId> =
            participants.values().map(|p| p.enclave_id).collect();

        info!(
            "Starting nonce distribution phase for {} nonces to {} enclaves",
            generated_nonces.len(),
            all_enclaves.len()
        );

        for (nonce_user_id, nonce_data) in &generated_nonces {
            let signer_index = self.calculate_signer_index(nonce_user_id, participants)?;

            let generating_enclave_id = participants
                .get(nonce_user_id)
                .map(|p| p.enclave_id)
                .ok_or(KeyMeldError::EnclaveError(format!(
                    "Participant {nonce_user_id} not found for nonce distribution"
                )))?;

            for enclave_id in &all_enclaves {
                if *enclave_id == generating_enclave_id {
                    continue;
                }

                let add_nonce_cmd = AddNonceCommand {
                    signing_session_id: signing_session_id.clone(),
                    keygen_session_id: keygen_session_id.clone(),
                    user_id: nonce_user_id.clone(),
                    signer_index,
                    nonce_data: nonce_data.clone(),
                };

                self.execute_with_retry(
                    enclave_id,
                    move || EnclaveCommand::AddNonce(add_nonce_cmd.clone()),
                    |response| match response {
                        EnclaveResponse::Success => Ok(()),
                        other => Err(KeyMeldError::EnclaveError(format!(
                            "Unexpected nonce distribution response for user {nonce_user_id} to enclave {enclave_id}: {other:?}"
                        ))),
                    },
                )
                .await?;
            }
        }

        Ok(generated_nonces)
    }

    pub async fn finalize_signature(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), KeyMeldError> {
        let session_assignment =
            self.get_session_assignment(keygen_session_id)?
                .ok_or(KeyMeldError::EnclaveError(format!(
                    "No session assignment found for keygen session {keygen_session_id}"
                )))?;

        let coordinator_enclave = session_assignment.coordinator_enclave;

        let cmd = FinalizeCommand {
            signing_session_id: signing_session_id.clone(),
            keygen_session_id: keygen_session_id.clone(),
        };

        match self
            .send_command_to_enclave(&coordinator_enclave, (EnclaveCommand::Finalize)(cmd))
            .await
        {
            Ok(EnclaveResponse::FinalSignature(resp)) => {
                Ok((resp.final_signature, resp.encrypted_adaptor_signatures))
            }
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
    ) -> Result<BTreeMap<UserId, musig2::PartialSignature>, KeyMeldError> {
        let mut partial_signatures = BTreeMap::new();
        let mut adaptor_signatures: BTreeMap<UserId, Vec<(uuid::Uuid, musig2::PartialSignature)>> =
            BTreeMap::new(); // Store adaptor signatures separately

        info!(
            "Starting partial signature generation for signing session {} with {} participants",
            signing_session_id,
            participants.len()
        );

        let mut successful_signatures = 0;

        for (user_id, participant) in participants {
            let sig_cmd = ParitialSignatureCommand {
                signing_session_id: signing_session_id.clone(),
                keygen_session_id: keygen_session_id.clone(),
                user_id: user_id.clone(),
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
                        match sig_resp.signature_data {
                            SignatureData::Regular(partial_signature) => {
                                partial_signatures.insert(user_id.clone(), partial_signature);
                                successful_signatures += 1;
                            }
                            SignatureData::Adaptor(adaptor_sigs) => {
                                adaptor_signatures.insert(user_id.clone(), adaptor_sigs);
                                successful_signatures += 1;
                            }
                        }
                    } else {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Invalid signature response from enclave for user {user_id}"
                        )));
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to generate partial signature for user {}: {}",
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
                    signature_data: SignatureData::Regular(*partial_signature),
                };

                match self
                    .send_command_to_enclave(
                        enclave_id,
                        EnclaveCommand::AddPartialSignature(add_signature_cmd),
                    )
                    .await
                {
                    Ok(EnclaveResponse::Success) => {}
                    Ok(response) => {
                        warn!(
                            "Unexpected partial signature distribution response: {:?}",
                            response
                        );
                    }
                    Err(e) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to distribute partial signature: {e}"
                        )));
                    }
                }
            }
        }

        for (sig_user_id, adaptor_sigs) in &adaptor_signatures {
            let signer_index = self.calculate_signer_index(sig_user_id, participants)?;

            for enclave_id in &all_enclaves {
                let add_signature_cmd = AddPartialSignatureCommand {
                    signing_session_id: signing_session_id.clone(),
                    keygen_session_id: keygen_session_id.clone(),
                    user_id: sig_user_id.clone(),
                    signer_index,
                    signature_data: SignatureData::Adaptor(adaptor_sigs.clone()),
                };

                match self
                    .send_command_to_enclave(
                        enclave_id,
                        EnclaveCommand::AddPartialSignature(add_signature_cmd),
                    )
                    .await
                {
                    Ok(EnclaveResponse::Success) => {}
                    Ok(response) => {
                        warn!(
                            "Unexpected adaptor signature distribution response: {:?}",
                            response
                        );
                    }
                    Err(e) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to distribute adaptor signatures: {e}"
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
            "Starting optimized signing session initialization for session {} with {} participants",
            params.signing_session_id,
            params.participants.len()
        );

        for (user_id, participant_data) in &params.participants {
            info!(
                "Participant {} assigned to enclave {} with enclave_data_len={}",
                user_id,
                participant_data.enclave_id,
                participant_data.enclave_encrypted_data.len()
            );
        }
        let session_assignment = self
            .get_session_assignment(&params.keygen_session_id)?
            .ok_or(KeyMeldError::EnclaveError(format!(
                "No session assignment found for keygen session {}",
                params.keygen_session_id
            )))?;

        let coordinator_enclave_id = session_assignment.coordinator_enclave;

        let mut enclave_participants: BTreeMap<EnclaveId, Vec<(&UserId, &ParticipantData)>> =
            BTreeMap::new();
        let mut all_required_enclaves = BTreeSet::new();

        for (user_id, assigned_enclave_id) in &session_assignment.user_enclave_assignments {
            if let Some(participant_data) = params.participants.get(user_id) {
                if participant_data.enclave_id != *assigned_enclave_id {
                    error!(
                        "User {} enclave assignment mismatch! Database has enclave {}, but EnclaveAssignmentManager expects enclave {}",
                        user_id,
                        participant_data.enclave_id.as_u32(),
                        assigned_enclave_id.as_u32()
                    );
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Enclave assignment mismatch for user {}: database has {}, assignment manager expects {}",
                        user_id,
                        participant_data.enclave_id.as_u32(),
                        assigned_enclave_id.as_u32()
                    )));
                }

                enclave_participants
                    .entry(*assigned_enclave_id)
                    .or_default()
                    .push((user_id, participant_data));
                all_required_enclaves.insert(*assigned_enclave_id);
            } else {
                error!(
                    "User {} found in session assignment but not in database participants",
                    user_id
                );
                return Err(KeyMeldError::EnclaveError(format!(
                    "User {user_id} in session assignment but not found in database participants"
                )));
            }
        }

        for user_id in params.participants.keys() {
            if !session_assignment
                .user_enclave_assignments
                .contains_key(user_id)
            {
                return Err(KeyMeldError::EnclaveError(format!(
                    "User {user_id} in database participants but not found in session assignment"
                )));
            }
        }

        all_required_enclaves.insert(coordinator_enclave_id);

        info!(
            "All required enclaves for signing session {}: {:?} (coordinator: {})",
            params.signing_session_id, all_required_enclaves, coordinator_enclave_id
        );

        info!(
            "About to copy session assignment from keygen {} to signing {}",
            params.keygen_session_id, params.signing_session_id
        );

        self.copy_session_assignment_for_signing(
            &params.keygen_session_id,
            params.signing_session_id.clone(),
        )
        .map_err(|e| {
            error!(
                "Failed to copy session assignment from keygen {} to signing {}: {}",
                params.keygen_session_id, params.signing_session_id, e
            );
            e
        })?;

        let copied_assignment = self
            .get_session_assignment(&params.signing_session_id)
            .map_err(|e| {
                error!(
                    "Failed to verify copied session assignment for {}: {}",
                    params.signing_session_id, e
                );
                e
            })?;

        match copied_assignment {
            Some(assignment) => {
                info!(
                    "Signing session {} assignment copied with coordinator: {} and {} user assignments: {:?}",
                    params.signing_session_id,
                    assignment.coordinator_enclave.as_u32(),
                    assignment.user_enclave_assignments.len(),
                    assignment.user_enclave_assignments
                );
            }
            None => {
                error!(
                    "Session assignment for signing session {} not found after copy operation",
                    params.signing_session_id
                );
                return Err(KeyMeldError::EnclaveError(
                    "Failed to verify session assignment copy".to_string(),
                ));
            }
        }

        info!(
            "Successfully created and verified signing session assignment for session {} based on keygen session {}",
            params.signing_session_id, params.keygen_session_id
        );

        let coordinator_init_cmd = InitSigningSessionCommand {
            keygen_session_id: params.keygen_session_id.clone(),
            signing_session_id: params.signing_session_id.clone(),
            encrypted_message: params.encrypted_message.clone(),
            timeout_secs: self.timeout_config.session_init_timeout_secs,
            taproot_tweak: params.taproot_tweak.clone(),
            expected_participant_count: params.participants.len(),
            encrypted_adaptor_configs: if params.encrypted_adaptor_configs.is_empty() {
                None
            } else {
                Some(params.encrypted_adaptor_configs.clone())
            },
        };

        info!(
            "Initializing coordinator enclave {} for signing session {}",
            coordinator_enclave_id, params.signing_session_id
        );

        self
            .execute_with_retry(
                &coordinator_enclave_id,
                move || EnclaveCommand::InitSigningSession(coordinator_init_cmd.clone()),
                |response| match response {
                    EnclaveResponse::Success => Ok(()),
                    other => Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response during coordinator signing session initialization: {other:?}"
                    ))),
                },
            )
            .await?;

        info!(
            "Successfully initialized coordinator enclave {} for signing session {}",
            coordinator_enclave_id, params.signing_session_id
        );

        let mut successfully_initialized_enclaves = BTreeSet::new();
        successfully_initialized_enclaves.insert(coordinator_enclave_id);

        for enclave_id in all_required_enclaves.iter() {
            if *enclave_id == coordinator_enclave_id {
                info!(
                    "Skipping enclave {} - already initialized as coordinator",
                    enclave_id
                );
                continue; // Already initialized
            }

            info!(
                "Initializing non-coordinator enclave {} for signing session {}",
                enclave_id, params.signing_session_id
            );

            let init_cmd = InitSigningSessionCommand {
                keygen_session_id: params.keygen_session_id.clone(),
                signing_session_id: params.signing_session_id.clone(),
                encrypted_message: params.encrypted_message.clone(),
                timeout_secs: self.timeout_config.session_init_timeout_secs,
                taproot_tweak: params.taproot_tweak.clone(),
                expected_participant_count: params.participants.len(),
                encrypted_adaptor_configs: if params.encrypted_adaptor_configs.is_empty() {
                    None
                } else {
                    Some(params.encrypted_adaptor_configs.clone())
                },
            };

            match self
                .execute_with_retry(
                    enclave_id,
                    move || EnclaveCommand::InitSigningSession(init_cmd.clone()),
                    |response| match response {
                        EnclaveResponse::Success => Ok(()),
                        other => Err(KeyMeldError::EnclaveError(format!(
                            "Unexpected response during signing session initialization: {other:?}"
                        ))),
                    },
                )
                .await
            {
                Ok(_) => {
                    info!(
                        "Successfully initialized signing session on non-coordinator enclave {}",
                        enclave_id
                    );
                    successfully_initialized_enclaves.insert(*enclave_id);
                }
                Err(e) => {
                    error!(
                        "Failed to initialize signing session on enclave {}: {}",
                        enclave_id, e
                    );

                    return Err(KeyMeldError::EnclaveError(format!(
                        "Failed to initialize signing session on required enclave {enclave_id}: {e}. Cannot proceed without all enclaves."
                    )));
                }
            }
        }

        info!(
            "Successfully initialized signing session {} on all {} required enclaves: {:?}",
            params.signing_session_id,
            successfully_initialized_enclaves.len(),
            successfully_initialized_enclaves
        );

        info!(
            "Signing session {} participants inherited from keygen session {} - no additional participant setup needed",
            params.signing_session_id,
            params.keygen_session_id
        );

        info!(
            "Successfully inherited all {} participants across {} enclaves for signing session {}",
            params.participants.len(),
            all_required_enclaves.len(),
            params.signing_session_id
        );

        Ok(())
    }

    async fn distribute_session_secret_with_retry(
        &self,
        session_id: &SessionId,
        encrypted_secret: &EncryptedSessionSecret,
        _max_retries: u32,
    ) -> Result<(), KeyMeldError> {
        let target_enclave_id = encrypted_secret.target_enclave_id;
        let session_id = session_id.to_owned();
        let session_id_cpy = session_id.clone();
        let encrypted_session_secret = encrypted_secret.encrypted_session_secret.clone();

        self.execute_with_retry(
            &target_enclave_id,
            move || {
                EnclaveCommand::DistributeSessionSecret(DistributeSessionSecretCommand {
                    keygen_session_id: session_id.clone(),
                    encrypted_session_secret: encrypted_session_secret.clone(),
                })
            },
            move |response| match response {
                EnclaveResponse::Success => {
                    info!(
                        "Successfully distributed session secret to enclave {} for session {}",
                        target_enclave_id, session_id_cpy.clone()
                    );
                    Ok(())
                }
                other => Err(KeyMeldError::EnclaveError(format!(
                    "Unexpected response from enclave {target_enclave_id} during session secret distribution: {other:?}"
                ))),
            },
        )
        .await
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
        let session_assignment = self
            .get_session_assignment(keygen_session_id)?
            .ok_or(KeyMeldError::EnclaveError(format!(
                "No session assignment found for session {keygen_session_id}"
            )))
            .inspect_err(|err| {
                error!("Error getting session assignment: {}", err);
            })?;

        let enclaves_with_participants = session_assignment.get_all_assigned_enclaves();

        let fresh_enclave_public_keys = self
            .collect_enclave_public_keys(&enclaves_with_participants)
            .await?;

        let mut expected_participants: Vec<UserId> = participants.keys().cloned().collect();
        expected_participants.sort_by(|a, b| b.cmp(a));

        let mut coordinator_encrypted_secrets = Vec::new();
        for enclave_id in &enclaves_with_participants {
            let init_cmd = InitKeygenSessionCommand {
                keygen_session_id: keygen_session_id.clone(),
                coordinator_encrypted_private_key: if *enclave_id == *coordinator_enclave_id {
                    Some(coordinator_encrypted_private_key.to_string())
                } else {
                    None
                },
                coordinator_user_id: if *enclave_id == *coordinator_enclave_id {
                    Some(session_assignment.coordinator_user_id.clone())
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
                expected_participants: expected_participants.clone(),
                enclave_public_keys: fresh_enclave_public_keys.clone(),
            };

            match self
                .execute_with_retry(
                    enclave_id,
                    move || EnclaveCommand::InitKeygenSession(init_cmd.clone()),
                    Ok,
                )
                .await?
            {
                EnclaveResponse::KeygenInitialized(response)
                    if *enclave_id == *coordinator_enclave_id =>
                {
                    info!(
                        "Coordinator enclave {} initialized and encrypted session secret for {} other enclaves (coordinator will advance directly to CollectingNonces)",
                        enclave_id, response.encrypted_session_secrets.len()
                    );
                    coordinator_encrypted_secrets = response.encrypted_session_secrets;
                }
                EnclaveResponse::Success => {}
                response => {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response from enclave {enclave_id} during keygen initialization: {response:?}"
                    )));
                }
            }
        }

        // Distribute session secrets to non-coordinator enclaves
        // These enclaves should now be in DistributingSecrets state waiting for their session secret
        // Skip this step if enclaves are already past this state
        if !coordinator_encrypted_secrets.is_empty() {
            info!(
                "Checking if session secrets need to be distributed to {} non-coordinator enclaves for session {}",
                coordinator_encrypted_secrets.len(),
                keygen_session_id
            );

            for encrypted_secret in coordinator_encrypted_secrets {
                match self
                    .distribute_session_secret_with_retry(
                        keygen_session_id,
                        &encrypted_secret,
                        3, // max retries
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(e)
                        if e.to_string()
                            .contains("Session not in correct state for secret distribution") =>
                    {
                        info!(
                            "Enclave {} already has session secret or is past DistributingSecrets state, skipping distribution",
                            encrypted_secret.target_enclave_id
                        );
                        // This is OK - the enclave is already in a later state
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }

        info!(
            "Orchestrating participant registration for {} participants in keygen session {}",
            participants.len(),
            keygen_session_id
        );

        let coordinator_in_participants = participants
            .iter()
            .find(|(_, p)| p.enclave_id == *coordinator_enclave_id);

        match coordinator_in_participants {
            Some((coord_user_id, _)) => {
                info!(
                    "Coordinator {} found in participants list, assigned to enclave {}",
                    coord_user_id, coordinator_enclave_id
                );
            }
            None => {
                warn!(
                    "Coordinator NOT found in participants list! This may cause missing public key distribution. Coordinator enclave: {}",
                    coordinator_enclave_id
                );
                // Log all participant assignments for debugging
                for (user_id, participant) in participants.iter() {
                    info!(
                        "Participant {} assigned to enclave {}",
                        user_id, participant.enclave_id
                    );
                }
            }
        }

        // For keygen sessions, use the new orchestration approach:
        // 1. Add each participant only to their assigned enclave (with private key)
        // 2. Assigned enclave encrypts public key for other enclaves
        // 3. Distribute encrypted public keys to other enclaves
        for (user_id, participant) in participants {
            info!(
                "Orchestrating registration of participant {} to assigned enclave {}",
                user_id, participant.enclave_id
            );

            self.orchestrate_participant_registration(
                keygen_session_id,
                user_id,
                &participant.enclave_id,
                participant.enclave_encrypted_data.clone(),
            )
            .await?;

            info!(
                "Successfully orchestrated registration of participant {} across all enclaves",
                user_id
            );
        }

        info!(
            "Participant addition phase completed for session {}, getting aggregate public key",
            keygen_session_id
        );

        let Some(session_assignment) = self.get_session_assignment(keygen_session_id)? else {
            return Err(KeyMeldError::EnclaveError(format!(
                "missing keygen session {keygen_session_id}"
            )));
        };

        // Use execute_with_retry to handle race condition where key aggregation context
        // might not be ready immediately after participants are added. The musig processor
        // creates the key aggregation context when participant_count >= expected_count,
        // but there can be a timing window between participant addition and context creation.
        let aggregate_public_key_bytes = self
            .execute_with_retry(
                &session_assignment.coordinator_enclave,
                || {
                    EnclaveCommand::GetAggregatePublicKey(GetAggregatePublicKeyCommand {
                        keygen_session_id: keygen_session_id.clone(),
                    })
                },
                |response| match response {
                    EnclaveResponse::AggregatePublicKey(response) => {
                        Ok(response.aggregate_public_key)
                    }
                    response => Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response for aggregate public key request: {response:?}"
                    ))),
                },
            )
            .await?;

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
        identifiers::{EnclaveId, SessionId, UserId},
        ParticipantData,
    };
    use std::collections::{BTreeMap, HashSet};

    fn create_test_participants() -> BTreeMap<UserId, ParticipantData> {
        let mut participants = BTreeMap::new();

        for i in 0..3 {
            let user_id = UserId::new_v7();
            let participant = ParticipantData {
                user_id: user_id.clone(),
                enclave_id: EnclaveId::from(i),
                enclave_key_epoch: 1,
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
            encrypted_adaptor_configs: String::new(),
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
}
