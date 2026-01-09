use crate::database::Database;
use crate::session::keygen::KeygenSessionStatus;
use crate::session::types::ParticipantData;
use crate::{config::KmsConfig, SigningSessionStatus};
use futures::stream::{FuturesUnordered, StreamExt};
use keymeld_core::{
    identifiers::{EnclaveId, SessionId, UserId},
    managed_vsock::{
        client::{ClientMetrics, VsockClient},
        config::{RetryConfig, TimeoutConfig},
        pool::ConnectionStats,
    },
    protocol::{
        AddParticipantsBatchCommand, Command, ConfigureCommand, DistributeNoncesCommand,
        DistributeParticipantPublicKeysBatchCommand, EnclaveCommand, EnclaveOutcome,
        EnclavePublicKeyInfo, EncryptedParticipantPublicKey, EncryptedSessionSecret,
        FinalizeSignatureCommand, GetAggregatePublicKeyCommand, InitKeygenSessionCommand,
        InitSigningSessionCommand, KeygenCommand, KeygenOutcome, MusigCommand, MusigOutcome,
        Outcome, ParticipantRegistrationData, RestoreUserKeyCommand, SigningCommand,
        SigningOutcome, SystemCommand, SystemOutcome, UserKeyCommand,
    },
    AggregatePublicKey, AttestationDocument, KeyMeldError,
};
use keymeld_sdk::SigningBatchItem;
use rand::seq::SliceRandom;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tracing::{debug, error, info, warn};

use super::distribution::{EnclaveAssignmentManager, SessionAssignment};

type EnclaveClient = VsockClient<Command, Outcome>;

type BatchParticipantResult = (EnclaveId, Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>);

/// Result of keygen session initialization, containing aggregate key and encrypted public keys
/// for session restoration.
#[derive(Debug, Clone)]
pub struct KeygenInitResult {
    pub aggregate_public_key: AggregatePublicKey,
    pub participant_encrypted_public_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
    pub enclave_encrypted_session_secrets: Vec<EncryptedSessionSecret>,
}

#[derive(Debug)]
pub struct OperationResult<T> {
    pub enclave_id: EnclaveId,
    pub result: Result<T, KeyMeldError>,
}

#[derive(Debug, Clone)]
pub struct SigningSessionInitParams {
    pub keygen_session_id: SessionId,
    pub signing_session_id: SessionId,
    /// Batch items to sign (single message = batch of 1)
    pub batch_items: Vec<SigningBatchItem>,
    pub participants: BTreeMap<UserId, ParticipantData>,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub encrypted_taproot_tweak: String,
}

#[derive(Debug, Clone)]
pub struct EnclaveConfig {
    pub id: u32,
    pub cid: u32,
    pub port: u32,
}

/// Statistics about session restoration after restart
#[derive(Debug, Default)]
pub struct RestorationStats {
    pub keygen_restored: u32,
    pub keygen_failed: u32,
    pub signing_reset: u32,
    pub signing_failed: u32,
    pub user_keys_restored: u32,
    pub user_keys_failed: u32,
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

#[derive(Debug, Clone)]
pub struct ComprehensiveMetrics {
    pub connection_stats: ConnectionStats,
    pub client_metrics: ClientMetrics,
}

pub struct EnclaveManager {
    clients: BTreeMap<EnclaveId, EnclaveClient>,
    enclave_info: Arc<dashmap::DashMap<EnclaveId, EnclaveInfo>>,
    is_configured: bool,
    /// Lock-free assignment manager using DashMap internally.
    /// No external locking needed - all methods are thread-safe.
    assignment_manager: EnclaveAssignmentManager,
    #[allow(dead_code)]
    // Used during construction to configure clients, kept for potential future use
    timeout_config: TimeoutConfig,
}

impl EnclaveManager {
    /// Orchestrate batch participant registration across enclaves
    /// Groups participants by their assigned enclave and sends batch commands
    pub async fn orchestrate_participants_batch_registration(
        &self,
        session_id: &SessionId,
        participants: &BTreeMap<UserId, ParticipantData>,
    ) -> Result<Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>, KeyMeldError> {
        info!(
            "Orchestrating batch registration of {} participants for session {}",
            participants.len(),
            session_id
        );

        // Group participants by their assigned enclave
        let mut participants_by_enclave: BTreeMap<EnclaveId, Vec<ParticipantRegistrationData>> =
            BTreeMap::new();

        for (user_id, participant) in participants {
            participants_by_enclave
                .entry(participant.enclave_id)
                .or_default()
                .push(ParticipantRegistrationData {
                    user_id: user_id.clone(),
                    enclave_encrypted_data: participant.enclave_encrypted_data.clone(),
                    auth_pubkey: participant.auth_pubkey.clone(),
                    require_signing_approval: participant.require_signing_approval,
                });
        }

        info!(
            "Grouped {} participants across {} enclaves",
            participants.len(),
            participants_by_enclave.len()
        );

        // Step 1: Send AddParticipantsBatch to each enclave in parallel using FuturesUnordered
        let mut add_batch_futures: FuturesUnordered<_> = participants_by_enclave
            .iter()
            .map(|(enclave_id, enclave_participants)| {
                let enclave_id = *enclave_id;
                let participants_clone = enclave_participants.clone();
                let session_id = session_id.clone();

                async move {
                    info!(
                        "Sending AddParticipantsBatch to enclave {} with {} participants",
                        enclave_id,
                        participants_clone.len()
                    );

                    let batch_cmd = AddParticipantsBatchCommand {
                        keygen_session_id: session_id.clone(),
                        participants: participants_clone,
                    };

                    let command = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                        KeygenCommand::AddParticipantsBatch(batch_cmd),
                    )));

                    let outcome = self.send_command_to_enclave(&enclave_id, command).await?;

                    match outcome.response {
                        EnclaveOutcome::Musig(MusigOutcome::Keygen(
                            KeygenOutcome::ParticipantsAddedBatch(batch_response),
                        )) => {
                            info!(
                                "Added batch of {} participants to enclave {}",
                                batch_response.participants.len(),
                                enclave_id
                            );
                            Ok((enclave_id, batch_response.encrypted_public_keys))
                        }
                        _ => Err(KeyMeldError::EnclaveError(format!(
                            "Unexpected response from enclave {} when adding participant batch: {:?}",
                            enclave_id, outcome.response
                        ))),
                    }
                }
            })
            .collect();

        // Execute all AddParticipantsBatch commands - process as they complete
        let mut batch_results: Vec<BatchParticipantResult> = Vec::new();
        while let Some(result) = add_batch_futures.next().await {
            batch_results.push(result?);
        }

        info!(
            "Added participants to {} enclaves, now distributing public keys",
            batch_results.len()
        );

        // Step 2: Distribute public keys to other enclaves
        // Collect all public keys that need to be distributed to each enclave
        let session_assignment =
            self.get_session_assignment(session_id)?
                .ok_or(KeyMeldError::EnclaveError(format!(
                    "No session assignment found for session {session_id}"
                )))?;

        let session_enclaves = session_assignment.get_all_assigned_enclaves();

        // For each enclave, collect the public keys it needs to receive
        let mut keys_to_distribute: BTreeMap<EnclaveId, Vec<(UserId, String)>> = BTreeMap::new();

        for (source_enclave_id, encrypted_keys_batch) in &batch_results {
            for (user_id, encrypted_keys) in encrypted_keys_batch {
                for encrypted_key in encrypted_keys {
                    // Only distribute to enclaves that are part of this session
                    if session_enclaves.contains(&encrypted_key.target_enclave_id)
                        && encrypted_key.target_enclave_id != *source_enclave_id
                    {
                        keys_to_distribute
                            .entry(encrypted_key.target_enclave_id)
                            .or_default()
                            .push((user_id.clone(), encrypted_key.encrypted_public_key.clone()));
                    }
                }
            }
        }

        info!(
            "Distributing public keys to {} enclaves",
            keys_to_distribute.len()
        );

        // Step 3: Send DistributeParticipantPublicKeysBatch to each target enclave using FuturesUnordered
        let mut distribute_futures: FuturesUnordered<_> = keys_to_distribute
            .into_iter()
            .map(|(target_enclave_id, keys)| {
                let session_id = session_id.clone();

                async move {
                    info!(
                        "Sending DistributeParticipantPublicKeysBatch to enclave {} with {} keys",
                        target_enclave_id,
                        keys.len()
                    );

                    let batch_cmd = DistributeParticipantPublicKeysBatchCommand {
                        keygen_session_id: session_id,
                        participants_public_keys: keys,
                    };

                    let command = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                        KeygenCommand::DistributeParticipantPublicKeysBatch(batch_cmd),
                    )));

                    self.send_command_to_enclave(&target_enclave_id, command)
                        .await?;

                    debug!("Distributed public keys to enclave {}", target_enclave_id);

                    Ok::<(), KeyMeldError>(())
                }
            })
            .collect();

        // Execute all distribution commands - process as they complete
        while let Some(result) = distribute_futures.next().await {
            result?;
        }

        info!(
            "Completed batch participant registration for {} participants in session {}",
            participants.len(),
            session_id
        );

        // Collect all encrypted public keys from all enclaves for storage
        let all_encrypted_public_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)> =
            batch_results
                .into_iter()
                .flat_map(|(_, keys)| keys)
                .collect();

        Ok(all_encrypted_public_keys)
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
    ) -> Result<Self, KeyMeldError> {
        let mut clients = BTreeMap::new();
        let mut enclave_info = BTreeMap::new();

        let now = SystemTime::now();

        for config in enclave_configs {
            let enclave_id = EnclaveId::from(config.id);
            let client = VsockClient::with_config(
                config.cid,
                config.port,
                &timeout_config,
                &RetryConfig::default(),
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
            enclave_info: Arc::new(dashmap::DashMap::from_iter(enclave_info)),
            is_configured: false,
            assignment_manager,
            timeout_config,
        })
    }

    pub fn get_enclave_client(&self, enclave_id: &EnclaveId) -> Option<&EnclaveClient> {
        self.clients.get(enclave_id)
    }

    pub fn get_all_enclave_ids(&self) -> Vec<EnclaveId> {
        self.clients.keys().cloned().collect()
    }

    pub fn get_enclave_key_epoch(&self, enclave_id: &EnclaveId) -> Option<u64> {
        self.enclave_info.get(enclave_id).map(|info| info.key_epoch)
    }

    pub fn update_enclave_attestation(
        &self,
        enclave_id: &EnclaveId,
        attestation: AttestationDocument,
    ) {
        if let Some(mut info) = self.enclave_info.get_mut(enclave_id) {
            info.attestation_document = Some(attestation);
        }
    }

    pub fn clients(&self) -> &BTreeMap<EnclaveId, EnclaveClient> {
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
            .assign_enclaves_for_session_with_coordinator(
                session_id,
                user_ids,
                coordinator_user_id,
                coordinator_enclave_id,
            )
    }

    pub fn create_session_assignment_with_distributed_coordinator(
        &self,
        session_id: SessionId,
        user_ids: &[UserId],
        coordinator_user_id: &UserId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        self.assignment_manager
            .assign_enclaves_for_session_with_distributed_coordinator(
                session_id,
                user_ids,
                coordinator_user_id,
            )
    }

    pub fn copy_session_assignment_for_signing(
        &self,
        keygen_session_id: &SessionId,
        signing_session_id: SessionId,
    ) -> Result<SessionAssignment, KeyMeldError> {
        self.assignment_manager
            .copy_session_assignment_for_signing(keygen_session_id, signing_session_id)
    }

    pub fn get_session_assignment(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionAssignment>, KeyMeldError> {
        Ok(self.assignment_manager.get_session_assignment(session_id))
    }

    pub fn remove_session_assignment(
        &self,
        session_id: &SessionId,
    ) -> Result<Option<SessionAssignment>, KeyMeldError> {
        Ok(self.assignment_manager.remove_session(session_id))
    }

    pub fn restore_session_assignment(
        &self,
        assignment: SessionAssignment,
    ) -> Result<(), KeyMeldError> {
        self.assignment_manager
            .restore_session_assignment(assignment);
        Ok(())
    }

    pub fn enclave_info(&self) -> Result<BTreeMap<EnclaveId, EnclaveInfo>, KeyMeldError> {
        let mut result = BTreeMap::new();
        for entry in self.enclave_info.iter() {
            result.insert(*entry.key(), entry.value().clone());
        }
        Ok(result)
    }

    pub async fn health_check(&self) -> BTreeMap<EnclaveId, bool> {
        let mut results = BTreeMap::new();
        for (enclave_id, client) in &self.clients {
            let healthy = client
                .health_check::<keymeld_core::protocol::EnclaveHealthCheck>()
                .await
                .unwrap_or(false);
            results.insert(*enclave_id, healthy);
        }
        results
    }

    pub fn get_enclave_info(&self, enclave_id: &EnclaveId) -> Option<EnclaveInfo> {
        self.enclave_info.get(enclave_id).map(|info| info.clone())
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
        command: Command,
    ) -> Result<Outcome, KeyMeldError> {
        let start_time = Instant::now();

        let client = self
            .clients
            .get(enclave_id)
            .ok_or(KeyMeldError::EnclaveError(format!(
                "Enclave {enclave_id} not found"
            )))
            .inspect_err(|err| error!("{err}"))?;

        match client.send_command(command.into()).await {
            Ok(response) => Ok(response.response),
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
        F: Fn() -> Command + Send + Sync,
        R: Fn(EnclaveOutcome) -> Result<T, KeyMeldError> + Send + Sync,
    {
        debug!("Executing command on enclave {}", enclave_id);

        match self.send_command_to_enclave(enclave_id, command_fn()).await {
            Ok(outcome) => match response_mapper(outcome.response) {
                Ok(result) => {
                    debug!("Command succeeded for enclave {}", enclave_id);
                    Ok(result)
                }
                Err(e) => {
                    error!("Response mapping failed for enclave {}: {}", enclave_id, e);
                    Err(e)
                }
            },
            Err(e) => {
                error!("Command failed for enclave {}: {}", enclave_id, e);
                Err(e)
            }
        }
    }

    pub async fn get_aggregate_public_key(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<String, KeyMeldError> {
        let command = GetAggregatePublicKeyCommand {
            keygen_session_id: keygen_session_id.clone(),
        };

        let Some(session_assignment) = self.get_session_assignment(keygen_session_id)? else {
            return Err(KeyMeldError::EnclaveError(format!(
                "missing keygen session {keygen_session_id}"
            )));
        };

        // Get all enclaves that participated in this keygen session
        let participating_enclaves = session_assignment.get_all_assigned_enclaves();

        info!(
            "Requesting aggregate public key for session {} from {} participating enclaves: {:?}",
            keygen_session_id,
            participating_enclaves.len(),
            participating_enclaves
        );

        // Try each participating enclave until one succeeds
        // Randomize the order to distribute load across enclaves
        let mut randomized_enclaves: Vec<_> = participating_enclaves.into_iter().collect();
        randomized_enclaves.shuffle(&mut rand::rng());

        let mut last_error = None;
        for enclave_id in randomized_enclaves {
            let cmd = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                KeygenCommand::GetAggregatePublicKey(command.clone()),
            )));

            match self.send_command_to_enclave(&enclave_id, cmd).await {
                Ok(outcome) => match outcome.response {
                    EnclaveOutcome::Musig(MusigOutcome::Keygen(
                        KeygenOutcome::AggregatePublicKey(response),
                    )) => {
                        debug!(
                            "Retrieved aggregate public key for session {} from enclave {}",
                            keygen_session_id,
                            enclave_id.as_u32()
                        );
                        return Ok(response.encrypted_aggregate_public_key);
                    }
                    other => {
                        let error = KeyMeldError::EnclaveError(format!(
                            "Unexpected response for aggregate public key request from enclave {}: {:?}",
                            enclave_id.as_u32(), other
                        ));
                        warn!("{}", error);
                        last_error = Some(error);
                    }
                },
                Err(e) => {
                    warn!(
                        "Failed to get aggregate public key from enclave {}: {}, trying next enclave",
                        enclave_id.as_u32(), e
                    );
                    last_error = Some(e);
                }
            }
        }

        // If all enclaves failed, return the last error
        Err(last_error.unwrap_or_else(|| {
            KeyMeldError::EnclaveError(format!(
                "No participating enclaves available for session {}",
                keygen_session_id
            ))
        }))
    }

    pub async fn get_enclave_public_info(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<(String, Option<AttestationDocument>, u32, u64, u64, u64), KeyMeldError> {
        let command = Command::new(EnclaveCommand::System(SystemCommand::GetPublicInfo));

        match self.send_command_to_enclave(enclave_id, command).await {
            Ok(outcome) => match outcome.response {
                EnclaveOutcome::System(SystemOutcome::PublicInfo(response)) => Ok((
                    response.public_key,
                    response.attestation_document,
                    response.active_sessions,
                    response.uptime_seconds,
                    response.key_epoch,
                    response.key_generation_time,
                )),
                EnclaveOutcome::Error(err) => Err(KeyMeldError::EnclaveError(format!(
                    "Enclave {enclave_id} returned error: {}",
                    err.error
                ))),
                other => Err(KeyMeldError::EnclaveError(format!(
                    "Unexpected response from enclave {enclave_id}: {:?}",
                    other
                ))),
            },
            Err(e) => Err(e),
        }
    }

    pub async fn initialize_enclave_public_keys(&self) -> Result<usize, KeyMeldError> {
        let enclave_ids: Vec<EnclaveId> =
            self.enclave_info.iter().map(|entry| *entry.key()).collect();
        let mut successful_count = 0;

        for enclave_id in &enclave_ids {
            match self.get_enclave_public_info(enclave_id).await {
                Ok((public_key, attestation_response, _, _, key_epoch, key_generation_time)) => {
                    if let Some(mut info) = self.enclave_info.get_mut(enclave_id) {
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

    /// Validate enclave epoch and reconfigure with KMS keys if restart detected.
    ///
    /// This function detects enclave restarts by comparing the current public key and epoch
    /// with cached values. On restart detection, it sends a Configure command with the
    /// encrypted KMS keys from the database so the enclave can decrypt session data.
    ///
    /// Both `db` and `kms_config` must be provided for proper restart recovery.
    /// Without them, the enclave won't be able to decrypt existing session data after restart.
    pub async fn validate_enclave_epoch_with_kms(
        &self,
        enclave_id: &EnclaveId,
        db: Option<&Database>,
        kms_config: Option<&KmsConfig>,
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

                // Build ConfigureCommand - with KMS info if available, otherwise just epoch sync
                let configure_cmd = if let (Some(db), Some(kms_config)) = (db, kms_config) {
                    // Full KMS reconfiguration - get encrypted keys from database
                    let kms_endpoint = kms_config
                        .endpoint_url
                        .clone()
                        .unwrap_or_else(|| "aws-kms".to_string());
                    let kms_key_id = kms_config.key_id.clone();

                    let (encrypted_dek, encrypted_private_key) = match db
                        .get_enclave_master_key(*enclave_id)
                        .await
                    {
                        Ok(Some(keys)) if keys.kms_key_id == kms_key_id => {
                            info!(
                                    "Found existing KMS keys for enclave {} (epoch: {}), sending for reconfiguration",
                                    enclave_id, keys.key_epoch
                                );
                            (
                                Some(keys.kms_encrypted_dek),
                                Some(keys.encrypted_private_key),
                            )
                        }
                        Ok(Some(keys)) => {
                            warn!(
                                    "KMS key rotation detected for enclave {}: stored_key={}, config_key={}",
                                    enclave_id, keys.kms_key_id, kms_key_id
                                );
                            (None, None)
                        }
                        Ok(None) => {
                            info!(
                                    "No existing keys found for enclave {} during restart, enclave will generate new keys",
                                    enclave_id
                                );
                            (None, None)
                        }
                        Err(e) => {
                            warn!(
                                    "Failed to get master key for enclave {} from database: {}, proceeding without keys",
                                    enclave_id, e
                                );
                            (None, None)
                        }
                    };

                    info!(
                        "Reconfiguring enclave {} with KMS (endpoint: {}, has_keys: {})",
                        enclave_id,
                        kms_endpoint,
                        encrypted_dek.is_some()
                    );

                    ConfigureCommand {
                        enclave_id: *enclave_id,
                        key_epoch: Some(new_epoch),
                        kms_endpoint: Some(kms_endpoint),
                        kms_key_id: Some(kms_key_id),
                        encrypted_dek,
                        encrypted_private_key,
                    }
                } else {
                    // Simple epoch sync only (no KMS info)
                    ConfigureCommand {
                        enclave_id: *enclave_id,
                        key_epoch: Some(new_epoch),
                        kms_endpoint: None,
                        kms_key_id: None,
                        encrypted_dek: None,
                        encrypted_private_key: None,
                    }
                };

                let command = Command::new(EnclaveCommand::System(SystemCommand::Configure(
                    configure_cmd,
                )));

                match self.send_command_to_enclave(enclave_id, command).await {
                    Ok(outcome) => {
                        match &outcome.response {
                            EnclaveOutcome::System(SystemOutcome::Configured(configured)) => {
                                info!(
                                    "Enclave {} reconfigured with KMS (newly_generated: {})",
                                    enclave_id, configured.newly_generated
                                );

                                // Store newly generated keys in database
                                if configured.newly_generated {
                                    if let Some(db) = db {
                                        if let Some(kms_config) = kms_config {
                                            if let Err(e) = db
                                                .store_enclave_master_key(
                                                    *enclave_id,
                                                    &configured.encrypted_dek,
                                                    &configured.encrypted_private_key,
                                                    &kms_config.key_id,
                                                )
                                                .await
                                            {
                                                error!(
                                                    "Failed to store master key for enclave {}: {}",
                                                    enclave_id, e
                                                );
                                            } else {
                                                info!(
                                                    "Stored new encrypted master keys for enclave {}",
                                                    enclave_id
                                                );
                                            }
                                        }
                                    }
                                }

                                // Update cached info with new public key
                                let new_public_key = hex::encode(&configured.public_key);
                                if let Some(mut info) = self.enclave_info.get_mut(enclave_id) {
                                    info.public_key = Some(new_public_key);
                                    info.key_epoch = new_epoch;
                                    info.key_generation_time = SystemTime::now();
                                }

                                return Ok(true);
                            }
                            EnclaveOutcome::System(SystemOutcome::Success) => {
                                info!(
                                    "Reconfigured enclave {} with epoch {} (no KMS)",
                                    enclave_id, new_epoch
                                );

                                // Fetch the new public key after reconfiguration
                                let new_public_key =
                                    match self.get_enclave_public_info(enclave_id).await {
                                        Ok((pk, _, _, _, _, _)) => pk,
                                        Err(_) => current_public_key,
                                    };

                                if let Some(mut info) = self.enclave_info.get_mut(enclave_id) {
                                    info.public_key = Some(new_public_key);
                                    info.key_epoch = new_epoch;
                                    info.key_generation_time = SystemTime::now();
                                }

                                return Ok(true);
                            }
                            other => {
                                warn!(
                                    "Unexpected response from configure command for enclave {}: {:?}",
                                    enclave_id, other
                                );
                            }
                        }
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
        if let Some(info) = self.enclave_info.get(enclave_id) {
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
        self.enclave_info.get(enclave_id).map(|info| info.clone())
    }

    pub async fn get_enclave_public_key(
        &self,
        enclave_id: &EnclaveId,
    ) -> Result<String, KeyMeldError> {
        let (public_key, _, _, _, _, _) = self.get_enclave_public_info(enclave_id).await?;
        Ok(public_key)
    }

    pub fn get_enclave_ids(&self) -> Vec<EnclaveId> {
        self.enclave_info.iter().map(|entry| *entry.key()).collect()
    }

    pub async fn orchestrate_keygen_session_initialization(
        &self,
        keygen_session_id: &SessionId,
        coordinator_enclave_id: &EnclaveId,
        coordinator_encrypted_private_key: &str,
        encrypted_session_secret: &str,
        participants: &BTreeMap<UserId, ParticipantData>,
        encrypted_taproot_tweak: &str,
    ) -> Result<KeygenInitResult, KeyMeldError> {
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

        info!(
            "Initializing keygen session {} on {} enclaves synchronously to prevent race conditions",
            keygen_session_id,
            enclaves_with_participants.len()
        );

        // Map of enclave_id -> encrypted session secret (populated after coordinator init)
        let mut encrypted_secrets_by_enclave: HashMap<EnclaveId, String> = HashMap::new();
        // Also store the full EncryptedSessionSecret structs for session restoration
        let mut all_encrypted_session_secrets: Vec<EncryptedSessionSecret> = Vec::new();

        // First, initialize the coordinator enclave to get encrypted session secrets for all other enclaves
        {
            let init_cmd = InitKeygenSessionCommand {
                keygen_session_id: keygen_session_id.clone(),
                coordinator_encrypted_private_key: Some(
                    coordinator_encrypted_private_key.to_string(),
                ),
                coordinator_user_id: Some(session_assignment.coordinator_user_id.clone()),
                encrypted_session_secret: Some(encrypted_session_secret.to_string()),
                timeout_secs: 1800,
                encrypted_taproot_tweak: encrypted_taproot_tweak.to_string(),
                expected_participant_count: participants.len(),
                expected_participants: expected_participants.clone(),
                enclave_public_keys: fresh_enclave_public_keys.clone(),
            };

            info!(
                "Initializing keygen session on coordinator enclave {} first",
                coordinator_enclave_id
            );

            let result = self
                .execute_with_retry(
                    coordinator_enclave_id,
                    move || {
                        Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                            KeygenCommand::InitSession(init_cmd.clone()),
                        )))
                    },
                    Ok,
                )
                .await;

            match result? {
                EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::KeygenInitialized(
                    response,
                ))) => {
                    info!(
                        "Coordinator enclave {} initialized and encrypted session secret for {} other enclaves",
                        coordinator_enclave_id, response.encrypted_session_secrets.len()
                    );
                    // Store encrypted secrets by target enclave ID
                    for secret in response.encrypted_session_secrets {
                        encrypted_secrets_by_enclave.insert(
                            secret.target_enclave_id,
                            secret.encrypted_session_secret.clone(),
                        );
                        // Also store the full struct for session restoration
                        all_encrypted_session_secrets.push(secret);
                    }
                    // Add the coordinator's own encrypted session secret
                    all_encrypted_session_secrets.push(EncryptedSessionSecret {
                        target_enclave_id: *coordinator_enclave_id,
                        encrypted_session_secret: encrypted_session_secret.to_string(),
                    });
                }
                response => {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response from coordinator enclave {coordinator_enclave_id} during keygen initialization: {response:?}"
                    )));
                }
            }
        }

        // Now initialize all non-coordinator enclaves with their encrypted session secret in parallel
        let non_coordinator_enclaves: Vec<_> = enclaves_with_participants
            .iter()
            .filter(|id| **id != *coordinator_enclave_id)
            .cloned()
            .collect();

        if !non_coordinator_enclaves.is_empty() {
            info!(
                "Initializing keygen session on {} non-coordinator enclaves in parallel",
                non_coordinator_enclaves.len()
            );

            let mut init_futures: FuturesUnordered<_> = non_coordinator_enclaves
                .into_iter()
                .map(|enclave_id| {
                    let enclave_encrypted_secret =
                        encrypted_secrets_by_enclave.get(&enclave_id).cloned();

                    let init_cmd = InitKeygenSessionCommand {
                        keygen_session_id: keygen_session_id.clone(),
                        coordinator_encrypted_private_key: None,
                        coordinator_user_id: None,
                        encrypted_session_secret: enclave_encrypted_secret,
                        timeout_secs: 1800,
                        encrypted_taproot_tweak: encrypted_taproot_tweak.to_string(),
                        expected_participant_count: participants.len(),
                        expected_participants: expected_participants.clone(),
                        enclave_public_keys: fresh_enclave_public_keys.clone(),
                    };

                    async move {
                        let command = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                            KeygenCommand::InitSession(init_cmd),
                        )));

                        let response = self.send_command_to_enclave(&enclave_id, command).await?;

                        match response.response {
                            EnclaveOutcome::Musig(MusigOutcome::Keygen(
                                KeygenOutcome::KeygenInitialized(_),
                            )) => {
                                info!(
                                    "Non-coordinator enclave {} initialized successfully (returned KeygenInitialized)",
                                    enclave_id
                                );
                                Ok(enclave_id)
                            }
                            EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::Success)) => {
                                info!(
                                    "Non-coordinator enclave {} initialized successfully",
                                    enclave_id
                                );
                                Ok(enclave_id)
                            }
                            other => Err(KeyMeldError::EnclaveError(format!(
                                "Unexpected response from enclave {} during keygen initialization: {:?}",
                                enclave_id, other
                            ))),
                        }
                    }
                })
                .collect();

            // Wait for all non-coordinator enclaves to initialize
            while let Some(result) = init_futures.next().await {
                result?;
            }
        }

        info!(
            "All {} enclaves successfully initialized for session {} with session secrets distributed during init",
            enclaves_with_participants.len(),
            keygen_session_id
        );

        // Session secrets are now distributed during init - no separate distribution needed

        info!(
            "Orchestrating participant registration for {} participants in keygen session {} - all enclaves are now synchronized",
            participants.len(),
            keygen_session_id
        );

        // For keygen sessions, use batch orchestration:
        // 1. Group participants by assigned enclave
        // 2. Send AddParticipantsBatch to each enclave (in parallel)
        // 3. Collect encrypted public keys from all enclaves
        // 4. Send DistributeParticipantPublicKeysBatch to distribute keys (in parallel)
        let participant_encrypted_public_keys = self
            .orchestrate_participants_batch_registration(keygen_session_id, participants)
            .await?;

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
                    Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                        KeygenCommand::GetAggregatePublicKey(GetAggregatePublicKeyCommand {
                            keygen_session_id: keygen_session_id.clone(),
                        }),
                    )))
                },
                |outcome| match outcome {
                    EnclaveOutcome::Musig(MusigOutcome::Keygen(
                        KeygenOutcome::AggregatePublicKey(response),
                    )) => Ok(response.encrypted_aggregate_public_key),
                    outcome => Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response for aggregate public key request: {outcome:?}"
                    ))),
                },
            )
            .await?;

        info!(
            "Keygen session initialization completed successfully for session {}",
            keygen_session_id
        );

        Ok(KeygenInitResult {
            aggregate_public_key: aggregate_public_key_bytes,
            participant_encrypted_public_keys,
            enclave_encrypted_session_secrets: all_encrypted_session_secrets,
        })
    }

    pub fn get_connection_stats(&self) -> BTreeMap<EnclaveId, ConnectionStats> {
        let mut stats = BTreeMap::new();
        for (enclave_id, client) in &self.clients {
            stats.insert(*enclave_id, client.get_connection_stats());
        }
        stats
    }

    pub fn get_client_metrics(&self) -> BTreeMap<EnclaveId, ClientMetrics> {
        let mut metrics = BTreeMap::new();
        for (enclave_id, client) in &self.clients {
            metrics.insert(*enclave_id, client.get_client_metrics());
        }
        metrics
    }

    pub fn get_comprehensive_metrics(&self) -> BTreeMap<EnclaveId, ComprehensiveMetrics> {
        let mut metrics = BTreeMap::new();
        for (enclave_id, client) in &self.clients {
            metrics.insert(
                *enclave_id,
                ComprehensiveMetrics {
                    connection_stats: client.get_connection_stats(),
                    client_metrics: client.get_client_metrics(),
                },
            );
        }
        metrics
    }

    pub async fn orchestrate_init_signing_session(
        &self,
        params: SigningSessionInitParams,
    ) -> Result<BTreeMap<UserId, String>, KeyMeldError> {
        info!(
            "Initializing signing session {} with {} participants",
            params.signing_session_id,
            params.participants.len()
        );

        self.get_session_assignment(&params.keygen_session_id)?
            .ok_or(KeyMeldError::EnclaveError(format!(
                "No session assignment found for keygen session {}",
                params.keygen_session_id
            )))?;

        self.copy_session_assignment_for_signing(
            &params.keygen_session_id,
            params.signing_session_id.clone(),
        )?;

        // Group participants by enclave to send one batched command per enclave
        let mut users_by_enclave: BTreeMap<EnclaveId, Vec<UserId>> = BTreeMap::new();
        for (user_id, participant_data) in &params.participants {
            users_by_enclave
                .entry(participant_data.enclave_id)
                .or_default()
                .push(user_id.clone());
        }

        info!(
            "Grouped {} participants across {} enclaves for signing session {}",
            params.participants.len(),
            users_by_enclave.len(),
            params.signing_session_id
        );

        // Initialize all enclaves in parallel using FuturesUnordered - one command per enclave
        let mut init_futures: FuturesUnordered<_> = users_by_enclave
            .into_iter()
            .map(|(enclave_id, user_ids)| {
                // Convert SigningBatchItem to EnclaveBatchItem
                let enclave_batch_items: Vec<keymeld_core::protocol::EnclaveBatchItem> = params
                    .batch_items
                    .iter()
                    .map(|item| keymeld_core::protocol::EnclaveBatchItem {
                        batch_item_id: item.batch_item_id,
                        encrypted_message: item.encrypted_message.clone().unwrap_or_default(),
                        encrypted_adaptor_configs: item.encrypted_adaptor_configs.clone(),
                    })
                    .collect();

                let init_cmd = InitSigningSessionCommand {
                    keygen_session_id: params.keygen_session_id.clone(),
                    signing_session_id: params.signing_session_id.clone(),
                    user_ids: user_ids.clone(),
                    encrypted_taproot_tweak: params.encrypted_taproot_tweak.clone(),
                    expected_participant_count: params.participants.len(),
                    approval_signatures: vec![], // TODO: Pass approval signatures from request
                    batch_items: enclave_batch_items,
                };

                let command = Command::new(EnclaveCommand::Musig(MusigCommand::Signing(
                    SigningCommand::InitSession(init_cmd),
                )));

                async move {
                    let response = self.send_command_to_enclave(&enclave_id, command).await?;
                    match response.response {
                        EnclaveOutcome::Musig(MusigOutcome::Signing(SigningOutcome::Nonces(
                            nonces_response,
                        ))) => {
                            info!(
                                "Initialized signing session on enclave {} and received {} nonces",
                                enclave_id,
                                nonces_response.nonces.len()
                            );
                            Ok(nonces_response.nonces)
                        }
                        other => Err(KeyMeldError::EnclaveError(format!(
                            "Unexpected response when initializing signing session on enclave {} (users: {:?}): {:?}",
                            enclave_id, user_ids, other
                        ))),
                    }
                }
            })
            .collect();

        let mut all_nonces = BTreeMap::new();
        while let Some(result) = init_futures.next().await {
            let nonces = result?;
            for (user_id, nonce_data) in nonces {
                all_nonces.insert(user_id, nonce_data);
            }
        }

        info!(
            "Signing session {} initialized on all enclaves, collected {} nonces",
            params.signing_session_id,
            all_nonces.len()
        );

        Ok(all_nonces)
    }

    pub async fn orchestrate_distribute_nonces(
        &self,
        signing_session_id: &SessionId,
        participants: &BTreeMap<UserId, ParticipantData>,
        all_nonces: BTreeMap<UserId, String>,
    ) -> Result<BTreeMap<UserId, String>, KeyMeldError> {
        info!(
            "Distributing {} encrypted nonces for signing session {} to {} participants",
            all_nonces.len(),
            signing_session_id,
            participants.len()
        );

        let nonces_vec: Vec<(UserId, String)> = all_nonces.into_iter().collect();
        let mut all_partial_signatures = BTreeMap::new();

        // Group participants by enclave to send one command per enclave
        let mut participants_by_enclave: BTreeMap<EnclaveId, Vec<UserId>> = BTreeMap::new();
        for (user_id, participant_data) in participants {
            participants_by_enclave
                .entry(participant_data.enclave_id)
                .or_default()
                .push(user_id.clone());
        }

        // Send distribute_nonces to all enclaves in parallel using FuturesUnordered
        let mut distribute_futures: FuturesUnordered<_> = participants_by_enclave
            .into_iter()
            .map(|(enclave_id, enclave_users)| {
                let distribute_cmd = DistributeNoncesCommand {
                    signing_session_id: signing_session_id.clone(),
                    nonces: nonces_vec.clone(),
                };

                let command = Command::new(EnclaveCommand::Musig(MusigCommand::Signing(
                    SigningCommand::DistributeNonces(distribute_cmd),
                )));

                async move {
                    let response = self.send_command_to_enclave(&enclave_id, command).await?;

                    match response.response {
                        EnclaveOutcome::Musig(MusigOutcome::Signing(SigningOutcome::PartialSignature(
                            sig_response,
                        ))) => {
                            info!(
                                "Distributed nonces to enclave {} and received {} partial signatures",
                                enclave_id,
                                sig_response.partial_signatures.len()
                            );
                            Ok(sig_response.partial_signatures)
                        }
                        other => {
                            Err(KeyMeldError::EnclaveError(format!(
                                "Unexpected response when distributing nonces to enclave {} (users: {:?}): {:?}",
                                enclave_id, enclave_users, other
                            )))
                        }
                    }
                }
            })
            .collect();

        // Process results as they complete
        while let Some(result) = distribute_futures.next().await {
            let partial_sigs = result?;
            for (user_id, encrypted_sig) in partial_sigs {
                all_partial_signatures.insert(user_id, encrypted_sig);
            }
        }

        info!(
            "Nonces distributed for signing session {}, collected {} partial signatures",
            signing_session_id,
            all_partial_signatures.len()
        );

        Ok(all_partial_signatures)
    }

    pub async fn orchestrate_finalize_signature(
        &self,
        _keygen_session_id: &SessionId,
        signing_session_id: &SessionId,
        _participants: &BTreeMap<UserId, ParticipantData>,
        all_partial_signatures: BTreeMap<UserId, String>,
    ) -> Result<Vec<keymeld_sdk::BatchItemResult>, KeyMeldError> {
        info!(
            "Finalizing signature for signing session {} with {} partial signatures",
            signing_session_id,
            all_partial_signatures.len()
        );

        let session_assignment =
            self.get_session_assignment(signing_session_id)?
                .ok_or(KeyMeldError::EnclaveError(format!(
                    "No session assignment found for signing session {}",
                    signing_session_id
                )))?;

        let coordinator_enclave = session_assignment.coordinator_enclave;

        // Convert BTreeMap to Vec for the command
        let partial_signatures_vec: Vec<(UserId, String)> =
            all_partial_signatures.into_iter().collect();

        // Send finalize command to coordinator enclave
        let finalize_cmd = FinalizeSignatureCommand {
            signing_session_id: signing_session_id.clone(),
            partial_signatures: partial_signatures_vec,
        };

        let command = Command::new(EnclaveCommand::Musig(MusigCommand::Signing(
            SigningCommand::FinalizeSignature(finalize_cmd),
        )));

        let response = self
            .send_command_to_enclave(&coordinator_enclave, command)
            .await?;

        match response.response {
            EnclaveOutcome::Musig(MusigOutcome::Signing(SigningOutcome::FinalSignature(
                final_sig_response,
            ))) => {
                info!(
                    "Finalized {} batch results for signing session {}",
                    final_sig_response.batch_results.len(),
                    signing_session_id
                );

                // Convert EnclaveBatchResult to BatchItemResult
                let batch_results = final_sig_response
                    .batch_results
                    .into_iter()
                    .map(|r| keymeld_sdk::BatchItemResult {
                        batch_item_id: r.batch_item_id,
                        signature: r.encrypted_final_signature,
                        adaptor_signatures: r.encrypted_adaptor_signatures,
                        error: r.error,
                    })
                    .collect();

                Ok(batch_results)
            }
            other => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response when finalizing signature: {:?}",
                other
            ))),
        }
    }

    /// Restore sessions for a specific enclave after gateway/enclave restart.
    ///
    /// This re-initializes:
    /// 1. Completed keygen sessions (long-lived, needed for signing)
    /// 2. Active signing sessions (reset to CollectingParticipants state)
    pub async fn restore_sessions_for_enclave(
        &self,
        enclave_id: &EnclaveId,
        db: &Database,
    ) -> Result<RestorationStats, KeyMeldError> {
        let mut stats = RestorationStats::default();

        info!("Starting session restoration for enclave {}", enclave_id);

        // Step 1: Restore completed keygen sessions
        // This replays the keygen initialization to restore session state in the enclave
        let keygen_sessions = db
            .get_restorable_keygen_sessions_for_enclave(enclave_id.as_u32())
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to query keygen sessions: {}", e))
            })?;

        info!(
            "Found {} completed keygen sessions to restore for enclave {}",
            keygen_sessions.len(),
            enclave_id
        );

        for keygen_status in keygen_sessions {
            match self
                .restore_keygen_session(enclave_id, &keygen_status, db)
                .await
            {
                Ok(_) => {
                    stats.keygen_restored += 1;
                    debug!("Restored keygen session for enclave {}", enclave_id);
                }
                Err(e) => {
                    stats.keygen_failed += 1;
                    warn!(
                        "Failed to restore keygen session for enclave {}: {}",
                        enclave_id, e
                    );
                }
            }
        }

        // Step 2: Reset active signing sessions
        let signing_sessions = db
            .get_active_signing_sessions_for_enclave(enclave_id.as_u32())
            .await
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to query signing sessions: {}", e))
            })?;

        info!(
            "Found {} active signing sessions to reset for enclave {}",
            signing_sessions.len(),
            enclave_id
        );

        for signing_status in signing_sessions {
            let signing_session_id = match &signing_status {
                SigningSessionStatus::CollectingParticipants(s) => &s.signing_session_id,
                SigningSessionStatus::InitializingSession(s) => &s.signing_session_id,
                SigningSessionStatus::DistributingNonces(s) => &s.signing_session_id,
                SigningSessionStatus::FinalizingSignature(s) => &s.signing_session_id,
                _ => continue, // Skip completed/failed
            };

            match db
                .reset_signing_session_to_collecting(signing_session_id)
                .await
            {
                Ok(_) => {
                    stats.signing_reset += 1;
                    info!(
                        "Reset signing session {} to collecting_participants",
                        signing_session_id
                    );
                }
                Err(e) => {
                    stats.signing_failed += 1;
                    warn!(
                        "Failed to reset signing session {}: {}",
                        signing_session_id, e
                    );
                }
            }
        }

        // Step 3: Restore user keys (for single-signer operations)
        let user_keys = db
            .get_user_keys_for_enclave(*enclave_id)
            .await
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to query user keys: {}", e)))?;

        info!(
            "Found {} user keys to restore for enclave {}",
            user_keys.len(),
            enclave_id
        );

        for key in user_keys {
            match self.restore_user_key(enclave_id, &key).await {
                Ok(_) => {
                    stats.user_keys_restored += 1;
                    debug!(
                        "Restored user key {} for user {} to enclave {}",
                        key.key_id, key.user_id, enclave_id
                    );
                }
                Err(e) => {
                    stats.user_keys_failed += 1;
                    warn!(
                        "Failed to restore user key {} for user {} to enclave {}: {}",
                        key.key_id, key.user_id, enclave_id, e
                    );
                }
            }
        }

        info!(
            "Session restoration complete for enclave {}: {} keygen restored, {} keygen failed, {} signing reset, {} signing failed, {} user keys restored, {} user keys failed",
            enclave_id,
            stats.keygen_restored,
            stats.keygen_failed,
            stats.signing_reset,
            stats.signing_failed,
            stats.user_keys_restored,
            stats.user_keys_failed,
        );

        Ok(stats)
    }

    /// Restore a single user key to an enclave
    async fn restore_user_key(
        &self,
        enclave_id: &EnclaveId,
        key: &crate::database::UserKey,
    ) -> Result<(), KeyMeldError> {
        let command = EnclaveCommand::UserKey(UserKeyCommand::RestoreKey(RestoreUserKeyCommand {
            user_id: key.user_id.clone(),
            key_id: key.key_id.clone(),
            encrypted_private_key: hex::encode(&key.encrypted_private_key),
            auth_pubkey: key.auth_pubkey.clone(),
            origin_keygen_session_id: key.origin_keygen_session_id.clone(),
            created_at: key.created_at as u64,
        }));

        let outcome = self
            .send_command_to_enclave(enclave_id, command.into())
            .await?;

        match outcome.response {
            keymeld_core::protocol::EnclaveOutcome::UserKey(
                keymeld_core::protocol::UserKeyOutcome::KeyRestored(_),
            ) => Ok(()),
            other => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected outcome restoring user key: {:?}",
                other
            ))),
        }
    }

    /// Restore a single keygen session to an enclave
    async fn restore_keygen_session(
        &self,
        enclave_id: &EnclaveId,
        keygen_status: &KeygenSessionStatus,
        _db: &Database,
    ) -> Result<(), KeyMeldError> {
        let completed = match keygen_status {
            KeygenSessionStatus::Completed(c) => c,
            _ => {
                return Err(KeyMeldError::InvalidState(
                    "Expected completed keygen session".to_string(),
                ))
            }
        };

        let keygen_session_id = &completed.keygen_session_id;

        info!(
            "Restoring keygen session {} to enclave {}",
            keygen_session_id, enclave_id
        );

        // Restore the session assignment in the assignment manager
        let user_ids: Vec<UserId> = completed.registered_participants.keys().cloned().collect();

        // Find the coordinator user from the participants
        let coordinator_user_id = completed
            .registered_participants
            .iter()
            .find(|(_, p)| p.enclave_id == completed.coordinator_enclave_id)
            .map(|(user_id, _)| user_id.clone())
            .unwrap_or_else(|| user_ids.first().cloned().unwrap_or_else(UserId::new_v7));

        // Create session assignment
        let session_assignment = self.create_session_assignment_with_coordinator(
            keygen_session_id.clone(),
            &user_ids,
            &coordinator_user_id,
            completed.coordinator_enclave_id,
        )?;

        // Collect enclave public keys for all participating enclaves
        // Use cached keys to avoid network calls during restoration
        let participating_enclaves = session_assignment.get_all_assigned_enclaves();

        // Check that all participating enclaves have valid cached public keys before proceeding
        // This prevents deadlock when multiple enclaves restart simultaneously
        let mut enclave_public_keys = Vec::new();
        for eid in &participating_enclaves {
            if let Some(cached_info) = self.get_cached_enclave_info(eid) {
                if let Some(public_key) = cached_info.public_key {
                    enclave_public_keys.push(EnclavePublicKeyInfo {
                        enclave_id: *eid,
                        public_key,
                    });
                } else {
                    warn!(
                        "Enclave {} has no cached public key, skipping session {} restoration",
                        eid, keygen_session_id
                    );
                    return Err(KeyMeldError::EnclaveNotReady(format!(
                        "Enclave {} has no cached public key",
                        eid
                    )));
                }
            } else {
                warn!(
                    "Enclave {} not in cache, skipping session {} restoration",
                    eid, keygen_session_id
                );
                return Err(KeyMeldError::EnclaveNotReady(format!(
                    "Enclave {} not in cache",
                    eid
                )));
            }
        }

        // Sort participants for consistent ordering
        let mut expected_participants: Vec<UserId> = completed.expected_participants.clone();
        expected_participants.sort_by(|a, b| b.cmp(a));

        // Initialize keygen session on this enclave
        let is_coordinator = *enclave_id == completed.coordinator_enclave_id;

        // Find the correct encrypted session secret for this enclave
        // Each enclave has its own encrypted version of the session secret
        let encrypted_session_secret_for_enclave = completed
            .enclave_encrypted_session_secrets
            .iter()
            .find(|s| s.target_enclave_id == *enclave_id)
            .map(|s| s.encrypted_session_secret.clone())
            .or_else(|| {
                // Fallback for backwards compatibility: use coordinator's secret if this is the coordinator
                if is_coordinator {
                    Some(completed.encrypted_session_secret.clone())
                } else {
                    warn!(
                        "No encrypted session secret found for enclave {} in session {}, session may have been created before session restoration was supported",
                        enclave_id, keygen_session_id
                    );
                    None
                }
            });

        let init_cmd = InitKeygenSessionCommand {
            keygen_session_id: keygen_session_id.clone(),
            coordinator_encrypted_private_key: if is_coordinator {
                Some(completed.coordinator_encrypted_private_key.clone())
            } else {
                None
            },
            coordinator_user_id: if is_coordinator {
                Some(coordinator_user_id.clone())
            } else {
                None
            },
            encrypted_session_secret: encrypted_session_secret_for_enclave,
            timeout_secs: 1800,
            encrypted_taproot_tweak: completed.encrypted_taproot_tweak.clone(),
            expected_participant_count: completed.registered_participants.len(),
            expected_participants: expected_participants.clone(),
            enclave_public_keys: enclave_public_keys.clone(),
        };

        let command = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
            KeygenCommand::InitSession(init_cmd),
        )));

        let response = self.send_command_to_enclave(enclave_id, command).await?;

        match response.response {
            EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::KeygenInitialized(_)))
            | EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::Success)) => {
                info!(
                    "Keygen session {} initialized on enclave {}",
                    keygen_session_id, enclave_id
                );
            }
            other => {
                return Err(KeyMeldError::EnclaveError(format!(
                    "Unexpected response initializing keygen session on enclave {}: {:?}",
                    enclave_id, other
                )));
            }
        }

        // Add participants to this enclave
        let participants_for_enclave: Vec<ParticipantRegistrationData> = completed
            .registered_participants
            .iter()
            .filter(|(_, p)| p.enclave_id == *enclave_id)
            .map(|(user_id, p)| ParticipantRegistrationData {
                user_id: user_id.clone(),
                enclave_encrypted_data: p.enclave_encrypted_data.clone(),
                auth_pubkey: p.auth_pubkey.clone(),
                require_signing_approval: p.require_signing_approval,
            })
            .collect();

        if !participants_for_enclave.is_empty() {
            let batch_cmd = AddParticipantsBatchCommand {
                keygen_session_id: keygen_session_id.clone(),
                participants: participants_for_enclave,
            };

            let command = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                KeygenCommand::AddParticipantsBatch(batch_cmd),
            )));

            let response = self.send_command_to_enclave(enclave_id, command).await?;

            match response.response {
                EnclaveOutcome::Musig(MusigOutcome::Keygen(
                    KeygenOutcome::ParticipantsAddedBatch(batch_response),
                )) => {
                    info!(
                        "Added {} participants to keygen session {} on enclave {}",
                        batch_response.participants.len(),
                        keygen_session_id,
                        enclave_id
                    );
                }
                other => {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Unexpected response adding participants on enclave {}: {:?}",
                        enclave_id, other
                    )));
                }
            }
        }

        // Distribute public keys from OTHER enclaves to this enclave
        // This uses the stored encrypted public keys from the completed keygen session
        // Each enclave needs the public keys from participants on other enclaves to
        // compute the aggregate key for signing
        let keys_for_this_enclave: Vec<(UserId, String)> = completed
            .participant_encrypted_public_keys
            .iter()
            .flat_map(|(user_id, encrypted_keys)| {
                encrypted_keys
                    .iter()
                    .filter(|k| k.target_enclave_id == *enclave_id)
                    .map(|k| (user_id.clone(), k.encrypted_public_key.clone()))
            })
            .collect();

        if !keys_for_this_enclave.is_empty() {
            info!(
                "Distributing {} public keys to enclave {} for session {}",
                keys_for_this_enclave.len(),
                enclave_id,
                keygen_session_id
            );

            let dist_cmd = DistributeParticipantPublicKeysBatchCommand {
                keygen_session_id: keygen_session_id.clone(),
                participants_public_keys: keys_for_this_enclave,
            };

            let command = Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
                KeygenCommand::DistributeParticipantPublicKeysBatch(dist_cmd),
            )));

            match self.send_command_to_enclave(enclave_id, command).await {
                Ok(_response) => {
                    debug!(
                        "Distributed public keys to enclave {} for session {}",
                        enclave_id, keygen_session_id
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to distribute public keys to enclave {} for session {}: {}",
                        enclave_id, keygen_session_id, e
                    );
                    return Err(e);
                }
            }
        }

        info!(
            "Restored keygen session {} on enclave {}",
            keygen_session_id, enclave_id
        );

        Ok(())
    }

    pub async fn cleanup_unhealthy_connections(&self) -> Result<u32, KeyMeldError> {
        let mut total_cleaned = 0u32;

        for (enclave_id, client) in &self.clients {
            let count = client.cleanup_unhealthy_connections().await;
            total_cleaned += count as u32;
            if count > 0 {
                info!(
                    "Cleaned up {} unhealthy connections for enclave {}",
                    count,
                    enclave_id.as_u32()
                );
            }
        }

        if total_cleaned > 0 {
            info!("Total unhealthy connections cleaned up: {}", total_cleaned);
        }

        Ok(total_cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{EnclaveId, SessionId, UserId};
    use std::collections::{BTreeMap, HashSet};

    fn create_test_participants() -> BTreeMap<UserId, ParticipantData> {
        let mut participants = BTreeMap::new();

        for i in 0..3 {
            let user_id = UserId::new_v7();
            let participant = ParticipantData {
                user_id: user_id.clone(),
                user_key_id: i as i64,
                enclave_id: EnclaveId::from(i),
                enclave_key_epoch: 1,
                session_encrypted_data: Some(format!("session_data_{}", i)),
                enclave_encrypted_data: format!("enclave_data_{}", i),
                auth_pubkey: vec![1, 2, 3],
                require_signing_approval: false,
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
            encrypted_taproot_tweak: "encrypted_tweak".to_string(),
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
