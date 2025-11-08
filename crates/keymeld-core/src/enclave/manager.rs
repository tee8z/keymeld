use crate::{
    api::TaprootTweak,
    enclave::{
        AddNonceCommand, AddPartialSignatureCommand, GenerateNonceCommand,
        InitKeygenSessionCommand, InitSigningSessionCommand, ParitialSignatureCommand,
    },
    identifiers::{EnclaveId, SessionId, UserId},
    session::AggregatePublicKey,
    KeyMeldError, ParticipantData,
};
use musig2::PubNonce;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, RwLock},
    time::SystemTime,
};
use tokio::time::{sleep, Duration};
use tracing::{debug, warn};

use super::{
    client::VsockClient,
    distribution::{EnclaveAssignmentManager, SessionAssignment},
    protocol::{
        AddParticipantCommand, AttestationResponse, EnclaveCommand, EnclaveResponse,
        FinalizeCommand, GetAggregateNonceCommand, GetAggregatePublicKeyCommand,
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
    enclave_info: Mutex<BTreeMap<EnclaveId, EnclaveInfo>>,
    is_configured: bool,
    assignment_manager: RwLock<EnclaveAssignmentManager>,
}

impl EnclaveManager {
    pub fn new(enclave_configs: Vec<EnclaveConfig>) -> Self {
        let mut clients = BTreeMap::new();
        let mut enclave_info = BTreeMap::new();

        let now = SystemTime::now();
        for config in enclave_configs {
            let enclave_id = EnclaveId::from(config.id);
            let client = VsockClient::new(config.cid, config.port);

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

        Self {
            clients,
            enclave_info: Mutex::new(enclave_info),
            is_configured: false,
            assignment_manager: RwLock::new(assignment_manager),
        }
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
            .unwrap()
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
            .unwrap()
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
            .unwrap()
            .copy_session_assignment_for_signing(keygen_session_id, signing_session_id)
    }

    pub fn get_session_assignment(&self, session_id: &SessionId) -> Option<SessionAssignment> {
        self.assignment_manager
            .read()
            .unwrap()
            .get_session_assignment(session_id)
    }

    pub fn remove_session_assignment(&self, session_id: &SessionId) -> Option<SessionAssignment> {
        self.assignment_manager
            .write()
            .unwrap()
            .remove_session(session_id)
    }

    pub fn restore_session_assignment(&self, assignment: SessionAssignment) {
        self.assignment_manager
            .write()
            .unwrap()
            .restore_session_assignment(assignment);
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
        let client = self.clients.get(enclave_id).ok_or_else(|| {
            KeyMeldError::EnclaveError(format!("Enclave {} not found", enclave_id))
        })?;

        client.send_command(command).await
    }

    pub async fn get_aggregate_public_key(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let command = GetAggregatePublicKeyCommand {
            keygen_session_id: keygen_session_id.clone(),
        };

        let Some(session_assignment) = self
            .assignment_manager
            .read()
            .unwrap()
            .get_session_assignment(keygen_session_id)
        else {
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
        public_key: &[u8],
        enclave_id: &EnclaveId,
    ) -> Result<(), KeyMeldError> {
        let add_participant_cmd = AddParticipantCommand {
            keygen_session_id: Some(session_id.clone()),
            signing_session_id: None,
            user_id: user_id.clone(),
            public_key: public_key.to_vec(),
            encrypted_private_key: None,
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
        debug!(
            "Starting nonce orchestration for signing session {}",
            signing_session_id
        );

        let mut generated_nonces = BTreeMap::new();

        for (user_id, participant) in participants {
            let nonce_cmd = GenerateNonceCommand {
                signing_session_id: signing_session_id.clone(),
                keygen_session_id: keygen_session_id.clone(),
                user_id: user_id.clone(),
                encrypted_private_key: Some(participant.encrypted_private_key.clone()),
                signer_index: self.calculate_signer_index(user_id, participants)?,
            };

            let mut attempts = 0;
            //TODO(@tee8z): make configurable
            const MAX_ATTEMPTS: u32 = 3;

            loop {
                attempts += 1;
                match self
                    .send_command_to_enclave(
                        &participant.enclave_id,
                        EnclaveCommand::GenerateNonce(nonce_cmd.clone()),
                    )
                    .await
                {
                    Ok(EnclaveResponse::Nonce(nonce_resp)) => {
                        generated_nonces.insert(user_id.clone(), nonce_resp.public_nonce);
                        break;
                    }
                    Ok(response) => {
                        if attempts >= MAX_ATTEMPTS {
                            return Err(KeyMeldError::EnclaveError(format!(
                                "Invalid nonce response from enclave for user {} after {} attempts: {:?}",
                                user_id.as_str(), MAX_ATTEMPTS, response
                            )));
                        } else {
                            warn!("Invalid nonce response for user {}, retrying", user_id);
                            //TODO(@tee8z): make configurable
                            sleep(Duration::from_millis(300)).await;
                        }
                    }
                    Err(e) => {
                        if attempts >= MAX_ATTEMPTS {
                            return Err(KeyMeldError::EnclaveError(format!(
                                "Failed to generate nonce for user {} after {} attempts: {}",
                                user_id.as_str(),
                                MAX_ATTEMPTS,
                                e
                            )));
                        } else {
                            warn!(
                                "Failed to generate nonce for user {}, retrying: {}",
                                user_id, e
                            );
                            //TODO(@tee8z): make configurable
                            sleep(Duration::from_millis(300)).await;
                        }
                    }
                }
            }
        }

        debug!("Starting nonce distribution phase");

        let all_enclaves: BTreeSet<EnclaveId> =
            participants.values().map(|p| p.enclave_id).collect();

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
                    .send_command_to_enclave(enclave_id, EnclaveCommand::AddNonce(add_nonce_cmd))
                    .await
                {
                    Ok(EnclaveResponse::Success(_)) => {}
                    Ok(response) => {
                        warn!("Unexpected nonce distribution response: {:?}", response);
                    }
                    Err(e) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to distribute nonce: {}",
                            e
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
            self.get_session_assignment(keygen_session_id)
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
            self.get_session_assignment(keygen_session_id)
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

        debug!(
            "Starting partial signature generation for signing session {}",
            signing_session_id
        );

        for (user_id, participant) in participants {
            let sig_cmd = ParitialSignatureCommand {
                signing_session_id: signing_session_id.clone(),
                keygen_session_id: keygen_session_id.clone(),
                user_id: user_id.clone(),
                aggregate_nonce: aggregate_nonce.clone(),
                encrypted_private_key: Some(participant.encrypted_private_key.clone()),
            };

            let response = self
                .send_command_to_enclave(
                    &participant.enclave_id,
                    EnclaveCommand::SignPartialSignature(sig_cmd),
                )
                .await?;

            if let EnclaveResponse::Signature(sig_resp) = response {
                partial_signatures.insert(user_id.clone(), sig_resp.partial_signature);
            } else {
                return Err(KeyMeldError::EnclaveError(format!(
                    "Invalid signature response from enclave for user {}",
                    user_id
                )));
            }
        }

        debug!("Starting partial signature distribution phase");

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
        let session_assignment = self
            .get_session_assignment(&params.keygen_session_id)
            .ok_or_else(|| {
                KeyMeldError::EnclaveError(format!(
                    "No session assignment found for keygen session {}",
                    params.keygen_session_id
                ))
            })?;

        let coordinator_enclave_id = session_assignment.coordinator_enclave;

        let mut enclave_participants: BTreeMap<EnclaveId, Vec<(&UserId, &ParticipantData)>> =
            BTreeMap::new();
        for (user_id, participant_data) in &params.participants {
            enclave_participants
                .entry(participant_data.enclave_id)
                .or_default()
                .push((user_id, participant_data));
        }

        // Initialize sessions in all enclaves that have participants
        for (enclave_id, _participants_in_enclave) in &enclave_participants {
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
                //TODO(@tee8z): make configurable
                timeout_secs: 1800,
                taproot_tweak: params.taproot_tweak.clone(),
                expected_participant_count: params.participants.len(),
            };

            self.send_command_to_enclave(enclave_id, EnclaveCommand::InitSigningSession(init_cmd))
                .await?;
        }

        // Add all participant public keys to all enclaves for signing session
        for (enclave_id, _participants_in_enclave) in &enclave_participants {
            for (user_id, participant) in &params.participants {
                let public_key_bytes = participant.public_key.serialize().to_vec();

                // Only provide private key to the participant's assigned enclave
                let encrypted_private_key = if *enclave_id == participant.enclave_id {
                    Some(participant.encrypted_private_key.clone())
                } else {
                    None
                };

                let add_participant_cmd = AddParticipantCommand {
                    keygen_session_id: Some(params.keygen_session_id.clone()),
                    signing_session_id: Some(params.signing_session_id.clone()),
                    user_id: user_id.clone(),
                    public_key: public_key_bytes,
                    encrypted_private_key,
                };

                let mut attempts = 0;
                //TODO(@tee8z): make configurable
                const MAX_ATTEMPTS: u32 = 3;

                loop {
                    attempts += 1;
                    match self
                        .send_command_to_enclave(
                            enclave_id,
                            EnclaveCommand::AddParticipant(add_participant_cmd.clone()),
                        )
                        .await
                    {
                        Ok(_) => break,
                        Err(e) => {
                            if attempts >= MAX_ATTEMPTS {
                                return Err(KeyMeldError::EnclaveError(format!(
                                    "Failed to add participant {} to enclave {} after {} attempts: {}",
                                    user_id, enclave_id, MAX_ATTEMPTS, e
                                )));
                            } else {
                                warn!("Failed to add participant {}, retrying: {}", user_id, e);
                                sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            }
        }

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
        let session_assignment =
            self.get_session_assignment(keygen_session_id)
                .ok_or_else(|| {
                    KeyMeldError::EnclaveError(format!(
                        "No session assignment found for session {}",
                        keygen_session_id
                    ))
                })?;

        let enclaves_with_participants = session_assignment.get_all_assigned_enclaves();

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
            };

            self.send_command_to_enclave(enclave_id, EnclaveCommand::InitKeygenSession(init_cmd))
                .await
                .map_err(|e| {
                    KeyMeldError::EnclaveError(format!(
                        "Failed to initialize keygen session {} in enclave {}: {}",
                        keygen_session_id, enclave_id, e
                    ))
                })?;
        }

        // Add all participant public keys to all enclaves for aggregate key computation
        for enclave_id in &enclaves_with_participants {
            for (user_id, participant) in participants {
                let add_participant_cmd = AddParticipantCommand {
                    keygen_session_id: Some(keygen_session_id.clone()),
                    signing_session_id: None,
                    user_id: user_id.clone(),
                    public_key: participant.public_key.serialize().to_vec(),
                    // Only provide private key to the participant's assigned enclave
                    encrypted_private_key: if *enclave_id == participant.enclave_id {
                        Some(participant.encrypted_private_key.clone())
                    } else {
                        None
                    },
                };

                self.send_command_to_enclave(
                    enclave_id,
                    EnclaveCommand::AddParticipant(add_participant_cmd),
                )
                .await
                .map_err(|e| {
                    KeyMeldError::EnclaveError(format!(
                        "Failed to add participant {} to enclave {}: {}",
                        user_id, enclave_id, e
                    ))
                })?;
            }
        }

        let aggregate_public_key = self.get_aggregate_public_key(keygen_session_id).await?;

        let aggregate_key = AggregatePublicKey::new(
            aggregate_public_key,
            participants.keys().cloned().collect(),
            vec![],
        );

        Ok(aggregate_key)
    }
}
