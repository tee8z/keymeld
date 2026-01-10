use std::collections::BTreeMap;

use crate::client::KeyMeldClient;
use crate::credentials::SessionCredentials;
use crate::error::{CryptoError, KeygenError, SdkError};
use crate::types::{
    GetAvailableSlotsResponse, InitializeKeygenSessionRequest, InitializeKeygenSessionResponse,
    KeygenSessionStatusResponse, KeygenStatusKind, RegisterKeygenParticipantRequest,
    RegisterKeygenParticipantResponse, ReserveKeygenSessionRequest, ReserveKeygenSessionResponse,
    SessionId, SubsetDefinition, TaprootTweak, UserId,
};
use keymeld_core::crypto::SecureCrypto;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct KeygenOptions {
    pub(crate) timeout_secs: Option<u64>,
    pub(crate) max_signing_sessions: Option<u32>,
    pub(crate) taproot_tweak: TaprootTweak,
    pub(crate) require_signing_approval: bool,
}

impl KeygenOptions {
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }

    pub fn max_signings(mut self, count: u32) -> Self {
        self.max_signing_sessions = Some(count);
        self
    }

    pub fn tweak(mut self, tweak: TaprootTweak) -> Self {
        self.taproot_tweak = tweak;
        self
    }

    pub fn require_approval(mut self) -> Self {
        self.require_signing_approval = true;
        self
    }

    pub fn approval(mut self, required: bool) -> Self {
        self.require_signing_approval = required;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct JoinOptions {
    pub(crate) require_signing_approval: bool,
}

impl JoinOptions {
    pub fn require_approval(mut self) -> Self {
        self.require_signing_approval = true;
        self
    }

    pub fn approval(mut self, required: bool) -> Self {
        self.require_signing_approval = required;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct RegisterOptions {
    pub(crate) require_signing_approval: bool,
}

impl RegisterOptions {
    pub fn require_approval(mut self) -> Self {
        self.require_signing_approval = true;
        self
    }

    pub fn approval(mut self, required: bool) -> Self {
        self.require_signing_approval = required;
        self
    }
}

pub struct KeygenManager<'a> {
    client: &'a KeyMeldClient,
}

impl<'a> KeygenManager<'a> {
    pub(crate) fn new(client: &'a KeyMeldClient) -> Self {
        Self { client }
    }

    pub async fn create_session(
        &self,
        participants: Vec<UserId>,
        options: KeygenOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        self.create_session_internal(participants, vec![], options)
            .await
    }

    pub async fn create_session_with_subsets(
        &self,
        participants: Vec<UserId>,
        subsets: Vec<SubsetDefinition>,
        options: KeygenOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        self.create_session_internal(participants, subsets, options)
            .await
    }

    async fn create_session_internal(
        &self,
        participants: Vec<UserId>,
        subsets: Vec<SubsetDefinition>,
        options: KeygenOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for creating keygen session".to_string(),
            )
        })?;

        let credentials = SessionCredentials::generate()?;
        let session_secret = credentials.export_session_secret();
        let session_secret_hex = hex::encode(session_secret);

        let keygen_session_id = SessionId::new_v7();

        let encrypted_taproot_tweak = credentials.encrypt(
            &serde_json::to_vec(&options.taproot_tweak)
                .map_err(|e| SdkError::Internal(format!("Failed to serialize tweak: {}", e)))?,
            "taproot_tweak",
        )?;

        let reserve_request = ReserveKeygenSessionRequest {
            keygen_session_id: keygen_session_id.clone(),
            coordinator_user_id: self.client.user_id().clone(),
            expected_participants: participants.clone(),
            timeout_secs: options.timeout_secs.unwrap_or(3600),
            max_signing_sessions: options.max_signing_sessions,
            encrypted_taproot_tweak,
            subset_definitions: subsets,
        };

        let reserve_response: ReserveKeygenSessionResponse = self
            .client
            .http()
            .post(
                &self.client.url("/api/v1/keygen/reserve"),
                &reserve_request,
                &[],
            )
            .await?;

        let encrypted_session_secret =
            credentials.encrypt_secret_for_enclave(&reserve_response.coordinator_public_key)?;

        let encrypted_coordinator_key = user_credentials
            .encrypt_private_key_for_enclave(&reserve_response.coordinator_public_key)?;

        let session_data = KeygenSessionData {
            coordinator_pubkey: user_credentials.public_key_bytes(),
            aggregate_pubkey: None,
        };
        let encrypted_session_data = credentials.encrypt(
            &serde_json::to_vec(&session_data).map_err(|e| {
                SdkError::Internal(format!("Failed to serialize session data: {}", e))
            })?,
            "keygen_session",
        )?;

        let enclave_data = KeygenEnclaveData {
            coordinator_private_key: encrypted_coordinator_key.clone(),
            session_secret: session_secret_hex,
        };
        let encrypted_enclave_data = SecureCrypto::ecies_encrypt_from_hex(
            &reserve_response.coordinator_public_key,
            &serde_json::to_vec(&enclave_data).map_err(|e| {
                SdkError::Internal(format!("Failed to serialize enclave data: {}", e))
            })?,
        )
        .map_err(|e| SdkError::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;

        let initialize_request = InitializeKeygenSessionRequest {
            coordinator_pubkey: user_credentials.public_key_bytes(),
            coordinator_encrypted_private_key: encrypted_coordinator_key,
            session_public_key: credentials.public_key_bytes(),
            encrypted_session_secret,
            encrypted_session_data,
            encrypted_enclave_data: hex::encode(&encrypted_enclave_data),
            enclave_key_epoch: reserve_response.coordinator_key_epoch,
        };

        let _init_response: InitializeKeygenSessionResponse = self
            .client
            .http()
            .post(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/initialize", keygen_session_id)),
                &initialize_request,
                &[],
            )
            .await?;

        Ok(KeygenSession {
            session_id: keygen_session_id,
            credentials,
            status: KeygenStatusKind::CollectingParticipants,
            aggregate_key: None,
            subset_aggregates: BTreeMap::new(),
            coordinator_enclave_pubkey: Some(reserve_response.coordinator_public_key),
            coordinator_enclave_key_epoch: Some(reserve_response.coordinator_key_epoch),
            is_registered: false,
            client: self.client,
        })
    }

    pub async fn join_session(
        &self,
        session_id: SessionId,
        session_secret: &[u8; 32],
        options: JoinOptions,
    ) -> Result<KeygenSession<'a>, SdkError> {
        let credentials = SessionCredentials::from_session_secret(session_secret)?;

        let slots: GetAvailableSlotsResponse = self
            .client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/slots", session_id)),
                &[],
            )
            .await?;

        let our_slot = slots
            .available_slots
            .iter()
            .find(|s| &s.user_id == self.client.user_id() && !s.claimed)
            .ok_or_else(|| SdkError::Keygen(KeygenError::NoAvailableSlots(session_id.clone())))?;

        let enclave_info = self
            .client
            .health()
            .get_enclave_key(our_slot.enclave_id.as_u32())
            .await?;

        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for joining keygen session".to_string(),
            )
        })?;

        let session_signature = credentials.sign_session_request(&session_id.to_string())?;

        let encrypted_session_data = credentials.encrypt(
            &serde_json::to_vec(&KeygenParticipantSessionData {
                participant_public_keys: {
                    let mut map = BTreeMap::new();
                    map.insert(
                        self.client.user_id().clone(),
                        user_credentials.public_key_bytes(),
                    );
                    map
                },
            })
            .map_err(|e| SdkError::Internal(format!("Failed to serialize: {}", e)))?,
            "keygen_participant_session",
        )?;

        let encrypted_private_key =
            user_credentials.encrypt_private_key_for_enclave(&enclave_info.public_key)?;

        let auth_pubkey = user_credentials.derive_session_auth_pubkey(&session_id.to_string())?;

        let register_request = RegisterKeygenParticipantRequest {
            keygen_session_id: session_id.clone(),
            user_id: self.client.user_id().clone(),
            encrypted_private_key,
            public_key: user_credentials.public_key_bytes(),
            encrypted_session_data,
            enclave_public_key: enclave_info.public_key.clone(),
            enclave_key_epoch: enclave_info.key_epoch,
            require_signing_approval: options.require_signing_approval,
            auth_pubkey,
        };

        let response: RegisterKeygenParticipantResponse = self
            .client
            .http()
            .post(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/participants", session_id)),
                &register_request,
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        Ok(KeygenSession {
            session_id,
            credentials,
            status: response.status,
            aggregate_key: None,
            subset_aggregates: BTreeMap::new(),
            coordinator_enclave_pubkey: Some(enclave_info.public_key),
            coordinator_enclave_key_epoch: Some(enclave_info.key_epoch),
            is_registered: true,
            client: self.client,
        })
    }

    pub async fn get_available_slots(
        &self,
        session_id: &SessionId,
    ) -> Result<GetAvailableSlotsResponse, SdkError> {
        self.client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/slots", session_id)),
                &[],
            )
            .await
    }

    pub async fn restore_session(
        &self,
        session_id: SessionId,
        credentials: SessionCredentials,
    ) -> Result<KeygenSession<'a>, SdkError> {
        let session_signature = credentials.sign_session_request(&session_id.to_string())?;

        let status_response: KeygenSessionStatusResponse = self
            .client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/status", session_id)),
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        Ok(KeygenSession {
            session_id,
            credentials,
            status: status_response.status,
            aggregate_key: status_response.aggregate_public_key,
            subset_aggregates: status_response.encrypted_subset_aggregates,
            coordinator_enclave_pubkey: None,
            coordinator_enclave_key_epoch: None,
            is_registered: true,
            client: self.client,
        })
    }
}

pub struct KeygenSession<'a> {
    session_id: SessionId,
    credentials: SessionCredentials,
    status: KeygenStatusKind,
    aggregate_key: Option<crate::types::AggregatePublicKey>,
    subset_aggregates: BTreeMap<Uuid, String>,
    coordinator_enclave_pubkey: Option<String>,
    coordinator_enclave_key_epoch: Option<u64>,
    is_registered: bool,
    client: &'a KeyMeldClient,
}

impl<'a> KeygenSession<'a> {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn status(&self) -> &KeygenStatusKind {
        &self.status
    }

    pub fn credentials(&self) -> &SessionCredentials {
        &self.credentials
    }

    pub fn is_registered(&self) -> bool {
        self.is_registered
    }

    pub async fn register_self(
        &mut self,
        options: RegisterOptions,
    ) -> Result<&KeygenStatusKind, SdkError> {
        if self.is_registered {
            return Err(SdkError::InvalidInput(
                "Already registered as a participant".to_string(),
            ));
        }

        let enclave_pubkey = self.coordinator_enclave_pubkey.as_ref().ok_or_else(|| {
            SdkError::InvalidInput("Enclave public key not available - cannot register".to_string())
        })?;
        let enclave_key_epoch = self.coordinator_enclave_key_epoch.ok_or_else(|| {
            SdkError::InvalidInput("Enclave key epoch not available - cannot register".to_string())
        })?;

        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput("User credentials required for registration".to_string())
        })?;

        let session_signature = self
            .credentials
            .sign_session_request(&self.session_id.to_string())?;

        let encrypted_private_key =
            user_credentials.encrypt_private_key_for_enclave(enclave_pubkey)?;

        let session_data = KeygenParticipantSessionData {
            participant_public_keys: {
                let mut map = BTreeMap::new();
                map.insert(
                    self.client.user_id().clone(),
                    user_credentials.public_key_bytes(),
                );
                map
            },
        };
        let encrypted_session_data = self.credentials.encrypt(
            &serde_json::to_vec(&session_data)
                .map_err(|e| SdkError::Internal(format!("Failed to serialize: {}", e)))?,
            "keygen_participant_session",
        )?;

        let auth_pubkey =
            user_credentials.derive_session_auth_pubkey(&self.session_id.to_string())?;

        let register_request = RegisterKeygenParticipantRequest {
            keygen_session_id: self.session_id.clone(),
            user_id: self.client.user_id().clone(),
            encrypted_private_key,
            public_key: user_credentials.public_key_bytes(),
            encrypted_session_data,
            enclave_public_key: enclave_pubkey.clone(),
            enclave_key_epoch,
            require_signing_approval: options.require_signing_approval,
            auth_pubkey,
        };

        let response: RegisterKeygenParticipantResponse = self
            .client
            .http()
            .post(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/participants", self.session_id)),
                &register_request,
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        self.status = response.status;
        self.is_registered = true;

        Ok(&self.status)
    }

    pub async fn refresh_status(&mut self) -> Result<&KeygenStatusKind, SdkError> {
        let session_signature = self
            .credentials
            .sign_session_request(&self.session_id.to_string())?;

        let response: KeygenSessionStatusResponse = self
            .client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/keygen/{}/status", self.session_id)),
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        self.status = response.status;
        self.aggregate_key = response.aggregate_public_key;
        self.subset_aggregates = response.encrypted_subset_aggregates;

        Ok(&self.status)
    }

    pub async fn wait_for_completion(
        &mut self,
    ) -> Result<&crate::types::AggregatePublicKey, SdkError> {
        let config = self.client.polling_config().clone();
        let mut delay = config.initial_delay;

        for attempt in 1..=config.max_attempts {
            self.refresh_status().await?;

            match self.status {
                KeygenStatusKind::Completed => {
                    if self.aggregate_key.is_some() {
                        return self.aggregate_key.as_ref().ok_or_else(|| {
                            SdkError::Keygen(KeygenError::Failed(
                                "No aggregate key available".to_string(),
                            ))
                        });
                    } else {
                        return Err(SdkError::Keygen(KeygenError::Failed(
                            "Keygen completed but no aggregate key returned".to_string(),
                        )));
                    }
                }
                KeygenStatusKind::Failed => {
                    return Err(SdkError::Keygen(KeygenError::Failed(
                        "Keygen session failed".to_string(),
                    )));
                }
                _ => {
                    if attempt >= config.max_attempts {
                        break;
                    }
                    #[cfg(not(target_arch = "wasm32"))]
                    tokio::time::sleep(delay).await;
                    #[cfg(target_arch = "wasm32")]
                    gloo_timers::future::TimeoutFuture::new(delay.as_millis() as u32).await;

                    let next_delay_ms =
                        (delay.as_millis() as f64 * config.backoff_multiplier) as u64;
                    delay = std::time::Duration::from_millis(next_delay_ms).min(config.max_delay);
                }
            }
        }

        Err(SdkError::Keygen(KeygenError::Timeout))
    }

    pub fn decrypt_aggregate_key(&self) -> Result<Vec<u8>, SdkError> {
        let encrypted_key = self.aggregate_key.as_ref().ok_or_else(|| {
            SdkError::Keygen(KeygenError::Failed(
                "No aggregate key available".to_string(),
            ))
        })?;

        self.credentials
            .decrypt(encrypted_key, "aggregate_public_key")
    }

    pub fn subset_aggregate(&self, subset_id: &Uuid) -> Option<&String> {
        self.subset_aggregates.get(subset_id)
    }

    pub fn decrypt_subset_aggregate(&self, subset_id: &Uuid) -> Result<Vec<u8>, SdkError> {
        let encrypted_key = self.subset_aggregates.get(subset_id).ok_or_else(|| {
            SdkError::Keygen(KeygenError::Failed(format!(
                "Subset {} not found",
                subset_id
            )))
        })?;

        self.credentials.decrypt(encrypted_key, "subset_aggregate")
    }

    pub fn export_session_secret(&self) -> [u8; 32] {
        self.credentials.export_session_secret()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeygenSessionData {
    coordinator_pubkey: Vec<u8>,
    aggregate_pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeygenEnclaveData {
    coordinator_private_key: String,
    session_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeygenParticipantSessionData {
    participant_public_keys: BTreeMap<UserId, Vec<u8>>,
}
