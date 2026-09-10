use crate::client::KeyMeldClient;
use crate::credentials::SessionCredentials;
use crate::error::{SdkError, SigningError};
use crate::managers::keygen::KeygenSession;
use crate::types::{
    BatchItemResult, CreateSigningSessionRequest, CreateSigningSessionResponse, SessionId,
    SigningBatchItem, SigningMode, SigningSessionStatusResponse, SigningStatusKind, TaprootTweak,
    UserId,
};
use keymeld_core::authorization::{ParticipantApproval, SigningAuthorization};
use uuid::Uuid;

// Re-export adaptor types from keymeld-core
pub use keymeld_core::protocol::{AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType};
use std::collections::BTreeMap;

#[cfg(not(target_arch = "wasm32"))]
fn approval_timestamp() -> Result<u64, SdkError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| SdkError::Internal(e.to_string()))
}

#[cfg(target_arch = "wasm32")]
fn approval_timestamp() -> Result<u64, SdkError> {
    use wasm_bindgen::prelude::wasm_bindgen;
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date, js_name = now)]
        fn date_now() -> f64;
    }
    let seconds = date_now() / 1000.0;
    if !seconds.is_finite() || seconds < 0.0 || seconds >= u64::MAX as f64 {
        return Err(SdkError::Internal(
            "Browser returned an invalid current time".into(),
        ));
    }
    Ok(seconds.floor() as u64)
}

#[derive(Debug, Clone, Default)]
pub struct SigningOptions {
    pub(crate) timeout_secs: Option<u64>,
}

impl SigningOptions {
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = Some(secs);
        self
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchSigningItem {
    pub(crate) id: Uuid,
    pub(crate) message: [u8; 32],
    pub(crate) mode: BatchSigningMode,
    pub(crate) taproot_tweak: TaprootTweak,
    pub(crate) subset_id: Option<Uuid>,
}

impl BatchSigningItem {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn message(&self) -> &[u8; 32] {
        &self.message
    }
    pub fn mode(&self) -> &BatchSigningMode {
        &self.mode
    }
    pub fn taproot_tweak(&self) -> &TaprootTweak {
        &self.taproot_tweak
    }
    pub fn subset_id(&self) -> Option<Uuid> {
        self.subset_id
    }

    pub fn new(message: [u8; 32]) -> Self {
        Self {
            id: Uuid::now_v7(),
            message,
            mode: BatchSigningMode::Regular,
            taproot_tweak: TaprootTweak::None,
            subset_id: None,
        }
    }

    pub fn adaptor(message: [u8; 32], configs: Vec<AdaptorConfig>) -> Self {
        Self {
            id: Uuid::now_v7(),
            message,
            mode: BatchSigningMode::Adaptor { configs },
            taproot_tweak: TaprootTweak::None,
            subset_id: None,
        }
    }

    pub fn with_subset(mut self, subset_id: Uuid) -> Self {
        self.subset_id = Some(subset_id);
        self
    }

    pub fn with_tweak(mut self, tweak: TaprootTweak) -> Self {
        self.taproot_tweak = tweak;
        self
    }

    pub fn with_id(mut self, id: Uuid) -> Self {
        self.id = id;
        self
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum BatchSigningMode {
    Regular,
    Adaptor { configs: Vec<AdaptorConfig> },
}

#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub batch_item_id: Uuid,
    pub signature: Option<Vec<u8>>,
    pub adaptor_signatures: Option<BTreeMap<Uuid, AdaptorSignatureResult>>,
    pub error: Option<String>,
}

pub struct SigningManager<'a> {
    client: &'a KeyMeldClient,
}

impl<'a> SigningManager<'a> {
    pub(crate) fn new(client: &'a KeyMeldClient) -> Self {
        Self { client }
    }

    pub async fn sign(
        &self,
        keygen_session: &KeygenSession<'_>,
        message: [u8; 32],
        options: SigningOptions,
    ) -> Result<SigningSession<'a>, SdkError> {
        let item = BatchSigningItem::new(message);
        self.sign_batch(keygen_session, vec![item], options).await
    }

    pub async fn sign_adaptor(
        &self,
        keygen_session: &KeygenSession<'_>,
        message: [u8; 32],
        adaptor_configs: Vec<AdaptorConfig>,
        options: SigningOptions,
    ) -> Result<SigningSession<'a>, SdkError> {
        let item = BatchSigningItem::adaptor(message, adaptor_configs);
        self.sign_batch(keygen_session, vec![item], options).await
    }

    pub async fn sign_batch(
        &self,
        keygen_session: &KeygenSession<'_>,
        items: Vec<BatchSigningItem>,
        options: SigningOptions,
    ) -> Result<SigningSession<'a>, SdkError> {
        if items.is_empty() {
            return Err(SdkError::InvalidInput(
                "At least one batch item required".to_string(),
            ));
        }

        keygen_session.verify_roster()?;
        let authority = keygen_session.authorization_credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "Signing requires authority credentials independent of the shared session secret"
                    .into(),
            )
        })?;
        let keygen_credentials = keygen_session.credentials();
        let signing_session_id = SessionId::new_v7();

        let batch_items = self.encrypt_batch_items(&items, keygen_credentials)?;

        let credentials =
            SessionCredentials::from_session_secret(&keygen_credentials.export_session_secret())?;

        let enclave_batch_items: Vec<_> = batch_items
            .iter()
            .map(SigningBatchItem::to_enclave_batch_item)
            .collect();
        let signing_authorization = SigningAuthorization::sign(
            &authority.export_secret(),
            keygen_session.session_id(),
            &signing_session_id,
            options.timeout_secs.unwrap_or(300),
            &enclave_batch_items,
        )?;
        let request = CreateSigningSessionRequest {
            signing_authorization,
            signing_session_id: signing_session_id.clone(),
            keygen_session_id: keygen_session.session_id().clone(),
            timeout_secs: options.timeout_secs.unwrap_or(300),
            batch_items,
        };

        let session_signature =
            credentials.sign_session_request(&keygen_session.session_id().to_string())?;

        let response: CreateSigningSessionResponse = self
            .client
            .http()
            .post(
                &self.client.url("/api/v1/signing"),
                &request,
                &[("X-Session-Signature", &session_signature)],
            )
            .await?;

        if response.signing_session_id != request.signing_session_id
            || response.keygen_session_id != request.keygen_session_id
        {
            return Err(SdkError::InvalidInput(
                "Gateway changed the authorized signing session identity".into(),
            ));
        }

        let mut session = SigningSession {
            batch_items: request.batch_items,
            signing_session_id: response.signing_session_id,
            keygen_session_id: response.keygen_session_id,
            credentials,
            status: response.status,
            batch_results: vec![],
            participants_requiring_approval: vec![],
            approved_participants: vec![],
            client: self.client,
        };
        session.refresh_status().await?;
        Ok(session)
    }

    pub async fn restore_session(
        &self,
        signing_session_id: SessionId,
        keygen_session: &KeygenSession<'_>,
    ) -> Result<SigningSession<'a>, SdkError> {
        keygen_session.verify_roster()?;
        let keygen_credentials = keygen_session.credentials();

        let credentials =
            SessionCredentials::from_session_secret(&keygen_credentials.export_session_secret())?;

        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput("User credentials required for signing status".to_string())
        })?;

        let user_signature = user_credentials.sign_for_session(
            &signing_session_id.to_string(),
            &self.client.user_id().to_string(),
            &keygen_session.session_id().to_string(),
        )?;

        let status_response: SigningSessionStatusResponse = self
            .client
            .http()
            .get(
                &self.client.url(&format!(
                    "/api/v1/signing/{}/status/{}",
                    signing_session_id,
                    self.client.user_id()
                )),
                &[("x-user-signature", &user_signature)],
            )
            .await?;

        if status_response.signing_session_id != signing_session_id
            || &status_response.keygen_session_id != keygen_session.session_id()
        {
            return Err(SdkError::InvalidInput(
                "Gateway returned a different signing session or keygen roster".into(),
            ));
        }

        Ok(SigningSession {
            batch_items: status_response.batch_items,
            signing_session_id: status_response.signing_session_id,
            keygen_session_id: status_response.keygen_session_id,
            credentials,
            status: status_response.status,
            batch_results: status_response.batch_results,
            participants_requiring_approval: status_response.participants_requiring_approval,
            approved_participants: status_response.approved_participants,
            client: self.client,
        })
    }

    fn encrypt_batch_items(
        &self,
        items: &[BatchSigningItem],
        credentials: &SessionCredentials,
    ) -> Result<Vec<SigningBatchItem>, SdkError> {
        items
            .iter()
            .map(|item| {
                // Encrypt the hex-encoded message (enclave expects hex string after decryption)
                let message_hex = hex::encode(item.message);
                let encrypted_message =
                    credentials.encrypt(message_hex.as_bytes(), "session_data")?;

                let tweak_json = serde_json::to_vec(&item.taproot_tweak)
                    .map_err(|e| SdkError::Internal(format!("Failed to serialize tweak: {}", e)))?;
                let encrypted_taproot_tweak = credentials.encrypt(&tweak_json, "session_data")?;

                let signing_mode = match &item.mode {
                    BatchSigningMode::Regular => SigningMode::Regular { encrypted_message },
                    BatchSigningMode::Adaptor { configs } => {
                        if configs.is_empty() {
                            return Err(SdkError::InvalidInput(
                                "Adaptor signing requires at least one Single adaptor config"
                                    .into(),
                            ));
                        }
                        keymeld_core::validation::validate_decrypted_adaptor_configs(configs)?;
                        let configs_json = serde_json::to_vec(configs).map_err(|e| {
                            SdkError::Internal(format!(
                                "Failed to serialize adaptor configs: {}",
                                e
                            ))
                        })?;
                        let encrypted_adaptor_configs =
                            credentials.encrypt(&configs_json, "adaptor_configs")?;

                        SigningMode::Adaptor {
                            encrypted_message,
                            encrypted_adaptor_configs,
                        }
                    }
                };

                Ok(SigningBatchItem {
                    batch_item_id: item.id,
                    message_hash: item.message.to_vec(),
                    signing_mode,
                    encrypted_taproot_tweak,
                    subset_id: item.subset_id,
                })
            })
            .collect()
    }
}

pub struct SigningSession<'a> {
    batch_items: Vec<SigningBatchItem>,
    signing_session_id: SessionId,
    keygen_session_id: SessionId,
    credentials: SessionCredentials,
    status: SigningStatusKind,
    batch_results: Vec<BatchItemResult>,
    participants_requiring_approval: Vec<UserId>,
    approved_participants: Vec<UserId>,
    client: &'a KeyMeldClient,
}

impl<'a> SigningSession<'a> {
    pub fn session_id(&self) -> &SessionId {
        &self.signing_session_id
    }

    pub fn keygen_session_id(&self) -> &SessionId {
        &self.keygen_session_id
    }

    pub fn status(&self) -> &SigningStatusKind {
        &self.status
    }

    pub fn credentials(&self) -> &SessionCredentials {
        &self.credentials
    }

    pub fn requires_approval(&self) -> bool {
        !self.participants_requiring_approval.is_empty()
            && self.participants_requiring_approval.len() > self.approved_participants.len()
    }

    pub fn participants_requiring_approval(&self) -> &[UserId] {
        &self.participants_requiring_approval
    }

    pub fn approved_participants(&self) -> &[UserId] {
        &self.approved_participants
    }

    /// Decrypt the complete batch so callers can review every signing parameter.
    pub fn pending_batch(&self) -> Result<Vec<BatchSigningItem>, SdkError> {
        self.batch_items
            .iter()
            .map(|item| {
                let message_hex = self
                    .credentials
                    .decrypt(item.signing_mode.encrypted_message(), "session_data")?;
                let message_bytes = hex::decode(&message_hex)?;
                let message: [u8; 32] = message_bytes.try_into().map_err(|_| {
                    SdkError::InvalidInput("Signing message must contain exactly 32 bytes".into())
                })?;
                let taproot_tweak = serde_json::from_slice(
                    &self
                        .credentials
                        .decrypt(&item.encrypted_taproot_tweak, "session_data")?,
                )?;
                let mode = match &item.signing_mode {
                    SigningMode::Regular { .. } => BatchSigningMode::Regular,
                    SigningMode::Adaptor {
                        encrypted_adaptor_configs,
                        ..
                    } => BatchSigningMode::Adaptor {
                        configs: serde_json::from_slice(
                            &self
                                .credentials
                                .decrypt(encrypted_adaptor_configs, "adaptor_configs")?,
                        )?,
                    },
                };
                Ok(BatchSigningItem {
                    id: item.batch_item_id,
                    message,
                    mode,
                    taproot_tweak,
                    subset_id: item.subset_id,
                })
            })
            .collect()
    }

    /// Approve only a batch whose plaintext parameters match the caller's review.
    pub async fn approve(&mut self, expected_items: &[BatchSigningItem]) -> Result<(), SdkError> {
        self.refresh_status().await?;
        if serde_json::to_value(expected_items)? != serde_json::to_value(self.pending_batch()?)? {
            return Err(SdkError::InvalidInput(
                "Signing batch differs from the reviewed messages or signing parameters".into(),
            ));
        }
        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput("User credentials required for signing approval".to_string())
        })?;
        let user_signature = user_credentials.sign_for_session(
            &self.signing_session_id.to_string(),
            &self.client.user_id().to_string(),
            &self.keygen_session_id.to_string(),
        )?;
        let (auth_key, _) = keymeld_core::crypto::SecureCrypto::derive_session_auth_keypair(
            &user_credentials.private_key_bytes(),
            &self.keygen_session_id.to_string(),
        )?;
        let timestamp = approval_timestamp()?;
        let batch: Vec<_> = self
            .batch_items
            .iter()
            .map(SigningBatchItem::to_enclave_batch_item)
            .collect();
        let approval = ParticipantApproval::sign(
            &auth_key.secret_bytes(),
            self.client.user_id().clone(),
            &self.keygen_session_id,
            &self.signing_session_id,
            timestamp,
            &batch,
        )?;
        let url = self.client.url(&format!(
            "/api/v1/signing/{}/approve/{}",
            self.signing_session_id,
            self.client.user_id(),
        ));
        self.client
            .http()
            .post_json_no_response(&url, &approval, &[("x-user-signature", &user_signature)])
            .await?;
        self.refresh_status().await?;
        Ok(())
    }

    pub async fn refresh_status(&mut self) -> Result<&SigningStatusKind, SdkError> {
        let user_credentials = self.client.credentials().ok_or_else(|| {
            SdkError::InvalidInput("User credentials required for signing status".to_string())
        })?;

        let user_signature = user_credentials.sign_for_session(
            &self.signing_session_id.to_string(),
            &self.client.user_id().to_string(),
            &self.keygen_session_id.to_string(),
        )?;

        let response: SigningSessionStatusResponse = self
            .client
            .http()
            .get(
                &self.client.url(&format!(
                    "/api/v1/signing/{}/status/{}",
                    self.signing_session_id,
                    self.client.user_id()
                )),
                &[("x-user-signature", &user_signature)],
            )
            .await?;

        if response.signing_session_id != self.signing_session_id
            || response.keygen_session_id != self.keygen_session_id
            || serde_json::to_value(&response.batch_items)?
                != serde_json::to_value(&self.batch_items)?
        {
            return Err(SdkError::InvalidInput(
                "Gateway changed the signing session or its immutable batch".into(),
            ));
        }
        self.status = response.status;
        self.batch_results = response.batch_results;
        self.participants_requiring_approval = response.participants_requiring_approval;
        self.approved_participants = response.approved_participants;

        Ok(&self.status)
    }

    pub async fn wait_for_completion(&mut self) -> Result<Vec<SignatureResult>, SdkError> {
        let config = self.client.polling_config().clone();
        let mut delay = config.initial_delay;

        for attempt in 1..=config.max_attempts {
            self.refresh_status().await?;

            match self.status {
                SigningStatusKind::Completed => {
                    return self.decrypt_results();
                }
                SigningStatusKind::Failed => {
                    return Err(SdkError::Signing(SigningError::Failed(
                        "Signing session failed".to_string(),
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

        Err(SdkError::Signing(SigningError::Timeout))
    }

    pub fn raw_results(&self) -> &[BatchItemResult] {
        &self.batch_results
    }

    pub fn decrypt_results(&self) -> Result<Vec<SignatureResult>, SdkError> {
        self.batch_results
            .iter()
            .map(|result| {
                let signature = if let Some(ref encrypted_sig) = result.signature {
                    Some(self.credentials.decrypt(encrypted_sig, "signature")?)
                } else {
                    None
                };

                let adaptor_signatures =
                    if let Some(ref encrypted_adaptor) = result.adaptor_signatures {
                        let decrypted = self
                            .credentials
                            .decrypt(encrypted_adaptor, "adaptor_signatures")?;
                        let sigs: BTreeMap<Uuid, AdaptorSignatureResult> =
                            serde_json::from_slice(&decrypted).map_err(|e| {
                                SdkError::Internal(format!("Failed to parse adaptor sigs: {}", e))
                            })?;
                        Some(sigs)
                    } else {
                        None
                    };

                Ok(SignatureResult {
                    batch_item_id: result.batch_item_id,
                    signature,
                    adaptor_signatures,
                    error: result.error.clone(),
                })
            })
            .collect()
    }

    pub fn export_session_secret(&self) -> [u8; 32] {
        self.credentials.export_session_secret()
    }
}

#[cfg(test)]
mod adaptor_validation_tests {
    use super::*;

    #[test]
    fn sdk_refuses_unsupported_adaptors_before_creating_a_request() {
        let client = KeyMeldClient::builder("http://127.0.0.1:1", UserId::new_v7())
            .build()
            .unwrap();
        let manager = client.signer();
        let credentials = SessionCredentials::generate().unwrap();
        let point = hex::encode(
            secp256k1::SecretKey::from_byte_array([24; 32])
                .unwrap()
                .public_key(secp256k1::SECP256K1)
                .serialize(),
        );
        for configs in [
            vec![],
            vec![AdaptorConfig::and(vec![point.clone(), point.clone()])],
            vec![AdaptorConfig::or(vec![point.clone(), point.clone()])],
        ] {
            assert!(manager
                .encrypt_batch_items(
                    &[BatchSigningItem::adaptor([25; 32], configs)],
                    &credentials
                )
                .is_err());
        }
        let item = BatchSigningItem::adaptor([25; 32], vec![AdaptorConfig::single(point)]);
        assert!(manager.encrypt_batch_items(&[item], &credentials).is_ok());
    }
}
