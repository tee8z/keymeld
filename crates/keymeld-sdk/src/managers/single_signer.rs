use crate::client::KeyMeldClient;
use crate::credentials::SessionCredentials;
use crate::error::{CryptoError, KeyError, SdkError, SigningError};
use crate::polling::{poll_until, PollResult};
use crate::types::{
    DeleteUserKeyResponse, ImportUserKeyRequest, ImportUserKeyResponse, KeyId, KeyStatusResponse,
    ListUserKeysResponse, ReserveKeySlotRequest, ReserveKeySlotResponse, SignSingleRequest,
    SignSingleResponse, SignatureType, SingleSigningStatus, SingleSigningStatusResponse,
    UserKeyInfo,
};
use keymeld_core::crypto::SecureCrypto;

#[derive(Debug, Clone)]
pub struct KeySlotReservation {
    pub key_id: KeyId,
    pub enclave_public_key: String,
    pub enclave_key_epoch: u64,
}

impl From<ReserveKeySlotResponse> for KeySlotReservation {
    fn from(response: ReserveKeySlotResponse) -> Self {
        Self {
            key_id: response.key_id,
            enclave_public_key: response.enclave_public_key,
            enclave_key_epoch: response.enclave_key_epoch,
        }
    }
}

// On non-WASM targets, futures must be Send for use with multi-threaded runtimes.
// On WASM, there's only a single thread so Send is not required (and reqwest's WASM
// implementation doesn't support it).
#[cfg(not(target_arch = "wasm32"))]
pub trait SingleSignerOps {
    fn reserve_key_slot(
        &self,
    ) -> impl std::future::Future<Output = Result<KeySlotReservation, SdkError>> + Send;

    fn import_key(
        &self,
        reservation: &KeySlotReservation,
        private_key: &[u8],
    ) -> impl std::future::Future<Output = Result<KeyId, SdkError>> + Send;

    fn list_keys(
        &self,
        key_id: &KeyId,
    ) -> impl std::future::Future<Output = Result<Vec<UserKeyInfo>, SdkError>> + Send;

    fn sign(
        &self,
        key_id: &KeyId,
        message_hash: [u8; 32],
        signature_type: SignatureType,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SdkError>> + Send;

    fn delete_key(
        &self,
        key_id: &KeyId,
    ) -> impl std::future::Future<Output = Result<(), SdkError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait SingleSignerOps {
    fn reserve_key_slot(
        &self,
    ) -> impl std::future::Future<Output = Result<KeySlotReservation, SdkError>>;

    fn import_key(
        &self,
        reservation: &KeySlotReservation,
        private_key: &[u8],
    ) -> impl std::future::Future<Output = Result<KeyId, SdkError>>;

    fn list_keys(
        &self,
        key_id: &KeyId,
    ) -> impl std::future::Future<Output = Result<Vec<UserKeyInfo>, SdkError>>;

    fn sign(
        &self,
        key_id: &KeyId,
        message_hash: [u8; 32],
        signature_type: SignatureType,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, SdkError>>;

    fn delete_key(&self, key_id: &KeyId)
        -> impl std::future::Future<Output = Result<(), SdkError>>;
}

impl SingleSignerOps for KeyMeldClient {
    async fn reserve_key_slot(&self) -> Result<KeySlotReservation, SdkError> {
        let request = ReserveKeySlotRequest {
            user_id: self.user_id().clone(),
        };

        let response: ReserveKeySlotResponse = self
            .http()
            .post(&self.url("/api/v1/keys/reserve"), &request, &[])
            .await?;

        Ok(response.into())
    }

    async fn import_key(
        &self,
        reservation: &KeySlotReservation,
        private_key: &[u8],
    ) -> Result<KeyId, SdkError> {
        // Validate private key length
        if private_key.len() != 32 {
            return Err(SdkError::InvalidInput(format!(
                "Private key must be 32 bytes, got {}",
                private_key.len()
            )));
        }

        // Get user credentials for authentication
        let credentials = self.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for key import. Call set_credentials() first."
                    .to_string(),
            )
        })?;

        // Encrypt the private key to the enclave's public key
        let encrypted_private_key =
            SecureCrypto::ecies_encrypt_from_hex(&reservation.enclave_public_key, private_key)
                .map_err(|e| SdkError::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;

        // Generate auth signature
        let auth_signature = credentials
            .sign_user_request(&reservation.key_id.to_string(), &self.user_id().to_string())?;

        let request = ImportUserKeyRequest {
            key_id: reservation.key_id.clone(),
            user_id: self.user_id().clone(),
            encrypted_private_key: hex::encode(&encrypted_private_key),
            auth_pubkey: credentials.auth_public_key_bytes(),
            enclave_public_key: reservation.enclave_public_key.clone(),
        };

        let _response: ImportUserKeyResponse = self
            .http()
            .post(
                &self.url("/api/v1/keys/import"),
                &request,
                &[("X-User-Signature", &auth_signature)],
            )
            .await?;

        // Wait for the async import to complete
        self.wait_for_key_import(&reservation.key_id).await?;

        Ok(reservation.key_id.clone())
    }

    async fn list_keys(&self, key_id: &KeyId) -> Result<Vec<UserKeyInfo>, SdkError> {
        let credentials = self.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for listing keys. Call set_credentials() first."
                    .to_string(),
            )
        })?;

        let auth_signature =
            credentials.sign_user_request(&key_id.to_string(), &self.user_id().to_string())?;

        let response: ListUserKeysResponse = self
            .http()
            .get(
                &self.url(&format!(
                    "/api/v1/keys/{}?key_id={}",
                    self.user_id(),
                    key_id
                )),
                &[("X-User-Signature", &auth_signature)],
            )
            .await?;

        Ok(response.keys)
    }

    async fn sign(
        &self,
        key_id: &KeyId,
        message_hash: [u8; 32],
        signature_type: SignatureType,
    ) -> Result<Vec<u8>, SdkError> {
        let credentials = self.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for signing. Call set_credentials() first.".to_string(),
            )
        })?;

        // Generate a session for this signing request
        let session_credentials = SessionCredentials::generate()?;
        let session_secret = session_credentials.export_session_secret();

        // Encrypt the message with the session secret
        let message_hex = hex::encode(message_hash);
        let encrypted_message =
            session_credentials.encrypt(message_hex.as_bytes(), "session_data")?;

        // We need to get the enclave public key for this key
        // First, get the key info
        let auth_signature =
            credentials.sign_user_request(&key_id.to_string(), &self.user_id().to_string())?;

        // Get key status to find the enclave (validates key exists)
        let _key_status: KeyStatusResponse = self
            .http()
            .get(
                &self.url(&format!(
                    "/api/v1/keys/{}/{}/status",
                    self.user_id(),
                    key_id
                )),
                &[("X-User-Signature", &auth_signature)],
            )
            .await
            .map_err(|_| SdkError::Key(KeyError::NotFound(key_id.clone())))?;

        // We need the enclave public key - let's get it from the health endpoint
        // This is a bit of a workaround; ideally the key status would include this
        let enclaves = self.health().list_enclaves().await?;

        // Find the enclave for this key (we'll use the first healthy one as fallback)
        let enclave = enclaves
            .enclaves
            .iter()
            .find(|e| e.healthy)
            .ok_or_else(|| SdkError::Internal("No healthy enclaves available".to_string()))?;

        let enclave_public_key = &enclave.public_key;

        // Encrypt the session secret to the enclave's public key
        let encrypted_session_secret =
            SecureCrypto::ecies_encrypt_from_hex(enclave_public_key, &session_secret)
                .map_err(|e| SdkError::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;

        // Generate approval signature
        let approval_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let approval_signature = credentials.sign_approval(
            &encrypted_message,
            &key_id.to_string(),
            approval_timestamp,
        )?;

        let request = SignSingleRequest {
            user_id: self.user_id().clone(),
            key_id: key_id.clone(),
            encrypted_message,
            signature_type,
            encrypted_session_secret: hex::encode(&encrypted_session_secret),
            approval_signature,
            approval_timestamp,
        };

        let auth_signature =
            credentials.sign_user_request(&key_id.to_string(), &self.user_id().to_string())?;

        let response: SignSingleResponse = self
            .http()
            .post(
                &self.url("/api/v1/sign/single"),
                &request,
                &[("X-User-Signature", &auth_signature)],
            )
            .await?;

        // Wait for signing to complete
        let signature = self
            .wait_for_signing_completion(&response.signing_session_id, &session_credentials, key_id)
            .await?;

        Ok(signature)
    }

    async fn delete_key(&self, key_id: &KeyId) -> Result<(), SdkError> {
        let credentials = self.credentials().ok_or_else(|| {
            SdkError::InvalidInput(
                "User credentials required for deleting keys. Call set_credentials() first."
                    .to_string(),
            )
        })?;

        let auth_signature =
            credentials.sign_user_request(&key_id.to_string(), &self.user_id().to_string())?;

        let _response: DeleteUserKeyResponse = self
            .http()
            .delete(
                &self.url(&format!("/api/v1/keys/{}/{}", self.user_id(), key_id)),
                &[("X-User-Signature", &auth_signature)],
            )
            .await?;

        Ok(())
    }
}

// Private helper methods
impl KeyMeldClient {
    /// Wait for a key import to complete.
    async fn wait_for_key_import(&self, key_id: &KeyId) -> Result<(), SdkError> {
        let credentials = self
            .credentials()
            .ok_or_else(|| SdkError::InvalidInput("User credentials required".to_string()))?;

        let config = self.polling_config();
        let key_id = key_id.clone();

        poll_until(config, || async {
            let auth_signature =
                credentials.sign_user_request(&key_id.to_string(), &self.user_id().to_string())?;

            let response: Result<KeyStatusResponse, SdkError> = self
                .http()
                .get(
                    &self.url(&format!(
                        "/api/v1/keys/{}/{}/status",
                        self.user_id(),
                        key_id
                    )),
                    &[("X-User-Signature", &auth_signature)],
                )
                .await;

            match response {
                Ok(status) => match status.status.as_str() {
                    "completed" => Ok(PollResult::Ready(())),
                    "failed" => {
                        let msg = status
                            .error_message
                            .unwrap_or_else(|| "Unknown error".to_string());
                        Err(SdkError::Key(KeyError::ImportFailed(msg)))
                    }
                    "pending" | "processing" => Ok(PollResult::Pending),
                    _ => Ok(PollResult::Pending),
                },
                Err(SdkError::Api(crate::error::ApiError::HttpError { status: 404, .. })) => {
                    // Key not yet in status endpoint - still being processed
                    Ok(PollResult::Pending)
                }
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|e| match e {
            SdkError::Internal(ref msg) if msg.contains("timed out") => {
                SdkError::Key(KeyError::Timeout)
            }
            other => other,
        })
    }

    /// Wait for a signing operation to complete.
    async fn wait_for_signing_completion(
        &self,
        signing_session_id: &crate::types::SessionId,
        session_credentials: &SessionCredentials,
        key_id: &KeyId,
    ) -> Result<Vec<u8>, SdkError> {
        let credentials = self
            .credentials()
            .ok_or_else(|| SdkError::InvalidInput("User credentials required".to_string()))?;

        let config = self.polling_config();
        let signing_session_id = signing_session_id.clone();
        let key_id = key_id.clone();

        poll_until(config, || async {
            let auth_signature =
                credentials.sign_user_request(&key_id.to_string(), &self.user_id().to_string())?;

            let response: SingleSigningStatusResponse = self
                .http()
                .get(
                    &self.url(&format!(
                        "/api/v1/sign/single/{}/status/{}",
                        signing_session_id,
                        self.user_id()
                    )),
                    &[("X-User-Signature", &auth_signature)],
                )
                .await?;

            match response.status {
                SingleSigningStatus::Completed => {
                    if let Some(ref encrypted_signature) = response.encrypted_signature {
                        // Decrypt the signature
                        let signature =
                            session_credentials.decrypt(encrypted_signature, "signature")?;
                        Ok(PollResult::Ready(signature))
                    } else {
                        Err(SdkError::Signing(SigningError::Failed(
                            "Signing completed but no signature returned".to_string(),
                        )))
                    }
                }
                SingleSigningStatus::Failed => {
                    let msg = response
                        .error_message
                        .unwrap_or_else(|| "Unknown error".to_string());
                    Err(SdkError::Key(KeyError::SigningFailed {
                        key_id: key_id.clone(),
                        reason: msg,
                    }))
                }
                SingleSigningStatus::Pending | SingleSigningStatus::Processing => {
                    Ok(PollResult::Pending)
                }
            }
        })
        .await
        .map_err(|e| match e {
            SdkError::Internal(ref msg) if msg.contains("timed out") => {
                SdkError::Key(KeyError::Timeout)
            }
            other => other,
        })
    }
}
