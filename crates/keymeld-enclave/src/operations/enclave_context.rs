use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aws_sdk_kms::Client as KmsClient;
use dashmap::DashMap;
use keymeld_core::{
    crypto::{SecureCrypto, SessionSecret},
    identifiers::EnclaveId,
    managed_socket::config::TimeoutConfig,
    protocol::{CryptoError, EnclaveError},
    EncryptedData,
};
use rand::Rng;
use std::collections::HashMap;
use zeroize::{Zeroize, Zeroizing};

use super::kms_recipient::{KmsRecipient, KmsResponseProtection};
use crate::attestation::AttestationManager;

/// Shared enclave context - read-only data accessible by all sessions
pub struct EnclaveSharedContext {
    pub enclave_id: EnclaveId,
    pub(crate) confidential_dispatch: bool,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub master_dek: Option<[u8; 32]>, // Data Encryption Key from KMS, never persisted in plaintext
    pub enclave_public_keys: DashMap<EnclaveId, String>, // Other enclaves' public keys
    pub attestation_manager: Option<AttestationManager>,
    pub config: TimeoutConfig,
    pub escrow_verifiers: std::sync::Arc<crate::escrow_verifier::VerifierRegistry>,
    pub escrow_capabilities: keymeld_core::escrow_capabilities::EscrowCapabilities,
}

impl EnclaveSharedContext {
    pub fn new(
        enclave_id: EnclaveId,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        attestation_manager: Option<AttestationManager>,
        config: TimeoutConfig,
    ) -> Self {
        Self {
            enclave_id,
            confidential_dispatch: false,
            public_key,
            private_key,
            master_dek: None, // Will be initialized via init_keys_with_kms()
            enclave_public_keys: DashMap::new(),
            attestation_manager,
            config,
            escrow_verifiers: std::sync::Arc::new(Default::default()),
            escrow_capabilities: keymeld_core::escrow_capabilities::EscrowCapabilities::for_service(
                cfg!(feature = "escrow"),
            ),
        }
    }

    pub async fn init_keys_with_kms(
        &mut self,
        kms_client: &KmsClient,
        kms_key_id: &str,
        encrypted_dek: Option<Vec<u8>>,
        encrypted_private_key: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), EnclaveError> {
        let manager = self.attestation_manager.as_ref().ok_or_else(|| {
            EnclaveError::Crypto(CryptoError::Other(
                "KMS requires an initialized NSM attestation manager".into(),
            ))
        })?;
        let protection = KmsResponseProtection::Recipient(KmsRecipient::new(manager)?);
        self.init_keys_with_kms_protection(
            kms_client,
            kms_key_id,
            encrypted_dek,
            encrypted_private_key,
            protection,
        )
        .await
    }

    /// Explicit escape hatch for local simulation with an unattested KMS emulator.
    /// The operator selects this only from its enclave-local development setting.
    pub async fn init_keys_with_kms_development(
        &mut self,
        kms_client: &KmsClient,
        kms_key_id: &str,
        encrypted_dek: Option<Vec<u8>>,
        encrypted_private_key: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), EnclaveError> {
        self.init_keys_with_kms_protection(
            kms_client,
            kms_key_id,
            encrypted_dek,
            encrypted_private_key,
            KmsResponseProtection::DevelopmentPlaintext,
        )
        .await
    }

    async fn init_keys_with_kms_protection(
        &mut self,
        kms_client: &KmsClient,
        kms_key_id: &str,
        encrypted_dek: Option<Vec<u8>>,
        encrypted_private_key: Option<Vec<u8>>,
        protection: KmsResponseProtection,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), EnclaveError> {
        match (encrypted_dek, encrypted_private_key) {
            (Some(enc_dek), Some(enc_privkey)) => {
                // Restart scenario: decrypt existing keys
                let encryption_context = self.build_encryption_context();

                let response = kms_client
                    .decrypt()
                    .key_id(kms_key_id)
                    .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(enc_dek.clone()))
                    .set_encryption_context(Some(encryption_context))
                    .set_recipient(protection.recipient_info())
                    .send()
                    .await
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::Other(format!(
                            "Failed to decrypt DEK from KMS: {e}"
                        )))
                    })?;

                let dek_array = protection.decrypt_dek(
                    response.plaintext(), response.ciphertext_for_recipient(),
                )?;

                let private_key_bytes = Zeroizing::new(self.decrypt_private_key_with_dek(&dek_array, &enc_privkey)?);

                let secret_key = secp256k1::SecretKey::from_byte_array(
                    private_key_bytes.as_slice().try_into().map_err(|_| {
                        EnclaveError::Crypto(CryptoError::Other(
                            "Invalid private key length".to_string()
                        ))
                    })?
                ).map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!(
                        "Invalid private key: {e}"
                    )))
                })?;

                let public_key = secp256k1::PublicKey::from_secret_key(
                    &secp256k1::Secp256k1::new(),
                    &secret_key
                );
                let public_key_bytes = public_key.serialize().to_vec();

                // Store in memory
                self.master_dek.zeroize();
                self.master_dek = Some(*dek_array);
                self.private_key.zeroize();
                self.private_key = private_key_bytes.to_vec();
                self.public_key = public_key_bytes.clone();

                // Return same encrypted values (no re-encryption needed)
                Ok((enc_dek, enc_privkey, public_key_bytes))
            }

            (None, None) => {
                // First boot scenario: generate new keys
                let keypair = SecureCrypto::generate_enclave_keypair().map_err(|e| {
                    EnclaveError::Crypto(CryptoError::KeypairGeneration(format!("{e}")))
                })?;

                let private_key_bytes = Zeroizing::new(keypair.0.secret_bytes().to_vec());
                let public_key_bytes = keypair.1.serialize().to_vec();

                let encryption_context = self.build_encryption_context();

                let response = kms_client
                    .generate_data_key()
                    .key_id(kms_key_id)
                    .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                    .set_encryption_context(Some(encryption_context))
                    .set_recipient(protection.recipient_info())
                    .send()
                    .await
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::Other(format!(
                            "Failed to generate DEK from KMS: {e}"
                        )))
                    })?;

                let dek_array = protection.decrypt_dek(
                    response.plaintext(), response.ciphertext_for_recipient(),
                )?;

                let encrypted_dek = response
                    .ciphertext_blob()
                    .filter(|ciphertext| !ciphertext.as_ref().is_empty())
                    .ok_or_else(|| {
                        EnclaveError::Crypto(CryptoError::Other(
                            "No encrypted DEK returned from KMS".to_string(),
                        ))
                    })?
                    .as_ref()
                    .to_vec();

                let encrypted_private_key = self.encrypt_private_key_with_dek(&dek_array, &private_key_bytes)?;

                // Store in memory
                self.master_dek.zeroize();
                self.master_dek = Some(*dek_array);
                self.private_key.zeroize();
                self.private_key = private_key_bytes.to_vec();
                self.public_key = public_key_bytes.clone();

                // Return encrypted versions for gateway to store
                Ok((encrypted_dek, encrypted_private_key, public_key_bytes))
            }

            _ => Err(EnclaveError::Crypto(CryptoError::Other(
                "Invalid key state: must provide both encrypted_dek and encrypted_private_key, or neither".to_string()
            )))
        }
    }

    /// Bind persisted KMS ciphertext to this enclave's logical identity.
    /// This caller-supplied AAD is not attestation; measured PCRs are in Recipient.
    fn build_encryption_context(&self) -> HashMap<String, String> {
        let mut context = HashMap::new();
        context.insert(
            "enclave_id".to_string(),
            self.enclave_id.as_u32().to_string(),
        );

        context
    }

    fn encrypt_private_key_with_dek(
        &self,
        dek: &[u8; 32],
        private_key: &[u8],
    ) -> Result<Vec<u8>, EnclaveError> {
        let cipher = Aes256Gcm::new(dek.into());

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, private_key).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to encrypt private key: {e}"
            )))
        })?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    fn decrypt_private_key_with_dek(
        &self,
        dek: &[u8; 32],
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, EnclaveError> {
        if encrypted_data.len() < 12 {
            return Err(EnclaveError::Crypto(CryptoError::Other(
                "Encrypted data too short to contain nonce".to_string(),
            )));
        }

        let cipher = Aes256Gcm::new(dek.into());

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to decrypt private key: {e}"
            )))
        })?;

        Ok(plaintext)
    }

    /// Get the master DEK if it has been initialized
    pub fn get_master_dek(&self) -> Option<&[u8; 32]> {
        self.master_dek.as_ref()
    }

    pub fn encrypt_session_secret_for_enclave(
        &self,
        target_public_key_hex: &str,
        session_secret: &SessionSecret,
    ) -> Result<String, EnclaveError> {
        let session_secret_bytes = session_secret.as_bytes();
        let encrypted_bytes =
            SecureCrypto::ecies_encrypt_from_hex(target_public_key_hex, session_secret_bytes)
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!(
                        "Failed to encrypt session secret: {e}"
                    )))
                })?;

        Ok(hex::encode(encrypted_bytes))
    }

    pub fn add_enclave_public_key(&self, enclave_id: EnclaveId, public_key: String) {
        self.enclave_public_keys.insert(enclave_id, public_key);
    }

    pub fn get_enclave_public_key(&self, enclave_id: &EnclaveId) -> Option<String> {
        self.enclave_public_keys.get(enclave_id).map(|k| k.clone())
    }

    pub fn decrypt_with_ecies(
        &self,
        encrypted_hex: &str,
        error_context: &str,
    ) -> Result<Vec<u8>, EnclaveError> {
        let secret_key = self.get_enclave_secret_key()?;

        let encrypted_bytes = hex::decode(encrypted_hex).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to decode hex data for {error_context}: {e}"
            )))
        })?;

        SecureCrypto::ecies_decrypt(&secret_key, &encrypted_bytes).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to decrypt {error_context}: {e}"
            )))
        })
    }

    pub fn get_enclave_secret_key(&self) -> Result<musig2::secp256k1::SecretKey, EnclaveError> {
        let private_key_array: [u8; 32] = if self.private_key.len() >= 32 {
            self.private_key[..32].try_into().unwrap()
        } else {
            return Err(EnclaveError::Crypto(CryptoError::Other(
                "Private key too short".to_string(),
            )));
        };

        musig2::secp256k1::SecretKey::from_byte_array(private_key_array).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!("Invalid secret key: {e}")))
        })
    }

    pub fn decrypt_private_key_from_coordinator(
        &self,
        encrypted_private_key: &str,
    ) -> Result<Vec<u8>, EnclaveError> {
        self.decrypt_with_ecies(encrypted_private_key, "coordinator private key")
    }

    pub fn finalize_and_encrypt_signature(
        &self,
        signature_data: &[u8],
        session_secret: &SessionSecret,
    ) -> Result<EncryptedData, EnclaveError> {
        session_secret
            .encrypt(signature_data, "signature")
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to encrypt signature: {e}"
                )))
            })
    }

    pub fn encrypt_adaptor_signatures(
        &self,
        adaptor_signatures: &[crate::musig::AdaptorSignatureResult],
        session_secret: &SessionSecret,
    ) -> Result<EncryptedData, EnclaveError> {
        let serialized = serde_json::to_vec(adaptor_signatures).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to serialize adaptor signatures: {e}"
            )))
        })?;

        session_secret
            .encrypt(&serialized, "adaptor_signatures")
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to encrypt adaptor signatures: {e}"
                )))
            })
    }
}

impl Clone for EnclaveSharedContext {
    fn clone(&self) -> Self {
        Self {
            enclave_id: self.enclave_id,
            confidential_dispatch: self.confidential_dispatch,
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            master_dek: self.master_dek,
            enclave_public_keys: self.enclave_public_keys.clone(),
            attestation_manager: self.attestation_manager.clone(),
            config: self.config.clone(),
            escrow_verifiers: self.escrow_verifiers.clone(),
            escrow_capabilities: self.escrow_capabilities,
        }
    }
}

impl Drop for EnclaveSharedContext {
    fn drop(&mut self) {
        self.private_key.zeroize();
        self.master_dek.zeroize();
    }
}

impl std::fmt::Debug for EnclaveSharedContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnclaveSharedContext")
            .field("enclave_id", &self.enclave_id)
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .field("master_dek_initialized", &self.master_dek.is_some())
            .field("attestation_manager", &self.attestation_manager)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod kms_tests {
    use super::super::kms_recipient::test_support;
    use super::*;
    use aws_sdk_kms::config::{Credentials, Region};
    use axum::{body::Bytes, extract::State, http::StatusCode, routing::post, Json, Router};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy, Default)]
    enum ResponseMode {
        #[default]
        Recipient,
        Plaintext,
        Both,
        Missing,
        WrongRecipient,
        InvalidCiphertext,
    }

    #[derive(Default)]
    struct Fixture {
        mode: ResponseMode,
        requests: Vec<Value>,
    }

    async fn kms_fixture(
        State(state): State<Arc<Mutex<Fixture>>>,
        body: Bytes,
    ) -> (StatusCode, Json<Value>) {
        let request: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(request["KeyId"], "pinned-key");
        assert_eq!(request["EncryptionContext"], json!({"enclave_id": "17"}));
        assert_eq!(
            request["Recipient"]["KeyEncryptionAlgorithm"],
            "RSAES_OAEP_SHA_256"
        );
        let document = STANDARD
            .decode(
                request["Recipient"]["AttestationDocument"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        let evidence: std::collections::BTreeMap<String, serde_bytes::ByteBuf> =
            serde_cbor::from_slice(&document).unwrap();
        let recipient_key = evidence["public_key"].as_ref();
        assert_eq!(
            openssl::pkey::PKey::public_key_from_der(recipient_key)
                .unwrap()
                .bits(),
            2048
        );
        if request.get("CiphertextBlob").is_some() {
            assert_eq!(request["CiphertextBlob"], STANDARD.encode(b"sealed-dek"));
        } else {
            assert_eq!(request["KeySpec"], "AES_256");
        }
        let mode = {
            let mut fixture = state.lock().unwrap();
            fixture.requests.push(request);
            fixture.mode
        };
        let mut response =
            json!({"KeyId": "pinned-key", "CiphertextBlob": STANDARD.encode(b"sealed-dek")});
        match mode {
            ResponseMode::Recipient | ResponseMode::Both => {
                response["CiphertextForRecipient"] = STANDARD
                    .encode(test_support::envelope(recipient_key, &[0x33; 32]))
                    .into();
                if matches!(mode, ResponseMode::Both) {
                    response["Plaintext"] = STANDARD.encode([0x33; 32]).into();
                }
            }
            ResponseMode::Plaintext => response["Plaintext"] = STANDARD.encode([0x33; 32]).into(),
            ResponseMode::Missing => {}
            ResponseMode::WrongRecipient => {
                let other = test_support::recipient();
                response["CiphertextForRecipient"] = STANDARD
                    .encode(test_support::envelope(
                        &test_support::public_key(&other),
                        &[0x33; 32],
                    ))
                    .into();
            }
            ResponseMode::InvalidCiphertext => {
                response["CiphertextForRecipient"] = STANDARD.encode([0; 256]).into()
            }
        }
        (StatusCode::OK, Json(response))
    }

    struct ServerTask(tokio::task::JoinHandle<()>);
    impl Drop for ServerTask {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn fixture() -> (KmsClient, Arc<Mutex<Fixture>>, ServerTask) {
        let state = Arc::new(Mutex::new(Fixture::default()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/", post(kms_fixture))
            .with_state(state.clone());
        let server = ServerTask(tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        }));
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-west-2"))
            .credentials_provider(Credentials::new("test", "test", None, None, "kms-fixture"))
            .endpoint_url(endpoint)
            .load()
            .await;
        (KmsClient::new(&config), state, server)
    }

    fn context() -> EnclaveSharedContext {
        EnclaveSharedContext::new(
            EnclaveId::new(17),
            Vec::new(),
            Vec::new(),
            None,
            TimeoutConfig::default(),
        )
    }

    fn protection() -> KmsResponseProtection {
        KmsResponseProtection::Recipient(test_support::recipient())
    }

    #[tokio::test]
    async fn generate_and_restore_send_recipient_and_only_install_unwrapped_keys() {
        let (client, state, _server) = fixture().await;
        let mut first = context();
        let (encrypted_dek, encrypted_key, public_key) = first
            .init_keys_with_kms_protection(&client, "pinned-key", None, None, protection())
            .await
            .unwrap();
        assert_eq!(first.master_dek, Some([0x33; 32]));
        let mut restored = context();
        let result = restored
            .init_keys_with_kms_protection(
                &client,
                "pinned-key",
                Some(encrypted_dek),
                Some(encrypted_key),
                protection(),
            )
            .await
            .unwrap();
        assert_eq!(result.2, public_key);
        assert_eq!(first.private_key, restored.private_key);
        let state = state.lock().unwrap();
        assert_eq!(state.requests.len(), 2);
        assert_ne!(
            state.requests[0]["Recipient"]["AttestationDocument"],
            state.requests[1]["Recipient"]["AttestationDocument"]
        );
    }

    #[tokio::test]
    async fn generate_and_restore_reject_plaintext_missing_invalid_and_wrong_recipient() {
        let (client, state, _server) = fixture().await;
        let hierarchy = context()
            .init_keys_with_kms_protection(&client, "pinned-key", None, None, protection())
            .await
            .unwrap();
        for mode in [
            ResponseMode::Plaintext,
            ResponseMode::Both,
            ResponseMode::Missing,
            ResponseMode::WrongRecipient,
            ResponseMode::InvalidCiphertext,
        ] {
            state.lock().unwrap().mode = mode;
            for restart in [false, true] {
                let mut rejected = context();
                let result = rejected
                    .init_keys_with_kms_protection(
                        &client,
                        "pinned-key",
                        restart.then(|| hierarchy.0.clone()),
                        restart.then(|| hierarchy.1.clone()),
                        protection(),
                    )
                    .await;
                assert!(result.is_err());
                assert!(rejected.private_key.is_empty());
                assert!(rejected.public_key.is_empty());
                assert!(rejected.master_dek.is_none());
            }
        }
    }

    #[tokio::test]
    async fn strict_kms_never_falls_back_when_attestation_is_unavailable() {
        let (client, state, _server) = fixture().await;
        assert!(context()
            .init_keys_with_kms(&client, "pinned-key", None, None)
            .await
            .is_err());
        let mut disabled = context();
        disabled.attestation_manager = Some(AttestationManager::mock());
        assert!(disabled
            .init_keys_with_kms(&client, "pinned-key", None, None)
            .await
            .is_err());
        assert!(state.lock().unwrap().requests.is_empty());
    }

    #[test]
    fn configured_pcrs_are_not_kms_encryption_context() {
        let mut context = context();
        let mut config = crate::attestation::AttestationConfig {
            enabled: false,
            ..Default::default()
        };
        config
            .required_pcrs
            .insert("PCR0".into(), "caller-supplied".into());
        context.attestation_manager = Some(AttestationManager::new(config).unwrap());
        assert_eq!(
            context.build_encryption_context(),
            HashMap::from([("enclave_id".into(), "17".into())])
        );
    }
}
