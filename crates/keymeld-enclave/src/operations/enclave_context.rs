use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use aws_sdk_kms::Client as KmsClient;
use dashmap::DashMap;
use keymeld_core::{
    crypto::{SecureCrypto, SessionSecret},
    identifiers::EnclaveId,
    managed_vsock::config::TimeoutConfig,
    protocol::{CryptoError, EnclaveError},
    EncryptedData,
};
use rand::Rng;
use std::collections::HashMap;

use crate::attestation::AttestationManager;

/// Shared enclave context - read-only data accessible by all sessions
#[derive(Debug)]
pub struct EnclaveSharedContext {
    pub enclave_id: EnclaveId,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub master_dek: Option<[u8; 32]>, // Data Encryption Key from KMS, never persisted in plaintext
    pub enclave_public_keys: DashMap<EnclaveId, String>, // Other enclaves' public keys
    pub attestation_manager: Option<AttestationManager>,
    pub config: TimeoutConfig,
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
            public_key,
            private_key,
            master_dek: None, // Will be initialized via init_keys_with_kms()
            enclave_public_keys: DashMap::new(),
            attestation_manager,
            config,
        }
    }

    pub async fn init_keys_with_kms(
        &mut self,
        kms_client: &KmsClient,
        kms_key_id: &str,
        encrypted_dek: Option<Vec<u8>>,
        encrypted_private_key: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), EnclaveError> {
        match (encrypted_dek, encrypted_private_key) {
            (Some(enc_dek), Some(enc_privkey)) => {
                // Restart scenario: decrypt existing keys
                let encryption_context = self.build_encryption_context();

                let response = kms_client
                    .decrypt()
                    .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(enc_dek.clone()))
                    .set_encryption_context(Some(encryption_context))
                    .send()
                    .await
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::Other(format!(
                            "Failed to decrypt DEK from KMS: {e}"
                        )))
                    })?;

                let plaintext_dek = response
                    .plaintext()
                    .ok_or_else(|| {
                        EnclaveError::Crypto(CryptoError::Other(
                            "No plaintext DEK returned from KMS".to_string(),
                        ))
                    })?
                    .as_ref()
                    .to_vec();

                let dek_array: [u8; 32] = plaintext_dek.clone().try_into().map_err(|_| {
                    EnclaveError::Crypto(CryptoError::Other(
                        "DEK must be exactly 32 bytes".to_string(),
                    ))
                })?;

                let private_key_bytes = self.decrypt_private_key_with_dek(&dek_array, &enc_privkey)?;

                let secret_key = secp256k1::SecretKey::from_byte_array(
                    private_key_bytes.clone().try_into().map_err(|_| {
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
                self.master_dek = Some(dek_array);
                self.private_key = private_key_bytes;
                self.public_key = public_key_bytes.clone();

                // Return same encrypted values (no re-encryption needed)
                Ok((enc_dek, enc_privkey, public_key_bytes))
            }

            (None, None) => {
                // First boot scenario: generate new keys
                let keypair = SecureCrypto::generate_enclave_keypair().map_err(|e| {
                    EnclaveError::Crypto(CryptoError::KeypairGeneration(format!("{e}")))
                })?;

                let private_key_bytes = keypair.0.secret_bytes().to_vec();
                let public_key_bytes = keypair.1.serialize().to_vec();

                let encryption_context = self.build_encryption_context();

                let response = kms_client
                    .generate_data_key()
                    .key_id(kms_key_id)
                    .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
                    .set_encryption_context(Some(encryption_context))
                    .send()
                    .await
                    .map_err(|e| {
                        EnclaveError::Crypto(CryptoError::Other(format!(
                            "Failed to generate DEK from KMS: {e}"
                        )))
                    })?;

                let plaintext_dek = response
                    .plaintext()
                    .ok_or_else(|| {
                        EnclaveError::Crypto(CryptoError::Other(
                            "No plaintext DEK returned from KMS".to_string(),
                        ))
                    })?
                    .as_ref()
                    .to_vec();

                let encrypted_dek = response
                    .ciphertext_blob()
                    .ok_or_else(|| {
                        EnclaveError::Crypto(CryptoError::Other(
                            "No encrypted DEK returned from KMS".to_string(),
                        ))
                    })?
                    .as_ref()
                    .to_vec();

                let dek_array: [u8; 32] = plaintext_dek.clone().try_into().map_err(|_| {
                    EnclaveError::Crypto(CryptoError::Other(
                        "DEK must be exactly 32 bytes".to_string(),
                    ))
                })?;

                let encrypted_private_key = self.encrypt_private_key_with_dek(&dek_array, &private_key_bytes)?;

                // Store in memory
                self.master_dek = Some(dek_array);
                self.private_key = private_key_bytes;
                self.public_key = public_key_bytes.clone();

                // Return encrypted versions for gateway to store
                Ok((encrypted_dek, encrypted_private_key, public_key_bytes))
            }

            _ => Err(EnclaveError::Crypto(CryptoError::Other(
                "Invalid key state: must provide both encrypted_dek and encrypted_private_key, or neither".to_string()
            )))
        }
    }

    /// Build encryption context for KMS requests
    /// In production this would include real Nitro attestation PCRs
    fn build_encryption_context(&self) -> HashMap<String, String> {
        let mut context = HashMap::new();
        context.insert(
            "enclave_id".to_string(),
            self.enclave_id.as_u32().to_string(),
        );

        // Add PCR values from attestation manager if available
        if let Some(ref manager) = self.attestation_manager {
            for (pcr_name, pcr_value) in &manager.config().required_pcrs {
                context.insert(format!("pcr_{}", pcr_name), pcr_value.clone());
            }
        }

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
            public_key: self.public_key.clone(),
            private_key: self.private_key.clone(),
            master_dek: self.master_dek,
            enclave_public_keys: self.enclave_public_keys.clone(),
            attestation_manager: self.attestation_manager.clone(),
            config: self.config.clone(),
        }
    }
}
