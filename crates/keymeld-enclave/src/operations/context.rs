use crate::attestation::AttestationManager;
use dashmap::DashMap;
use keymeld_core::enclave::{CryptoError, EnclaveError};
use keymeld_core::{crypto::SecureCrypto, identifiers::EnclaveId, EncryptedData, SessionSecret};

pub struct EnclaveContext {
    pub enclave_id: EnclaveId,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub enclave_public_keys: DashMap<EnclaveId, String>,
    pub attestation_manager: Option<AttestationManager>,
}

impl EnclaveContext {
    pub fn new(
        enclave_id: EnclaveId,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        attestation_manager: Option<AttestationManager>,
    ) -> Self {
        Self {
            enclave_id,
            public_key,
            private_key,
            enclave_public_keys: DashMap::new(),
            attestation_manager,
        }
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
        adaptor_signatures: &[keymeld_core::musig::AdaptorSignatureResult],
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

impl Clone for EnclaveContext {
    fn clone(&self) -> Self {
        Self {
            enclave_id: self.enclave_id,
            public_key: self.public_key.to_owned(),
            private_key: self.private_key.to_owned(),
            enclave_public_keys: self.enclave_public_keys.to_owned(),
            attestation_manager: self.attestation_manager.to_owned(),
        }
    }
}
