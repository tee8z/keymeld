use crate::KeyMeldError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng as RandOsRng, TryRngCore};
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tracing::{trace, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    #[zeroize(skip)]
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl KeyMaterial {
    pub const fn new(private_key: Vec<u8>) -> Self {
        Self {
            private_key,
            key_id: None,
        }
    }

    pub const fn with_id(private_key: Vec<u8>, key_id: String) -> Self {
        Self {
            private_key,
            key_id: Some(key_id),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.private_key
    }

    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    pub fn zeroize_now(&mut self) {
        self.private_key.zeroize();
        if let Some(ref mut id) = self.key_id {
            id.zeroize();
        }
    }

    pub fn from_secp256k1_secret(secret_key: &SecretKey) -> Self {
        Self {
            private_key: secret_key.secret_bytes().to_vec(),
            key_id: None,
        }
    }

    pub fn to_secp256k1_secret(&self) -> Result<SecretKey, KeyMeldError> {
        if self.private_key.len() != 32 {
            return Err(KeyMeldError::CryptoError(
                "Invalid secret key length".to_string(),
            ));
        }
        SecretKey::from_byte_array(
            self.private_key
                .clone()
                .try_into()
                .map_err(|_| KeyMeldError::CryptoError("Invalid key length".to_string()))?,
        )
        .map_err(|e| KeyMeldError::CryptoError(e.to_string()))
    }

    pub fn data(&self) -> &[u8] {
        &self.private_key
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedPublicKey {
    pub public_key: String,
    pub attestation_document: String,
    pub timestamp: u64,
    pub pcr_measurements: HashMap<String, String>,
}

pub struct SecureCrypto;

impl Default for SecureCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureCrypto {
    pub const fn new() -> Self {
        Self
    }

    pub fn generate_secure_seed() -> Result<[u8; 32], KeyMeldError> {
        let mut seed = [0u8; 32];
        RandOsRng.try_fill_bytes(&mut seed).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to generate random seed: {e}"))
        })?;
        Ok(seed)
    }

    pub fn generate_secure_nonce(
        session_id: &str,
        user_id: &str,
    ) -> Result<[u8; 32], KeyMeldError> {
        let mut nonce_seed = [0u8; 32];
        RandOsRng.try_fill_bytes(&mut nonce_seed).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to generate random nonce: {e}"))
        })?;

        let mut hasher = Sha256::new();
        hasher.update(nonce_seed);
        hasher.update(session_id.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| KeyMeldError::CryptoError(format!("Time error: {e}")))?
                .as_nanos()
                .to_le_bytes(),
        );

        let final_nonce: [u8; 32] = hasher.finalize().into();
        Ok(final_nonce)
    }

    pub fn generate_enclave_keypair() -> Result<(SecretKey, PublicKey), KeyMeldError> {
        let secret_key = SecretKey::new(&mut rand::rng());
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);
        Ok((secret_key, public_key))
    }

    pub fn ecies_encrypt(
        public_key: &PublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyMeldError> {
        let ephemeral_secret = SecretKey::new(&mut rand::rng());
        let ephemeral_public = PublicKey::from_secret_key(SECP256K1, &ephemeral_secret);
        let shared_secret = SharedSecret::new(public_key, &ephemeral_secret);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
        let mut encryption_key = [0u8; 32];
        hk.expand(b"keymeld-ecies-encrypt", &mut encryption_key)
            .map_err(|e| KeyMeldError::CryptoError(format!("HKDF error: {e}")))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&encryption_key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| KeyMeldError::CryptoError(format!("AES-GCM encryption error: {e}")))?;
        let mut result = Vec::new();
        result.extend_from_slice(&ephemeral_public.serialize());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn ecies_decrypt(
        secret_key: &SecretKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeyMeldError> {
        if ciphertext.len() < 33 + 12 {
            return Err(KeyMeldError::CryptoError(
                "Ciphertext too short".to_string(),
            ));
        }
        let ephemeral_public = PublicKey::from_slice(&ciphertext[0..33])
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid ephemeral public key: {e}")))?;

        let nonce = Nonce::from_slice(&ciphertext[33..45]);
        let actual_ciphertext = &ciphertext[45..];
        let shared_secret = SharedSecret::new(&ephemeral_public, secret_key);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
        let mut decryption_key = [0u8; 32];
        hk.expand(b"keymeld-ecies-encrypt", &mut decryption_key)
            .map_err(|e| KeyMeldError::CryptoError(format!("HKDF error: {e}")))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&decryption_key));
        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| KeyMeldError::CryptoError(format!("AES-GCM decryption error: {e}")))?;

        Ok(plaintext)
    }

    pub fn ecies_encrypt_from_hex(
        public_key_hex: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyMeldError> {
        let public_key_bytes = hex::decode(public_key_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid public key hex: {e}")))?;

        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid public key: {e}")))?;

        Self::ecies_encrypt(&public_key, plaintext)
    }

    pub fn verify_attestation_and_extract_key(
        attestation_doc: &str,
        expected_pcr_measurements: &HashMap<String, String>,
    ) -> Result<String, KeyMeldError> {
        let attestation_bytes = hex::decode(attestation_doc)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid base64 attestation: {e}")))?;

        let parsed_doc: serde_cbor::Value =
            serde_cbor::from_slice(&attestation_bytes).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to parse attestation CBOR: {e}"))
            })?;

        let pcrs = Self::extract_pcr_measurements(&parsed_doc)?;

        for (pcr_index, expected_value) in expected_pcr_measurements {
            let actual_value = pcrs
                .get(pcr_index)
                .ok_or_else(|| KeyMeldError::CryptoError(format!("Missing PCR {pcr_index}")))?;

            if actual_value != expected_value {
                return Err(KeyMeldError::CryptoError(format!(
                    "PCR {pcr_index} mismatch: expected {expected_value}, got {actual_value}"
                )));
            }
        }

        let public_key = Self::extract_public_key_from_attestation(&parsed_doc)?;

        Ok(public_key)
    }

    fn extract_pcr_measurements(
        doc: &serde_cbor::Value,
    ) -> Result<HashMap<String, String>, KeyMeldError> {
        let mut pcrs = HashMap::new();

        if let serde_cbor::Value::Map(map) = doc {
            if let Some(serde_cbor::Value::Map(pcr_map)) =
                map.get(&serde_cbor::Value::Text("pcrs".to_string()))
            {
                for (key, value) in pcr_map {
                    if let (
                        serde_cbor::Value::Integer(pcr_idx),
                        serde_cbor::Value::Bytes(pcr_value),
                    ) = (key, value)
                    {
                        pcrs.insert(pcr_idx.to_string(), hex::encode(pcr_value));
                    }
                }
            }
        }

        Ok(pcrs)
    }

    fn extract_public_key_from_attestation(
        doc: &serde_cbor::Value,
    ) -> Result<String, KeyMeldError> {
        if let serde_cbor::Value::Map(map) = doc {
            if let Some(serde_cbor::Value::Bytes(user_data)) =
                map.get(&serde_cbor::Value::Text("user_data".to_string()))
            {
                let user_data_str = String::from_utf8(user_data.clone()).map_err(|e| {
                    KeyMeldError::CryptoError(format!("Invalid user_data UTF-8: {e}"))
                })?;

                let user_data_json: serde_json::Value = serde_json::from_str(&user_data_str)
                    .map_err(|e| {
                        KeyMeldError::CryptoError(format!("Invalid user_data JSON: {}", e))
                    })?;

                if let Some(public_key) = user_data_json.get("enclave_public_key") {
                    if let Some(key_str) = public_key.as_str() {
                        return Ok(key_str.to_string());
                    }
                }
            }
        }

        Err(KeyMeldError::CryptoError(
            "No public key found in attestation".to_string(),
        ))
    }

    pub fn create_attestation_with_public_key(
        public_key: &PublicKey,
        attestation_doc: Vec<u8>,
        pcr_measurements: HashMap<String, String>,
    ) -> Result<AttestedPublicKey, KeyMeldError> {
        let public_key_hex = hex::encode(public_key.serialize());
        let attestation_hex = hex::encode(&attestation_doc);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| KeyMeldError::CryptoError(format!("Time error: {}", e)))?
            .as_secs();

        Ok(AttestedPublicKey {
            public_key: public_key_hex,
            attestation_document: attestation_hex,
            timestamp,
            pcr_measurements,
        })
    }
}

impl SecureCrypto {
    pub fn generate_session_secret() -> Result<String, KeyMeldError> {
        let seed = Self::generate_secure_seed()?;
        Ok(hex::encode(seed))
    }

    pub fn derive_session_encryption_key(
        session_id: &str,
        user_id: &str,
    ) -> Result<[u8; 32], KeyMeldError> {
        let salt = b"keymeld-session-secret-v1";
        let info = format!("{}:{}", session_id, user_id);
        let hk = Hkdf::<Sha256>::new(Some(salt), info.as_bytes());

        let mut key = [0u8; 32];
        hk.expand(b"session-secret-key", &mut key)
            .map_err(|e| KeyMeldError::CryptoError(format!("Key derivation failed: {}", e)))?;

        Ok(key)
    }

    pub fn hash_encrypted_secret(encrypted_secret: &str) -> String {
        let hash = Sha256::digest(encrypted_secret.as_bytes());
        hex::encode(hash)
    }

    pub fn validate_encrypted_session_secret(
        encrypted_secret: Option<&str>,
        stored_hash: Option<&str>,
    ) -> Result<(), KeyMeldError> {
        let encrypted = encrypted_secret
            .ok_or_else(|| KeyMeldError::ValidationError("Session secret required".to_string()))?;
        let stored = stored_hash.ok_or_else(|| {
            KeyMeldError::ValidationError("Session secret hash missing".to_string())
        })?;

        let provided_hash = Self::hash_encrypted_secret(encrypted);

        trace!("Session secret validation - hash comparison");

        if provided_hash.as_bytes().ct_eq(stored.as_bytes()).into() {
            Ok(())
        } else {
            warn!("Session secret validation failed");
            Err(KeyMeldError::ValidationError(
                "Invalid session secret".to_string(),
            ))
        }
    }

    pub fn decrypt_signature_data(
        encrypted_data_json: &serde_json::Value,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let ciphertext = encrypted_data_json
            .get("ciphertext")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KeyMeldError::CryptoError("Missing ciphertext field".to_string()))?;

        let nonce = encrypted_data_json
            .get("nonce")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KeyMeldError::CryptoError("Missing nonce field".to_string()))?;

        let context = encrypted_data_json
            .get("context")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeyMeldError::CryptoError("Missing context field".to_string()))?;

        if context != "signature" {
            return Err(KeyMeldError::CryptoError(
                "Invalid context for signature decryption".to_string(),
            ));
        }

        let ciphertext_bytes: Vec<u8> = ciphertext
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect();

        let nonce_bytes: Vec<u8> = nonce
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect();

        if nonce_bytes.len() != 12 {
            return Err(KeyMeldError::CryptoError(
                "Invalid nonce length".to_string(),
            ));
        }

        let secret_bytes = hex::decode(session_secret).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to decode hex session secret: {}", e))
        })?;

        if secret_bytes.len() != 32 {
            return Err(KeyMeldError::CryptoError(
                "Invalid session secret length".to_string(),
            ));
        }

        let hk = Hkdf::<Sha256>::new(None, &secret_bytes);
        let mut derived_key = [0u8; 32];
        hk.expand(context.as_bytes(), &mut derived_key)
            .map_err(|e| KeyMeldError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_ref = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce_ref, ciphertext_bytes.as_ref())
            .map_err(|e| KeyMeldError::CryptoError(format!("Decryption failed: {}", e)))?;

        Ok(decrypted)
    }

    pub fn decrypt_message_data(
        encrypted_data_json: &serde_json::Value,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let ciphertext = encrypted_data_json
            .get("ciphertext")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KeyMeldError::CryptoError("Missing ciphertext field".to_string()))?;

        let nonce = encrypted_data_json
            .get("nonce")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KeyMeldError::CryptoError("Missing nonce field".to_string()))?;

        let context = encrypted_data_json
            .get("context")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KeyMeldError::CryptoError("Missing context field".to_string()))?;

        if context != "message" {
            return Err(KeyMeldError::CryptoError(
                "Invalid context for message decryption".to_string(),
            ));
        }

        let ciphertext_bytes: Vec<u8> = ciphertext
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect();

        let nonce_bytes: Vec<u8> = nonce
            .iter()
            .map(|v| v.as_u64().unwrap_or(0) as u8)
            .collect();

        if nonce_bytes.len() != 12 {
            return Err(KeyMeldError::CryptoError(
                "Invalid nonce length".to_string(),
            ));
        }

        let secret_bytes = hex::decode(session_secret).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to decode hex session secret: {}", e))
        })?;

        if secret_bytes.len() != 32 {
            return Err(KeyMeldError::CryptoError(
                "Invalid session secret length".to_string(),
            ));
        }

        let hk = Hkdf::<Sha256>::new(None, &secret_bytes);
        let mut derived_key = [0u8; 32];
        hk.expand(context.as_bytes(), &mut derived_key)
            .map_err(|e| KeyMeldError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_ref = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce_ref, ciphertext_bytes.as_ref())
            .map_err(|e| KeyMeldError::CryptoError(format!("Decryption failed: {}", e)))?;

        Ok(decrypted)
    }

    pub fn hash_message(message: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn generate_message_hmac(
        message_hash: &[u8],
        session_secret: &str,
    ) -> Result<String, KeyMeldError> {
        type HmacSha256 = Hmac<Sha256>;

        let secret_bytes = hex::decode(session_secret)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid session secret hex: {}", e)))?;

        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&secret_bytes)
            .map_err(|e| KeyMeldError::CryptoError(format!("HMAC key init failed: {}", e)))?;

        mac.update(message_hash);
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }

    pub fn validate_message_hmac(
        message_hash: &[u8],
        provided_hmac: &str,
        session_secret: &str,
    ) -> Result<(), KeyMeldError> {
        let expected_hmac = Self::generate_message_hmac(message_hash, session_secret)?;

        if provided_hmac
            .as_bytes()
            .ct_eq(expected_hmac.as_bytes())
            .into()
        {
            Ok(())
        } else {
            Err(KeyMeldError::ValidationError(
                "Invalid session message HMAC".to_string(),
            ))
        }
    }

    /// Validates HMAC for session operations (keygen or signing)
    pub fn validate_session_hmac(
        session_id: &str,
        user_id: &str,
        provided_hmac: &str,
        session_secret: &str,
    ) -> Result<(), KeyMeldError> {
        // Use consolidated method for keygen operations (no message data)
        Self::validate_consolidated_hmac(session_id, user_id, provided_hmac, session_secret, None)
    }

    /// Validates HMAC for signing operations with message hash
    pub fn validate_signing_hmac(
        session_id: &str,
        user_id: &str,
        provided_hmac: &str,
        session_secret: &str,
        message_hash: &[u8],
    ) -> Result<(), KeyMeldError> {
        // Use consolidated method for signing operations (with message data)
        Self::validate_consolidated_hmac(
            session_id,
            user_id,
            provided_hmac,
            session_secret,
            Some(message_hash),
        )
    }

    /// Consolidated HMAC validation method that handles both keygen and signing operations
    pub fn validate_consolidated_hmac(
        session_id: &str,
        user_id: &str,
        provided_hmac: &str,
        session_secret: &str,
        message_data: Option<&[u8]>,
    ) -> Result<(), KeyMeldError> {
        trace!("Validating consolidated HMAC");

        let (message_to_validate, hmac_value) = if let Some(msg_data) = message_data {
            // For signing operations: use provided message hash directly, no nonce parsing
            (msg_data.to_vec(), provided_hmac)
        } else {
            // For keygen operations: parse nonce:hmac format and reconstruct message
            let (nonce, hmac_val) = provided_hmac.split_once(':').ok_or_else(|| {
                KeyMeldError::ValidationError(
                    "Invalid HMAC format, expected 'nonce:hmac'".to_string(),
                )
            })?;

            let message_data = format!("{}:{}:{}", session_id, user_id, nonce);
            (message_data.as_bytes().to_vec(), hmac_val)
        };

        let expected_hmac = Self::generate_hmac_for_data(&message_to_validate, session_secret)?;

        if hmac_value.as_bytes().ct_eq(expected_hmac.as_bytes()).into() {
            Ok(())
        } else {
            warn!("Consolidated HMAC validation failed");
            Err(KeyMeldError::ValidationError(
                "Invalid session HMAC".to_string(),
            ))
        }
    }

    /// Internal helper to generate HMAC for raw data
    fn generate_hmac_for_data(data: &[u8], session_secret: &str) -> Result<String, KeyMeldError> {
        type HmacSha256 = Hmac<Sha256>;

        let secret_bytes = hex::decode(session_secret)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid session secret hex: {}", e)))?;

        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&secret_bytes)
            .map_err(|e| KeyMeldError::CryptoError(format!("HMAC key init failed: {}", e)))?;

        mac.update(data);
        let result = mac.finalize();

        Ok(hex::encode(result.into_bytes()))
    }

    /// Generates HMAC for participant registration using session secret
    pub fn generate_registration_hmac(
        data: &str,
        session_secret: &str,
    ) -> Result<String, KeyMeldError> {
        Self::generate_hmac_for_data(data.as_bytes(), session_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SECP256K1;

    #[test]
    fn test_secure_seed_generation() {
        let seed1 = SecureCrypto::generate_secure_seed().expect("Failed to generate seed1");
        let seed2 = SecureCrypto::generate_secure_seed().expect("Failed to generate seed2");

        assert_ne!(seed1, seed2);
        assert_eq!(seed1.len(), 32);
        assert_eq!(seed2.len(), 32);
    }

    #[test]
    fn test_secure_nonce_generation() {
        let nonce1 = SecureCrypto::generate_secure_nonce("session1", "user1").unwrap();
        let nonce2 = SecureCrypto::generate_secure_nonce("session1", "user1").unwrap();

        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);
    }

    #[test]
    fn test_enclave_keypair_generation() {
        let (secret1, public1) = SecureCrypto::generate_enclave_keypair().unwrap();
        let (secret2, public2) = SecureCrypto::generate_enclave_keypair().unwrap();

        assert_ne!(secret1.secret_bytes(), secret2.secret_bytes());
        assert_ne!(public1, public2);

        let derived_public1 = PublicKey::from_secret_key(SECP256K1, &secret1);
        assert_eq!(derived_public1, public1);
    }

    #[test]
    fn test_key_material_secp256k1_conversion() {
        let secret_key = SecretKey::new(&mut rand::rng());
        let key_material = KeyMaterial::from_secp256k1_secret(&secret_key);
        let recovered_secret = key_material.to_secp256k1_secret().unwrap();

        assert_eq!(secret_key.secret_bytes(), recovered_secret.secret_bytes());
    }

    #[test]
    fn test_session_secret_generation() {
        let secret1 = SecureCrypto::generate_session_secret().unwrap();
        let secret2 = SecureCrypto::generate_session_secret().unwrap();

        assert_ne!(secret1, secret2);
        assert_eq!(secret1.len(), 64); // 32 bytes hex encoded = 64 chars
        assert_eq!(secret2.len(), 64);

        // Verify it's valid hex
        hex::decode(&secret1).expect("Generated secret should be valid hex");
        hex::decode(&secret2).expect("Generated secret should be valid hex");
    }

    #[test]
    fn test_message_hmac_generation_and_validation() {
        let session_secret = SecureCrypto::generate_session_secret().unwrap();
        let message_hash = vec![1, 2, 3, 4, 5];

        let hmac = SecureCrypto::generate_message_hmac(&message_hash, &session_secret).unwrap();

        // HMAC should be valid hex
        hex::decode(&hmac).expect("HMAC should be valid hex");

        // Validation should succeed with correct HMAC
        assert!(SecureCrypto::validate_message_hmac(&message_hash, &hmac, &session_secret).is_ok());

        // Validation should fail with wrong HMAC
        let wrong_hmac = "deadbeef";
        assert!(
            SecureCrypto::validate_message_hmac(&message_hash, wrong_hmac, &session_secret)
                .is_err()
        );

        // Validation should fail with wrong message
        let wrong_message = vec![6, 7, 8, 9, 10];
        assert!(
            SecureCrypto::validate_message_hmac(&wrong_message, &hmac, &session_secret).is_err()
        );
    }

    #[test]
    fn test_session_hmac_validation() {
        let session_secret = SecureCrypto::generate_session_secret().unwrap();
        let session_id = "test-session-123";
        let user_id = "test-user-456";
        let nonce = "1234567890abcdef"; // Mock nonce for testing

        // Generate expected HMAC with nonce format
        let data = format!("{}:{}:{}", session_id, user_id, nonce);
        let expected_hmac =
            SecureCrypto::generate_registration_hmac(&data, &session_secret).unwrap();
        let nonce_hmac_format = format!("{}:{}", nonce, expected_hmac);

        // Validation should succeed with correct HMAC in nonce:hmac format
        assert!(SecureCrypto::validate_session_hmac(
            session_id,
            user_id,
            &nonce_hmac_format,
            &session_secret
        )
        .is_ok());

        // Validation should fail with wrong HMAC
        let wrong_hmac = format!("{}:deadbeef", nonce);
        assert!(SecureCrypto::validate_session_hmac(
            session_id,
            user_id,
            &wrong_hmac,
            &session_secret
        )
        .is_err());

        // Validation should fail with wrong session_id
        let wrong_session_id = "wrong-session-789";
        assert!(SecureCrypto::validate_session_hmac(
            wrong_session_id,
            user_id,
            &nonce_hmac_format,
            &session_secret
        )
        .is_err());

        // Validation should fail with wrong user_id
        let wrong_user_id = "wrong-user-789";
        assert!(SecureCrypto::validate_session_hmac(
            session_id,
            wrong_user_id,
            &nonce_hmac_format,
            &session_secret
        )
        .is_err());

        // Validation should fail with invalid format (no colon)
        assert!(SecureCrypto::validate_session_hmac(
            session_id,
            user_id,
            "invalidformat",
            &session_secret
        )
        .is_err());
    }

    #[test]
    fn test_registration_hmac_generation() {
        let session_secret = SecureCrypto::generate_session_secret().unwrap();
        let data1 = "session1:user1";
        let data2 = "session2:user2";

        // Generate HMACs for different data
        let hmac1 = SecureCrypto::generate_registration_hmac(data1, &session_secret).unwrap();
        let hmac2 = SecureCrypto::generate_registration_hmac(data2, &session_secret).unwrap();

        // HMACs should be different for different data
        assert_ne!(hmac1, hmac2);

        // HMAC should be deterministic for the same data
        let hmac1_again = SecureCrypto::generate_registration_hmac(data1, &session_secret).unwrap();
        assert_eq!(hmac1, hmac1_again);

        // HMAC should be different for different secrets
        let different_secret = SecureCrypto::generate_session_secret().unwrap();
        let hmac_different_secret =
            SecureCrypto::generate_registration_hmac(data1, &different_secret).unwrap();
        assert_ne!(hmac1, hmac_different_secret);
    }

    #[test]
    fn test_key_derivation_consistency() {
        let session_id = "test-session";
        let user_id = "test-user";

        let key1 = SecureCrypto::derive_session_encryption_key(session_id, user_id).unwrap();
        let key2 = SecureCrypto::derive_session_encryption_key(session_id, user_id).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1, key2);

        // Different session_id should produce different key
        let key3 =
            SecureCrypto::derive_session_encryption_key("different-session", user_id).unwrap();
        assert_ne!(key1, key3);

        // Different user_id should produce different key
        let key4 =
            SecureCrypto::derive_session_encryption_key(session_id, "different-user").unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_ecies_encrypt_decrypt() {
        let secret_key = SecretKey::new(&mut rand::rng());
        let public_key = PublicKey::from_secret_key(SECP256K1, &secret_key);

        let plaintext = b"Hello, ECIES encryption!";
        let ciphertext = SecureCrypto::ecies_encrypt(&public_key, plaintext).unwrap();
        let decrypted = SecureCrypto::ecies_decrypt(&secret_key, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_ecies_different_keys_fail() {
        let secret_key1 = SecretKey::new(&mut rand::rng());
        let public_key1 = PublicKey::from_secret_key(SECP256K1, &secret_key1);

        let secret_key2 = SecretKey::new(&mut rand::rng());

        let plaintext = b"Hello, ECIES encryption!";
        let ciphertext = SecureCrypto::ecies_encrypt(&public_key1, plaintext).unwrap();

        let result = SecureCrypto::ecies_decrypt(&secret_key2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_encryption_key_derivation() {
        let session_id = "test-session-123";
        let user_id = "user-456";

        let key1 = SecureCrypto::derive_session_encryption_key(session_id, user_id).unwrap();
        let key2 = SecureCrypto::derive_session_encryption_key(session_id, user_id).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);

        let key3 =
            SecureCrypto::derive_session_encryption_key("different-session", user_id).unwrap();
        assert_ne!(key1, key3);

        let key4 =
            SecureCrypto::derive_session_encryption_key(session_id, "different-user").unwrap();
        assert_ne!(key1, key4);
    }

    #[test]
    fn test_session_secret_hash() {
        let encrypted_secret = "deadbeef1234567890abcdef";
        let hash1 = SecureCrypto::hash_encrypted_secret(encrypted_secret);
        let hash2 = SecureCrypto::hash_encrypted_secret(encrypted_secret);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
        assert!(hex::decode(&hash1).is_ok());

        let hash3 = SecureCrypto::hash_encrypted_secret("different_secret");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_session_secret_validation() {
        let encrypted_secret = "deadbeef1234567890abcdef";
        let correct_hash = SecureCrypto::hash_encrypted_secret(encrypted_secret);
        let wrong_hash = SecureCrypto::hash_encrypted_secret("wrong_secret");

        assert!(SecureCrypto::validate_encrypted_session_secret(
            Some(encrypted_secret),
            Some(&correct_hash)
        )
        .is_ok());

        assert!(SecureCrypto::validate_encrypted_session_secret(
            Some(encrypted_secret),
            Some(&wrong_hash)
        )
        .is_err());

        assert!(
            SecureCrypto::validate_encrypted_session_secret(None, Some(&correct_hash)).is_err()
        );

        assert!(
            SecureCrypto::validate_encrypted_session_secret(Some(encrypted_secret), None).is_err()
        );

        assert!(SecureCrypto::validate_encrypted_session_secret(None, None).is_err());
    }

    #[test]
    fn test_generate_message_hmac() {
        let session_secret = SecureCrypto::generate_session_secret().unwrap();
        let message_hash = b"test message hash for hmac validation";

        let hmac1 = SecureCrypto::generate_message_hmac(message_hash, &session_secret).unwrap();
        let hmac2 = SecureCrypto::generate_message_hmac(message_hash, &session_secret).unwrap();

        assert_eq!(hmac1, hmac2);
        assert_eq!(hmac1.len(), 64);

        let different_message = b"different message hash";
        let hmac3 =
            SecureCrypto::generate_message_hmac(different_message, &session_secret).unwrap();
        assert_ne!(hmac1, hmac3);
    }

    #[test]
    fn test_validate_message_hmac() {
        let session_secret = SecureCrypto::generate_session_secret().unwrap();
        let message_hash = b"test message for validation";

        let valid_hmac =
            SecureCrypto::generate_message_hmac(message_hash, &session_secret).unwrap();

        assert!(
            SecureCrypto::validate_message_hmac(message_hash, &valid_hmac, &session_secret).is_ok()
        );

        let invalid_hmac = "invalid_hmac_value";
        assert!(
            SecureCrypto::validate_message_hmac(message_hash, invalid_hmac, &session_secret)
                .is_err()
        );

        let different_secret = SecureCrypto::generate_session_secret().unwrap();
        assert!(
            SecureCrypto::validate_message_hmac(message_hash, &valid_hmac, &different_secret)
                .is_err()
        );

        let different_message = b"different message";
        assert!(SecureCrypto::validate_message_hmac(
            different_message,
            &valid_hmac,
            &session_secret
        )
        .is_err());
    }

    #[test]
    fn test_hmac_workflow_integration() {
        let session_secret = SecureCrypto::generate_session_secret().unwrap();
        let message_hash = sha2::Sha256::digest(b"Bitcoin transaction to sign").to_vec();

        let participant_hmac =
            SecureCrypto::generate_message_hmac(&message_hash, &session_secret).unwrap();

        let validation_result =
            SecureCrypto::validate_message_hmac(&message_hash, &participant_hmac, &session_secret);
        assert!(validation_result.is_ok());

        let hmac2 = SecureCrypto::generate_message_hmac(&message_hash, &session_secret).unwrap();
        assert_eq!(participant_hmac, hmac2);
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SessionSecret {
    key: [u8; 32],
}

impl SessionSecret {
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(&Aes256Gcm::generate_key(&mut OsRng));
        Self { key }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    fn derive_key(&self, context: &str) -> Key<Aes256Gcm> {
        let hk = Hkdf::<Sha256>::new(None, self.as_bytes());
        let mut derived_key = [0u8; 32];
        hk.expand(context.as_bytes(), &mut derived_key)
            .expect("HKDF expand should not fail with valid inputs");
        *Key::<Aes256Gcm>::from_slice(&derived_key)
    }

    pub fn encrypt(&self, data: &[u8], context: &str) -> Result<EncryptedData> {
        let key = self.derive_key(context);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.to_vec(),
            context: context.to_string(),
        })
    }

    pub fn decrypt(&self, encrypted: &EncryptedData, expected_context: &str) -> Result<Vec<u8>> {
        if encrypted.context != expected_context {
            return Err(anyhow!(
                "Context mismatch: expected '{}', got '{}'",
                expected_context,
                encrypted.context
            ));
        }

        let key = self.derive_key(&encrypted.context);
        let cipher = Aes256Gcm::new(&key);

        if encrypted.nonce.len() != 12 {
            return Err(anyhow!(
                "Invalid nonce length: expected 12 bytes, got {}",
                encrypted.nonce.len()
            ));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))
    }

    pub fn encrypt_message(&self, message: &str) -> Result<EncryptedData> {
        self.encrypt(message.as_bytes(), "message")
    }

    pub fn decrypt_message(&self, encrypted: &EncryptedData) -> Result<String> {
        let decrypted = self.decrypt(encrypted, "message")?;
        String::from_utf8(decrypted)
            .map_err(|e| anyhow!("Failed to decode message as UTF-8: {}", e))
    }

    pub fn encrypt_signature(&self, signature: &[u8]) -> Result<EncryptedData> {
        self.encrypt(signature, "signature")
    }

    pub fn decrypt_signature(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        self.decrypt(encrypted, "signature")
    }

    pub fn hash_message(message: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn verify_message_hash(message: &str, expected_hash: &[u8]) -> bool {
        let computed_hash = Self::hash_message(message);
        computed_hash == expected_hash
    }
}

impl std::fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionSecret")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Zeroize for SessionSecret {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub context: String,
}

impl EncryptedData {
    pub fn to_hex_json(&self) -> Result<String> {
        let json_str = serde_json::to_string(self)
            .map_err(|e| anyhow!("Failed to serialize encrypted data: {}", e))?;
        Ok(hex::encode(json_str.as_bytes()))
    }

    pub fn from_hex_json(encoded: &str) -> Result<Self> {
        let json_bytes =
            hex::decode(encoded).map_err(|e| anyhow!("Failed to decode hex: {}", e))?;

        let json_str = String::from_utf8(json_bytes)
            .map_err(|e| anyhow!("Failed to decode JSON string: {}", e))?;

        serde_json::from_str(&json_str)
            .map_err(|e| anyhow!("Failed to deserialize encrypted data: {}", e))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| anyhow!("Failed to serialize to bytes: {}", e))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data).map_err(|e| anyhow!("Failed to deserialize from bytes: {}", e))
    }
}

#[cfg(test)]
mod session_secret_tests {
    use super::*;

    #[test]
    fn test_session_secret_creation() {
        let secret1 = SessionSecret::new_random();
        let secret2 = SessionSecret::new_random();

        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_message() {
        let secret = SessionSecret::new_random();
        let message = "Hello, zero-knowledge world!";

        let encrypted = secret.encrypt_message(message).unwrap();
        let decrypted = secret.decrypt_message(&encrypted).unwrap();

        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_signature() {
        let secret = SessionSecret::new_random();
        let signature = vec![1, 2, 3, 4, 5];

        let encrypted = secret.encrypt_signature(&signature).unwrap();
        let decrypted = secret.decrypt_signature(&encrypted).unwrap();

        assert_eq!(signature, decrypted);
    }

    #[test]
    fn test_signature_encryption_decryption() {
        let secret = SessionSecret::new_random();
        let signature = vec![1, 2, 3, 4, 5];

        let encrypted = secret.encrypt_signature(&signature).unwrap();
        let decrypted = secret.decrypt_signature(&encrypted).unwrap();

        assert_eq!(signature, decrypted);

        // Test with different signature
        let signature2 = vec![10, 20, 30, 40, 50];
        let encrypted2 = secret.encrypt_signature(&signature2).unwrap();
        let decrypted2 = secret.decrypt_signature(&encrypted2).unwrap();

        assert_eq!(signature2, decrypted2);
        assert_ne!(signature, signature2);
    }

    #[test]
    fn test_message_hash_verification() {
        let message = "test message";
        let hash = SessionSecret::hash_message(message);

        assert!(SessionSecret::verify_message_hash(message, &hash));
        assert!(!SessionSecret::verify_message_hash("wrong message", &hash));
    }

    #[test]
    fn test_context_isolation() {
        let secret = SessionSecret::new_random();
        let data = b"test data";

        let encrypted1 = secret.encrypt(data, "context1").unwrap();
        let encrypted2 = secret.encrypt(data, "context2").unwrap();

        assert!(secret.decrypt(&encrypted1, "context2").is_err());
        assert!(secret.decrypt(&encrypted2, "context1").is_err());

        assert_eq!(
            data,
            secret.decrypt(&encrypted1, "context1").unwrap().as_slice()
        );
        assert_eq!(
            data,
            secret.decrypt(&encrypted2, "context2").unwrap().as_slice()
        );
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let secret = SessionSecret::new_random();
        let message = "test message";
        let encrypted = secret.encrypt_message(message).unwrap();

        let json = encrypted.to_hex_json().unwrap();
        let deserialized = EncryptedData::from_hex_json(&json).unwrap();

        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
        assert_eq!(encrypted.nonce, deserialized.nonce);
        assert_eq!(encrypted.context, deserialized.context);

        let decrypted = secret.decrypt_message(&deserialized).unwrap();
        assert_eq!(message, decrypted);
    }
}
