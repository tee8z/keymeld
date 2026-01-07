use crate::KeyMeldError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use hkdf::Hkdf;

use rand::{rngs::OsRng as RandOsRng, TryRngCore};
use secp256k1::{ecdh::SharedSecret, ecdsa::Signature, Message, PublicKey, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyMaterial {
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl Debug for KeyMaterial {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.debug_struct("KeyMaterial")
            .field("private_key", &"<redacted>")
            .field("key_id", &self.key_id)
            .finish()
    }
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
        RandOsRng
            .try_fill_bytes(&mut seed)
            .map_err(|e| KeyMeldError::RandomGenerationError(Box::new(e)))?;
        Ok(seed)
    }

    pub fn generate_secure_nonce(
        session_id: &str,
        user_id: &str,
    ) -> Result<[u8; 32], KeyMeldError> {
        let mut nonce_seed = [0u8; 32];
        RandOsRng
            .try_fill_bytes(&mut nonce_seed)
            .map_err(|e| KeyMeldError::RandomGenerationError(Box::new(e)))?;

        let mut hasher = Sha256::new();
        hasher.update(nonce_seed);
        hasher.update(session_id.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(KeyMeldError::TimeError)?
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
            .map_err(|e| KeyMeldError::HkdfError(e.to_string()))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&encryption_key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| KeyMeldError::EncryptionError(e.to_string()))?;
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
        let ephemeral_public =
            PublicKey::from_slice(&ciphertext[0..33]).map_err(KeyMeldError::InvalidKey)?;

        let nonce = Nonce::from_slice(&ciphertext[33..45]);
        let actual_ciphertext = &ciphertext[45..];
        let shared_secret = SharedSecret::new(&ephemeral_public, secret_key);
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_ref());
        let mut decryption_key = [0u8; 32];
        hk.expand(b"keymeld-ecies-encrypt", &mut decryption_key)
            .map_err(|e| KeyMeldError::HkdfError(e.to_string()))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&decryption_key));
        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| KeyMeldError::DecryptionError(e.to_string()))?;

        Ok(plaintext)
    }

    pub fn ecies_encrypt_from_hex(
        public_key_hex: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KeyMeldError> {
        let public_key_bytes = hex::decode(public_key_hex).map_err(KeyMeldError::HexDecodeError)?;

        let public_key =
            PublicKey::from_slice(&public_key_bytes).map_err(KeyMeldError::InvalidKey)?;

        Self::ecies_encrypt(&public_key, plaintext)
    }

    pub fn verify_attestation_and_extract_key(
        attestation_doc: &str,
        expected_pcr_measurements: &HashMap<String, String>,
    ) -> Result<String, KeyMeldError> {
        let attestation_bytes =
            hex::decode(attestation_doc).map_err(KeyMeldError::HexDecodeError)?;

        let parsed_doc: serde_cbor::Value =
            serde_cbor::from_slice(&attestation_bytes).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to parse attestation CBOR: {e}"))
            })?;

        let pcrs = Self::extract_pcr_measurements(&parsed_doc)?;

        for (pcr_index, expected_value) in expected_pcr_measurements {
            let actual_value = pcrs
                .get(pcr_index)
                .ok_or(KeyMeldError::CryptoError(format!(
                    "Missing PCR {pcr_index}"
                )))?;

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

        if let CborValue::Map(map) = doc {
            if let Some(CborValue::Map(pcr_map)) = map.get(&CborValue::Text("pcrs".to_string())) {
                for (key, value) in pcr_map {
                    if let (CborValue::Integer(pcr_idx), CborValue::Bytes(pcr_value)) = (key, value)
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
        if let CborValue::Map(map) = doc {
            if let Some(CborValue::Bytes(user_data)) =
                map.get(&CborValue::Text("user_data".to_string()))
            {
                let user_data_str = String::from_utf8(user_data.clone()).map_err(|e| {
                    KeyMeldError::CryptoError(format!("Invalid user_data UTF-8: {e}"))
                })?;

                let user_data_json: JsonValue =
                    serde_json::from_str(&user_data_str).map_err(|e| {
                        KeyMeldError::CryptoError(format!("Invalid user_data JSON: {e}"))
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
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(KeyMeldError::TimeError)?
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
        let info = format!("{session_id}:{user_id}");
        let hk = Hkdf::<Sha256>::new(Some(salt), info.as_bytes());

        let mut key = [0u8; 32];
        hk.expand(b"session-secret-key", &mut key)
            .map_err(|e| KeyMeldError::HkdfError(e.to_string()))?;

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
        let encrypted = encrypted_secret.ok_or(KeyMeldError::ValidationError(
            "Session secret required".to_string(),
        ))?;
        let stored = stored_hash.ok_or(KeyMeldError::ValidationError(
            "Session secret hash missing".to_string(),
        ))?;

        let provided_hash = Self::hash_encrypted_secret(encrypted);

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
        encrypted: &EncryptedData,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let secret = SessionSecret::from_hex(session_secret)?;
        secret.decrypt(encrypted, "signature")
    }

    pub fn decrypt_message_data(
        encrypted: &EncryptedData,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let secret = SessionSecret::from_hex(session_secret)?;
        secret.decrypt(encrypted, "message")
    }

    pub fn hash_message(message: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn validate_user_hmac(
        expected_user_id: &str,
        user_hmac: &str,
        user_public_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        let parts: Vec<&str> = user_hmac.split(':').collect();
        if parts.len() != 3 {
            return Err(KeyMeldError::ValidationError(
                "Invalid user HMAC format, expected 'user_id:nonce:hmac'".to_string(),
            ));
        }

        let hmac_user_id = parts[0];
        let nonce = parts[1];
        let signature_hex = parts[2];
        if hmac_user_id != expected_user_id {
            return Err(KeyMeldError::ValidationError(
                "User ID in HMAC does not match expected user ID".to_string(),
            ));
        }
        if user_public_key.len() != 33 && user_public_key.len() != 65 {
            return Err(KeyMeldError::ValidationError(
                "Invalid public key length".to_string(),
            ));
        }
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid signature hex: {e}")))?;
        let message_to_verify = format!("{hmac_user_id}:{nonce}");
        let message_hash = Sha256::digest(message_to_verify.as_bytes());
        let public_key = PublicKey::from_slice(user_public_key)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid public key: {e}")))?;
        let signature = Signature::from_compact(&signature_bytes)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid signature format: {e}")))?;
        let message_hash_array: [u8; 32] = message_hash.into();
        let message = Message::from_digest(message_hash_array);
        signature.verify(message, &public_key).map_err(|e| {
            KeyMeldError::ValidationError(format!("Signature verification failed: {e}"))
        })?;

        Ok(())
    }

    pub fn encrypt_adaptor_configs(
        data: &[u8],
        session_secret: &str,
    ) -> Result<EncryptedData, KeyMeldError> {
        Self::encrypt_with_context(data, session_secret, "adaptor_configs")
    }

    pub fn decrypt_adaptor_configs(
        encrypted: &EncryptedData,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let secret = SessionSecret::from_hex(session_secret)?;
        secret.decrypt(encrypted, "adaptor_configs")
    }

    pub fn encrypt_adaptor_signatures(
        data: &[u8],
        session_secret: &str,
    ) -> Result<EncryptedData, KeyMeldError> {
        Self::encrypt_with_context(data, session_secret, "adaptor_signatures")
    }

    pub fn decrypt_adaptor_signatures(
        encrypted: &EncryptedData,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let secret = SessionSecret::from_hex(session_secret)?;
        secret.decrypt(encrypted, "adaptor_signatures")
    }

    fn encrypt_with_context(
        data: &[u8],
        session_secret: &str,
        context: &str,
    ) -> Result<EncryptedData, KeyMeldError> {
        let secret_bytes = hex::decode(session_secret).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to decode hex session secret: {e}"))
        })?;

        if secret_bytes.len() != 32 {
            return Err(KeyMeldError::CryptoError(
                "Invalid session secret length".to_string(),
            ));
        }

        let hk = Hkdf::<Sha256>::new(None, &secret_bytes);
        let mut derived_key = [0u8; 32];
        hk.expand(context.as_bytes(), &mut derived_key)
            .map_err(|e| KeyMeldError::HkdfError(e.to_string()))?;

        let key = Key::<Aes256Gcm>::from_slice(&derived_key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| KeyMeldError::EncryptionError(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.to_vec(),
            context: context.to_string(),
        })
    }

    pub fn encrypt_session_data(
        data: &str,
        session_secret: &str,
    ) -> Result<EncryptedData, KeyMeldError> {
        Self::encrypt_with_context(data.as_bytes(), session_secret, "session_data")
    }

    pub fn decrypt_session_data(
        encrypted: &EncryptedData,
        session_secret: &str,
    ) -> Result<String, KeyMeldError> {
        let secret = SessionSecret::from_hex(session_secret)?;
        let decrypted_bytes = secret.decrypt(encrypted, "session_data")?;
        String::from_utf8(decrypted_bytes).map_err(|e| {
            KeyMeldError::CryptoError(format!(
                "Failed to convert decrypted session data to string: {e}"
            ))
        })
    }

    pub fn encrypt_structured_data_with_session_key<T: serde::Serialize>(
        data: &T,
        session_secret: &str,
        context: &str,
    ) -> Result<EncryptedData, KeyMeldError> {
        let json = serde_json::to_string(data)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to serialize data: {e}")))?;
        Self::encrypt_with_context(json.as_bytes(), session_secret, context)
    }

    pub fn decrypt_structured_data_with_session_key<T: serde::de::DeserializeOwned>(
        encrypted: &EncryptedData,
        session_secret: &str,
        context: &str,
    ) -> Result<T, KeyMeldError> {
        let secret = SessionSecret::from_hex(session_secret)?;
        secret.decrypt_value(encrypted, context)
    }

    pub fn encrypt_structured_data_with_enclave_key<T: serde::Serialize>(
        data: &T,
        enclave_public_key_hex: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let json = serde_json::to_string(data)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to serialize data: {e}")))?;
        Self::ecies_encrypt_from_hex(enclave_public_key_hex, json.as_bytes())
    }

    pub fn decrypt_structured_data_with_enclave_key<T: serde::de::DeserializeOwned>(
        encrypted_data: &[u8],
        enclave_private_key: &secp256k1::SecretKey,
    ) -> Result<T, KeyMeldError> {
        let decrypted_bytes = Self::ecies_decrypt(enclave_private_key, encrypted_data)?;
        let json_str = String::from_utf8(decrypted_bytes).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to convert decrypted bytes to string: {e}"))
        })?;
        serde_json::from_str(&json_str)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to deserialize data: {e}")))
    }

    pub fn generate_session_seed() -> Result<Vec<u8>, KeyMeldError> {
        let seed = Self::generate_secure_seed()?;
        Ok(seed.to_vec())
    }

    pub fn derive_private_key_from_seed(seed: &[u8]) -> Result<SecretKey, KeyMeldError> {
        if seed.len() < 32 {
            return Err(KeyMeldError::ValidationError(
                "Seed must be at least 32 bytes".to_string(),
            ));
        }

        let salt = b"keymeld-session-auth-v1";
        let hk = Hkdf::<Sha256>::new(Some(salt), seed);

        let mut key_material = [0u8; 32];
        hk.expand(b"session-auth-key", &mut key_material)
            .map_err(|e| KeyMeldError::HkdfError(e.to_string()))?;

        SecretKey::from_byte_array(key_material)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid private key: {e}")))
    }

    pub fn derive_public_key_from_seed(seed: &[u8]) -> Result<PublicKey, KeyMeldError> {
        let private_key = Self::derive_private_key_from_seed(seed)?;
        Ok(PublicKey::from_secret_key(SECP256K1, &private_key))
    }

    pub fn derive_session_auth_keypair(
        signing_privkey: &[u8; 32],
        keygen_session_id: &str,
    ) -> Result<(SecretKey, PublicKey), KeyMeldError> {
        let hk = Hkdf::<Sha256>::new(None, signing_privkey);
        let mut auth_privkey_bytes = [0u8; 32];

        let info = format!("keymeld-session-auth-v1:{keygen_session_id}");
        hk.expand(info.as_bytes(), &mut auth_privkey_bytes)
            .map_err(|e| KeyMeldError::HkdfError(e.to_string()))?;

        let auth_privkey = SecretKey::from_byte_array(auth_privkey_bytes)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid private key: {e}")))?;
        let auth_pubkey = PublicKey::from_secret_key(SECP256K1, &auth_privkey);

        Ok((auth_privkey, auth_pubkey))
    }

    pub fn sign_auth_message_with_session_key(
        signing_privkey: &[u8; 32],
        keygen_session_id: &str,
        signing_session_id: &str,
        user_id: &str,
        nonce: &[u8],
    ) -> Result<Vec<u8>, KeyMeldError> {
        let (auth_privkey, _) =
            Self::derive_session_auth_keypair(signing_privkey, keygen_session_id)?;

        let mut message = Vec::new();
        message.extend_from_slice(signing_session_id.as_bytes());
        message.extend_from_slice(user_id.as_bytes());
        message.extend_from_slice(nonce);

        let message_hash = Sha256::digest(&message);
        let msg = Message::from_digest(message_hash.into());

        let signature = SECP256K1.sign_ecdsa(msg, &auth_privkey);
        Ok(signature.serialize_compact().to_vec())
    }

    pub fn verify_auth_signature_with_session_key(
        auth_pubkey: &PublicKey,
        signing_session_id: &str,
        user_id: &str,
        nonce: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, KeyMeldError> {
        let mut message = Vec::new();
        message.extend_from_slice(signing_session_id.as_bytes());
        message.extend_from_slice(user_id.as_bytes());
        message.extend_from_slice(nonce);

        let message_hash = Sha256::digest(&message);
        let msg = Message::from_digest(message_hash.into());

        let signature = Signature::from_compact(signature_bytes)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid signature: {e}")))?;

        match SECP256K1.verify_ecdsa(msg, &signature, auth_pubkey) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn sign_session_message(
        session_id: &str,
        nonce: &str,
        seed: &[u8],
    ) -> Result<String, KeyMeldError> {
        let private_key = Self::derive_private_key_from_seed(seed)?;

        let message_str = format!("{session_id}:{nonce}");
        let message_hash = Sha256::digest(message_str.as_bytes());

        let message = Message::from_digest(message_hash.into());

        let signature = SECP256K1.sign_ecdsa(message, &private_key);
        Ok(hex::encode(signature.serialize_compact()))
    }

    pub fn validate_session_signature(
        session_id: &str,
        nonce: &str,
        signature_hex: &str,
        public_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        let message_str = format!("{session_id}:{nonce}");
        let message_hash = Sha256::digest(message_str.as_bytes());

        let message = Message::from_digest(message_hash.into());

        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid signature hex: {e}")))?;
        let signature = Signature::from_compact(&signature_bytes)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid signature format: {e}")))?;

        let public_key = PublicKey::from_slice(public_key)
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid public key: {e}")))?;

        SECP256K1
            .verify_ecdsa(message, &signature, &public_key)
            .map_err(|_| KeyMeldError::ValidationError("Invalid session signature".to_string()))?;

        Ok(())
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
        assert_eq!(secret1.len(), 64);
        assert_eq!(secret2.len(), 64);

        hex::decode(&secret1).expect("Generated secret should be valid hex");
        hex::decode(&secret2).expect("Generated secret should be valid hex");
    }

    #[test]
    fn test_seed_based_authentication() {
        let seed = SecureCrypto::generate_session_seed().unwrap();
        assert_eq!(seed.len(), 32);

        let private_key = SecureCrypto::derive_private_key_from_seed(&seed).unwrap();
        let public_key = SecureCrypto::derive_public_key_from_seed(&seed).unwrap();

        let private_key2 = SecureCrypto::derive_private_key_from_seed(&seed).unwrap();
        let public_key2 = SecureCrypto::derive_public_key_from_seed(&seed).unwrap();

        assert_eq!(private_key.secret_bytes(), private_key2.secret_bytes());
        assert_eq!(public_key.serialize(), public_key2.serialize());

        let session_id = "test-session-123";
        let nonce = "1234567890abcdef";

        let signature = SecureCrypto::sign_session_message(session_id, nonce, &seed).unwrap();
        assert!(SecureCrypto::validate_session_signature(
            session_id,
            nonce,
            &signature,
            &public_key.serialize()
        )
        .is_ok());

        assert!(SecureCrypto::validate_session_signature(
            session_id,
            nonce,
            "invalid_signature",
            &public_key.serialize()
        )
        .is_err());

        assert!(SecureCrypto::validate_session_signature(
            "wrong-session",
            nonce,
            &signature,
            &public_key.serialize()
        )
        .is_err());

        assert!(SecureCrypto::validate_session_signature(
            session_id,
            "wrong-nonce",
            &signature,
            &public_key.serialize()
        )
        .is_err());
    }

    #[test]
    fn test_key_derivation_consistency() {
        let session_id = "test-session";
        let user_id = "test-user";

        let key1 = SecureCrypto::derive_session_encryption_key(session_id, user_id).unwrap();
        let key2 = SecureCrypto::derive_session_encryption_key(session_id, user_id).unwrap();

        assert_eq!(key1, key2);

        let key3 =
            SecureCrypto::derive_session_encryption_key("different-session", user_id).unwrap();
        assert_ne!(key1, key3);

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

    pub fn from_hex(hex_string: &str) -> Result<Self, KeyMeldError> {
        let bytes = hex::decode(hex_string).map_err(KeyMeldError::HexDecodeError)?;
        if bytes.len() != 32 {
            return Err(KeyMeldError::ValidationError(
                "Session secret must be 32 bytes".to_string(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self { key })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.key)
    }

    fn derive_key(&self, context: &str) -> Key<Aes256Gcm> {
        let hk = Hkdf::<Sha256>::new(None, self.as_bytes());
        let mut derived_key = [0u8; 32];
        hk.expand(context.as_bytes(), &mut derived_key)
            .expect("HKDF expand should not fail with valid inputs");
        *Key::<Aes256Gcm>::from_slice(&derived_key)
    }

    pub fn encrypt(&self, data: &[u8], context: &str) -> Result<EncryptedData, KeyMeldError> {
        let key = self.derive_key(context);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| KeyMeldError::EncryptionError(e.to_string()))?;

        Ok(EncryptedData {
            ciphertext,
            nonce: nonce.to_vec(),
            context: context.to_string(),
        })
    }

    pub fn decrypt(
        &self,
        encrypted: &EncryptedData,
        expected_context: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        if encrypted.context != expected_context {
            return Err(KeyMeldError::ValidationError(format!(
                "Context mismatch: expected '{}', got '{}'",
                expected_context, encrypted.context
            )));
        }

        let key = self.derive_key(&encrypted.context);
        let cipher = Aes256Gcm::new(&key);

        if encrypted.nonce.len() != 12 {
            return Err(KeyMeldError::ValidationError(format!(
                "Invalid nonce length: expected 12 bytes, got {}",
                encrypted.nonce.len()
            )));
        }

        let nonce = Nonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| KeyMeldError::DecryptionError(e.to_string()))
    }

    pub fn encrypt_message(&self, message: &str) -> Result<EncryptedData, KeyMeldError> {
        self.encrypt(message.as_bytes(), "message")
    }

    pub fn decrypt_message(&self, encrypted: &EncryptedData) -> Result<String, KeyMeldError> {
        let decrypted = self.decrypt(encrypted, "message")?;
        String::from_utf8(decrypted).map_err(|e| {
            KeyMeldError::ValidationError(format!("Failed to decode message as UTF-8: {e}"))
        })
    }

    pub fn encrypt_signature(&self, signature: &[u8]) -> Result<EncryptedData, KeyMeldError> {
        self.encrypt(signature, "signature")
    }

    pub fn decrypt_signature(&self, encrypted: &EncryptedData) -> Result<Vec<u8>, KeyMeldError> {
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

impl Debug for SessionSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
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
    /// Encode to hex: [context_len: 1 byte][context bytes][nonce: 12 bytes][ciphertext]
    pub fn to_hex(&self) -> Result<String, KeyMeldError> {
        let context_bytes = self.context.as_bytes();
        if context_bytes.len() > 255 {
            return Err(KeyMeldError::ValidationError(
                "Context string too long (max 255 bytes)".to_string(),
            ));
        }
        if self.nonce.len() != 12 {
            return Err(KeyMeldError::ValidationError(format!(
                "Invalid nonce length: expected 12 bytes, got {}",
                self.nonce.len()
            )));
        }

        let mut bytes = Vec::new();
        bytes.push(context_bytes.len() as u8);
        bytes.extend_from_slice(context_bytes);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);

        Ok(hex::encode(bytes))
    }

    /// Decode from hex: [context_len: 1 byte][context bytes][nonce: 12 bytes][ciphertext]
    pub fn from_hex(encoded: &str) -> Result<Self, KeyMeldError> {
        let bytes = hex::decode(encoded).map_err(KeyMeldError::HexDecodeError)?;

        if bytes.is_empty() {
            return Err(KeyMeldError::ValidationError(
                "Encrypted data cannot be empty".to_string(),
            ));
        }

        let context_len = bytes[0] as usize;
        if bytes.len() < 1 + context_len + 12 {
            return Err(KeyMeldError::ValidationError(format!(
                "Encrypted data too short: expected at least {} bytes, got {}",
                1 + context_len + 12,
                bytes.len()
            )));
        }

        let context = String::from_utf8(bytes[1..1 + context_len].to_vec())
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid UTF-8 in context: {e}")))?;

        let nonce = bytes[1 + context_len..1 + context_len + 12].to_vec();
        let ciphertext = bytes[1 + context_len + 12..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            context,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, KeyMeldError> {
        let context_bytes = self.context.as_bytes();
        if context_bytes.len() > 255 {
            return Err(KeyMeldError::ValidationError(
                "Context string too long (max 255 bytes)".to_string(),
            ));
        }

        let mut bytes = Vec::new();
        bytes.push(context_bytes.len() as u8);
        bytes.extend_from_slice(context_bytes);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        Ok(bytes)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, KeyMeldError> {
        if data.is_empty() {
            return Err(KeyMeldError::ValidationError(
                "Encrypted data cannot be empty".to_string(),
            ));
        }

        let context_len = data[0] as usize;
        if data.len() < 1 + context_len + 12 {
            return Err(KeyMeldError::ValidationError(format!(
                "Encrypted data too short: expected at least {} bytes, got {}",
                1 + context_len + 12,
                data.len()
            )));
        }

        let context = String::from_utf8(data[1..1 + context_len].to_vec())
            .map_err(|e| KeyMeldError::ValidationError(format!("Invalid UTF-8 in context: {e}")))?;

        let nonce = data[1 + context_len..1 + context_len + 12].to_vec();
        let ciphertext = data[1 + context_len + 12..].to_vec();

        Ok(Self {
            ciphertext,
            nonce,
            context,
        })
    }
}

impl SessionSecret {
    /// Encrypts a serializable value with a specific context
    pub fn encrypt_value<T: serde::Serialize>(
        &self,
        value: &T,
        context: &str,
    ) -> Result<EncryptedData, KeyMeldError> {
        let serialized = serde_json::to_vec(value).map_err(|e| {
            KeyMeldError::SerializationError(format!("Failed to serialize value: {e}"))
        })?;
        self.encrypt(&serialized, context)
    }

    /// Decrypts and deserializes a value with context validation
    pub fn decrypt_value<T: serde::de::DeserializeOwned>(
        &self,
        encrypted: &EncryptedData,
        expected_context: &str,
    ) -> Result<T, KeyMeldError> {
        let decrypted = self.decrypt(encrypted, expected_context)?;
        serde_json::from_slice(&decrypted).map_err(|e| {
            KeyMeldError::SerializationError(format!("Failed to deserialize value: {e}"))
        })
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

        let hex = encrypted.to_hex().unwrap();
        let deserialized = EncryptedData::from_hex(&hex).unwrap();

        assert_eq!(encrypted.ciphertext, deserialized.ciphertext);
        assert_eq!(encrypted.nonce, deserialized.nonce);
        assert_eq!(encrypted.context, deserialized.context);

        let decrypted = secret.decrypt_message(&deserialized).unwrap();
        assert_eq!(message, decrypted);
    }
}
