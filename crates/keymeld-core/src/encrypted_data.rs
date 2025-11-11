use anyhow;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::EncryptedData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenSessionData {
    pub coordinator_pubkey: Vec<u8>,
    pub aggregate_pubkey: Option<Vec<u8>>,
}

impl KeygenSessionData {
    pub fn new(coordinator_pubkey: Vec<u8>) -> Self {
        Self {
            coordinator_pubkey,
            aggregate_pubkey: None,
        }
    }

    pub fn with_aggregate_key(mut self, aggregate_pubkey: Vec<u8>) -> Self {
        self.aggregate_pubkey = Some(aggregate_pubkey);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenEnclaveData {
    pub coordinator_private_key: String,
    pub session_secret: String,
}

impl KeygenEnclaveData {
    pub fn new(coordinator_private_key: String, session_secret: String) -> Self {
        Self {
            coordinator_private_key,
            session_secret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenParticipantSessionData {
    pub public_key: Vec<u8>,
}

impl KeygenParticipantSessionData {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenParticipantEnclaveData {
    pub private_key: String,
}

impl KeygenParticipantEnclaveData {
    pub fn new(private_key: String) -> Self {
        Self { private_key }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigningSessionData {
    pub message: Option<String>,
    pub signed_message: Option<Vec<u8>>,
}

impl SigningSessionData {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_message(mut self, message: String) -> Self {
        self.message = Some(message);
        self
    }

    pub fn with_signed_message(mut self, signed_message: Vec<u8>) -> Self {
        self.signed_message = Some(signed_message);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningEnclaveData {
    pub coordinator_private_key: String,
    pub session_secret: String,
}

impl SigningEnclaveData {
    pub fn new(coordinator_private_key: String, session_secret: String) -> Self {
        Self {
            coordinator_private_key,
            session_secret,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningParticipantSessionData {
    pub public_key: Vec<u8>,
}

impl SigningParticipantSessionData {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningParticipantEnclaveData {
    pub private_key: String,
    pub public_key: Vec<u8>,
}

impl SigningParticipantEnclaveData {
    pub fn new(private_key: String, public_key: Vec<u8>) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

pub trait EncryptedDataOps {
    fn encrypt_with_session_secret(
        &self,
        session_secret: &crate::crypto::SessionSecret,
        context: &str,
    ) -> Result<String, anyhow::Error>
    where
        Self: Serialize,
    {
        let json_bytes = serde_json::to_vec(self)?;
        let encrypted = session_secret.encrypt(&json_bytes, context)?;
        encrypted.to_hex_json()
    }

    fn decrypt_with_session_secret<T>(
        encrypted_hex: &str,
        session_secret: &crate::crypto::SessionSecret,
        context: &str,
    ) -> Result<T, anyhow::Error>
    where
        T: for<'de> Deserialize<'de>,
    {
        let encrypted = EncryptedData::from_hex_json(encrypted_hex)?;
        let decrypted_bytes = session_secret.decrypt(&encrypted, context)?;
        let data: T = serde_json::from_slice(&decrypted_bytes)?;
        Ok(data)
    }
}

impl EncryptedDataOps for KeygenSessionData {}
impl EncryptedDataOps for KeygenEnclaveData {}
impl EncryptedDataOps for KeygenParticipantSessionData {}
impl EncryptedDataOps for KeygenParticipantEnclaveData {}
impl EncryptedDataOps for SigningSessionData {}
impl EncryptedDataOps for SigningEnclaveData {}
impl EncryptedDataOps for SigningParticipantSessionData {}
impl EncryptedDataOps for SigningParticipantEnclaveData {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SessionSecret;

    #[test]
    fn test_keygen_session_data_serialization() {
        let data = KeygenSessionData::new(vec![1, 2, 3, 4]).with_aggregate_key(vec![5, 6, 7, 8]);

        let json = serde_json::to_string(&data).unwrap();
        let deserialized: KeygenSessionData = serde_json::from_str(&json).unwrap();

        assert_eq!(data.coordinator_pubkey, deserialized.coordinator_pubkey);
        assert_eq!(data.aggregate_pubkey, deserialized.aggregate_pubkey);
    }

    #[test]
    fn test_keygen_enclave_data_serialization() {
        let data = KeygenEnclaveData::new(
            "encrypted_private_key".to_string(),
            "session_secret".to_string(),
        );

        let json = serde_json::to_string(&data).unwrap();
        let deserialized: KeygenEnclaveData = serde_json::from_str(&json).unwrap();

        assert_eq!(
            data.coordinator_private_key,
            deserialized.coordinator_private_key
        );
        assert_eq!(data.session_secret, deserialized.session_secret);
    }

    #[test]
    fn test_signing_session_data_builder() {
        let data = SigningSessionData::new()
            .with_message("test message".to_string())
            .with_signed_message(vec![9, 10, 11, 12]);

        assert_eq!(data.message, Some("test message".to_string()));
        assert_eq!(data.signed_message, Some(vec![9, 10, 11, 12]));
    }

    #[test]
    fn test_encryption_roundtrip() {
        let session_secret = SessionSecret::new_random();
        let original_data = KeygenSessionData::new(vec![1, 2, 3, 4]);

        let encrypted = original_data
            .encrypt_with_session_secret(&session_secret, "test")
            .unwrap();

        let decrypted_data: KeygenSessionData =
            <KeygenSessionData as EncryptedDataOps>::decrypt_with_session_secret(
                &encrypted,
                &session_secret,
                "test",
            )
            .unwrap();

        assert_eq!(
            original_data.coordinator_pubkey,
            decrypted_data.coordinator_pubkey
        );
        assert_eq!(
            original_data.aggregate_pubkey,
            decrypted_data.aggregate_pubkey
        );
    }
}
