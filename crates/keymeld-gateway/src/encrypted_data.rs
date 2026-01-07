use keymeld_core::{
    crypto::SessionSecret, protocol::AdaptorConfig, EncryptedData, KeyMeldError, PartialSignature,
    PubNonce,
};
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Clone, Debug)]
pub enum SessionData {
    Keygen(KeygenSessionData),
    Signing(SigningSessionData),
}

#[derive(Clone, Debug)]
pub enum EnclaveData {
    Keygen(KeygenEnclaveData),
    Signing(SigningEnclaveData),
}

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
    pub participant_public_keys: std::collections::BTreeMap<crate::identifiers::UserId, Vec<u8>>,
}

impl Default for KeygenParticipantSessionData {
    fn default() -> Self {
        Self::new()
    }
}

impl KeygenParticipantSessionData {
    pub fn new() -> Self {
        Self {
            participant_public_keys: std::collections::BTreeMap::new(),
        }
    }

    pub fn new_with_public_key(
        user_id: crate::identifiers::UserId,
        participant_public_key: Vec<u8>,
    ) -> Self {
        let mut participant_public_keys = std::collections::BTreeMap::new();
        participant_public_keys.insert(user_id, participant_public_key);
        Self {
            participant_public_keys,
        }
    }

    pub fn add_participant(&mut self, user_id: crate::identifiers::UserId, public_key: Vec<u8>) {
        self.participant_public_keys.insert(user_id, public_key);
    }

    pub fn get_all_public_keys(&self) -> Vec<Vec<u8>> {
        self.participant_public_keys.values().cloned().collect()
    }

    pub fn participant_count(&self) -> usize {
        self.participant_public_keys.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SigningSessionData {
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub signed_message: Option<Vec<u8>>,
    pub adaptor_configs: Vec<AdaptorConfig>,
    pub adaptor_signatures: Option<Vec<Vec<u8>>>,
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
    #[serde(
        serialize_with = "serialize_option_pubnonce",
        deserialize_with = "deserialize_option_pubnonce",
        default
    )]
    pub public_nonces: Option<PubNonce>,
    #[serde(
        serialize_with = "serialize_option_partial_signature",
        deserialize_with = "deserialize_option_partial_signature",
        default
    )]
    pub partial_signature: Option<PartialSignature>,
}

impl Default for SigningParticipantSessionData {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningParticipantSessionData {
    pub fn new() -> Self {
        Self {
            public_nonces: None,
            partial_signature: None,
        }
    }

    pub fn with_nonces(mut self, nonces: PubNonce) -> Self {
        self.public_nonces = Some(nonces);
        self
    }

    pub fn with_partial_signature(mut self, signature: PartialSignature) -> Self {
        self.partial_signature = Some(signature);
        self
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

fn serialize_option_pubnonce<S>(nonces: &Option<PubNonce>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match nonces {
        Some(nonces) => {
            let bytes = nonces.serialize();
            serializer.serialize_some(&bytes.to_vec())
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_option_pubnonce<'de, D>(deserializer: D) -> Result<Option<PubNonce>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Option<Vec<u8>> = Option::deserialize(deserializer)?;
    match bytes {
        Some(bytes) => PubNonce::from_bytes(&bytes)
            .map(Some)
            .map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}

fn serialize_option_partial_signature<S>(
    signature: &Option<PartialSignature>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match signature {
        Some(signature) => {
            let bytes = signature.serialize();
            serializer.serialize_some(&bytes.to_vec())
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_option_partial_signature<'de, D>(
    deserializer: D,
) -> Result<Option<PartialSignature>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: Option<Vec<u8>> = Option::deserialize(deserializer)?;
    match bytes {
        Some(bytes) => {
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("Invalid partial signature length"));
            }
            let array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("Failed to convert bytes to array"))?;
            Ok(Some(
                PartialSignature::try_from(array.as_slice()).map_err(serde::de::Error::custom)?,
            ))
        }
        None => Ok(None),
    }
}

pub trait EncryptedDataOps {
    fn encrypt_with_session_secret(
        &self,
        session_secret: &SessionSecret,
        context: &str,
    ) -> Result<String, KeyMeldError>
    where
        Self: Serialize,
    {
        let json_bytes = serde_json::to_vec(self)
            .map_err(|e| KeyMeldError::SerializationError(e.to_string()))?;
        let encrypted = session_secret.encrypt(&json_bytes, context)?;
        encrypted.to_hex()
    }

    fn decrypt_with_session_secret<T>(
        encrypted_hex: &str,
        session_secret: &SessionSecret,
        context: &str,
    ) -> Result<T, KeyMeldError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let encrypted = EncryptedData::from_hex(encrypted_hex)?;
        let decrypted_bytes = session_secret.decrypt(&encrypted, context)?;
        let data: T = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| KeyMeldError::SerializationError(e.to_string()))?;
        Ok(data)
    }
}

impl EncryptedDataOps for KeygenSessionData {}
impl EncryptedDataOps for KeygenEnclaveData {}
impl EncryptedDataOps for KeygenParticipantSessionData {}
impl EncryptedDataOps for SigningSessionData {}
impl EncryptedDataOps for SigningEnclaveData {}
impl EncryptedDataOps for SigningParticipantSessionData {}
impl EncryptedDataOps for SigningParticipantEnclaveData {}

#[cfg(test)]
mod tests {
    use super::*;

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
