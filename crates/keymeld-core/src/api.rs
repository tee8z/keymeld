use crate::{
    crypto::SecureCrypto,
    identifiers::{EnclaveId, SessionId, UserId},
    AggregatePublicKey, EncryptedData, KeyMeldError, KeygenStatusKind, SigningStatusKind,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use utoipa::ToSchema;

use crate::musig::{AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CreateKeygenSessionRequest {
    pub keygen_session_id: SessionId,
    pub coordinator_user_id: UserId,
    pub coordinator_pubkey: Vec<u8>,
    pub coordinator_encrypted_private_key: String,
    pub coordinator_enclave_id: EnclaveId,
    pub expected_participants: Vec<UserId>,
    pub timeout_secs: u64,
    pub session_public_key: Vec<u8>,
    pub encrypted_session_secret: String,
    pub encrypted_session_data: String,
    pub encrypted_enclave_data: String,
    pub max_signing_sessions: Option<u32>,
    #[serde(default)]
    pub taproot_tweak_config: TaprootTweak,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaprootTweak {
    /// No tweaking - use plain MuSig2 aggregate key
    #[default]
    None,
    /// Unspendable taproot tweak (key-path only spending)
    UnspendableTaproot,
    /// Taproot tweak with specific merkle root (commits to tapscript tree)
    TaprootWithMerkleRoot { merkle_root: [u8; 32] },
    /// Plain scalar tweak
    PlainTweak { tweak: [u8; 32] },
    /// X-only scalar tweak
    XOnlyTweak { tweak: [u8; 32] },
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CreateKeygenSessionResponse {
    pub keygen_session_id: SessionId,
    pub coordinator_enclave_id: EnclaveId,
    pub status: KeygenStatusKind,
    pub expected_participants: usize,
    pub expires_at: u64,
    pub enclave_epochs: HashMap<EnclaveId, u64>,
    pub session_secret: String,
    pub session_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterKeygenParticipantRequest {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub encrypted_private_key: String,
    pub public_key: Vec<u8>,
    pub encrypted_session_data: String,
    pub enclave_public_key: String,
    #[serde(default)]
    pub require_signing_approval: bool,
    pub auth_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct RegisterKeygenParticipantResponse {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub status: KeygenStatusKind,
    pub participants_registered: usize,
    pub expected_participants: usize,
    pub signer_index: usize,
    pub assigned_enclave_id: EnclaveId,
    #[serde(default)]
    pub require_signing_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct KeygenSessionStatusResponse {
    pub keygen_session_id: SessionId,
    pub status: KeygenStatusKind,
    pub expected_participants: usize,
    pub registered_participants: usize,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CreateSigningSessionRequest {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message_hash: Vec<u8>,
    pub encrypted_message: Option<String>,
    pub timeout_secs: u64,
    #[serde(default)]
    pub encrypted_adaptor_configs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct CreateSigningSessionResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub status: SigningStatusKind,
    pub participants_count: usize,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct SigningSessionStatusResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub status: SigningStatusKind,
    pub participants_registered: usize,
    pub expected_participants: usize,
    pub final_signature: Option<String>,
    pub expires_at: u64,
    /// Participants that require explicit approval before signing can proceed
    #[serde(default)]
    pub participants_requiring_approval: Vec<UserId>,
    /// Participants who have already provided their approval
    #[serde(default)]
    pub approved_participants: Vec<UserId>,
    #[serde(default)]
    pub adaptor_signatures: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct EnclaveAssignmentResponse {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_public_key: String,
    pub enclave_cid: u32,
    pub enclave_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct AvailableUserSlot {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub signer_index: usize,
    pub claimed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct GetAvailableSlotsResponse {
    pub session_id: SessionId,
    pub available_slots: Vec<AvailableUserSlot>,
    pub total_slots: usize,
    pub claimed_slots: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct EnclavePublicKeyResponse {
    pub enclave_id: u32,
    pub public_key: String,
    pub attestation_document: String,
    pub pcr_measurements: HashMap<String, String>,
    pub timestamp: u64,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct EnclaveHealthResponse {
    pub enclave_id: EnclaveId,
    pub healthy: bool,
    pub public_key: String,
    pub attestation_document: String,
    pub active_sessions: u32,
    pub uptime_seconds: u64,
    pub key_epoch: u64,
    pub key_generation_time: u64,
    pub last_health_check: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ListEnclavesResponse {
    pub enclaves: Vec<EnclaveHealthResponse>,
    pub total_enclaves: u32,
    pub healthy_enclaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct HealthCheckResponse {
    pub status: String,
    pub version: String,
    pub active_sessions: u32,
    pub healthy_enclaves: u32,
    pub total_enclaves: u32,
    pub database_stats: Option<DatabaseStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct DatabaseStats {
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub total_participants: i64,
    pub database_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ApiVersionResponse {
    pub service: String,
    pub version: String,
    pub api_version: String,
    pub features: ApiFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ApiFeatures {
    pub service_participation: bool,
    pub user_authentication: bool,
    pub enclave_isolation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub struct ErrorResponse {
    pub error_code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub retryable: bool,
}

pub mod validation {
    use super::*;

    pub struct Validator;

    impl Validator {
        pub fn validate_non_empty_string(
            value: &str,
            field_name: &str,
        ) -> Result<(), KeyMeldError> {
            if value.is_empty() {
                return Err(KeyMeldError::InvalidConfiguration(format!(
                    "{field_name} cannot be empty"
                )));
            }
            Ok(())
        }

        pub fn validate_vec_length<T>(
            vec: &[T],
            min: Option<usize>,
            max: Option<usize>,
            field_name: &str,
        ) -> Result<(), KeyMeldError> {
            if let Some(min_len) = min {
                if vec.len() < min_len {
                    return Err(KeyMeldError::InvalidConfiguration(format!(
                        "{field_name} must have at least {min_len} items"
                    )));
                }
            }
            if let Some(max_len) = max {
                if vec.len() > max_len {
                    return Err(KeyMeldError::InvalidConfiguration(format!(
                        "{} must have at most {} items (max: {})",
                        field_name,
                        vec.len(),
                        max_len
                    )));
                }
            }
            Ok(())
        }

        pub fn validate_timeout_range(timeout: Option<u64>) -> Result<(), KeyMeldError> {
            if let Some(timeout_val) = timeout {
                if timeout_val == 0 || timeout_val > 86400 {
                    return Err(KeyMeldError::InvalidConfiguration(
                        "Timeout must be between 1 and 86400 seconds".to_string(),
                    ));
                }
            }
            Ok(())
        }
    }

    pub fn generate_session_secret() -> Result<String, KeyMeldError> {
        SecureCrypto::generate_session_secret()
    }

    pub fn validate_encrypted_session_secret(
        encrypted_secret: &str,
        stored_hash: &str,
    ) -> Result<(), KeyMeldError> {
        SecureCrypto::validate_encrypted_session_secret(Some(encrypted_secret), Some(stored_hash))
    }

    pub fn decrypt_signature_with_secret(
        encrypted_signature_hex: &str,
        session_secret: &str,
    ) -> Result<Vec<u8>, KeyMeldError> {
        let encrypted_data = EncryptedData::from_hex_json(encrypted_signature_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex JSON: {e}")))?;

        SecureCrypto::decrypt_signature_data(
            &serde_json::to_value(&encrypted_data).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to serialize encrypted data: {e}"))
            })?,
            session_secret,
        )
    }

    pub fn decrypt_message_with_secret(
        encrypted_message_hex: &str,
        session_secret: &str,
    ) -> Result<String, KeyMeldError> {
        let encrypted_data = EncryptedData::from_hex_json(encrypted_message_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex JSON: {e}")))?;

        let decrypted_bytes = SecureCrypto::decrypt_message_data(
            &serde_json::to_value(&encrypted_data).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to serialize encrypted data: {e}"))
            })?,
            session_secret,
        )?;

        String::from_utf8(decrypted_bytes)
            .map_err(|e| KeyMeldError::CryptoError(format!("Invalid UTF-8: {e}")))
    }

    pub fn validate_session_signature(
        session_id: &str,
        signature_header: &str,
        session_public_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        let (nonce, signature_hex) =
            signature_header
                .split_once(':')
                .ok_or(KeyMeldError::ValidationError(
                    "Invalid signature format, expected 'nonce:signature'".to_string(),
                ))?;

        SecureCrypto::validate_session_signature(
            session_id,
            nonce,
            signature_hex,
            session_public_key,
        )
    }

    pub fn validate_create_keygen_session_request(
        request: &CreateKeygenSessionRequest,
    ) -> Result<(), KeyMeldError> {
        Validator::validate_vec_length(
            &request.coordinator_pubkey,
            Some(33),
            Some(65),
            "Coordinator public key",
        )?;

        Validator::validate_non_empty_string(
            &request.coordinator_encrypted_private_key,
            "Coordinator encrypted private key",
        )?;

        Validator::validate_vec_length(
            &request.expected_participants,
            Some(1),
            Some(1000),
            "Expected participants",
        )?;
        Validator::validate_timeout_range(Some(request.timeout_secs))?;
        Validator::validate_vec_length(
            &request.session_public_key,
            Some(33),
            Some(65),
            "Session public key",
        )?;
        Validator::validate_non_empty_string(
            &request.encrypted_session_secret,
            "Encrypted session secret",
        )?;
        Ok(())
    }

    pub fn validate_register_keygen_participant_request(
        request: &RegisterKeygenParticipantRequest,
        session_signature: &str,
    ) -> Result<(), KeyMeldError> {
        Validator::validate_non_empty_string(
            &request.encrypted_private_key,
            "Encrypted private key",
        )?;
        Validator::validate_non_empty_string(
            &request.encrypted_session_data,
            "Encrypted session data",
        )?;
        Validator::validate_non_empty_string(session_signature, "Session signature")?;
        Ok(())
    }

    pub fn validate_create_signing_session_request(
        request: &CreateSigningSessionRequest,
    ) -> Result<(), KeyMeldError> {
        Validator::validate_vec_length(&request.message_hash, Some(32), Some(32), "Message hash")?;
        if let Some(encrypted_message) = &request.encrypted_message {
            Validator::validate_non_empty_string(encrypted_message, "Encrypted message")?;
        }
        Validator::validate_timeout_range(Some(request.timeout_secs))?;

        if !request.encrypted_adaptor_configs.is_empty() {
            Validator::validate_non_empty_string(
                &request.encrypted_adaptor_configs,
                "Encrypted adaptor configs",
            )?;
        }
        Ok(())
    }

    pub fn decrypt_adaptor_configs(
        encrypted_configs_hex: &str,
        session_secret: &str,
    ) -> Result<Vec<AdaptorConfig>, KeyMeldError> {
        if encrypted_configs_hex.is_empty() {
            return Ok(Vec::new());
        }

        let encrypted_data = EncryptedData::from_hex_json(encrypted_configs_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex JSON: {e}")))?;

        let decrypted_bytes = SecureCrypto::decrypt_adaptor_configs(
            &serde_json::to_value(&encrypted_data).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to serialize encrypted data: {e}"))
            })?,
            session_secret,
        )?;

        serde_json::from_slice(&decrypted_bytes).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to deserialize adaptor configs: {e}"))
        })
    }

    pub fn encrypt_adaptor_configs_for_client(
        configs: &[AdaptorConfig],
        session_secret: &str,
    ) -> Result<String, KeyMeldError> {
        if configs.is_empty() {
            return Ok(String::new());
        }

        let serialized = serde_json::to_vec(configs).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to serialize adaptor configs: {e}"))
        })?;

        let encrypted_data = SecureCrypto::encrypt_adaptor_configs(&serialized, session_secret)?;

        encrypted_data
            .to_hex_json()
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to encode to hex JSON: {e}")))
    }

    pub fn validate_decrypted_adaptor_configs(
        configs: &[AdaptorConfig],
    ) -> Result<(), KeyMeldError> {
        for config in configs {
            match config.adaptor_type {
                AdaptorType::Single => {
                    if config.adaptor_points.len() != 1 {
                        return Err(KeyMeldError::InvalidConfiguration(
                            "Single adaptor requires exactly 1 point".to_string(),
                        ));
                    }
                }
                AdaptorType::And => {
                    if config.adaptor_points.len() < 2 {
                        return Err(KeyMeldError::InvalidConfiguration(
                            "And adaptor requires at least 2 points".to_string(),
                        ));
                    }
                }
                AdaptorType::Or => {
                    if config.adaptor_points.len() < 2 {
                        return Err(KeyMeldError::InvalidConfiguration(
                            "Or adaptor requires at least 2 points".to_string(),
                        ));
                    }
                    if config.hints.is_none() {
                        return Err(KeyMeldError::InvalidConfiguration(
                            "Or adaptor requires hints".to_string(),
                        ));
                    }
                }
            }

            for point_hex in &config.adaptor_points {
                if point_hex.len() != 66 {
                    return Err(KeyMeldError::InvalidConfiguration(
                        "Adaptor point must be 66 hex characters (33 bytes compressed secp256k1)"
                            .to_string(),
                    ));
                }

                let point_bytes = match hex::decode(point_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Err(KeyMeldError::InvalidConfiguration(
                            "Adaptor point must be valid hex".to_string(),
                        ))
                    }
                };

                if point_bytes[0] != 0x02 && point_bytes[0] != 0x03 {
                    return Err(KeyMeldError::InvalidConfiguration(
                        "Adaptor point must be a valid compressed secp256k1 point".to_string(),
                    ));
                }
            }

            if let Some(hints) = &config.hints {
                for hint in hints {
                    match hint {
                        AdaptorHint::Scalar(bytes) => {
                            if bytes.len() != 32 {
                                return Err(KeyMeldError::InvalidConfiguration(
                                    "Scalar hint must be 32 bytes".to_string(),
                                ));
                            }
                        }
                        AdaptorHint::Point(bytes) => {
                            if bytes.len() != 33 {
                                return Err(KeyMeldError::InvalidConfiguration(
                                    "Point hint must be 33 bytes".to_string(),
                                ));
                            }
                            if bytes[0] != 0x02 && bytes[0] != 0x03 {
                                return Err(KeyMeldError::InvalidConfiguration(
                                    "Point hint must be a valid compressed secp256k1 point"
                                        .to_string(),
                                ));
                            }
                        }
                        AdaptorHint::Hash(bytes) => {
                            if bytes.len() != 32 {
                                return Err(KeyMeldError::InvalidConfiguration(
                                    "Hash hint must be 32 bytes".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub fn decrypt_adaptor_signatures_with_secret(
        encrypted_signatures_hex: &str,
        session_secret: &str,
    ) -> Result<Vec<AdaptorSignatureResult>, KeyMeldError> {
        if encrypted_signatures_hex.is_empty() {
            return Ok(Vec::new());
        }

        let encrypted_data = EncryptedData::from_hex_json(encrypted_signatures_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex JSON: {e}")))?;

        let decrypted_bytes = SecureCrypto::decrypt_adaptor_signatures(
            &serde_json::to_value(&encrypted_data).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to serialize encrypted data: {e}"))
            })?,
            session_secret,
        )?;

        serde_json::from_slice(&decrypted_bytes).map_err(|e| {
            KeyMeldError::CryptoError(format!("Failed to deserialize adaptor signatures: {e}"))
        })
    }

    pub fn encrypt_session_data(data: &str, session_secret: &str) -> Result<String, KeyMeldError> {
        let encrypted_data = SecureCrypto::encrypt_session_data(data, session_secret)?;
        encrypted_data
            .to_hex_json()
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to encode hex JSON: {e}")))
    }

    pub fn decrypt_session_data(
        encrypted_data_hex: &str,
        session_secret: &str,
    ) -> Result<String, KeyMeldError> {
        if encrypted_data_hex.is_empty() {
            return Ok(String::new());
        }

        let encrypted_data = EncryptedData::from_hex_json(encrypted_data_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex JSON: {e}")))?;

        SecureCrypto::decrypt_session_data(
            &serde_json::to_value(&encrypted_data).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to serialize encrypted data: {e}"))
            })?,
            session_secret,
        )
    }

    pub fn encrypt_structured_data_with_session_key<T: serde::Serialize>(
        data: &T,
        session_secret: &str,
        context: &str,
    ) -> Result<String, KeyMeldError> {
        let encrypted_data =
            SecureCrypto::encrypt_structured_data_with_session_key(data, session_secret, context)?;
        encrypted_data
            .to_hex_json()
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to encode hex JSON: {e}")))
    }

    pub fn decrypt_structured_data_with_session_key<T: serde::de::DeserializeOwned>(
        encrypted_data_hex: &str,
        session_secret: &str,
        context: &str,
    ) -> Result<T, KeyMeldError> {
        if encrypted_data_hex.is_empty() {
            return Err(KeyMeldError::CryptoError(
                "Empty encrypted data".to_string(),
            ));
        }

        let encrypted_data = EncryptedData::from_hex_json(encrypted_data_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex JSON: {e}")))?;

        SecureCrypto::decrypt_structured_data_with_session_key(
            &serde_json::to_value(&encrypted_data).map_err(|e| {
                KeyMeldError::CryptoError(format!("Failed to serialize encrypted data: {e}"))
            })?,
            session_secret,
            context,
        )
    }

    pub fn encrypt_structured_data_with_enclave_key<T: serde::Serialize>(
        data: &T,
        enclave_public_key_hex: &str,
    ) -> Result<String, KeyMeldError> {
        let encrypted_bytes =
            SecureCrypto::encrypt_structured_data_with_enclave_key(data, enclave_public_key_hex)?;
        Ok(hex::encode(encrypted_bytes))
    }

    pub fn decrypt_structured_data_with_enclave_key<T: serde::de::DeserializeOwned>(
        encrypted_data_hex: &str,
        enclave_private_key: &secp256k1::SecretKey,
    ) -> Result<T, KeyMeldError> {
        if encrypted_data_hex.is_empty() {
            return Err(KeyMeldError::CryptoError(
                "Empty encrypted data".to_string(),
            ));
        }

        let encrypted_bytes = hex::decode(encrypted_data_hex)
            .map_err(|e| KeyMeldError::CryptoError(format!("Failed to decode hex: {e}")))?;

        SecureCrypto::decrypt_structured_data_with_enclave_key(
            &encrypted_bytes,
            enclave_private_key,
        )
    }
}
