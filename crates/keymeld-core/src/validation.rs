use crate::{
    crypto::SecureCrypto,
    protocol::{AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType},
    EncryptedData, KeyMeldError, SessionSecret,
};

pub struct Validator;

impl Validator {
    pub fn validate_non_empty_string(value: &str, field_name: &str) -> Result<(), KeyMeldError> {
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
                    "{field_name} exceeds max {max_len} items"
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
    let encrypted_data = EncryptedData::from_hex(encrypted_signature_hex)?;
    let secret = SessionSecret::from_hex(session_secret)?;
    secret.decrypt(&encrypted_data, "signature")
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

    SecureCrypto::validate_session_signature(session_id, nonce, signature_hex, session_public_key)
}

pub fn decrypt_message_with_secret(
    encrypted_message_hex: &str,
    session_secret: &str,
) -> Result<String, KeyMeldError> {
    let encrypted_data = EncryptedData::from_hex(encrypted_message_hex)?;
    let secret = SessionSecret::from_hex(session_secret)?;
    let decrypted_bytes = secret.decrypt(&encrypted_data, "message")?;
    String::from_utf8(decrypted_bytes)
        .map_err(|e| KeyMeldError::CryptoError(format!("Invalid UTF-8: {e}")))
}

pub fn encrypt_session_data(data: &str, session_secret: &str) -> Result<String, KeyMeldError> {
    let secret = SessionSecret::from_hex(session_secret)?;
    let encrypted_data = secret.encrypt(data.as_bytes(), "session_data")?;
    encrypted_data.to_hex()
}

/// Encrypt session data and return as JSON (for single-signer signing)
pub fn encrypt_session_data_json(data: &str, session_secret: &str) -> Result<String, KeyMeldError> {
    let secret = SessionSecret::from_hex(session_secret)?;
    let encrypted_data = secret.encrypt(data.as_bytes(), "message")?;
    serde_json::to_string(&encrypted_data).map_err(|e| {
        KeyMeldError::SerializationError(format!("Failed to serialize EncryptedData: {}", e))
    })
}

pub fn decrypt_session_data(
    encrypted_data_hex: &str,
    session_secret: &str,
) -> Result<String, KeyMeldError> {
    if encrypted_data_hex.is_empty() {
        return Ok(String::new());
    }

    let encrypted_data = EncryptedData::from_hex(encrypted_data_hex)?;
    let secret = SessionSecret::from_hex(session_secret)?;
    let decrypted_bytes = secret.decrypt(&encrypted_data, "session_data")?;
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
) -> Result<String, KeyMeldError> {
    let secret = SessionSecret::from_hex(session_secret)?;
    let encrypted_data = secret.encrypt_value(data, context)?;
    encrypted_data.to_hex()
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

    let encrypted_data = EncryptedData::from_hex(encrypted_data_hex)?;
    let secret = SessionSecret::from_hex(session_secret)?;
    secret.decrypt_value(&encrypted_data, context)
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

    SecureCrypto::decrypt_structured_data_with_enclave_key(&encrypted_bytes, enclave_private_key)
}

pub fn decrypt_adaptor_configs(
    encrypted_configs_hex: &str,
    session_secret: &str,
) -> Result<Vec<AdaptorConfig>, KeyMeldError> {
    if encrypted_configs_hex.is_empty() {
        return Ok(Vec::new());
    }

    let encrypted_data = EncryptedData::from_hex(encrypted_configs_hex)?;
    let secret = SessionSecret::from_hex(session_secret)?;
    let decrypted_bytes = secret.decrypt(&encrypted_data, "adaptor_configs")?;

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

    let secret = SessionSecret::from_hex(session_secret)?;
    let encrypted_data = secret.encrypt(&serialized, "adaptor_configs")?;
    encrypted_data.to_hex()
}

pub fn validate_decrypted_adaptor_configs(configs: &[AdaptorConfig]) -> Result<(), KeyMeldError> {
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
                                "Point hint must be a valid compressed secp256k1 point".to_string(),
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
) -> Result<std::collections::BTreeMap<uuid::Uuid, AdaptorSignatureResult>, KeyMeldError> {
    if encrypted_signatures_hex.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }

    let encrypted_data = EncryptedData::from_hex(encrypted_signatures_hex)?;
    let secret = SessionSecret::from_hex(session_secret)?;
    let decrypted_bytes = secret.decrypt(&encrypted_data, "adaptor_signatures")?;

    serde_json::from_slice(&decrypted_bytes).map_err(|e| {
        KeyMeldError::CryptoError(format!("Failed to deserialize adaptor signatures: {e}"))
    })
}
