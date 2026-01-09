//! User Key Command Handler
//!
//! Handles UserKeyCommand dispatching for:
//! - ImportKey: Decrypt ECIES-encrypted private key, validate secp256k1, store in memory
//! - SignSingle: Sign a message with a stored key (Schnorr/ECDSA)
//! - ListKeys: Return key metadata (no public keys)
//! - DeleteKey: Remove from memory
//! - StoreFromKeygen: Copy key from keygen session to UserKeyStore
//! - RestoreKey: Restore key from encrypted persistence record

use keymeld_core::{
    crypto::{SecureCrypto, SessionSecret},
    identifiers::SessionId,
    protocol::{
        CryptoError, DeleteUserKeyCommand, EnclaveError, ImportUserKeyCommand, KeyDeletedResponse,
        KeyImportedResponse, KeyListResponse, KeyRestoredResponse, KeyStoredFromKeygenResponse,
        ListUserKeysCommand, RestoreUserKeyCommand, SignSingleCommand, SignatureType,
        SingleSignatureResponse, StoreKeyFromKeygenCommand, UserKeyCommand, UserKeyInfo,
        UserKeyOutcome, ValidationError,
    },
    KeyMaterial,
};
use secp256k1::{ecdsa::Signature as EcdsaSignature, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::{
    enclave_context::EnclaveSharedContext,
    user_key_store::{EncryptedUserKeyRecord, UserKeyStore},
};
use crate::musig::MusigProcessor;

/// Handle a UserKeyCommand and return the appropriate outcome
pub async fn handle_user_key_command(
    cmd: UserKeyCommand,
    user_key_store: &UserKeyStore,
    enclave_ctx: &EnclaveSharedContext,
    keygen_sessions: Option<&dashmap::DashMap<SessionId, Arc<MusigProcessor>>>,
) -> Result<UserKeyOutcome, EnclaveError> {
    match cmd {
        UserKeyCommand::ImportKey(import_cmd) => {
            handle_import_key(import_cmd, user_key_store, enclave_ctx).await
        }
        UserKeyCommand::SignSingle(sign_cmd) => {
            handle_sign_single(sign_cmd, user_key_store, enclave_ctx).await
        }
        UserKeyCommand::ListKeys(list_cmd) => handle_list_keys(list_cmd, user_key_store).await,
        UserKeyCommand::DeleteKey(delete_cmd) => {
            handle_delete_key(delete_cmd, user_key_store).await
        }
        UserKeyCommand::StoreKeyFromKeygen(store_cmd) => {
            handle_store_from_keygen(store_cmd, user_key_store, keygen_sessions, enclave_ctx).await
        }
        UserKeyCommand::RestoreKey(restore_cmd) => {
            handle_restore_key(restore_cmd, user_key_store, enclave_ctx).await
        }
    }
}

/// Handle ImportUserKeyCommand - decrypt ECIES-encrypted private key and store
async fn handle_import_key(
    cmd: ImportUserKeyCommand,
    user_key_store: &UserKeyStore,
    enclave_ctx: &EnclaveSharedContext,
) -> Result<UserKeyOutcome, EnclaveError> {
    info!("Importing key {} for user {}", cmd.key_id, cmd.user_id);

    // Parse the enclave's private key for ECIES decryption
    let enclave_secret_key = SecretKey::from_byte_array(
        enclave_ctx.private_key.as_slice().try_into().map_err(|_| {
            EnclaveError::Crypto(CryptoError::Other(
                "Invalid enclave private key length".to_string(),
            ))
        })?,
    )
    .map_err(|e| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Invalid enclave private key: {}",
            e
        )))
    })?;

    // Decrypt the private key from ECIES ciphertext
    let encrypted_bytes = hex::decode(&cmd.encrypted_private_key).map_err(|e| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Invalid hex in encrypted_private_key: {}",
            e
        )))
    })?;

    let private_key_bytes = SecureCrypto::ecies_decrypt(&enclave_secret_key, &encrypted_bytes)
        .map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to decrypt private key: {}",
                e
            )))
        })?;

    // Validate it's a valid secp256k1 private key
    if private_key_bytes.len() != 32 {
        return Err(EnclaveError::Crypto(CryptoError::Other(format!(
            "Invalid private key length: expected 32, got {}",
            private_key_bytes.len()
        ))));
    }

    let private_key = KeyMaterial::new(private_key_bytes);

    // Get current timestamp
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Store the key
    let _public_key = user_key_store.store_key(
        cmd.user_id.clone(),
        cmd.key_id.clone(),
        private_key,
        cmd.auth_pubkey,
        None, // No origin keygen session for imported keys
        created_at,
    )?;

    info!(
        "Successfully imported key {} for user {}",
        cmd.key_id, cmd.user_id
    );

    Ok(UserKeyOutcome::KeyImported(KeyImportedResponse {
        user_id: cmd.user_id,
        key_id: cmd.key_id,
    }))
}

const MAX_APPROVAL_TIMESTAMP_AGE_SECS: u64 = 300;

/// Format: ECDSA(auth_privkey, SHA256(encrypted_message || key_id || timestamp))
fn validate_approval_signature(
    cmd: &SignSingleCommand,
    auth_pubkey: &[u8],
) -> Result<(), EnclaveError> {
    let secp = Secp256k1::new();

    // Check timestamp freshness
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if current_time > cmd.approval_timestamp
        && current_time - cmd.approval_timestamp > MAX_APPROVAL_TIMESTAMP_AGE_SECS
    {
        return Err(EnclaveError::Validation(ValidationError::Other(format!(
            "Approval signature has expired (age: {}s, max: {}s)",
            current_time - cmd.approval_timestamp,
            MAX_APPROVAL_TIMESTAMP_AGE_SECS
        ))));
    }

    let mut hasher = Sha256::new();
    hasher.update(cmd.encrypted_message.as_bytes());
    hasher.update(cmd.key_id.to_string().as_bytes());
    hasher.update(cmd.approval_timestamp.to_le_bytes());
    let approval_hash = hasher.finalize();

    // Parse the auth public key
    let pubkey = PublicKey::from_slice(auth_pubkey).map_err(|e| {
        EnclaveError::Validation(ValidationError::Other(format!(
            "Invalid auth_pubkey for key {}: {}",
            cmd.key_id, e
        )))
    })?;

    // Parse the approval signature (ECDSA compact format)
    let signature = EcdsaSignature::from_compact(&cmd.approval_signature).map_err(|e| {
        EnclaveError::Validation(ValidationError::Other(format!(
            "Invalid approval signature format for key {}: {}",
            cmd.key_id, e
        )))
    })?;

    // Create the message for verification
    let approval_hash_array: [u8; 32] = approval_hash.as_slice().try_into().map_err(|_| {
        EnclaveError::Validation(ValidationError::Other(
            "Approval hash is not 32 bytes".to_string(),
        ))
    })?;
    let msg = Message::from_digest(approval_hash_array);

    // Verify the signature
    secp.verify_ecdsa(msg, &signature, &pubkey).map_err(|e| {
        warn!(
            "Approval signature verification failed for key {}: {}",
            cmd.key_id, e
        );
        EnclaveError::Validation(ValidationError::Other(format!(
            "Invalid approval signature for key {}: signature verification failed",
            cmd.key_id
        )))
    })?;

    debug!(
        "Verified approval signature for single-signer key {}",
        cmd.key_id
    );

    Ok(())
}

/// Handle SignSingleCommand - sign a message with a stored key
async fn handle_sign_single(
    cmd: SignSingleCommand,
    user_key_store: &UserKeyStore,
    enclave_ctx: &EnclaveSharedContext,
) -> Result<UserKeyOutcome, EnclaveError> {
    debug!(
        "Single-signer signing for key {} user {}",
        cmd.key_id, cmd.user_id
    );

    // Get the stored key
    let key_entry = user_key_store
        .get_key(&cmd.user_id, &cmd.key_id)
        .ok_or_else(|| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Key not found: {}:{}",
                cmd.user_id, cmd.key_id
            )))
        })?;

    // Validate the approval signature before proceeding
    validate_approval_signature(&cmd, &key_entry.auth_pubkey)?;

    // Parse the enclave's private key to decrypt the session secret
    let enclave_secret_key = SecretKey::from_byte_array(
        enclave_ctx.private_key.as_slice().try_into().map_err(|_| {
            EnclaveError::Crypto(CryptoError::Other(
                "Invalid enclave private key length".to_string(),
            ))
        })?,
    )
    .map_err(|e| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Invalid enclave private key: {}",
            e
        )))
    })?;

    // Decrypt the session secret
    let encrypted_session_secret = hex::decode(&cmd.encrypted_session_secret).map_err(|e| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Invalid hex in encrypted_session_secret: {}",
            e
        )))
    })?;

    let session_secret_bytes =
        SecureCrypto::ecies_decrypt(&enclave_secret_key, &encrypted_session_secret).map_err(
            |e| {
                EnclaveError::Crypto(CryptoError::Other(format!(
                    "Failed to decrypt session secret: {}",
                    e
                )))
            },
        )?;

    let session_secret_array: [u8; 32] = session_secret_bytes.try_into().map_err(|_| {
        EnclaveError::Crypto(CryptoError::Other(
            "Session secret must be 32 bytes".to_string(),
        ))
    })?;
    let session_secret = SessionSecret::from_bytes(session_secret_array);

    // Decrypt the message using the session secret
    // The encrypted_message is hex-encoded EncryptedData
    let message_hex = keymeld_core::validation::decrypt_session_data(
        &cmd.encrypted_message,
        &hex::encode(session_secret.as_bytes()),
    )
    .map_err(|e| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Failed to decrypt message: {}",
            e
        )))
    })?;

    let message_bytes = hex::decode(&message_hex).map_err(|e| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Invalid hex in decrypted message: {}",
            e
        )))
    })?;

    // Parse the user's private key
    let user_secret_key =
        SecretKey::from_byte_array(key_entry.private_key.as_bytes().try_into().map_err(|_| {
            EnclaveError::Crypto(CryptoError::Other(
                "Invalid stored private key length".to_string(),
            ))
        })?)
        .map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Invalid stored private key: {}",
                e
            )))
        })?;

    // Sign the message based on signature type
    let secp = Secp256k1::new();
    let signature_bytes = match cmd.signature_type {
        SignatureType::SchnorrBip340 => {
            // BIP-340 Schnorr signature
            let keypair = secp256k1::Keypair::from_secret_key(&secp, &user_secret_key);

            // Hash the message for signing (BIP-340 expects 32-byte message)
            let message_hash: [u8; 32] = if message_bytes.len() == 32 {
                message_bytes.clone().try_into().map_err(|_| {
                    EnclaveError::Crypto(CryptoError::Other("Message must be 32 bytes".to_string()))
                })?
            } else {
                Sha256::digest(&message_bytes).into()
            };

            // sign_schnorr in 0.31.x takes &[u8] directly
            let sig = secp.sign_schnorr(&message_hash, &keypair);
            sig.to_byte_array().to_vec()
        }
        SignatureType::Ecdsa => {
            // ECDSA signature
            let message_hash: [u8; 32] = if message_bytes.len() == 32 {
                message_bytes.clone().try_into().map_err(|_| {
                    EnclaveError::Crypto(CryptoError::Other("Message must be 32 bytes".to_string()))
                })?
            } else {
                Sha256::digest(&message_bytes).into()
            };

            let msg = Message::from_digest(message_hash);

            // sign_ecdsa in 0.31.x takes impl Into<Message>, so pass msg not &msg
            let sig: EcdsaSignature = secp.sign_ecdsa(msg, &user_secret_key);
            sig.serialize_compact().to_vec()
        }
    };

    // Encrypt the signature with the session secret using "signature" context
    // so client can decrypt with decrypt_signature_with_secret()
    let encrypted_signature = session_secret
        .encrypt(&signature_bytes, "signature")
        .map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to encrypt signature: {}",
                e
            )))
        })?;

    debug!(
        "Successfully signed message for key {} (type: {:?})",
        cmd.key_id, cmd.signature_type
    );

    Ok(UserKeyOutcome::SingleSignature(SingleSignatureResponse {
        user_id: cmd.user_id,
        key_id: cmd.key_id,
        encrypted_signature: encrypted_signature.to_hex().map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Failed to hex-encode encrypted signature: {}",
                e
            )))
        })?,
        signature_type: cmd.signature_type,
    }))
}

/// Handle ListUserKeysCommand - return key metadata for a user
async fn handle_list_keys(
    cmd: ListUserKeysCommand,
    user_key_store: &UserKeyStore,
) -> Result<UserKeyOutcome, EnclaveError> {
    let keys = user_key_store.list_user_keys(&cmd.user_id);

    let key_infos: Vec<UserKeyInfo> = keys
        .into_iter()
        .map(|k| UserKeyInfo {
            key_id: k.key_id,
            user_id: k.user_id,
            origin_keygen_session_id: k.origin_keygen_session_id,
            created_at: k.created_at,
        })
        .collect();

    Ok(UserKeyOutcome::KeyList(KeyListResponse {
        user_id: cmd.user_id,
        keys: key_infos,
    }))
}

/// Handle DeleteUserKeyCommand - remove a key from the store
async fn handle_delete_key(
    cmd: DeleteUserKeyCommand,
    user_key_store: &UserKeyStore,
) -> Result<UserKeyOutcome, EnclaveError> {
    let deleted = user_key_store.delete_key(&cmd.user_id, &cmd.key_id);

    if deleted {
        info!("Deleted key {} for user {}", cmd.key_id, cmd.user_id);
    } else {
        warn!(
            "Key {} for user {} not found for deletion",
            cmd.key_id, cmd.user_id
        );
    }

    Ok(UserKeyOutcome::KeyDeleted(KeyDeletedResponse {
        user_id: cmd.user_id,
        key_id: cmd.key_id,
    }))
}

/// Handle StoreKeyFromKeygenCommand - copy key from keygen session to UserKeyStore
async fn handle_store_from_keygen(
    cmd: StoreKeyFromKeygenCommand,
    user_key_store: &UserKeyStore,
    keygen_sessions: Option<&dashmap::DashMap<SessionId, Arc<MusigProcessor>>>,
    enclave_ctx: &EnclaveSharedContext,
) -> Result<UserKeyOutcome, EnclaveError> {
    let keygen_sessions = keygen_sessions.ok_or_else(|| {
        EnclaveError::Crypto(CryptoError::Other(
            "Keygen sessions not available".to_string(),
        ))
    })?;

    // Get the keygen session
    let processor = keygen_sessions.get(&cmd.keygen_session_id).ok_or_else(|| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "Keygen session not found: {}",
            cmd.keygen_session_id
        )))
    })?;

    // Get the user's session data from the processor
    let user_session = processor
        .get_user_session_data(&cmd.user_id)
        .ok_or_else(|| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "User {} not found in keygen session {}",
                cmd.user_id, cmd.keygen_session_id
            )))
        })?;

    // Get the private key from the user session
    let private_key = user_session.private_key.clone().ok_or_else(|| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "No private key available for user {} in keygen session {}",
            cmd.user_id, cmd.keygen_session_id
        )))
    })?;

    // Get the auth_pubkey from the keygen session
    let auth_pubkey = user_session.auth_pubkey.clone().ok_or_else(|| {
        EnclaveError::Crypto(CryptoError::Other(format!(
            "No auth_pubkey available for user {} in keygen session {}",
            cmd.user_id, cmd.keygen_session_id
        )))
    })?;

    // Get current timestamp
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Store the key with origin keygen session reference
    user_key_store.store_key(
        cmd.user_id.clone(),
        cmd.key_id.clone(),
        private_key,
        auth_pubkey,
        Some(cmd.keygen_session_id.clone()),
        created_at,
    )?;

    // Export the key for gateway persistence
    let encrypted_record =
        user_key_store.export_key_for_persistence(&cmd.user_id, &cmd.key_id, enclave_ctx)?;

    info!(
        "Stored key {} from keygen session {} for user {}",
        cmd.key_id, cmd.keygen_session_id, cmd.user_id
    );

    Ok(UserKeyOutcome::KeyStoredFromKeygen(
        KeyStoredFromKeygenResponse {
            user_id: cmd.user_id,
            key_id: cmd.key_id,
            keygen_session_id: cmd.keygen_session_id,
            encrypted_private_key: hex::encode(&encrypted_record.encrypted_private_key),
        },
    ))
}

/// Handle RestoreUserKeyCommand - restore key from encrypted persistence record
async fn handle_restore_key(
    cmd: RestoreUserKeyCommand,
    user_key_store: &UserKeyStore,
    enclave_ctx: &EnclaveSharedContext,
) -> Result<UserKeyOutcome, EnclaveError> {
    let record = EncryptedUserKeyRecord {
        user_id: cmd.user_id.clone(),
        key_id: cmd.key_id.clone(),
        encrypted_private_key: hex::decode(&cmd.encrypted_private_key).map_err(|e| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Invalid hex in encrypted_private_key: {}",
                e
            )))
        })?,
        auth_pubkey: cmd.auth_pubkey,
        origin_keygen_session_id: cmd.origin_keygen_session_id.clone(),
        created_at: cmd.created_at,
    };

    user_key_store.restore_key(&record, enclave_ctx)?;

    info!(
        "Restored key {} for user {} (from keygen: {:?})",
        cmd.key_id, cmd.user_id, cmd.origin_keygen_session_id
    );

    Ok(UserKeyOutcome::KeyRestored(KeyRestoredResponse {
        user_id: cmd.user_id,
        key_id: cmd.key_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymeld_core::{identifiers::KeyId, UserId};

    /// Create a valid approval signature for testing
    fn create_approval_signature(
        auth_secret_key: &SecretKey,
        encrypted_message: &str,
        key_id: &KeyId,
        timestamp: u64,
    ) -> Vec<u8> {
        let secp = Secp256k1::new();

        // Construct the approval hash: SHA256(encrypted_message || key_id || timestamp)
        let mut hasher = Sha256::new();
        hasher.update(encrypted_message.as_bytes());
        hasher.update(key_id.to_string().as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let approval_hash = hasher.finalize();

        let approval_hash_array: [u8; 32] = approval_hash.as_slice().try_into().unwrap();
        let msg = Message::from_digest(approval_hash_array);

        let sig = secp.sign_ecdsa(msg, auth_secret_key);
        sig.serialize_compact().to_vec()
    }

    #[test]
    fn test_validate_approval_signature_success() {
        let secp = Secp256k1::new();
        let (auth_secret_key, auth_public_key) = secp.generate_keypair(&mut rand::rng());
        let auth_pubkey = auth_public_key.serialize().to_vec();

        let key_id = KeyId::new_v7();
        let encrypted_message = r#"{"nonce":"abc","ciphertext":"def"}"#.to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let approval_signature =
            create_approval_signature(&auth_secret_key, &encrypted_message, &key_id, timestamp);

        let cmd = SignSingleCommand {
            user_id: UserId::new_v7(),
            key_id,
            encrypted_message,
            signature_type: SignatureType::SchnorrBip340,
            encrypted_session_secret: "dummy".to_string(),
            approval_signature,
            approval_timestamp: timestamp,
        };

        let result = validate_approval_signature(&cmd, &auth_pubkey);
        assert!(
            result.is_ok(),
            "Valid approval signature should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_approval_signature_expired() {
        let secp = Secp256k1::new();
        let (auth_secret_key, auth_public_key) = secp.generate_keypair(&mut rand::rng());
        let auth_pubkey = auth_public_key.serialize().to_vec();

        let key_id = KeyId::new_v7();
        let encrypted_message = r#"{"nonce":"abc","ciphertext":"def"}"#.to_string();
        // Use a timestamp from 10 minutes ago (expired)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;

        let approval_signature =
            create_approval_signature(&auth_secret_key, &encrypted_message, &key_id, timestamp);

        let cmd = SignSingleCommand {
            user_id: UserId::new_v7(),
            key_id,
            encrypted_message,
            signature_type: SignatureType::SchnorrBip340,
            encrypted_session_secret: "dummy".to_string(),
            approval_signature,
            approval_timestamp: timestamp,
        };

        let result = validate_approval_signature(&cmd, &auth_pubkey);
        assert!(result.is_err(), "Expired approval should fail");
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("expired"),
            "Error should mention expiration: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_approval_signature_wrong_key() {
        let secp = Secp256k1::new();
        let (auth_secret_key, _) = secp.generate_keypair(&mut rand::rng());
        // Use a different public key than the one that signed
        let (_, wrong_public_key) = secp.generate_keypair(&mut rand::rng());
        let wrong_auth_pubkey = wrong_public_key.serialize().to_vec();

        let key_id = KeyId::new_v7();
        let encrypted_message = r#"{"nonce":"abc","ciphertext":"def"}"#.to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let approval_signature =
            create_approval_signature(&auth_secret_key, &encrypted_message, &key_id, timestamp);

        let cmd = SignSingleCommand {
            user_id: UserId::new_v7(),
            key_id,
            encrypted_message,
            signature_type: SignatureType::SchnorrBip340,
            encrypted_session_secret: "dummy".to_string(),
            approval_signature,
            approval_timestamp: timestamp,
        };

        let result = validate_approval_signature(&cmd, &wrong_auth_pubkey);
        assert!(result.is_err(), "Wrong public key should fail verification");
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("verification failed"),
            "Error should mention verification failure: {:?}",
            err
        );
    }

    #[test]
    fn test_validate_approval_signature_tampered_message() {
        let secp = Secp256k1::new();
        let (auth_secret_key, auth_public_key) = secp.generate_keypair(&mut rand::rng());
        let auth_pubkey = auth_public_key.serialize().to_vec();

        let key_id = KeyId::new_v7();
        let encrypted_message = r#"{"nonce":"abc","ciphertext":"def"}"#.to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Sign with original message
        let approval_signature =
            create_approval_signature(&auth_secret_key, &encrypted_message, &key_id, timestamp);

        // But send a different message
        let tampered_message = r#"{"nonce":"abc","ciphertext":"TAMPERED"}"#.to_string();

        let cmd = SignSingleCommand {
            user_id: UserId::new_v7(),
            key_id,
            encrypted_message: tampered_message,
            signature_type: SignatureType::SchnorrBip340,
            encrypted_session_secret: "dummy".to_string(),
            approval_signature,
            approval_timestamp: timestamp,
        };

        let result = validate_approval_signature(&cmd, &auth_pubkey);
        assert!(result.is_err(), "Tampered message should fail verification");
    }

    #[test]
    fn test_validate_approval_signature_invalid_format() {
        let secp = Secp256k1::new();
        let (_, auth_public_key) = secp.generate_keypair(&mut rand::rng());
        let auth_pubkey = auth_public_key.serialize().to_vec();

        let key_id = KeyId::new_v7();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let cmd = SignSingleCommand {
            user_id: UserId::new_v7(),
            key_id,
            encrypted_message: "test".to_string(),
            signature_type: SignatureType::SchnorrBip340,
            encrypted_session_secret: "dummy".to_string(),
            approval_signature: vec![1, 2, 3], // Invalid signature format
            approval_timestamp: timestamp,
        };

        let result = validate_approval_signature(&cmd, &auth_pubkey);
        assert!(result.is_err(), "Invalid signature format should fail");
        let err = result.unwrap_err();
        assert!(
            format!("{:?}", err).contains("Invalid approval signature format"),
            "Error should mention invalid format: {:?}",
            err
        );
    }
}
