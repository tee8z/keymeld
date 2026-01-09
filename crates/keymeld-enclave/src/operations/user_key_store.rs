//! User Key Store - In-memory storage for user private keys in the enclave
//!
//! This module provides secure storage for user private keys that are:
//! - Imported directly by users (encrypted to enclave's ECIES public key)
//! - Persisted from completed keygen sessions
//!
//! Keys are stored decrypted in enclave memory for signing operations.
//! For persistence, keys are re-encrypted to the enclave's ECIES public key.

use dashmap::DashMap;
use keymeld_core::{
    crypto::SecureCrypto,
    identifiers::{KeyId, SessionId, UserId},
    protocol::{CryptoError, EnclaveError},
    KeyMaterial,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use super::enclave_context::EnclaveSharedContext;

/// Entry for a stored user key
#[derive(Debug, Clone)]
pub struct UserKeyEntry {
    pub key_id: KeyId,
    pub user_id: UserId,
    /// Decrypted private key, stored in enclave memory only
    pub private_key: KeyMaterial,
    /// Public key derived from private key (never leaves enclave)
    pub public_key: Vec<u8>,
    /// Auth public key for request authentication (immutable)
    pub auth_pubkey: Vec<u8>,
    /// None = imported, Some = from keygen session
    pub origin_keygen_session_id: Option<SessionId>,
    /// Creation timestamp
    pub created_at: u64,
}

/// In-memory store for user keys (decrypted for use, re-encrypted for persistence)
#[derive(Debug, Default)]
pub struct UserKeyStore {
    /// Keys indexed by (user_id, key_id)
    keys: DashMap<(UserId, KeyId), UserKeyEntry>,
}

impl UserKeyStore {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
        }
    }

    /// Store a key that was decrypted from an ECIES-encrypted import
    pub fn store_key(
        &self,
        user_id: UserId,
        key_id: KeyId,
        private_key: KeyMaterial,
        auth_pubkey: Vec<u8>,
        origin_keygen_session_id: Option<SessionId>,
        created_at: u64,
    ) -> Result<Vec<u8>, EnclaveError> {
        // Derive the public key from the private key
        let secp = Secp256k1::new();
        let secret_key =
            SecretKey::from_byte_array(private_key.as_bytes().try_into().map_err(|_| {
                EnclaveError::Crypto(CryptoError::Other("Invalid private key length".to_string()))
            })?)
            .map_err(|e| {
                EnclaveError::Crypto(CryptoError::Other(format!("Invalid private key: {}", e)))
            })?;

        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes = public_key.serialize().to_vec();

        let entry = UserKeyEntry {
            key_id: key_id.clone(),
            user_id: user_id.clone(),
            private_key,
            public_key: public_key_bytes.clone(),
            auth_pubkey,
            origin_keygen_session_id,
            created_at,
        };

        self.keys.insert((user_id, key_id), entry);

        Ok(public_key_bytes)
    }

    /// Get a key by user_id and key_id
    pub fn get_key(&self, user_id: &UserId, key_id: &KeyId) -> Option<UserKeyEntry> {
        self.keys
            .get(&(user_id.clone(), key_id.clone()))
            .map(|r| r.clone())
    }

    /// List all keys for a user (returns metadata only, no private keys)
    pub fn list_user_keys(&self, user_id: &UserId) -> Vec<UserKeyInfo> {
        self.keys
            .iter()
            .filter(|entry| &entry.key().0 == user_id)
            .map(|entry| UserKeyInfo {
                key_id: entry.value().key_id.clone(),
                user_id: entry.value().user_id.clone(),
                origin_keygen_session_id: entry.value().origin_keygen_session_id.clone(),
                created_at: entry.value().created_at,
            })
            .collect()
    }

    /// Delete a key
    pub fn delete_key(&self, user_id: &UserId, key_id: &KeyId) -> bool {
        self.keys
            .remove(&(user_id.clone(), key_id.clone()))
            .is_some()
    }

    /// Check if a key exists
    pub fn has_key(&self, user_id: &UserId, key_id: &KeyId) -> bool {
        self.keys.contains_key(&(user_id.clone(), key_id.clone()))
    }

    /// Get all keys for an enclave (for persistence export)
    /// Returns entries that need to be re-encrypted for storage
    pub fn get_all_keys(&self) -> Vec<UserKeyEntry> {
        self.keys
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Export a key for persistence (re-encrypt to enclave's ECIES public key)
    pub fn export_key_for_persistence(
        &self,
        user_id: &UserId,
        key_id: &KeyId,
        enclave_ctx: &EnclaveSharedContext,
    ) -> Result<EncryptedUserKeyRecord, EnclaveError> {
        let entry = self.get_key(user_id, key_id).ok_or_else(|| {
            EnclaveError::Crypto(CryptoError::Other(format!(
                "Key not found: {}:{}",
                user_id, key_id
            )))
        })?;

        // Re-encrypt the private key to the enclave's public key
        let enclave_pubkey_hex = hex::encode(&enclave_ctx.public_key);
        let encrypted_private_key =
            SecureCrypto::ecies_encrypt_from_hex(&enclave_pubkey_hex, entry.private_key.as_bytes())
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!(
                        "Failed to encrypt key: {}",
                        e
                    )))
                })?;

        Ok(EncryptedUserKeyRecord {
            user_id: entry.user_id,
            key_id: entry.key_id,
            encrypted_private_key,
            auth_pubkey: entry.auth_pubkey,
            origin_keygen_session_id: entry.origin_keygen_session_id,
            created_at: entry.created_at,
        })
    }

    /// Restore a key from an encrypted record (decrypt from ECIES)
    pub fn restore_key(
        &self,
        record: &EncryptedUserKeyRecord,
        enclave_ctx: &EnclaveSharedContext,
    ) -> Result<(), EnclaveError> {
        // Parse the enclave's private key
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

        // Decrypt the private key using enclave's private key
        let private_key_bytes =
            SecureCrypto::ecies_decrypt(&enclave_secret_key, &record.encrypted_private_key)
                .map_err(|e| {
                    EnclaveError::Crypto(CryptoError::Other(format!(
                        "Failed to decrypt key: {}",
                        e
                    )))
                })?;

        let private_key = KeyMaterial::new(private_key_bytes);

        self.store_key(
            record.user_id.clone(),
            record.key_id.clone(),
            private_key,
            record.auth_pubkey.clone(),
            record.origin_keygen_session_id.clone(),
            record.created_at,
        )?;

        Ok(())
    }

    /// Get count of stored keys
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Key info returned to users (no private/public keys for privacy)
#[derive(Debug, Clone)]
pub struct UserKeyInfo {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub origin_keygen_session_id: Option<SessionId>,
    pub created_at: u64,
}

/// Encrypted key record for persistence
#[derive(Debug, Clone)]
pub struct EncryptedUserKeyRecord {
    pub user_id: UserId,
    pub key_id: KeyId,
    /// Private key ECIES encrypted to enclave's public key
    pub encrypted_private_key: Vec<u8>,
    /// Auth public key (not encrypted, used for request validation)
    pub auth_pubkey: Vec<u8>,
    /// Origin keygen session if from keygen
    pub origin_keygen_session_id: Option<SessionId>,
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve_key() {
        let store = UserKeyStore::new();
        let user_id = UserId::new_v7();
        let key_id = KeyId::new_v7();

        // Generate a valid secp256k1 private key
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::rng());
        let private_key = KeyMaterial::new(secret_key.secret_bytes().to_vec());

        let auth_pubkey = vec![1, 2, 3, 4];
        let created_at = 1234567890u64;

        let public_key = store
            .store_key(
                user_id.clone(),
                key_id.clone(),
                private_key.clone(),
                auth_pubkey.clone(),
                None,
                created_at,
            )
            .expect("Should store key");

        assert_eq!(public_key.len(), 33); // Compressed public key

        let retrieved = store.get_key(&user_id, &key_id).expect("Should find key");
        assert_eq!(retrieved.key_id, key_id);
        assert_eq!(retrieved.user_id, user_id);
        assert_eq!(retrieved.auth_pubkey, auth_pubkey);
        assert_eq!(retrieved.created_at, created_at);
        assert!(retrieved.origin_keygen_session_id.is_none());
    }

    #[test]
    fn test_list_user_keys() {
        let store = UserKeyStore::new();
        let user_id = UserId::new_v7();
        let secp = Secp256k1::new();

        // Store two keys for the same user
        for _ in 0..2 {
            let key_id = KeyId::new_v7();
            let (secret_key, _) = secp.generate_keypair(&mut rand::rng());
            let private_key = KeyMaterial::new(secret_key.secret_bytes().to_vec());
            store
                .store_key(user_id.clone(), key_id, private_key, vec![], None, 0)
                .unwrap();
        }

        let keys = store.list_user_keys(&user_id);
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_delete_key() {
        let store = UserKeyStore::new();
        let user_id = UserId::new_v7();
        let key_id = KeyId::new_v7();
        let secp = Secp256k1::new();
        let (secret_key, _) = secp.generate_keypair(&mut rand::rng());
        let private_key = KeyMaterial::new(secret_key.secret_bytes().to_vec());

        store
            .store_key(
                user_id.clone(),
                key_id.clone(),
                private_key,
                vec![],
                None,
                0,
            )
            .unwrap();

        assert!(store.has_key(&user_id, &key_id));
        assert!(store.delete_key(&user_id, &key_id));
        assert!(!store.has_key(&user_id, &key_id));
    }
}
