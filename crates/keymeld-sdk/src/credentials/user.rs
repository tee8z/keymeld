use crate::error::{CryptoError, SdkError};
use keymeld_core::crypto::SecureCrypto;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

pub struct UserCredentials {
    private_key: SecretKey,
    public_key: PublicKey,
    auth_private_key: SecretKey,
    auth_public_key: PublicKey,
}

impl UserCredentials {
    pub fn from_private_key(private_key: &[u8]) -> Result<Self, SdkError> {
        let private_key_array: [u8; 32] = private_key.try_into().map_err(|_| {
            SdkError::Crypto(CryptoError::InvalidKeyFormat(
                "Private key must be 32 bytes".to_string(),
            ))
        })?;

        let secp = Secp256k1::new();
        let private_key = SecretKey::from_byte_array(private_key_array)
            .map_err(|e| SdkError::Crypto(CryptoError::InvalidKeyFormat(e.to_string())))?;
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        let (auth_private_key, auth_public_key) =
            SecureCrypto::derive_session_auth_keypair(&private_key_array, "single_signer_auth")
                .map_err(|e| SdkError::Crypto(CryptoError::KeyDerivationFailed(e.to_string())))?;

        Ok(Self {
            private_key,
            public_key,
            auth_private_key,
            auth_public_key,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.serialize().to_vec()
    }

    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.private_key.secret_bytes()
    }

    pub fn auth_public_key(&self) -> &PublicKey {
        &self.auth_public_key
    }

    pub fn auth_public_key_bytes(&self) -> Vec<u8> {
        self.auth_public_key.serialize().to_vec()
    }

    pub fn encrypt_private_key_for_enclave(
        &self,
        enclave_public_key_hex: &str,
    ) -> Result<String, SdkError> {
        let encrypted =
            SecureCrypto::ecies_encrypt_from_hex(enclave_public_key_hex, &self.private_key_bytes())
                .map_err(|e| SdkError::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;
        Ok(hex::encode(encrypted))
    }

    pub fn derive_session_auth_pubkey(&self, keygen_session_id: &str) -> Result<Vec<u8>, SdkError> {
        let (_, auth_pubkey) =
            SecureCrypto::derive_session_auth_keypair(&self.private_key_bytes(), keygen_session_id)
                .map_err(|e| SdkError::Crypto(CryptoError::KeyDerivationFailed(e.to_string())))?;
        Ok(auth_pubkey.serialize().to_vec())
    }

    pub fn sign_for_session(
        &self,
        signing_session_id: &str,
        user_id: &str,
        keygen_session_id: &str,
    ) -> Result<String, SdkError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| SdkError::Crypto(CryptoError::RandomGenerationFailed(e.to_string())))?;

        let signature = SecureCrypto::sign_auth_message_with_session_key(
            &self.private_key_bytes(),
            keygen_session_id,
            signing_session_id,
            user_id,
            &nonce,
        )
        .map_err(|e| SdkError::Crypto(CryptoError::SigningFailed(e.to_string())))?;

        Ok(format!("{}:{}", hex::encode(nonce), hex::encode(signature)))
    }

    pub fn sign_user_request(&self, scope_id: &str, user_id: &str) -> Result<String, SdkError> {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| SdkError::Crypto(CryptoError::RandomGenerationFailed(e.to_string())))?;

        let mut hasher = Sha256::new();
        hasher.update(scope_id.as_bytes());
        hasher.update(user_id.as_bytes());
        hasher.update(nonce);
        let hash = hasher.finalize();

        let secp = Secp256k1::signing_only();
        let message = secp256k1::Message::from_digest(hash.into());
        let signature = secp.sign_ecdsa(message, &self.auth_private_key);

        Ok(format!(
            "{}:{}",
            hex::encode(nonce),
            hex::encode(signature.serialize_compact())
        ))
    }

    pub fn sign_approval(
        &self,
        encrypted_message: &str,
        key_id: &str,
        timestamp: u64,
    ) -> Result<Vec<u8>, SdkError> {
        let mut hasher = Sha256::new();
        hasher.update(encrypted_message.as_bytes());
        hasher.update(key_id.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash = hasher.finalize();

        let secp = Secp256k1::signing_only();
        let message = secp256k1::Message::from_digest(hash.into());
        let signature = secp.sign_ecdsa(message, &self.auth_private_key);

        Ok(signature.serialize_compact().to_vec())
    }
}

impl std::fmt::Debug for UserCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserCredentials")
            .field("public_key", &hex::encode(self.public_key.serialize()))
            .field(
                "auth_public_key",
                &hex::encode(self.auth_public_key.serialize()),
            )
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_private_key() {
        let private_key = [0x42u8; 32];
        let creds = UserCredentials::from_private_key(&private_key).unwrap();
        assert_eq!(creds.public_key_bytes().len(), 33);
        assert_eq!(creds.auth_public_key_bytes().len(), 33);
        assert_eq!(creds.private_key_bytes(), private_key);
    }

    #[test]
    fn test_invalid_private_key_length() {
        let private_key = [0x42u8; 16];
        let result = UserCredentials::from_private_key(&private_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_user_signature() {
        let private_key = [0x42u8; 32];
        let creds = UserCredentials::from_private_key(&private_key).unwrap();

        let signature = creds.sign_user_request("key-123", "user-456").unwrap();

        let parts: Vec<&str> = signature.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 32);
        assert_eq!(parts[1].len(), 128);
    }

    #[test]
    fn test_approval_signature() {
        let private_key = [0x42u8; 32];
        let creds = UserCredentials::from_private_key(&private_key).unwrap();

        let signature = creds
            .sign_approval("encrypted_msg", "key-123", 1234567890)
            .unwrap();
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_deterministic_derivation() {
        let private_key = [0x42u8; 32];
        let creds1 = UserCredentials::from_private_key(&private_key).unwrap();
        let creds2 = UserCredentials::from_private_key(&private_key).unwrap();

        assert_eq!(creds1.public_key_bytes(), creds2.public_key_bytes());
        assert_eq!(
            creds1.auth_public_key_bytes(),
            creds2.auth_public_key_bytes()
        );
    }

    #[test]
    fn test_session_auth_pubkey() {
        let private_key = [0x42u8; 32];
        let creds = UserCredentials::from_private_key(&private_key).unwrap();

        let auth_pubkey = creds
            .derive_session_auth_pubkey("keygen-session-123")
            .unwrap();
        assert_eq!(auth_pubkey.len(), 33);

        let auth_pubkey2 = creds
            .derive_session_auth_pubkey("keygen-session-123")
            .unwrap();
        assert_eq!(auth_pubkey, auth_pubkey2);

        let auth_pubkey3 = creds
            .derive_session_auth_pubkey("keygen-session-456")
            .unwrap();
        assert_ne!(auth_pubkey, auth_pubkey3);
    }

    #[test]
    fn test_sign_for_session() {
        let private_key = [0x42u8; 32];
        let creds = UserCredentials::from_private_key(&private_key).unwrap();

        let signature = creds
            .sign_for_session("signing-123", "user-456", "keygen-789")
            .unwrap();

        let parts: Vec<&str> = signature.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 32);
        assert_eq!(parts[1].len(), 128);
    }
}
