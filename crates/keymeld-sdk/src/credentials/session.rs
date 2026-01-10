use crate::error::{CryptoError, SdkError};
use keymeld_core::crypto::{EncryptedData, SecureCrypto, SessionSecret};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub struct SessionCredentials {
    seed: [u8; 32],
    session_private_key: SecretKey,
    session_public_key: PublicKey,
    session_secret: SessionSecret,
}

impl SessionCredentials {
    pub fn generate() -> Result<Self, SdkError> {
        let seed = SecureCrypto::generate_session_seed()
            .map_err(|e| SdkError::Crypto(CryptoError::RandomGenerationFailed(e.to_string())))?;

        let seed_array: [u8; 32] = seed.try_into().map_err(|_| {
            SdkError::Crypto(CryptoError::InvalidKeyFormat(
                "Seed not 32 bytes".to_string(),
            ))
        })?;

        Self::from_session_secret(&seed_array)
    }

    pub fn from_session_secret(secret: &[u8; 32]) -> Result<Self, SdkError> {
        let session_private_key = SecureCrypto::derive_private_key_from_seed(secret)
            .map_err(|e| SdkError::Crypto(CryptoError::KeyDerivationFailed(e.to_string())))?;

        let session_public_key = SecureCrypto::derive_public_key_from_seed(secret)
            .map_err(|e| SdkError::Crypto(CryptoError::KeyDerivationFailed(e.to_string())))?;

        let session_secret = SessionSecret::from_bytes(*secret);

        Ok(Self {
            seed: *secret,
            session_private_key,
            session_public_key,
            session_secret,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.session_public_key
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.session_public_key.serialize().to_vec()
    }

    pub fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }

    pub fn session_secret_hex(&self) -> String {
        hex::encode(self.seed)
    }

    pub fn export_session_secret(&self) -> [u8; 32] {
        self.seed
    }

    pub fn sign_session_request(&self, session_id: &str) -> Result<String, SdkError> {
        use sha2::{Digest, Sha256};

        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce)
            .map_err(|e| SdkError::Crypto(CryptoError::RandomGenerationFailed(e.to_string())))?;
        let nonce_hex = hex::encode(nonce);

        // Create the message to sign: session_id:nonce (matching gateway validation)
        let message = format!("{}:{}", session_id, nonce_hex);
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash = hasher.finalize();

        let secp = Secp256k1::signing_only();
        let msg = secp256k1::Message::from_digest(hash.into());
        let signature = secp.sign_ecdsa(msg, &self.session_private_key);

        Ok(format!(
            "{}:{}",
            nonce_hex,
            hex::encode(signature.serialize_compact())
        ))
    }

    pub fn encrypt(&self, data: &[u8], context: &str) -> Result<String, SdkError> {
        let encrypted = self
            .session_secret
            .encrypt(data, context)
            .map_err(|e| SdkError::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;
        Ok(encrypted.to_hex()?)
    }

    pub fn decrypt(&self, encrypted_hex: &str, context: &str) -> Result<Vec<u8>, SdkError> {
        let encrypted = EncryptedData::from_hex(encrypted_hex)
            .map_err(|e| SdkError::Crypto(CryptoError::DecryptionFailed(e.to_string())))?;
        self.session_secret
            .decrypt(&encrypted, context)
            .map_err(|e| SdkError::Crypto(CryptoError::DecryptionFailed(e.to_string())))
    }

    pub fn encrypt_secret_for_enclave(
        &self,
        enclave_public_key_hex: &str,
    ) -> Result<String, SdkError> {
        let encrypted = SecureCrypto::ecies_encrypt_from_hex(enclave_public_key_hex, &self.seed)
            .map_err(|e| SdkError::Crypto(CryptoError::EncryptionFailed(e.to_string())))?;
        Ok(hex::encode(encrypted))
    }
}

impl std::fmt::Debug for SessionCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCredentials")
            .field(
                "public_key",
                &hex::encode(self.session_public_key.serialize()),
            )
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SessionCredentials {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_credentials() {
        let creds = SessionCredentials::generate().unwrap();
        assert_eq!(creds.public_key_bytes().len(), 33);
    }

    #[test]
    fn test_restore_from_session_secret() {
        let creds1 = SessionCredentials::generate().unwrap();
        let secret = creds1.export_session_secret();

        let creds2 = SessionCredentials::from_session_secret(&secret).unwrap();
        assert_eq!(creds1.public_key_bytes(), creds2.public_key_bytes());
        assert_eq!(creds1.session_secret_hex(), creds2.session_secret_hex());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let creds = SessionCredentials::generate().unwrap();
        let data = b"test message";
        let context = "test";

        let encrypted = creds.encrypt(data, context).unwrap();
        let decrypted = creds.decrypt(&encrypted, context).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_session_signature() {
        let creds = SessionCredentials::generate().unwrap();
        let session_id = "test-session-123";

        let signature = creds.sign_session_request(session_id).unwrap();

        let parts: Vec<&str> = signature.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 32);
        assert_eq!(parts[1].len(), 128);
    }
}
