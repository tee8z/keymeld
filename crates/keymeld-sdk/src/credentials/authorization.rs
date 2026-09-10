use crate::error::{CryptoError, SdkError};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroize;

/// An independent signing authority or a single participant's invitation credential.
/// Keep this separate from the session secret shared with every participant.
#[derive(Clone)]
pub struct AuthorizationCredentials {
    secret: [u8; 32],
}

impl AuthorizationCredentials {
    pub fn generate() -> Result<Self, SdkError> {
        loop {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|e| {
                SdkError::Crypto(CryptoError::RandomGenerationFailed(e.to_string()))
            })?;
            if SecretKey::from_byte_array(bytes).is_ok() {
                return Ok(Self { secret: bytes });
            }
            bytes.zeroize();
        }
    }

    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, SdkError> {
        SecretKey::from_byte_array(*secret)
            .map_err(|e| SdkError::Crypto(CryptoError::InvalidKeyFormat(e.to_string())))?;
        Ok(Self { secret: *secret })
    }

    pub fn export_secret(&self) -> [u8; 32] {
        self.secret
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        let secret = SecretKey::from_byte_array(self.secret).expect("validated authorization key");
        PublicKey::from_secret_key(&Secp256k1::new(), &secret)
            .serialize()
            .to_vec()
    }
}

impl Drop for AuthorizationCredentials {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for AuthorizationCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationCredentials")
            .field("public_key", &hex::encode(self.public_key_bytes()))
            .field("secret", &"[REDACTED]")
            .finish()
    }
}
