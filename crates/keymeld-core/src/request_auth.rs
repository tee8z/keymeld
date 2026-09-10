//! Short-lived HTTP authentication proofs. The gateway durably consumes each
//! verified proof so retries must carry a fresh nonce, including after restart.

use crate::KeyMeldError;
use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

pub const MAX_AUTH_AGE_SECS: u64 = 300;
pub const MAX_AUTH_FUTURE_SKEW_SECS: u64 = 30;

#[derive(Clone, Copy, Debug)]
pub enum AuthKind {
    User,
    Session,
}

impl AuthKind {
    fn domain(self) -> &'static [u8] {
        match self {
            Self::User => b"keymeld-http-user-auth-v1",
            Self::Session => b"keymeld-http-session-auth-v1",
        }
    }
}

/// Wire format: `v1:unix_seconds:16_byte_nonce_hex:compact_ecdsa_signature_hex`.
#[derive(Clone, Debug)]
pub struct RequestAuth {
    pub timestamp: u64,
    nonce: [u8; 16],
    signature: Signature,
}

fn invalid(message: &str) -> KeyMeldError {
    KeyMeldError::ValidationError(message.to_owned())
}

pub fn validate_timestamp(timestamp: u64, now: u64) -> Result<(), KeyMeldError> {
    if now.saturating_sub(timestamp) > MAX_AUTH_AGE_SECS {
        return Err(invalid("Authentication proof has expired"));
    }
    if timestamp.saturating_sub(now) > MAX_AUTH_FUTURE_SKEW_SECS {
        return Err(invalid("Authentication timestamp is too far in the future"));
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now_timestamp_secs() -> Result<u64, KeyMeldError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(KeyMeldError::TimeError)
}

#[cfg(target_arch = "wasm32")]
pub fn now_timestamp_secs() -> Result<u64, KeyMeldError> {
    use wasm_bindgen::prelude::wasm_bindgen;
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date, js_name = now)]
        fn date_now() -> f64;
    }
    let seconds = date_now() / 1000.0;
    if !seconds.is_finite() || seconds < 0.0 || seconds >= u64::MAX as f64 {
        return Err(invalid("System clock is outside the supported range"));
    }
    Ok(seconds as u64)
}

pub fn delete_key_scope(key_id: &str) -> String {
    format!("keymeld-delete-user-key-v1:{key_id}")
}

impl RequestAuth {
    fn digest(
        kind: AuthKind,
        scope: &str,
        user_id: &str,
        timestamp: u64,
        nonce: &[u8; 16],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for component in [kind.domain(), scope.as_bytes(), user_id.as_bytes()] {
            hasher.update((component.len() as u64).to_be_bytes());
            hasher.update(component);
        }
        hasher.update(timestamp.to_be_bytes());
        hasher.update(nonce);
        hasher.finalize().into()
    }

    pub fn sign(
        kind: AuthKind,
        scope: &str,
        user_id: &str,
        private_key: &SecretKey,
        timestamp: u64,
        nonce: [u8; 16],
    ) -> Self {
        let message = Message::from_digest(Self::digest(kind, scope, user_id, timestamp, &nonce));
        Self {
            timestamp,
            nonce,
            signature: SECP256K1.sign_ecdsa(message, private_key),
        }
    }

    pub fn parse(header: &str) -> Result<Self, KeyMeldError> {
        let parts: Vec<_> = header.split(':').collect();
        if parts.len() != 4 || parts[0] != "v1" {
            return Err(invalid(
                "Expected v1:timestamp:nonce:signature authentication proof",
            ));
        }
        let timestamp = parts[1]
            .parse::<u64>()
            .map_err(|_| invalid("Invalid authentication timestamp"))?;
        if parts[1] != timestamp.to_string() || parts[2].len() != 32 || parts[3].len() != 128 {
            return Err(invalid("Invalid authentication proof encoding"));
        }
        let mut nonce = [0; 16];
        hex::decode_to_slice(parts[2], &mut nonce)
            .map_err(|_| invalid("Invalid authentication nonce"))?;
        let mut signature_bytes = [0; 64];
        hex::decode_to_slice(parts[3], &mut signature_bytes)
            .map_err(|_| invalid("Invalid authentication signature"))?;
        let signature = Signature::from_compact(&signature_bytes)
            .map_err(|_| invalid("Invalid authentication signature"))?;
        Ok(Self {
            timestamp,
            nonce,
            signature,
        })
    }

    pub fn to_header(&self) -> String {
        format!(
            "v1:{}:{}:{}",
            self.timestamp,
            hex::encode(self.nonce),
            hex::encode(self.signature.serialize_compact())
        )
    }

    pub fn verify(
        &self,
        kind: AuthKind,
        scope: &str,
        user_id: &str,
        public_key: &PublicKey,
        now: u64,
    ) -> Result<(), KeyMeldError> {
        validate_timestamp(self.timestamp, now)?;
        let message = Message::from_digest(Self::digest(
            kind,
            scope,
            user_id,
            self.timestamp,
            &self.nonce,
        ));
        SECP256K1
            .verify_ecdsa(message, &self.signature, public_key)
            .map_err(|_| invalid("Invalid authentication signature"))
    }

    /// Canonical proof identity: alternate hex or ECDSA encodings cannot create
    /// another replay-cache entry for the same signed commitment.
    pub fn replay_key(
        &self,
        kind: AuthKind,
        scope: &str,
        user_id: &str,
        public_key: &PublicKey,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"keymeld-http-replay-v1");
        hasher.update(public_key.serialize());
        hasher.update(Self::digest(
            kind,
            scope,
            user_id,
            self.timestamp,
            &self.nonce,
        ));
        hex::encode(hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proofs_bind_identity_scope_kind_timestamp_and_nonce() {
        let private_key = SecretKey::from_byte_array([42; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let proof = RequestAuth::sign(AuthKind::User, "ab", "c", &private_key, 1000, [3; 16]);
        let header = proof.to_header();
        let parsed = RequestAuth::parse(&header).unwrap();
        parsed
            .verify(AuthKind::User, "ab", "c", &public_key, 1000)
            .unwrap();
        assert!(parsed
            .verify(AuthKind::User, "a", "bc", &public_key, 1000)
            .is_err());
        assert!(parsed
            .verify(AuthKind::Session, "ab", "c", &public_key, 1000)
            .is_err());
        assert!(parsed
            .verify(
                AuthKind::User,
                &delete_key_scope("ab"),
                "c",
                &public_key,
                1000
            )
            .is_err());
        assert!(RequestAuth::parse(&header.replacen(":1000:", ":1001:", 1))
            .unwrap()
            .verify(AuthKind::User, "ab", "c", &public_key, 1000)
            .is_err());
        assert!(
            RequestAuth::parse(&header.replace(&hex::encode([3; 16]), &hex::encode([4; 16])))
                .unwrap()
                .verify(AuthKind::User, "ab", "c", &public_key, 1000)
                .is_err()
        );
    }

    #[test]
    fn expired_future_and_legacy_proofs_are_rejected() {
        let private_key = SecretKey::from_byte_array([42; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);
        let proof = RequestAuth::sign(AuthKind::User, "scope", "user", &private_key, 1000, [3; 16]);
        assert!(proof
            .verify(AuthKind::User, "scope", "user", &public_key, 1300)
            .is_ok());
        assert!(proof
            .verify(AuthKind::User, "scope", "user", &public_key, 1301)
            .is_err());
        assert!(proof
            .verify(AuthKind::User, "scope", "user", &public_key, 969)
            .is_err());
        assert!(proof
            .verify(AuthKind::User, "scope", "user", &public_key, 970)
            .is_ok());
        for header in [
            format!(
                "{}:{}",
                hex::encode([3; 16]),
                hex::encode(proof.signature.serialize_compact())
            ),
            proof.to_header().replacen("v1:", "v2:", 1),
            proof.to_header().replacen(":1000:", ":01000:", 1),
            format!("{}:extra", proof.to_header()),
        ] {
            assert!(RequestAuth::parse(&header).is_err());
        }
    }
}
