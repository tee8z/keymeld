//! End-to-end encrypted client/enclave transport. The gateway may inspect only
//! the routing header and ciphertext. Native protocol objects never cross that boundary.
use crate::{
    authorization::{authorization_digest, sign_authorization, verify_authorization},
    crypto::SecureCrypto,
    protocol::{Command, Outcome},
    EnclaveId, KeyMeldError,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const TRANSPORT_VERSION: u16 = 1;
pub const MAX_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PLAINTEXT_BYTES + 512;
pub const MAX_WIRE_BYTES: usize = MAX_CIPHERTEXT_BYTES * 2 + 1024;

fn valid_correlation(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid() -> KeyMeldError {
    KeyMeldError::ValidationError("Invalid confidential transport message".into())
}

/// No session identifiers, policy commitments, operation selectors or error text.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnclaveEnvelope {
    pub transport_version: u16,
    pub destination_enclave: EnclaveId,
    pub opaque_route_id: Uuid,
    pub correlation_id: String,
    pub ciphertext: String,
}

impl std::fmt::Debug for EnclaveEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnclaveEnvelope")
            .field("destination_enclave", &self.destination_enclave)
            .field("correlation_id", &self.correlation_id)
            .field("ciphertext_bytes", &(self.ciphertext.len() / 2))
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutingHeader {
    pub transport_version: u16,
    pub destination_enclave: EnclaveId,
    pub opaque_route_id: Uuid,
    pub correlation_id: String,
}

impl EnclaveEnvelope {
    pub fn header(&self) -> RoutingHeader {
        RoutingHeader {
            transport_version: self.transport_version,
            destination_enclave: self.destination_enclave,
            opaque_route_id: self.opaque_route_id,
            correlation_id: self.correlation_id.clone(),
        }
    }

    pub fn validate_bounds(&self) -> Result<(), KeyMeldError> {
        if self.transport_version != TRANSPORT_VERSION
            || self.opaque_route_id.is_nil()
            || !valid_correlation(&self.correlation_id)
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > MAX_CIPHERTEXT_BYTES * 2
            || !self.ciphertext.len().is_multiple_of(2)
            || !self.ciphertext.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl RoutingHeader {
    fn wrap(&self, ciphertext: Vec<u8>) -> Result<EnclaveEnvelope, KeyMeldError> {
        let result = EnclaveEnvelope {
            transport_version: self.transport_version,
            destination_enclave: self.destination_enclave,
            opaque_route_id: self.opaque_route_id,
            correlation_id: self.correlation_id.clone(),
            ciphertext: hex::encode(ciphertext),
        };
        result.validate_bounds()?;
        Ok(result)
    }
}

/// Everything in this object is private to the authorized client and enclave.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidentialRequest {
    pub header: RoutingHeader,
    pub enclave_public_key: Vec<u8>,
    pub enclave_key_epoch: u64,
    pub authority_public_key: Vec<u8>,
    pub response_public_key: Vec<u8>,
    pub command: Command,
    /// Secret blinding prevents the routing identifier from exposing dictionary-testable application hashes.
    pub request_nonce: [u8; 32],
    pub signature: Vec<u8>,
}

impl ConfidentialRequest {
    fn payload(&self) -> impl Serialize + '_ {
        (
            &self.header,
            &self.enclave_public_key,
            self.enclave_key_epoch,
            &self.authority_public_key,
            &self.response_public_key,
            &self.command,
            &self.request_nonce,
        )
    }

    fn correlation_commitment(&self) -> Result<[u8; 32], KeyMeldError> {
        authorization_digest(
            "confidential-routing-id-v1",
            &(
                &self.request_nonce,
                self.header.transport_version,
                self.header.destination_enclave,
                self.header.opaque_route_id,
                &self.enclave_public_key,
                self.enclave_key_epoch,
                &self.authority_public_key,
                &self.response_public_key,
                &self.command,
            ),
        )
    }

    pub fn sign(
        header: RoutingHeader,
        enclave_public_key: Vec<u8>,
        enclave_key_epoch: u64,
        authority_secret: &[u8; 32],
        response_public_key: Vec<u8>,
        command: Command,
    ) -> Result<Self, KeyMeldError> {
        let authority = SecretKey::from_byte_array(*authority_secret).map_err(|_| invalid())?;
        let mut result = Self {
            header,
            enclave_public_key,
            enclave_key_epoch,
            authority_public_key: PublicKey::from_secret_key(&Secp256k1::new(), &authority)
                .serialize()
                .to_vec(),
            response_public_key,
            command,
            request_nonce: SecureCrypto::generate_secure_seed()?,
            signature: Vec::new(),
        };
        result.header.correlation_id = hex::encode(result.correlation_commitment()?);
        let signature = sign_authorization(
            authority_secret,
            "confidential-request-v1",
            &result.payload(),
        )?;
        result.signature = signature;
        result.verify(
            &result.header,
            &result.enclave_public_key,
            enclave_key_epoch,
        )?;
        Ok(result)
    }

    pub fn digest(&self) -> Result<[u8; 32], KeyMeldError> {
        authorization_digest("confidential-request-v1", &self.payload())
    }

    pub fn verify(
        &self,
        header: &RoutingHeader,
        enclave_public_key: &[u8],
        enclave_key_epoch: u64,
    ) -> Result<(), KeyMeldError> {
        if &self.header != header
            || self.header.transport_version != TRANSPORT_VERSION
            || self.enclave_public_key != enclave_public_key
            || self.enclave_key_epoch != enclave_key_epoch
            || self.header.correlation_id != hex::encode(self.correlation_commitment()?)
            || !valid_correlation(&self.header.correlation_id)
            || self.header.opaque_route_id.is_nil()
        {
            return Err(invalid());
        }
        for key in [
            &self.enclave_public_key,
            &self.authority_public_key,
            &self.response_public_key,
        ] {
            let parsed = PublicKey::from_slice(key).map_err(|_| invalid())?;
            if parsed.serialize().as_slice() != key {
                return Err(invalid());
            }
        }
        verify_authorization(
            &self.authority_public_key,
            "confidential-request-v1",
            &self.payload(),
            &self.signature,
        )
        .map_err(|_| invalid())
    }

    pub fn encrypt(&self) -> Result<EnclaveEnvelope, KeyMeldError> {
        encrypt(&self.header, &self.enclave_public_key, self)
    }

    pub fn decrypt(
        envelope: &EnclaveEnvelope,
        enclave_secret: &SecretKey,
        enclave_key_epoch: u64,
    ) -> Result<Self, KeyMeldError> {
        let request: Self = decrypt(envelope, enclave_secret)?;
        let public = PublicKey::from_secret_key(&Secp256k1::new(), enclave_secret).serialize();
        request.verify(&envelope.header(), &public, enclave_key_epoch)?;
        Ok(request)
    }
}

/// Detailed errors are Outcomes too, and receive identical response protection.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidentialResponse {
    pub header: RoutingHeader,
    pub request_digest: [u8; 32],
    pub response_public_key: Vec<u8>,
    pub outcome: Outcome,
    pub signature: Vec<u8>,
}

impl ConfidentialResponse {
    fn payload(&self) -> impl Serialize + '_ {
        (
            &self.header,
            self.request_digest,
            &self.response_public_key,
            &self.outcome,
        )
    }

    pub fn encrypt(
        request: &ConfidentialRequest,
        outcome: Outcome,
        enclave_secret: &[u8; 32],
    ) -> Result<EnclaveEnvelope, KeyMeldError> {
        if outcome.command_id != request.command.command_id {
            return Err(invalid());
        }
        let mut response = Self {
            header: request.header.clone(),
            request_digest: request.digest()?,
            response_public_key: request.response_public_key.clone(),
            outcome,
            signature: Vec::new(),
        };
        let signature = sign_authorization(
            enclave_secret,
            "confidential-response-v1",
            &response.payload(),
        )?;
        response.signature = signature;
        encrypt(&response.header, &response.response_public_key, &response)
    }

    pub fn decrypt(
        envelope: &EnclaveEnvelope,
        request: &ConfidentialRequest,
        response_secret: &SecretKey,
    ) -> Result<Self, KeyMeldError> {
        let response: Self = decrypt(envelope, response_secret)?;
        let response_public =
            PublicKey::from_secret_key(&Secp256k1::new(), response_secret).serialize();
        if response.header != request.header
            || response.header != envelope.header()
            || response.request_digest != request.digest()?
            || response.response_public_key != request.response_public_key
            || response.response_public_key != response_public
            || response.outcome.command_id != request.command.command_id
        {
            return Err(invalid());
        }
        verify_authorization(
            &request.enclave_public_key,
            "confidential-response-v1",
            &response.payload(),
            &response.signature,
        )
        .map_err(|_| invalid())?;
        Ok(response)
    }
}

fn encrypt<T: Serialize>(
    header: &RoutingHeader,
    public: &[u8],
    value: &T,
) -> Result<EnclaveEnvelope, KeyMeldError> {
    let plaintext = Zeroizing::new(serde_json::to_vec(value).map_err(|_| invalid())?);
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid());
    }
    header.wrap(
        SecureCrypto::ecies_encrypt_from_hex(&hex::encode(public), &plaintext)
            .map_err(|_| invalid())?,
    )
}

fn decrypt<T: serde::de::DeserializeOwned>(
    envelope: &EnclaveEnvelope,
    secret: &SecretKey,
) -> Result<T, KeyMeldError> {
    envelope.validate_bounds()?;
    let ciphertext = hex::decode(&envelope.ciphertext).map_err(|_| invalid())?;
    let plaintext =
        Zeroizing::new(SecureCrypto::ecies_decrypt(secret, &ciphertext).map_err(|_| invalid())?);
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(invalid());
    }
    serde_json::from_slice(&plaintext).map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        EnclaveCommand, EnclaveError, EnclaveOutcome, ErrorResponse, SystemCommand, SystemOutcome,
        ValidationError,
    };
    fn public(secret: u8) -> Vec<u8> {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array([secret; 32]).unwrap(),
        )
        .serialize()
        .to_vec()
    }
    fn request() -> ConfidentialRequest {
        let command = Command::new(EnclaveCommand::System(SystemCommand::GetAttestation {
            nonce: b"private-attestation-challenge".to_vec(),
        }));
        ConfidentialRequest::sign(
            RoutingHeader {
                transport_version: TRANSPORT_VERSION,
                destination_enclave: EnclaveId::new(7),
                opaque_route_id: Uuid::now_v7(),
                correlation_id: String::new(),
            },
            public(2),
            9,
            &[3; 32],
            public(4),
            command,
        )
        .unwrap()
    }
    #[test]
    fn blinded_correlation_authenticates_the_entire_request_without_a_replay_index() {
        let original = request();
        let mut changed = original.clone();
        changed.command.created_at = std::time::UNIX_EPOCH;
        // End the payload borrow before reassigning the signature field.
        let signature =
            sign_authorization(&[3; 32], "confidential-request-v1", &changed.payload()).unwrap();
        changed.signature = signature;
        // Even the authorized signer cannot reuse the old routing identity for
        // different content. Evicting a ciphertext cache does not weaken this.
        assert!(changed.verify(&original.header, &public(2), 9).is_err());
        let independently_blinded = ConfidentialRequest::sign(
            original.header.clone(),
            public(2),
            9,
            &[3; 32],
            public(4),
            original.command.clone(),
        )
        .unwrap();
        assert_ne!(original.request_nonce, independently_blinded.request_nonce);
        assert_ne!(
            original.header.correlation_id,
            independently_blinded.header.correlation_id
        );
        independently_blinded
            .verify(&independently_blinded.header, &public(2), 9)
            .unwrap();
    }

    #[test]
    fn wire_and_debug_expose_only_routing_and_ciphertext() {
        let request = request();
        let envelope = request.encrypt().unwrap();
        let wire = serde_json::to_value(&envelope).unwrap();
        let keys: std::collections::BTreeSet<_> = wire
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "transport_version",
                "destination_enclave",
                "opaque_route_id",
                "correlation_id",
                "ciphertext"
            ]
            .into_iter()
            .collect()
        );
        let serialized = serde_json::to_string(&envelope).unwrap();
        for forbidden in [
            "GetAttestation",
            "authority_public_key",
            "response_public_key",
            "signature",
            "enclave_key_epoch",
        ] {
            assert!(!serialized.contains(forbidden));
            assert!(!format!("{envelope:?}").contains(forbidden));
        }
        let secret = SecretKey::from_byte_array([2; 32]).unwrap();
        let decrypted = ConfidentialRequest::decrypt(&envelope, &secret, 9).unwrap();
        assert_eq!(decrypted.digest().unwrap(), request.digest().unwrap());
    }
    #[test]
    fn every_outer_header_and_recipient_is_authenticated() {
        let request = request();
        let envelope = request.encrypt().unwrap();
        let secret = SecretKey::from_byte_array([2; 32]).unwrap();
        for field in 0..4 {
            let mut changed = envelope.clone();
            match field {
                0 => changed.transport_version += 1,
                1 => changed.destination_enclave = EnclaveId::new(8),
                2 => changed.opaque_route_id = Uuid::now_v7(),
                _ => changed.correlation_id = "01".repeat(32),
            }
            assert!(ConfidentialRequest::decrypt(&changed, &secret, 9).is_err());
        }
        assert!(ConfidentialRequest::decrypt(&envelope, &secret, 10).is_err());
        assert!(ConfidentialRequest::decrypt(
            &envelope,
            &SecretKey::from_byte_array([5; 32]).unwrap(),
            9
        )
        .is_err());
        let mut corrupt = envelope;
        let last = corrupt.ciphertext.pop().unwrap();
        corrupt.ciphertext.push(if last == '0' { '1' } else { '0' });
        assert!(ConfidentialRequest::decrypt(&corrupt, &secret, 9).is_err());
    }
    #[test]
    fn command_authority_and_response_recipient_cannot_be_substituted() {
        let request = request();
        for field in 0..4 {
            let mut changed = request.clone();
            match field {
                0 => changed.authority_public_key = public(5),
                1 => changed.response_public_key = public(5),
                2 => changed.command.command = EnclaveCommand::System(SystemCommand::Ping),
                _ => changed.command.command_id = Uuid::now_v7(),
            }
            assert!(changed.verify(&request.header, &public(2), 9).is_err());
        }
    }
    #[test]
    fn private_errors_are_encrypted_signed_and_bound_to_request() {
        let request = request();
        let outcome = Outcome::new(
            request.command.clone(),
            EnclaveOutcome::Error(ErrorResponse {
                error: EnclaveError::Validation(ValidationError::Other(
                    "private invoice recipient and signing policy".into(),
                )),
            }),
        );
        let response = ConfidentialResponse::encrypt(&request, outcome, &[2; 32]).unwrap();
        let wire = serde_json::to_string(&response).unwrap();
        assert!(!wire.contains("private invoice"));
        assert!(!wire.contains("Error"));
        let secret = SecretKey::from_byte_array([4; 32]).unwrap();
        assert!(matches!(
            ConfidentialResponse::decrypt(&response, &request, &secret)
                .unwrap()
                .outcome
                .response,
            EnclaveOutcome::Error(_)
        ));
        assert!(ConfidentialResponse::decrypt(
            &response,
            &request,
            &SecretKey::from_byte_array([3; 32]).unwrap()
        )
        .is_err());
        let mut other = request.clone();
        other.command.command = EnclaveCommand::System(SystemCommand::Ping);
        assert!(ConfidentialResponse::decrypt(&response, &other, &secret).is_err());
        let forged = ConfidentialResponse::encrypt(
            &request,
            Outcome::new(
                request.command.clone(),
                EnclaveOutcome::System(SystemOutcome::Success),
            ),
            &[5; 32],
        )
        .unwrap();
        assert!(ConfidentialResponse::decrypt(&forged, &request, &secret).is_err());
    }
    #[test]
    fn reject_unknown_fields_and_oversized_ciphertext_before_decryption() {
        let mut envelope = request().encrypt().unwrap();
        let mut wire = serde_json::to_value(&envelope).unwrap();
        wire["policy"] = serde_json::json!("must not be accepted");
        assert!(serde_json::from_value::<EnclaveEnvelope>(wire).is_err());
        envelope.ciphertext = "00".repeat(MAX_CIPHERTEXT_BYTES + 1);
        assert!(envelope.validate_bounds().is_err());
    }
}
