use crate::enclave::EnclaveManager;
pub use crypto::{EncryptedData, KeyMaterial, SessionSecret};
pub use identifiers::{CorrelationId, EnclaveId, SessionId, UserId};
use musig::MusigError;
pub use musig2::{
    secp256k1::PublicKey, AggNonce, BinaryEncoding, CompactSignature, FirstRound, KeyAggContext,
    PartialSignature, PubNonce, SecNonce, SecondRound,
};
use serde::{Deserialize, Serialize};
pub use session::{
    KeygenCollectingParticipants, KeygenCompleted, KeygenFailed, KeygenSessionStatus,
    KeygenStatusKind, ParticipantData, SigningCollectingParticipants, SigningSessionFull,
    SigningSessionStatus, SigningStatusKind,
};
use std::{collections::BTreeMap, string::String, string::ToString, vec::Vec};
use thiserror::Error;
pub use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type AggregatePublicKey = Vec<u8>;

pub mod api;
pub mod crypto;
pub mod enclave;
pub mod encrypted_data;
pub mod identifiers;
pub mod logging;
pub mod musig;

pub mod resilience;
pub mod session;

#[derive(Error, Debug)]
pub enum KeyMeldError {
    #[error("Invalid enclave configuration: {0}")]
    InvalidConfiguration(String),
    #[error("MuSig2 protocol error: {0}")]
    MuSigError(String),
    #[error("Enclave communication error: {0}")]
    EnclaveError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Random number generation failed")]
    RandomGenerationError(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("Time operation failed")]
    TimeError(#[source] std::time::SystemTimeError),
    #[error("HKDF key derivation failed: {0}")]
    HkdfError(String),
    #[error("AES-GCM encryption failed: {0}")]
    EncryptionError(String),
    #[error("AES-GCM decryption failed: {0}")]
    DecryptionError(String),
    #[error("Hex decoding failed")]
    HexDecodeError(#[source] hex::FromHexError),
    #[error("Invalid cryptographic key")]
    InvalidKey(#[source] secp256k1::Error),
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

impl From<MusigError> for KeyMeldError {
    fn from(error: MusigError) -> Self {
        KeyMeldError::MuSigError(error.to_string())
    }
}
#[async_trait::async_trait]
pub trait Advanceable<T>: Send {
    async fn process(self, enclave_manager: &EnclaveManager) -> Result<T, KeyMeldError>
    where
        Self: 'async_trait;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub pcrs: BTreeMap<String, Vec<u8>>,
    pub timestamp: u64,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_data: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

impl Zeroize for AttestationDocument {
    fn zeroize(&mut self) {
        for (_, pcr_value) in self.pcrs.iter_mut() {
            pcr_value.zeroize();
        }
        self.pcrs.clear();

        self.timestamp = 0;
        self.certificate.zeroize();
        self.signature.zeroize();

        if let Some(ref mut user_data) = self.user_data {
            user_data.zeroize();
        }
        if let Some(ref mut public_key) = self.public_key {
            public_key.zeroize();
        }
    }
}

impl ZeroizeOnDrop for AttestationDocument {}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub enclave_count: u32,
    pub active_enclaves: Vec<EnclaveId>,
    pub version: String,
}
