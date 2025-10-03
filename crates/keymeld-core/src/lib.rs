use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, string::String, string::ToString, vec::Vec};
use thiserror::Error;
pub use tracing::{debug, error, info, warn};

pub use musig2::{
    AggNonce, BinaryEncoding, CompactSignature, FirstRound, KeyAggContext, PartialSignature,
    PubNonce, SecNonce, SecondRound,
};

pub mod api;
pub mod crypto;
pub mod enclave;
pub mod identifiers;
pub mod musig;
pub mod session;

use musig::MusigError;

pub use crypto::{EncryptedData, KeyMaterial, SessionSecret};
pub use identifiers::{CorrelationId, EnclaveId, SessionId, UserId};
pub use session::{
    KeygenCollectingParticipants, KeygenCompleted, KeygenFailed, KeygenSessionStatus,
    KeygenStatusKind, ParticipantData, SigningCollectingParticipants, SigningSessionFull,
    SigningSessionStatus, SigningStatusKind,
};

#[derive(Error, Debug)]
pub enum KeyMeldError {
    #[error("Invalid enclave configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Key distribution error: {0}")]
    DistributionError(String),
    #[error("MuSig2 protocol error: {0}")]
    MuSigError(String),
    #[error("Enclave communication error: {0}")]
    EnclaveError(String),
    #[error("Key not found for user: {0}")]
    KeyNotFound(String),
    #[error("Session {0} would exceed enclave capacity")]
    SessionTooLarge(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
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
pub trait Advanceable<T> {
    async fn process(self, enclave_manager: &EnclaveManager) -> Result<T, KeyMeldError>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub pcrs: BTreeMap<String, Vec<u8>>,
    pub timestamp: u64,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub enclave_count: u32,
    pub active_enclaves: Vec<EnclaveId>,
    pub version: String,
}

use crate::enclave::EnclaveManager;
