use keymeld_core::identifiers::{SessionId, UserId};
use thiserror::Error;

use super::types::SessionPhase;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Musig2LibError(pub(crate) String);

impl std::fmt::Display for Musig2LibError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Musig2LibError {}

impl From<String> for Musig2LibError {
    fn from(err: String) -> Self {
        Musig2LibError(err)
    }
}

impl From<musig2::errors::KeyAggError> for Musig2LibError {
    fn from(err: musig2::errors::KeyAggError) -> Self {
        Musig2LibError(err.to_string())
    }
}

impl From<musig2::errors::TweakError> for Musig2LibError {
    fn from(err: musig2::errors::TweakError) -> Self {
        Musig2LibError(err.to_string())
    }
}

impl From<musig2::errors::RoundContributionError> for Musig2LibError {
    fn from(err: musig2::errors::RoundContributionError) -> Self {
        Musig2LibError(err.to_string())
    }
}

impl From<musig2::errors::RoundFinalizeError> for Musig2LibError {
    fn from(err: musig2::errors::RoundFinalizeError) -> Self {
        Musig2LibError(err.to_string())
    }
}

impl From<musig2::errors::SigningError> for Musig2LibError {
    fn from(err: musig2::errors::SigningError) -> Self {
        Musig2LibError(err.to_string())
    }
}

impl From<musig2::errors::SignerIndexError> for Musig2LibError {
    fn from(err: musig2::errors::SignerIndexError) -> Self {
        Musig2LibError(err.to_string())
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MusigError {
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Session not found: {0}")]
    SessionNotFound(SessionId),
    #[error("Wrong session phase: expected {expected:?}, got {actual:?}")]
    WrongPhase {
        expected: SessionPhase,
        actual: SessionPhase,
    },
    #[error("Session not ready: {0}")]
    NotReady(String),
    #[error("MuSig2 library error: {0}")]
    Musig2Error(#[source] Musig2LibError),
    #[error("Insufficient participants: expected {expected}, got {actual}")]
    InsufficientParticipants { expected: usize, actual: usize },
    #[error("Duplicate participant: {0}")]
    DuplicateParticipant(UserId),
    #[error("Invalid participant: {0}")]
    InvalidParticipant(UserId),
    #[error("Invalid adaptor configuration: {0}")]
    InvalidAdaptorConfig(String),
    #[error("Session already initialized: {0}")]
    SessionAlreadyInitialized(SessionId),
    #[error("Failed to acquire lock: {0}")]
    FailedLock(String),
    #[error("User not found: {0}")]
    UserNotFound(UserId),
    #[error("Session not ready: {0}")]
    SessionNotReady(String),
    #[error("Signing error: {0}")]
    SigningError(String),
}
