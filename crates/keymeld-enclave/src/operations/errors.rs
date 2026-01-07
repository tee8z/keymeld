use keymeld_core::{
    identifiers::{SessionId, UserId},
    protocol::{
        AttestationError, CryptoError, EnclaveError, InternalError, NonceError, PrivateKeyError,
        SessionError, SigningError, ValidationError,
    },
};
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum OperationError {
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Session not found")]
    SessionNotFound(SessionId),
    #[error("Enclave operation failed: {0}")]
    EnclaveError(String),
    #[error("Attestation error: {0}")]
    AttestationError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Missing private key for user {0}")]
    MissingPrivateKey(UserId),
    #[error("Invalid session secret")]
    InvalidSessionSecret,
    #[error("Participant not found: {0}")]
    ParticipantNotFound(UserId),
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Session initialization failed: {0}")]
    SessionInitializationFailed(String),
    #[error("Nonce generation failed: {0}")]
    NonceGenerationFailed(String),
    #[error("Signature generation failed: {0}")]
    SignatureGenerationFailed(String),
    #[error("Adaptor signature operation failed: {0}")]
    AdaptorSignatureError(String),
    #[error("Session secret distribution failed: {0}")]
    SessionSecretDistributionFailed(String),
    #[error("Musig operation failed: {0}")]
    MusigError(String),
    #[error("Duplicate participant: {0}")]
    DuplicateParticipant(UserId),
}

impl From<OperationError> for keymeld_core::protocol::EnclaveError {
    fn from(err: OperationError) -> Self {
        match err {
            OperationError::InvalidState(msg) => {
                EnclaveError::Validation(ValidationError::Other(msg))
            }
            OperationError::CryptoError(msg) => EnclaveError::Crypto(CryptoError::Other(msg)),
            OperationError::DecryptionFailed(msg) => {
                EnclaveError::Crypto(CryptoError::DecryptionFailed {
                    context: "operation".to_string(),
                    error: msg,
                })
            }
            OperationError::CryptographicError(msg) => {
                EnclaveError::Crypto(CryptoError::Other(msg))
            }
            OperationError::InvalidInput(msg) => {
                EnclaveError::Validation(ValidationError::Other(msg))
            }
            OperationError::SessionNotFound(session_id) => {
                EnclaveError::Session(SessionError::NotFound(session_id))
            }
            OperationError::EnclaveError(msg) => EnclaveError::Internal(InternalError::Other(msg)),
            OperationError::AttestationError(msg) => {
                EnclaveError::Attestation(AttestationError::Other(msg))
            }
            OperationError::ValidationError(msg) => {
                EnclaveError::Validation(ValidationError::Other(msg))
            }
            OperationError::MissingPrivateKey(user_id) => {
                EnclaveError::PrivateKey(PrivateKeyError::Missing { user_id })
            }
            OperationError::InvalidSessionSecret => {
                EnclaveError::Session(SessionError::SecretNotInitialized)
            }
            OperationError::ParticipantNotFound(user_id) => {
                EnclaveError::Validation(ValidationError::UserNotFound { user_id })
            }
            OperationError::SessionInitializationFailed(msg) => {
                EnclaveError::Session(SessionError::MusigInitialization(msg))
            }
            OperationError::NonceGenerationFailed(msg) => {
                EnclaveError::Nonce(NonceError::GenerationFailed {
                    user_id: UserId::default(), // Generic fallback since we don't have user_id here
                    error: msg,
                })
            }
            OperationError::SignatureGenerationFailed(msg) => {
                EnclaveError::Signing(SigningError::PartialSignatureGeneration {
                    user_id: UserId::default(), // Generic fallback since we don't have user_id here
                    error: msg,
                })
            }
            OperationError::AdaptorSignatureError(msg) => {
                EnclaveError::Signing(SigningError::AdaptorPartialSignatureGeneration(msg))
            }
            OperationError::SessionSecretDistributionFailed(msg) => EnclaveError::Internal(
                InternalError::Other(format!("Session secret distribution failed: {msg}")),
            ),
            OperationError::MusigError(msg) => {
                EnclaveError::Crypto(CryptoError::Other(format!("Musig error: {msg}")))
            }
            OperationError::InvalidStateTransition(msg) => {
                EnclaveError::Validation(ValidationError::Other(msg))
            }
            OperationError::SerializationError(msg) => {
                EnclaveError::Internal(InternalError::Serialization(msg))
            }
            OperationError::ValidationFailed(msg) => {
                EnclaveError::Validation(ValidationError::Other(msg))
            }
            OperationError::DuplicateParticipant(user_id) => EnclaveError::Validation(
                ValidationError::Other(format!("Duplicate participant: {user_id}")),
            ),
        }
    }
}

impl From<OperationError> for keymeld_core::KeyMeldError {
    fn from(err: OperationError) -> Self {
        match err {
            OperationError::InvalidState(msg) => keymeld_core::KeyMeldError::InvalidState(msg),
            OperationError::CryptoError(msg) => keymeld_core::KeyMeldError::CryptoError(msg),
            OperationError::DecryptionFailed(msg) => keymeld_core::KeyMeldError::CryptoError(msg),
            OperationError::CryptographicError(msg) => keymeld_core::KeyMeldError::CryptoError(msg),
            OperationError::InvalidInput(msg) => keymeld_core::KeyMeldError::ValidationError(msg),
            OperationError::EnclaveError(msg) => keymeld_core::KeyMeldError::EnclaveError(msg),
            OperationError::ValidationError(msg) => {
                keymeld_core::KeyMeldError::ValidationError(msg)
            }
            OperationError::InvalidStateTransition(msg) => {
                keymeld_core::KeyMeldError::ValidationError(msg)
            }
            OperationError::SerializationError(msg) => {
                keymeld_core::KeyMeldError::ValidationError(format!("Serialization error: {msg}"))
            }
            _ => keymeld_core::KeyMeldError::EnclaveError(format!("Operation error: {err:?}")),
        }
    }
}
