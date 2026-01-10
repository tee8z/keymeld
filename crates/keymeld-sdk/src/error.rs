use crate::types::{KeyId, SessionId, UserId};

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),
    #[error("API error: {0}")]
    Api(#[from] ApiError),
    #[error("Keygen error: {0}")]
    Keygen(#[from] KeygenError),
    #[error("Signing error: {0}")]
    Signing(#[from] SigningError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    #[error("Request timeout after {0:?}")]
    Timeout(std::time::Duration),
    #[error("Compression error: {0}")]
    Compression(String),
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("TLS error: {0}")]
    Tls(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("HTTP {status}: {message}")]
    HttpError { status: u16, message: String },
    #[error("Rate limited, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },
    #[error("Server error: {message} (code: {error_code})")]
    ServerError { error_code: String, message: String },
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("Session not found: {0}")]
    SessionNotFound(SessionId),
    #[error("Session expired: {0}")]
    SessionExpired(SessionId),
    #[error("Already registered in session {0}")]
    AlreadyRegistered(SessionId),
    #[error("Invalid participant count: expected {expected}, got {actual}")]
    InvalidParticipantCount { expected: usize, actual: usize },
    #[error("No available slots in session {0}")]
    NoAvailableSlots(SessionId),
    #[error("Keygen failed: {0}")]
    Failed(String),
    #[error("Timeout waiting for keygen completion")]
    Timeout,
    #[error("Session {session_id} in unexpected state: {state}")]
    UnexpectedState {
        session_id: SessionId,
        state: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("Signing session not found: {0}")]
    SessionNotFound(SessionId),
    #[error("Signing session expired: {0}")]
    SessionExpired(SessionId),
    #[error("Approval required from participants: {0:?}")]
    ApprovalRequired(Vec<UserId>),
    #[error("Signing failed: {0}")]
    Failed(String),
    #[error("Invalid batch item {batch_item_id}: {reason}")]
    InvalidBatchItem {
        batch_item_id: uuid::Uuid,
        reason: String,
    },
    #[error("Timeout waiting for signing completion")]
    Timeout,
    #[error("Keygen session not found: {0}")]
    KeygenSessionNotFound(SessionId),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Key not found: {0}")]
    NotFound(KeyId),
    #[error("Key import failed: {0}")]
    ImportFailed(String),
    #[error("Key deletion failed: {0}")]
    DeletionFailed(String),
    #[error("Signing failed for key {key_id}: {reason}")]
    SigningFailed { key_id: KeyId, reason: String },
    #[error("Timeout waiting for key operation")]
    Timeout,
    #[error("Key already exists: {0}")]
    AlreadyExists(KeyId),
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Random generation failed: {0}")]
    RandomGenerationFailed(String),
}

impl From<keymeld_core::KeyMeldError> for SdkError {
    fn from(err: keymeld_core::KeyMeldError) -> Self {
        use keymeld_core::KeyMeldError;
        match err {
            KeyMeldError::ValidationError(msg) => SdkError::InvalidInput(msg),
            KeyMeldError::CryptoError(msg) => SdkError::Crypto(CryptoError::EncryptionFailed(msg)),
            KeyMeldError::EncryptionError(msg) => {
                SdkError::Crypto(CryptoError::EncryptionFailed(msg))
            }
            KeyMeldError::DecryptionError(msg) => {
                SdkError::Crypto(CryptoError::DecryptionFailed(msg))
            }
            KeyMeldError::InvalidKey(_) => {
                SdkError::Crypto(CryptoError::InvalidKeyFormat("Invalid key".to_string()))
            }
            KeyMeldError::HkdfError(msg) => SdkError::Crypto(CryptoError::KeyDerivationFailed(msg)),
            KeyMeldError::SerializationError(msg) => SdkError::Internal(msg),
            KeyMeldError::InvalidConfiguration(msg) => SdkError::InvalidInput(msg),
            KeyMeldError::InvalidState(msg) => SdkError::Internal(msg),
            KeyMeldError::MuSigError(msg) => SdkError::Signing(SigningError::Failed(msg)),
            KeyMeldError::EnclaveError(msg) => SdkError::Internal(msg),
            KeyMeldError::EnclaveNotReady(msg) => SdkError::Internal(msg),
            KeyMeldError::RandomGenerationError(_) => SdkError::Crypto(
                CryptoError::RandomGenerationFailed("RNG failed".to_string()),
            ),
            KeyMeldError::TimeError(_) => SdkError::Internal("Time error".to_string()),
            KeyMeldError::HexDecodeError(_) => SdkError::Crypto(CryptoError::InvalidKeyFormat(
                "Hex decode error".to_string(),
            )),
        }
    }
}

#[cfg(feature = "client")]
impl From<reqwest::Error> for SdkError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            return SdkError::Network(NetworkError::Timeout(std::time::Duration::from_secs(30)));
        }
        #[cfg(not(target_arch = "wasm32"))]
        if err.is_connect() {
            return SdkError::Network(NetworkError::ConnectionFailed(err.to_string()));
        }
        SdkError::Network(NetworkError::ConnectionFailed(err.to_string()))
    }
}

impl From<serde_json::Error> for SdkError {
    fn from(err: serde_json::Error) -> Self {
        SdkError::Api(ApiError::InvalidResponse(err.to_string()))
    }
}

impl From<hex::FromHexError> for SdkError {
    fn from(err: hex::FromHexError) -> Self {
        SdkError::Crypto(CryptoError::InvalidKeyFormat(err.to_string()))
    }
}
