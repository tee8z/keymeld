use crate::{
    api::TaprootTweak,
    identifiers::{EnclaveId, SessionId, UserId},
    KeyMeldError,
};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum EnclaveCommand {
    Ping,
    Configure(ConfigureCommand),
    InitKeygenSession(InitKeygenSessionCommand),
    InitSigningSession(InitSigningSessionCommand),
    AddParticipant(AddParticipantCommand),
    GenerateNonce(GenerateNonceCommand),
    AddNonce(AddNonceCommand),
    GetAggregateNonce(GetAggregateNonceCommand),
    GetAggregatePublicKey(GetAggregatePublicKeyCommand),
    ValidateSessionHmac(ValidateSessionHmacCommand),
    ValidateKeygenParticipantHmac(ValidateKeygenParticipantHmacCommand),
    SignPartialSignature(ParitialSignatureCommand),
    AddPartialSignature(AddPartialSignatureCommand),
    Finalize(FinalizeCommand),
    ClearSession(ClearSessionCommand),
    DistributeSessionSecret(DistributeSessionSecretCommand),
    BatchDistributeSessionSecrets(BatchDistributeSessionSecretsCommand),
    GetPublicInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum EnclaveResponse {
    Success(SuccessResponse),
    Pong,
    Nonce(NonceResponse),
    Signature(SignatureResponse),
    FinalSignature(FinalSignatureResponse),
    AggregatePublicKey(AggregatePublicKeyResponse),
    AggregateNonce(AggregateNonceResponse),
    PublicInfo(PublicInfoResponse),
    Attestation(AttestationResponse),
    BatchSessionSecrets(BatchSessionSecretsResponse),
    EnclavePublicKeys(EnclavePublicKeysResponse),
    KeygenInitialized(KeygenInitializedResponse),
    SessionSecret(SessionSecretResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureCommand {
    pub region: String,
    pub enclave_id: EnclaveId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitKeygenSessionCommand {
    pub keygen_session_id: SessionId,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub timeout_secs: u64,
    pub taproot_tweak: TaprootTweak,
    pub expected_participant_count: usize,
    pub enclave_public_keys: Vec<EnclavePublicKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitSigningSessionCommand {
    pub keygen_session_id: SessionId,
    pub signing_session_id: SessionId,
    pub encrypted_message: String,
    pub coordinator_encrypted_private_key: Option<String>,
    pub encrypted_session_secret: Option<String>,
    pub timeout_secs: u64,
    pub taproot_tweak: TaprootTweak,
    pub expected_participant_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddParticipantCommand {
    pub keygen_session_id: Option<SessionId>,
    pub signing_session_id: Option<SessionId>,
    pub user_id: UserId,
    pub session_encrypted_data: String,
    pub enclave_encrypted_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateNonceCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub signer_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddNonceCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub signer_index: usize,
    pub nonce: PubNonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParitialSignatureCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub aggregate_nonce: PubNonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPartialSignatureCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub signer_index: usize,
    pub signature: PartialSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareAggregateNonceCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub aggregate_nonce: PubNonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAggregateNonceCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAggregatePublicKeyCommand {
    pub keygen_session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateSessionHmacCommand {
    pub signing_session_id: Option<SessionId>,
    pub keygen_session_id: Option<SessionId>,
    pub user_id: UserId,
    pub message_hash: Vec<u8>,
    pub session_hmac: String,
    pub encrypted_session_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidateKeygenParticipantHmacCommand {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub session_hmac: String,
    pub encrypted_session_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearSessionCommand {
    pub keygen_session_id: Option<SessionId>,
    pub signing_session_id: Option<SessionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributeSessionSecretCommand {
    pub keygen_session_id: SessionId,
    pub encrypted_session_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDistributeSessionSecretsCommand {
    pub keygen_session_id: SessionId,
    pub target_enclaves: Vec<EnclaveId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEnclavePublicKeysCommand {
    pub enclave_ids: Vec<EnclaveId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenInitializedResponse {
    pub keygen_session_id: SessionId,
    pub encrypted_session_secrets: Vec<EncryptedSessionSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub public_nonce: PubNonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub partial_signature: PartialSignature,
    pub public_nonce: PubNonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalSignatureResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub final_signature: Vec<u8>,
    pub participant_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatePublicKeyResponse {
    pub keygen_session_id: SessionId,
    pub aggregate_public_key: Vec<u8>,
    pub participant_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateKeyCompleteResponse {
    pub keygen_session_id: SessionId,
    pub aggregate_public_key: Vec<u8>,
    pub participant_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateNonceResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub aggregate_nonce: PubNonce,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInfoResponse {
    pub public_key: String,
    pub attestation_document: Option<AttestationResponse>,
    pub active_sessions: u32,
    pub uptime_seconds: u64,
    pub key_epoch: u64,
    pub key_generation_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub pcrs: BTreeMap<String, Vec<u8>>,
    pub timestamp: u64,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_data: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionHmacValidationResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub is_valid: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionSecret {
    pub target_enclave_id: EnclaveId,
    pub encrypted_session_secret: String, // Session secret encrypted with target enclave's public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSessionSecretsResponse {
    pub keygen_session_id: SessionId,
    pub encrypted_secrets: Vec<EncryptedSessionSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecretResponse {
    pub keygen_session_id: SessionId,
    pub session_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclavePublicKeyInfo {
    pub enclave_id: EnclaveId,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclavePublicKeysResponse {
    pub enclave_keys: Vec<EnclavePublicKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: EnclaveError,
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    #[error("Enclave not configured")]
    NotConfigured,
    #[error("Enclave already configured")]
    AlreadyConfigured,
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    #[error("Wrong phase: {0}")]
    WrongPhase(String),
    #[error("MuSig error: {0}")]
    MuSigError(String),
    #[error("HMAC invalid: {0}")]
    HmacInvalid(String),
    #[error("Memory exhausted")]
    MemoryExhausted,
    #[error("Session limit exceeded")]
    SessionLimitExceeded,
    #[error("Timeout")]
    Timeout,
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    #[error("Data decoding error: {0}")]
    DataDecodingError(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Session initialization failed: {0}")]
    SessionInitializationFailed(String),
    #[error("Participant error: {0}")]
    ParticipantError(String),
    #[error("Invalid session ID: {0}")]
    InvalidSessionId(String),
    #[error("Invalid session secret: {0}")]
    InvalidSessionSecret(String),
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Signature error: {0}")]
    SignatureError(String),
    #[error("Nonce error: {0}")]
    NonceError(String),
    #[error("Nonce generation failed: {0}")]
    NonceGenerationFailed(String),
    #[error("Aggregate key error: {0}")]
    AggregateKeyError(String),
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Finalization failed: {0}")]
    FinalizationFailed(String),
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    #[error("KeyMeld error: {0}")]
    KeyMeldError(String),
    #[error("Invalid attestation: {0}")]
    InvalidAttestation(String),
}

// Implement From conversions to preserve error details
impl From<hex::FromHexError> for EnclaveError {
    fn from(err: hex::FromHexError) -> Self {
        EnclaveError::DataDecodingError(err.to_string())
    }
}

impl From<musig2::secp256k1::Error> for EnclaveError {
    fn from(err: musig2::secp256k1::Error) -> Self {
        EnclaveError::InvalidPublicKey(err.to_string())
    }
}

impl From<KeyMeldError> for EnclaveError {
    fn from(err: KeyMeldError) -> Self {
        EnclaveError::KeyMeldError(err.to_string())
    }
}
