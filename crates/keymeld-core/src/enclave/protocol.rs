use crate::{
    api::TaprootTweak,
    identifiers::{EnclaveId, SessionId, UserId},
    AttestationDocument, KeyMeldError,
};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum EnclaveCommand {
    Ping,
    Configure(ConfigureCommand),
    GetPublicInfo,
    InitKeygenSession(InitKeygenSessionCommand),
    DistributeSessionSecret(DistributeSessionSecretCommand),
    AddParticipant(AddParticipantCommand),
    DistributeParticipantPublicKey(DistributeParticipantPublicKeyCommand),
    GetAggregatePublicKey(GetAggregatePublicKeyCommand),
    InitSigningSession(InitSigningSessionCommand),
    GenerateNonce(GenerateNonceCommand),
    AddNonce(AddNonceCommand),
    SignPartialSignature(ParitialSignatureCommand),
    AddPartialSignature(AddPartialSignatureCommand),
    Finalize(FinalizeCommand),
    ClearSession(ClearSessionCommand),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum EnclaveResponse {
    Success,
    ParticipantAdded(ParticipantAddedResponse),
    Pong,
    Nonce(NonceResponse),
    Signature(SignatureResponse),
    FinalSignature(FinalSignatureResponse),
    AggregatePublicKey(AggregatePublicKeyResponse),
    PublicInfo(PublicInfoResponse),
    Attestation(AttestationDocument),
    KeygenInitialized(KeygenInitializedResponse),
    AdaptorPartialSignature(AdaptorPartialSignatureResponse),
    AdaptorSignatures(AdaptorSignaturesResponse),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureCommand {
    pub enclave_id: EnclaveId,
    pub key_epoch: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitKeygenSessionCommand {
    pub keygen_session_id: SessionId,
    pub coordinator_encrypted_private_key: Option<String>,
    pub coordinator_user_id: Option<UserId>,
    pub encrypted_session_secret: Option<String>,
    pub timeout_secs: u64,
    pub taproot_tweak: TaprootTweak,
    pub expected_participant_count: usize,
    pub expected_participants: Vec<UserId>,
    pub enclave_public_keys: Vec<EnclavePublicKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitSigningSessionCommand {
    pub keygen_session_id: SessionId,
    pub signing_session_id: SessionId,
    pub encrypted_message: String,
    pub timeout_secs: u64,
    pub taproot_tweak: TaprootTweak,
    pub expected_participant_count: usize,
    pub encrypted_adaptor_configs: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddParticipantCommand {
    pub keygen_session_id: Option<SessionId>,
    pub signing_session_id: Option<SessionId>,
    pub user_id: UserId,
    pub enclave_encrypted_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributeParticipantPublicKeyCommand {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub encrypted_participant_public_key: String,
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
    pub nonce_data: NonceData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParitialSignatureCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddPartialSignatureCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub signer_index: usize,
    pub signature_data: SignatureData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAggregatePublicKeyCommand {
    pub keygen_session_id: SessionId,
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
pub struct GetEnclavePublicKeysCommand {
    pub enclave_ids: Vec<EnclaveId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedParticipantPublicKey {
    pub target_enclave_id: EnclaveId,
    pub encrypted_public_key: String, // Encrypted with target enclave's public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantAddedResponse {
    pub user_id: UserId,
    pub encrypted_public_keys: Vec<EncryptedParticipantPublicKey>,
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
    pub nonce_data: NonceData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureData {
    Regular(PartialSignature),
    Adaptor(Vec<(uuid::Uuid, PartialSignature)>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NonceData {
    Regular(PubNonce),
    Adaptor(Vec<(uuid::Uuid, PubNonce)>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub signature_data: SignatureData,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct FinalSignatureResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub final_signature: Vec<u8>,
    pub participant_count: usize,
    pub encrypted_adaptor_signatures: Option<Vec<u8>>,
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
    pub attestation_document: Option<AttestationDocument>,
    pub active_sessions: u32,
    pub uptime_seconds: u64,
    pub key_epoch: u64,
    pub key_generation_time: u64,
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
pub struct SessionSecretResponse {
    pub session_secret: String,
    pub enclave_id: EnclaveId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorPartialSignatureResponse {
    pub signing_session_id: SessionId,
    pub user_id: UserId,
    pub adaptor_id: uuid::Uuid,
    pub partial_signature: String, // Hex-encoded partial signature
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorSignaturesResponse {
    pub signing_session_id: SessionId,
    pub adaptor_signatures: String,
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

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

// Sub-error types for clean error handling

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum ValidationError {
    #[error("Encrypted message cannot be empty")]
    EmptyEncryptedMessage,
    #[error("Decrypted message is empty")]
    EmptyDecryptedMessage,
    #[error("User {user_id} not found in expected participants")]
    UserNotFound { user_id: UserId },
    #[error("Signer index {index} exceeds expected participant count {expected}")]
    IndexOutOfBounds { index: usize, expected: usize },
    #[error("Invalid private key length: expected 32 bytes, got {actual}")]
    InvalidPrivateKeyLength { actual: usize },
    #[error("Message too large: {size} bytes (max 4MB)")]
    MessageTooLarge { size: usize },
    #[error("Cannot process commands in {state} state")]
    InvalidStateForCommand { state: String },
    #[error("Expected participant count must be greater than 0")]
    ZeroParticipantCount,
    #[error("Timeout must be greater than 0")]
    ZeroTimeout,
    #[error("Invalid nonce length: expected 66 bytes, got {actual}")]
    InvalidNonceLength { actual: usize },
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum CryptoError {
    #[error("Failed to generate keypair: {0}")]
    KeypairGeneration(String),
    #[error("Failed to encrypt {context}: {error}")]
    EncryptionFailed { context: String, error: String },
    #[error("Failed to decrypt {context}: {error}")]
    DecryptionFailed { context: String, error: String },
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("Private key too short: expected 32 bytes, got {actual}")]
    PrivateKeyTooShort { actual: usize },
    #[error("Failed to finalize signature: {0}")]
    SignatureFinalization(String),
    #[error("Failed to aggregate signatures: {0}")]
    SignatureAggregation(String),
    #[error("Failed to add participant to musig processor: {0}")]
    ParticipantAddition(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum NonceError {
    #[error("Failed to generate nonce for user {user_id}: {error}")]
    GenerationFailed { user_id: UserId, error: String },
    #[error("Failed to add nonce for user {user_id}: {error}")]
    AddFailed { user_id: UserId, error: String },
    #[error("Invalid nonce length: expected 66 bytes, got {actual}")]
    InvalidLength { actual: usize },
    #[error("Aggregate nonce not available in state {state}")]
    NotAvailable { state: String },
    #[error("Cannot get aggregate nonce from non-signing session")]
    WrongSessionType,
    #[error("Failed to convert AggNonce to PubNonce: {0}")]
    ConversionFailed(String),
    #[error("Failed to get aggregate nonce: {0}")]
    AggregateNonceFailed(String),
    #[error("No nonce found for user {user_id}")]
    NonceNotFound { user_id: UserId },
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum SigningError {
    #[error("Failed to generate partial signature for user {user_id}: {error}")]
    PartialSignatureGeneration { user_id: UserId, error: String },
    #[error("Adaptor partial signature generation failed: {0}")]
    AdaptorPartialSignatureGeneration(String),
    #[error("Failed to deserialize partial signature: {0}")]
    PartialSignatureDeserialization(String),
    #[error("Failed to deserialize adaptor partial signature: {0}")]
    AdaptorPartialSignatureDeserialization(String),
    #[error("Failed to aggregate signatures: {0}")]
    SignatureAggregation(String),
    #[error("Adaptor signature aggregation failed: {0}")]
    AdaptorSignatureAggregation(String),
    #[error("Failed to get adaptor signature results: {0}")]
    AdaptorResultsRetrieval(String),
    #[error("No partial signature found for user {user_id}")]
    PartialSignatureNotFound { user_id: UserId },
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    NotFound(SessionId),
    #[error("Invalid session ID: {0}")]
    InvalidId(String),
    #[error("Session secret not initialized")]
    SecretNotInitialized,
    #[error("Invalid session secret length: expected 32 bytes, got {actual}")]
    InvalidSecretLength { actual: usize },
    #[error("Failed to initialize MuSig2 for keygen: {0}")]
    MusigInitialization(String),
    #[error("Failed to copy metadata from keygen {keygen_id} to signing {signing_id}: {error}")]
    MetadataCopy {
        keygen_id: SessionId,
        signing_id: SessionId,
        error: String,
    },
    #[error("Failed to update session message: {0}")]
    MessageUpdate(String),
    #[error("Failed to get aggregate public key: {0}")]
    AggregateKeyRetrieval(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum PhaseError {
    #[error("Keygen session not completed")]
    KeygenNotCompleted,
    #[error("Keygen session required to be in completed state: {state}")]
    KeygenInWrongState { state: String },
    #[error("Wrong phase: {0}")]
    WrongPhase(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum AttestationError {
    #[error("Failed to generate attestation: {0}")]
    GenerationFailed(String),
    #[error("Debug mode attestations not allowed")]
    DebugModeNotAllowed,
    #[error("Failed to parse measurements JSON: {0}")]
    MeasurementParsing(String),
    #[error("PCR {pcr_name} has invalid length: expected 48 bytes, got {actual}")]
    InvalidPcrLength { pcr_name: String, actual: usize },
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum InternalError {
    #[error("System time error")]
    SystemTime,
    #[error("NSM client not initialized")]
    NsmNotInitialized,
    #[error("MuSig processor not found for session")]
    MissingMusigProcessor,
    #[error("State inconsistency: {0}")]
    StateInconsistency(String),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Command processing failed: {0}")]
    CommandProcessing(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum PrivateKeyError {
    #[error("Missing private key for user {user_id}")]
    Missing { user_id: UserId },
    #[error("Invalid private key length: expected 32 bytes, got {actual}")]
    InvalidLength { actual: usize },
    #[error("Invalid private key: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum DataDecodingError {
    #[error("Hex decode failed: {0}")]
    HexDecode(String),
    #[error("Failed to decode {data_type}: {error}")]
    DecodeFailed { data_type: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum ParticipantError {
    #[error("Participant error: {0}")]
    Other(String),
}

// Main EnclaveError enum with hierarchical structure
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum EnclaveError {
    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Nonce(#[from] NonceError),

    #[error(transparent)]
    Signing(#[from] SigningError),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error(transparent)]
    Phase(#[from] PhaseError),

    #[error(transparent)]
    Attestation(#[from] AttestationError),

    #[error(transparent)]
    Internal(#[from] InternalError),

    #[error(transparent)]
    PrivateKey(#[from] PrivateKeyError),

    #[error(transparent)]
    DataDecoding(#[from] DataDecodingError),

    #[error(transparent)]
    Participant(#[from] ParticipantError),

    #[error(transparent)]
    Musig(#[from] crate::musig::MusigError),

    #[error("KeyMeld error: {0}")]
    KeyMeld(String),
}

impl From<hex::FromHexError> for EnclaveError {
    fn from(err: hex::FromHexError) -> Self {
        EnclaveError::DataDecoding(DataDecodingError::HexDecode(err.to_string()))
    }
}

impl From<musig2::secp256k1::Error> for EnclaveError {
    fn from(err: musig2::secp256k1::Error) -> Self {
        EnclaveError::Crypto(CryptoError::InvalidPublicKey(err.to_string()))
    }
}

impl From<KeyMeldError> for EnclaveError {
    fn from(err: KeyMeldError) -> Self {
        EnclaveError::KeyMeld(err.to_string())
    }
}
