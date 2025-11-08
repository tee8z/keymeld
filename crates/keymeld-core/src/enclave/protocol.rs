use crate::{
    api::TaprootTweak,
    identifiers::{EnclaveId, SessionId, UserId},
};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
    pub public_key: Vec<u8>,
    pub encrypted_private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateNonceCommand {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub encrypted_private_key: Option<String>,
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
    pub encrypted_private_key: Option<String>,
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
pub struct SuccessResponse {
    pub message: String,
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
    pub user_data: Vec<u8>,
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
pub struct ErrorResponse {
    pub error: EnclaveError,
    pub message: String,
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveError {
    NotConfigured,
    AlreadyConfigured,
    InvalidPrivateKey,
    SessionNotFound,
    WrongPhase,
    MuSigError(String),
    HmacInvalid,
    MemoryExhausted,
    SessionLimitExceeded,
    Timeout,
    Internal(String),
}

impl std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnclaveError::NotConfigured => write!(f, "Enclave not configured"),
            EnclaveError::AlreadyConfigured => write!(f, "Enclave already configured"),
            EnclaveError::InvalidPrivateKey => write!(f, "Invalid private key"),
            EnclaveError::SessionNotFound => write!(f, "Session not found"),
            EnclaveError::WrongPhase => write!(f, "Wrong phase"),
            EnclaveError::MuSigError(msg) => write!(f, "MuSig error: {}", msg),
            EnclaveError::HmacInvalid => write!(f, "HMAC invalid"),
            EnclaveError::MemoryExhausted => write!(f, "Memory exhausted"),
            EnclaveError::SessionLimitExceeded => write!(f, "Session limit exceeded"),
            EnclaveError::Timeout => write!(f, "Timeout"),
            EnclaveError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for EnclaveError {}
