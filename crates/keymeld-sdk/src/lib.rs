use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

pub use keymeld_core::crypto::{EncryptedData, SecureCrypto, SessionSecret};
pub use keymeld_core::hash_message;
pub use keymeld_core::identifiers::{EnclaveId, SessionId, UserId};
pub use keymeld_core::protocol::{
    AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, KeygenStatusKind,
    SigningStatusKind, TaprootTweak,
};
pub use keymeld_core::validation;
pub use keymeld_core::AggregatePublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReserveKeygenSessionRequest {
    pub keygen_session_id: SessionId,
    pub coordinator_user_id: UserId,
    pub expected_participants: Vec<UserId>,
    pub timeout_secs: u64,
    pub max_signing_sessions: Option<u32>,
    /// Optional taproot tweak. Empty string means no tweak.
    #[serde(default)]
    pub encrypted_taproot_tweak: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReserveKeygenSessionResponse {
    pub keygen_session_id: SessionId,
    pub coordinator_enclave_id: EnclaveId,
    pub coordinator_public_key: String,
    pub coordinator_key_epoch: u64,
    pub expected_participants: usize,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct InitializeKeygenSessionRequest {
    pub coordinator_pubkey: Vec<u8>,
    pub coordinator_encrypted_private_key: String,
    pub session_public_key: Vec<u8>,
    pub encrypted_session_secret: String,
    pub encrypted_session_data: String,
    pub encrypted_enclave_data: String,
    pub enclave_key_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct InitializeKeygenSessionResponse {
    pub keygen_session_id: SessionId,
    pub status: KeygenStatusKind,
    pub session_secret: String,
    pub session_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RegisterKeygenParticipantRequest {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub encrypted_private_key: String,
    pub public_key: Vec<u8>,
    pub encrypted_session_data: String,
    pub enclave_public_key: String,
    /// Enclave key epoch. 0 accepts any epoch; non-zero requires exact match.
    #[serde(default)]
    pub enclave_key_epoch: u64,
    #[serde(default)]
    pub require_signing_approval: bool,
    pub auth_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct RegisterKeygenParticipantResponse {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub status: KeygenStatusKind,
    pub participants_registered: usize,
    pub expected_participants: usize,
    pub signer_index: usize,
    pub assigned_enclave_id: EnclaveId,
    #[serde(default)]
    pub require_signing_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct KeygenSessionStatusResponse {
    pub keygen_session_id: SessionId,
    pub status: KeygenStatusKind,
    pub expected_participants: usize,
    pub registered_participants: usize,
    pub aggregate_public_key: Option<AggregatePublicKey>,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct CreateSigningSessionRequest {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub message_hash: Vec<u8>,
    pub encrypted_message: Option<String>,
    pub timeout_secs: u64,
    /// Optional adaptor signature configs. Empty string for regular signatures.
    #[serde(default)]
    pub encrypted_adaptor_configs: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct CreateSigningSessionResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub status: SigningStatusKind,
    pub participants_count: usize,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SigningSessionStatusResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub status: SigningStatusKind,
    pub participants_registered: usize,
    pub expected_participants: usize,
    pub final_signature: Option<String>,
    pub expires_at: u64,
    #[serde(default)]
    pub participants_requiring_approval: Vec<UserId>,
    #[serde(default)]
    pub approved_participants: Vec<UserId>,
    #[serde(default)]
    pub adaptor_signatures: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct EnclaveAssignmentResponse {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_public_key: String,
    pub enclave_cid: u32,
    pub enclave_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct AvailableUserSlot {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub signer_index: usize,
    pub claimed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct GetAvailableSlotsResponse {
    pub session_id: SessionId,
    pub available_slots: Vec<AvailableUserSlot>,
    pub total_slots: usize,
    pub claimed_slots: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct EnclavePublicKeyResponse {
    pub enclave_id: u32,
    pub public_key: String,
    pub attestation_document: String,
    pub pcr_measurements: HashMap<String, String>,
    pub timestamp: u64,
    pub healthy: bool,
    pub key_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct EnclaveHealthResponse {
    pub enclave_id: EnclaveId,
    pub healthy: bool,
    pub public_key: String,
    pub attestation_document: String,
    pub active_sessions: u32,
    pub uptime_seconds: u64,
    pub key_epoch: u64,
    pub key_generation_time: u64,
    pub last_health_check: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ListEnclavesResponse {
    pub enclaves: Vec<EnclaveHealthResponse>,
    pub total_enclaves: u32,
    pub healthy_enclaves: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct HealthCheckResponse {
    pub status: String,
    pub version: String,
    pub active_sessions: u32,
    pub healthy_enclaves: u32,
    pub total_enclaves: u32,
    pub database_stats: Option<DatabaseStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct DatabaseStats {
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub total_participants: i64,
    pub database_size_bytes: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ApiVersionResponse {
    pub service: String,
    pub version: String,
    pub api_version: String,
    pub features: ApiFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ApiFeatures {
    pub service_participation: bool,
    pub user_authentication: bool,
    pub enclave_isolation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ErrorResponse {
    pub error_code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
    pub retryable: bool,
}

pub fn validate_reserve_keygen_session_request(
    request: &ReserveKeygenSessionRequest,
) -> Result<(), keymeld_core::KeyMeldError> {
    validation::Validator::validate_vec_length(
        &request.expected_participants,
        Some(1),
        Some(1000),
        "Expected participants",
    )?;
    validation::Validator::validate_timeout_range(Some(request.timeout_secs))?;
    Ok(())
}

pub fn validate_initialize_keygen_session_request(
    request: &InitializeKeygenSessionRequest,
) -> Result<(), keymeld_core::KeyMeldError> {
    validation::Validator::validate_vec_length(
        &request.coordinator_pubkey,
        Some(33),
        Some(65),
        "Coordinator public key",
    )?;

    validation::Validator::validate_non_empty_string(
        &request.coordinator_encrypted_private_key,
        "Coordinator encrypted private key",
    )?;

    validation::Validator::validate_vec_length(
        &request.session_public_key,
        Some(33),
        Some(65),
        "Session public key",
    )?;
    validation::Validator::validate_non_empty_string(
        &request.encrypted_session_secret,
        "Encrypted session secret",
    )?;
    Ok(())
}

pub fn validate_register_keygen_participant_request(
    request: &RegisterKeygenParticipantRequest,
    session_signature: &str,
) -> Result<(), keymeld_core::KeyMeldError> {
    validation::Validator::validate_non_empty_string(
        &request.encrypted_private_key,
        "Encrypted private key",
    )?;
    validation::Validator::validate_non_empty_string(
        &request.encrypted_session_data,
        "Encrypted session data",
    )?;
    validation::Validator::validate_non_empty_string(session_signature, "Session signature")?;
    Ok(())
}

pub fn validate_create_signing_session_request(
    request: &CreateSigningSessionRequest,
) -> Result<(), keymeld_core::KeyMeldError> {
    validation::Validator::validate_vec_length(
        &request.message_hash,
        Some(32),
        Some(32),
        "Message hash",
    )?;
    if let Some(encrypted_message) = &request.encrypted_message {
        validation::Validator::validate_non_empty_string(encrypted_message, "Encrypted message")?;
    }
    validation::Validator::validate_timeout_range(Some(request.timeout_secs))?;

    Ok(())
}
