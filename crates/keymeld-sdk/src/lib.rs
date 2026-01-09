use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

pub use keymeld_core::crypto::{EncryptedData, SecureCrypto, SessionSecret};
pub use keymeld_core::hash_message;
pub use keymeld_core::identifiers::{EnclaveId, KeyId, SessionId, UserId};
pub use keymeld_core::protocol::{
    AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, KeygenStatusKind,
    SignatureType, SigningStatusKind, TaprootTweak, UserKeyInfo,
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
    pub timeout_secs: u64,

    // Single message fields (backward compat, used if batch_items is empty)
    #[serde(default)]
    pub message_hash: Vec<u8>,
    pub encrypted_message: Option<String>,
    /// Optional adaptor signature configs. Empty string for regular signatures.
    #[serde(default)]
    pub encrypted_adaptor_configs: String,

    // Batch of messages (takes precedence if non-empty)
    #[serde(default)]
    pub batch_items: Vec<SigningBatchItem>,
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
    pub expires_at: u64,
    #[serde(default)]
    pub participants_requiring_approval: Vec<UserId>,
    #[serde(default)]
    pub approved_participants: Vec<UserId>,

    // Single signature fields (backward compat / single-item batch)
    pub final_signature: Option<String>,
    #[serde(default)]
    pub adaptor_signatures: String,

    // Batch results (populated for batch sessions)
    #[serde(default)]
    pub batch_results: Vec<BatchItemResult>,
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

// ============================================================================
// User Key Management API Types
// ============================================================================

/// Request to reserve a key slot (step 1 of key import)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReserveKeySlotRequest {
    pub user_id: UserId,
}

/// Response from reserving a key slot
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReserveKeySlotResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_public_key: String,
    pub enclave_key_epoch: u64,
}

/// Request to import a user key (step 2 of key import)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImportUserKeyRequest {
    pub key_id: KeyId,
    pub user_id: UserId,
    /// Private key ECIES-encrypted to the assigned enclave's public key
    pub encrypted_private_key: String,
    /// Auth public key for authenticating future requests
    pub auth_pubkey: Vec<u8>,
    /// The enclave public key used for encryption (for validation)
    pub enclave_public_key: String,
}

/// Response after importing a user key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImportUserKeyResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
}

/// Response listing user's keys
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ListUserKeysResponse {
    pub user_id: UserId,
    pub keys: Vec<UserKeyInfo>,
}

/// Response after deleting a key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct DeleteUserKeyResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub deleted: bool,
}

/// Response for key operation status (import/store progress)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct KeyStatusResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    /// Status of the key operation: "pending", "processing", "completed", "failed"
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: u64,
}

/// Request to store a key from a completed keygen session
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct StoreKeyFromKeygenRequest {
    pub key_id: KeyId,
}

/// Response after storing key from keygen
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct StoreKeyFromKeygenResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub keygen_session_id: SessionId,
}

// ============================================================================
// Single-Signer Signing API Types
// ============================================================================

/// Request to create a single-signer signing session
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SignSingleRequest {
    pub user_id: UserId,
    pub key_id: KeyId,
    /// Message encrypted with session secret
    pub encrypted_message: String,
    pub signature_type: SignatureType,
    /// Session secret ECIES-encrypted to enclave's public key
    pub encrypted_session_secret: String,
    /// Approval signature: Sign(auth_privkey, SHA256(message_hash || key_id || approval_timestamp))
    /// Proves the user authorized this specific signing operation
    pub approval_signature: Vec<u8>,
    /// Timestamp used in approval signature (Unix timestamp in seconds)
    /// Enclave will reject if too old (prevents replay attacks)
    pub approval_timestamp: u64,
}

/// Response from creating a single-signer signing session
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SignSingleResponse {
    pub signing_session_id: SessionId,
    pub user_id: UserId,
    pub key_id: KeyId,
    pub status: SingleSigningStatus,
}

/// Status of a single-signer signing session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SingleSigningStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

/// Response for single-signer signing status query
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SingleSigningStatusResponse {
    pub signing_session_id: SessionId,
    pub user_id: UserId,
    pub key_id: KeyId,
    pub status: SingleSigningStatus,
    /// Signature encrypted with session secret (only when completed)
    pub encrypted_signature: Option<String>,
    pub signature_type: Option<SignatureType>,
    pub error_message: Option<String>,
}

// ============================================================================
// Batch Signing API Types
// ============================================================================

/// A single item in a batch signing request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SigningBatchItem {
    /// Unique identifier for this batch item (for correlation)
    pub batch_item_id: Uuid,
    /// The 32-byte message hash to sign
    pub message_hash: Vec<u8>,
    /// Optional encrypted message (for privacy)
    pub encrypted_message: Option<String>,
    /// Optional adaptor configuration for this specific message
    /// Empty string or None for regular signature
    pub encrypted_adaptor_configs: Option<String>,
}

/// Result for a single batch item
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct BatchItemResult {
    pub batch_item_id: Uuid,
    /// The final signature (if successful)
    pub signature: Option<String>,
    /// Adaptor signature results (if adaptor configs provided)
    pub adaptor_signatures: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Per-item approval for batch signing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct BatchItemApproval {
    pub batch_item_id: Uuid,
    /// Sign(auth_privkey, batch_item_id || message_hash || timestamp)
    pub signature: Vec<u8>,
    pub timestamp: u64,
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
    validation::Validator::validate_timeout_range(Some(request.timeout_secs))?;

    // If batch_items is non-empty, validate batch mode
    if !request.batch_items.is_empty() {
        validate_batch_signing_request(&request.batch_items)?;
    } else {
        // Single message mode (backward compat)
        validation::Validator::validate_vec_length(
            &request.message_hash,
            Some(32),
            Some(32),
            "Message hash",
        )?;
        if let Some(encrypted_message) = &request.encrypted_message {
            validation::Validator::validate_non_empty_string(
                encrypted_message,
                "Encrypted message",
            )?;
        }
    }

    Ok(())
}

/// Maximum number of items allowed in a batch signing request
pub const MAX_BATCH_SIZE: usize = 100;

pub fn validate_batch_signing_request(
    batch_items: &[SigningBatchItem],
) -> Result<(), keymeld_core::KeyMeldError> {
    use std::collections::HashSet;

    // Validate batch size
    if batch_items.is_empty() {
        return Err(keymeld_core::KeyMeldError::ValidationError(
            "Batch items cannot be empty".to_string(),
        ));
    }
    if batch_items.len() > MAX_BATCH_SIZE {
        return Err(keymeld_core::KeyMeldError::ValidationError(format!(
            "Batch size {} exceeds maximum of {}",
            batch_items.len(),
            MAX_BATCH_SIZE
        )));
    }

    // Validate unique batch item IDs
    let mut seen_ids = HashSet::new();
    for item in batch_items {
        if !seen_ids.insert(item.batch_item_id) {
            return Err(keymeld_core::KeyMeldError::ValidationError(format!(
                "Duplicate batch_item_id: {}",
                item.batch_item_id
            )));
        }

        // Validate each item's message hash
        validation::Validator::validate_vec_length(
            &item.message_hash,
            Some(32),
            Some(32),
            &format!("Message hash for batch item {}", item.batch_item_id),
        )?;

        // Validate encrypted message if present
        if let Some(encrypted_message) = &item.encrypted_message {
            validation::Validator::validate_non_empty_string(
                encrypted_message,
                &format!("Encrypted message for batch item {}", item.batch_item_id),
            )?;
        }
    }

    Ok(())
}
