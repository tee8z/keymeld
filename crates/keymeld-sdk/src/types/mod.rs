use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

// Re-export core types that are part of the API
pub use keymeld_core::identifiers::{EnclaveId, KeyId, SessionId, UserId};
pub use keymeld_core::protocol::{
    AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, KeygenStatusKind,
    SignatureType, SigningStatusKind, TaprootTweak, UserKeyInfo,
};
pub use keymeld_core::AggregatePublicKey;

pub const MAX_SUBSET_DEFINITIONS: usize = 200;
pub const MAX_BATCH_SIZE: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SubsetDefinition {
    pub subset_id: Uuid,
    pub participants: Vec<UserId>,
}

impl SubsetDefinition {
    pub fn new(participants: Vec<UserId>) -> Self {
        Self {
            subset_id: Uuid::now_v7(),
            participants,
        }
    }

    pub fn with_id(subset_id: Uuid, participants: Vec<UserId>) -> Self {
        Self {
            subset_id,
            participants,
        }
    }

    pub fn id(&self) -> Uuid {
        self.subset_id
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReserveKeygenSessionRequest {
    pub keygen_session_id: SessionId,
    pub coordinator_user_id: UserId,
    pub expected_participants: Vec<UserId>,
    pub timeout_secs: u64,
    pub max_signing_sessions: Option<u32>,
    #[serde(default)]
    pub encrypted_taproot_tweak: String,
    #[serde(default)]
    pub subset_definitions: Vec<SubsetDefinition>,
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
    #[serde(default)]
    pub encrypted_subset_aggregates: BTreeMap<Uuid, String>,
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
pub struct CreateSigningSessionRequest {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub timeout_secs: u64,
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
    #[serde(default)]
    pub batch_results: Vec<BatchItemResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SigningMode {
    Regular {
        encrypted_message: String,
    },
    Adaptor {
        encrypted_message: String,
        encrypted_adaptor_configs: String,
    },
}

impl SigningMode {
    pub fn encrypted_message(&self) -> &str {
        match self {
            SigningMode::Regular { encrypted_message } => encrypted_message,
            SigningMode::Adaptor {
                encrypted_message, ..
            } => encrypted_message,
        }
    }

    pub fn encrypted_adaptor_configs(&self) -> Option<&str> {
        match self {
            SigningMode::Regular { .. } => None,
            SigningMode::Adaptor {
                encrypted_adaptor_configs,
                ..
            } => Some(encrypted_adaptor_configs),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SigningBatchItem {
    pub batch_item_id: Uuid,
    pub message_hash: Vec<u8>,
    pub signing_mode: SigningMode,
    pub encrypted_taproot_tweak: String,
    #[serde(default)]
    pub subset_id: Option<Uuid>,
}

impl SigningBatchItem {
    pub fn new(
        message_hash: Vec<u8>,
        encrypted_taproot_tweak: String,
        signing_mode: SigningMode,
    ) -> Self {
        Self {
            batch_item_id: Uuid::now_v7(),
            message_hash,
            signing_mode,
            encrypted_taproot_tweak,
            subset_id: None,
        }
    }

    pub fn with_subset(mut self, subset_id: Uuid) -> Self {
        self.subset_id = Some(subset_id);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct BatchItemResult {
    pub batch_item_id: Uuid,
    pub signature: Option<String>,
    pub adaptor_signatures: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct BatchItemApproval {
    pub batch_item_id: Uuid,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ReserveKeySlotRequest {
    pub user_id: UserId,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImportUserKeyRequest {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub encrypted_private_key: String,
    pub auth_pubkey: Vec<u8>,
    pub enclave_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ImportUserKeyResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct ListUserKeysResponse {
    pub user_id: UserId,
    pub keys: Vec<UserKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct DeleteUserKeyResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct KeyStatusResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub status: String,
    pub error_message: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct StoreKeyFromKeygenRequest {
    pub key_id: KeyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct StoreKeyFromKeygenResponse {
    pub key_id: KeyId,
    pub user_id: UserId,
    pub keygen_session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SignSingleRequest {
    pub user_id: UserId,
    pub key_id: KeyId,
    pub encrypted_message: String,
    pub signature_type: SignatureType,
    pub encrypted_session_secret: String,
    pub approval_signature: Vec<u8>,
    pub approval_timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SignSingleResponse {
    pub signing_session_id: SessionId,
    pub user_id: UserId,
    pub key_id: KeyId,
    pub status: SingleSigningStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SingleSigningStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SingleSigningStatusResponse {
    pub signing_session_id: SessionId,
    pub user_id: UserId,
    pub key_id: KeyId,
    pub status: SingleSigningStatus,
    pub encrypted_signature: Option<String>,
    pub signature_type: Option<SignatureType>,
    pub error_message: Option<String>,
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
    keymeld_core::validation::Validator::validate_vec_length(
        &request.expected_participants,
        Some(1),
        Some(1000),
        "Expected participants",
    )?;
    keymeld_core::validation::Validator::validate_timeout_range(Some(request.timeout_secs))?;
    validate_subset_definitions(&request.subset_definitions, &request.expected_participants)?;
    Ok(())
}

pub fn validate_subset_definitions(
    subset_definitions: &[SubsetDefinition],
    expected_participants: &[UserId],
) -> Result<(), keymeld_core::KeyMeldError> {
    use std::collections::HashSet;

    // Check max subset count
    if subset_definitions.len() > MAX_SUBSET_DEFINITIONS {
        return Err(keymeld_core::KeyMeldError::ValidationError(format!(
            "Too many subset definitions: {} exceeds maximum of {}",
            subset_definitions.len(),
            MAX_SUBSET_DEFINITIONS
        )));
    }

    let expected_set: HashSet<_> = expected_participants.iter().collect();
    let mut seen_subset_ids = HashSet::new();

    for subset in subset_definitions {
        // Check for duplicate subset IDs
        if !seen_subset_ids.insert(subset.subset_id) {
            return Err(keymeld_core::KeyMeldError::ValidationError(format!(
                "Duplicate subset_id: {}",
                subset.subset_id
            )));
        }

        // Check subset has at least 2 participants
        if subset.participants.len() < 2 {
            return Err(keymeld_core::KeyMeldError::ValidationError(format!(
                "Subset {} must have at least 2 participants, got {}",
                subset.subset_id,
                subset.participants.len()
            )));
        }

        // Check all participants in subset are in expected_participants
        for user_id in &subset.participants {
            if !expected_set.contains(user_id) {
                return Err(keymeld_core::KeyMeldError::ValidationError(format!(
                    "Subset {} contains user {} who is not in expected_participants",
                    subset.subset_id, user_id
                )));
            }
        }

        // Check for duplicate participants within subset
        let mut seen_users = HashSet::new();
        for user_id in &subset.participants {
            if !seen_users.insert(user_id) {
                return Err(keymeld_core::KeyMeldError::ValidationError(format!(
                    "Subset {} contains duplicate user {}",
                    subset.subset_id, user_id
                )));
            }
        }
    }

    Ok(())
}

pub fn validate_initialize_keygen_session_request(
    request: &InitializeKeygenSessionRequest,
) -> Result<(), keymeld_core::KeyMeldError> {
    keymeld_core::validation::Validator::validate_vec_length(
        &request.coordinator_pubkey,
        Some(33),
        Some(65),
        "Coordinator public key",
    )?;

    keymeld_core::validation::Validator::validate_non_empty_string(
        &request.coordinator_encrypted_private_key,
        "Coordinator encrypted private key",
    )?;

    keymeld_core::validation::Validator::validate_vec_length(
        &request.session_public_key,
        Some(33),
        Some(65),
        "Session public key",
    )?;
    keymeld_core::validation::Validator::validate_non_empty_string(
        &request.encrypted_session_secret,
        "Encrypted session secret",
    )?;
    Ok(())
}

pub fn validate_register_keygen_participant_request(
    request: &RegisterKeygenParticipantRequest,
    session_signature: &str,
) -> Result<(), keymeld_core::KeyMeldError> {
    keymeld_core::validation::Validator::validate_non_empty_string(
        &request.encrypted_private_key,
        "Encrypted private key",
    )?;
    keymeld_core::validation::Validator::validate_non_empty_string(
        &request.encrypted_session_data,
        "Encrypted session data",
    )?;
    keymeld_core::validation::Validator::validate_non_empty_string(
        session_signature,
        "Session signature",
    )?;
    Ok(())
}

pub fn validate_create_signing_session_request(
    request: &CreateSigningSessionRequest,
) -> Result<(), keymeld_core::KeyMeldError> {
    keymeld_core::validation::Validator::validate_timeout_range(Some(request.timeout_secs))?;
    validate_batch_signing_request(&request.batch_items)?;
    Ok(())
}

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
        keymeld_core::validation::Validator::validate_vec_length(
            &item.message_hash,
            Some(32),
            Some(32),
            &format!("Message hash for batch item {}", item.batch_item_id),
        )?;

        // Validate signing mode
        match &item.signing_mode {
            SigningMode::Regular { encrypted_message } => {
                keymeld_core::validation::Validator::validate_non_empty_string(
                    encrypted_message,
                    &format!("Encrypted message for batch item {}", item.batch_item_id),
                )?;
            }
            SigningMode::Adaptor {
                encrypted_message,
                encrypted_adaptor_configs,
            } => {
                keymeld_core::validation::Validator::validate_non_empty_string(
                    encrypted_message,
                    &format!("Encrypted message for batch item {}", item.batch_item_id),
                )?;
                keymeld_core::validation::Validator::validate_non_empty_string(
                    encrypted_adaptor_configs,
                    &format!(
                        "Encrypted adaptor configs for batch item {}",
                        item.batch_item_id
                    ),
                )?;
            }
        }
    }

    Ok(())
}
