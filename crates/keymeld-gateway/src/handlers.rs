use crate::{
    database::Database,
    errors::{ApiError, ApiResult},
    headers::{SessionSignature, UserSignature},
    metrics::Metrics,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::{Json, Response},
};
use axum_extra::TypedHeader;
use keymeld_core::crypto::SecureCrypto;
use secp256k1::PublicKey;
use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use keymeld_core::{
    api::{
        validation::{
            validate_create_keygen_session_request, validate_create_signing_session_request,
            validate_register_keygen_participant_request,
            validate_session_signature as api_validate_session_signature,
        },
        ApiFeatures, ApiVersionResponse, AvailableUserSlot, CreateKeygenSessionRequest,
        CreateKeygenSessionResponse, CreateSigningSessionRequest, CreateSigningSessionResponse,
        DatabaseStats, EnclaveHealthResponse, EnclavePublicKeyResponse, ErrorResponse,
        GetAvailableSlotsResponse, HealthCheckResponse, KeygenSessionStatusResponse,
        ListEnclavesResponse, RegisterKeygenParticipantRequest, RegisterKeygenParticipantResponse,
        SigningSessionStatusResponse,
    },
    enclave::EnclaveManager,
    identifiers::{SessionId, UserId},
    resilience::GatewayLimits,
    session::{KeygenSessionStatus, KeygenStatusKind, SigningStatusKind},
    AttestationDocument,
};
use log::error;
use prometheus::Encoder;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub enclave_manager: Arc<EnclaveManager>,
    pub metrics: Arc<Metrics>,
    pub gateway_limits: GatewayLimits,
    pub nonce_cache: Arc<Mutex<NonceCache>>,
}

/// Simple in-memory nonce cache for replay protection
pub struct NonceCache {
    used_nonces: HashSet<String>,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceCache {
    pub fn new() -> Self {
        Self {
            used_nonces: HashSet::new(),
            cleanup_interval: Duration::from_secs(300), // Clean every 5 minutes
            last_cleanup: Instant::now(),
        }
    }

    /// Check if nonce is already used and mark it as used if not
    pub fn check_and_insert(&mut self, nonce_key: &str) -> bool {
        // Perform cleanup if needed
        if self.last_cleanup.elapsed() >= self.cleanup_interval {
            self.cleanup_old_nonces();
            self.last_cleanup = Instant::now();
        }

        // Check if nonce is already used
        if self.used_nonces.contains(nonce_key) {
            false // Nonce already used
        } else {
            self.used_nonces.insert(nonce_key.to_string());
            true // Nonce is new
        }
    }

    /// Simple cleanup - for production, implement TTL-based cleanup
    fn cleanup_old_nonces(&mut self) {
        // For now, just limit size to prevent unbounded growth
        if self.used_nonces.len() > 10000 {
            self.used_nonces.clear();
        }
    }
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = OK, description = "Exports prometheus metrics for the service"),
        (status = INTERNAL_SERVER_ERROR, description = "Something went wrong trying to export prometheus metrics"),
    )
)]
pub async fn metrics(State(state): State<AppState>) -> Result<Response<Body>, ApiError> {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = state.metrics.export_metrics()?;
    let mut buffer = vec![];
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| ApiError::Internal(format!("Failed to encode metrics: {e}")))?;
    Response::builder()
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .map_err(|e| ApiError::Internal(format!("Failed to build response: {e}")))
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    summary = "health check endpoint",
    description = "Returns quick health status of the KeyMeld Gateway service",
    responses(
        (status = 200, description = "Service is healthy"),
        (status = 500, description = "Service is unhealthy", body = ErrorResponse),
    )
)]
pub async fn health_check(State(state): State<AppState>) -> ApiResult<StatusCode> {
    state.db.health_check().await?;

    let enclave_health = state.enclave_manager.health_check().await;

    let healthy_enclaves = enclave_health.values().filter(|&healthy| *healthy).count() as u32;
    let total_enclaves = enclave_health.len() as u32;
    if total_enclaves != healthy_enclaves {
        error!("not all enclaves {total_enclaves} are healthy {healthy_enclaves}");
        return Ok(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(StatusCode::OK)
}

#[utoipa::path(
    get,
    path = "/health/detail",
    tag = "health",
    summary = "Detailed health check endpoint",
    description = "Returns the overall health status of the KeyMeld Gateway service",
    responses(
        (status = 200, description = "Service is healthy", body = HealthCheckResponse),
        (status = 500, description = "Service is unhealthy", body = ErrorResponse),
    )
)]
pub async fn health_check_detail(
    State(state): State<AppState>,
) -> ApiResult<Json<HealthCheckResponse>> {
    state.db.health_check().await?;

    let enclave_health = state.enclave_manager.health_check().await;

    let healthy_enclaves = enclave_health.values().filter(|&healthy| *healthy).count() as u32;
    let total_enclaves = enclave_health.len() as u32;

    let db_stats = state.db.get_stats().await?;

    let response = HealthCheckResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_sessions: db_stats.active_sessions as u32,
        healthy_enclaves,
        total_enclaves,
        database_stats: Some(DatabaseStats {
            total_sessions: db_stats.total_sessions,
            active_sessions: db_stats.active_sessions,
            total_participants: db_stats.total_participants,
            database_size_bytes: db_stats.database_size_bytes.map(|v| v as i64),
        }),
    };

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/enclaves",
    tag = "enclaves",
    summary = "List all available enclaves",
    description = "Returns a list of all configured enclaves with their health status",
    responses(
        (status = 200, description = "Enclaves listed successfully", body = ListEnclavesResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn list_enclaves(State(state): State<AppState>) -> ApiResult<Json<ListEnclavesResponse>> {
    debug!("Listing all enclaves");

    // Get cached enclave health data from database
    let enclave_health_data = state.db.get_all_enclave_health().await?;
    let total_enclaves = enclave_health_data.len();
    let mut enclaves = Vec::new();
    let mut healthy_count = 0;

    for health_info in enclave_health_data {
        if health_info.is_healthy {
            healthy_count += 1;
        }

        // Calculate uptime from startup_time if available
        let uptime_seconds = if health_info.startup_time > 0 {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
                .as_secs();
            if current_time > health_info.startup_time {
                current_time.saturating_sub(health_info.startup_time)
            } else {
                0
            }
        } else {
            0
        };

        let health_response = EnclaveHealthResponse {
            enclave_id: keymeld_core::identifiers::EnclaveId::from(health_info.enclave_id),
            healthy: health_info.is_healthy,
            public_key: health_info.public_key,
            attestation_document: health_info.attestation_document,
            active_sessions: health_info.active_sessions,
            uptime_seconds,
            key_epoch: health_info.key_epoch,
            key_generation_time: health_info.key_generation_time,
            last_health_check: health_info.cached_at as u64,
        };
        enclaves.push(health_response);
    }

    let response = ListEnclavesResponse {
        enclaves,
        total_enclaves: total_enclaves
            .try_into()
            .map_err(|e| ApiError::Internal(format!("Invalid enclave count: {e}")))?,
        healthy_enclaves: healthy_count,
    };

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/keygen",
    tag = "keygen",
    summary = "Create a new keygen session",
    description = "Creates a new MuSig2 keygen session for distributed key generation",
    request_body = CreateKeygenSessionRequest,
    responses(
        (status = 200, description = "Keygen session created successfully", body = CreateKeygenSessionResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn create_keygen_session(
    State(state): State<AppState>,
    Json(mut request): Json<CreateKeygenSessionRequest>,
) -> ApiResult<Json<CreateKeygenSessionResponse>> {
    info!("Creating keygen session: {}", request.keygen_session_id);

    validate_create_keygen_session_request(&request)
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {e}")))?;

    // Sort expected_participants in descending order (newest UUIDv7 first) for consistency
    // This ensures all enclaves use the same participant ordering for signer indices
    request.expected_participants.sort_by(|a, b| b.cmp(a));
    debug!(
        "After sorting expected_participants in gateway: {:?}",
        request.expected_participants
    );

    // Refresh enclave public keys to prevent key mismatch errors
    info!("Refreshing enclave public keys before keygen session creation");
    let key_refresh_start = std::time::Instant::now();
    state
        .enclave_manager
        .initialize_enclave_public_keys()
        .await
        .map_err(|e| {
            ApiError::enclave_communication(format!("Failed to refresh enclave public keys: {e}"))
        })?;
    info!(
        "Enclave public keys refreshed successfully in {:?} before keygen session {}",
        key_refresh_start.elapsed(),
        request.keygen_session_id
    );

    if state
        .db
        .get_keygen_session_by_id(&request.keygen_session_id)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("Keygen session already exists"));
    }

    let session_secret = state.db.create_keygen_session(&request).await?;
    state
        .enclave_manager
        .create_session_assignment_with_coordinator(
            request.keygen_session_id.clone(),
            &request.expected_participants,
            &request.coordinator_user_id,
            request.coordinator_enclave_id,
        )
        .map_err(|e| {
            ApiError::enclave_communication(format!("Failed to create session assignment: {e}"))
        })?;

    // Enclave initialization will be handled during coordinator processing phase
    // with proper enclave public keys via orchestrate_keygen_session_initialization

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
        .as_secs();

    let response = CreateKeygenSessionResponse {
        keygen_session_id: request.keygen_session_id,
        coordinator_enclave_id: request.coordinator_enclave_id,
        status: KeygenStatusKind::CollectingParticipants,
        expected_participants: request.expected_participants.len(),
        expires_at: current_time + request.timeout_secs,
        enclave_epochs: HashMap::new(),
        session_secret,
        session_public_key: request.session_public_key,
    };

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/keygen/{keygen_session_id}/participants",
    tag = "keygen",
    summary = "Register participant in keygen session",
    description = "Registers a participant in a keygen session for distributed key generation. Requires X-Session-Signature header containing ECDSA signature in format 'nonce:signature' using seed-derived private key.",
    params(
        ("keygen_session_id" = SessionId, Path, description = "Keygen session ID")
    ),
    request_body = RegisterKeygenParticipantRequest,
    security(
        ("SessionSignature" = [])
    ),
    responses(
        (status = 200, description = "Participant registered successfully", body = RegisterKeygenParticipantResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-Session-Signature header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn register_keygen_participant(
    State(state): State<AppState>,
    Path(keygen_session_id): Path<SessionId>,
    TypedHeader(session_signature): TypedHeader<SessionSignature>,
    Json(request): Json<RegisterKeygenParticipantRequest>,
) -> ApiResult<Json<RegisterKeygenParticipantResponse>> {
    debug!(
        "Registering participant {} in keygen session {}",
        request.user_id, keygen_session_id
    );

    validate_register_keygen_participant_request(&request, session_signature.value())
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {e}")))?;

    validate_session_signature(&state.db, &keygen_session_id, session_signature.value()).await?;

    let session_status = state
        .db
        .get_keygen_session_by_id(&keygen_session_id)
        .await?
        .ok_or(ApiError::not_found("Keygen session not found"))?;

    // Get the session assignment to validate participant's assigned enclave
    let session_assignment = state
        .enclave_manager
        .get_session_assignment(&keygen_session_id)
        .map_err(|e| ApiError::Internal(format!("Failed to get session assignment: {e}")))?
        .ok_or(ApiError::Internal(
            "Session assignment not found".to_string(),
        ))?;

    // Get the pre-assigned enclave for this participant
    let assigned_enclave = session_assignment
        .get_user_enclave(&request.user_id)
        .unwrap_or(session_assignment.coordinator_enclave);

    // Validate that the participant is using the correct enclave's public key
    let expected_public_key = match state
        .db
        .get_enclave_health(assigned_enclave.as_u32())
        .await?
    {
        Some(health_info) => health_info.public_key,
        None => {
            return Err(ApiError::EnclaveCommunication(format!(
                "Assigned enclave {} is not healthy",
                assigned_enclave.as_u32()
            )));
        }
    };

    if expected_public_key != request.enclave_public_key {
        return Err(ApiError::bad_request(format!(
            "Participant {} must use assigned enclave {} (public key: {}), but provided public key: {}",
            request.user_id,
            assigned_enclave.as_u32(),
            &expected_public_key[..16],
            &request.enclave_public_key[..16]
        )));
    }

    debug!(
        "Validated participant {} assignment to enclave {} (public key: {})",
        request.user_id,
        assigned_enclave,
        &request.enclave_public_key[..16]
    );

    let enclave_key_epoch = state
        .enclave_manager
        .get_enclave_key_epoch(&assigned_enclave)
        .ok_or(ApiError::EnclaveCommunication(format!(
            "Cannot get key epoch for enclave {assigned_enclave}"
        )))?;

    let session_encrypted_json = request.encrypted_session_data.clone();

    // The client already encrypted the private key for the target enclave,
    // so we can use it directly without JSON wrapper or double encryption
    let enclave_encrypted_hex = request.encrypted_private_key.clone();

    state
        .db
        .register_keygen_participant_with_encrypted_data(
            &keygen_session_id,
            &request,
            assigned_enclave,
            enclave_key_epoch,
            session_encrypted_json,
            enclave_encrypted_hex,
        )
        .await?;

    let current_count = state
        .db
        .get_keygen_participant_count(&keygen_session_id)
        .await?;
    let new_count = current_count + 1;

    let response = RegisterKeygenParticipantResponse {
        keygen_session_id: request.keygen_session_id,
        user_id: request.user_id,
        status: session_status.kind(),
        participants_registered: new_count,
        expected_participants: session_status.expected_participants_count(),
        signer_index: current_count,
        assigned_enclave_id: assigned_enclave,
        require_signing_approval: request.require_signing_approval,
    };

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/keygen/{keygen_session_id}/status",
    tag = "keygen",
    summary = "Get keygen session status",
    description = "Retrieves the current status and details of a keygen session. Requires X-Session-Signature header containing ECDSA signature in format 'nonce:signature' using seed-derived private key.",
    security(
        ("SessionSignature" = [])
    ),
    params(
        ("keygen_session_id" = SessionId, Path, description = "Keygen session ID")
    ),
    responses(
        (status = 200, description = "Keygen status retrieved successfully", body = KeygenSessionStatusResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-Session-Signature header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn get_keygen_status(
    State(state): State<AppState>,
    Path(keygen_session_id): Path<SessionId>,
    TypedHeader(session_signature): TypedHeader<SessionSignature>,
) -> ApiResult<Json<KeygenSessionStatusResponse>> {
    debug!("Getting keygen session status: {}", keygen_session_id);

    let session_status = state
        .db
        .get_keygen_session_by_id(&keygen_session_id)
        .await?
        .ok_or(ApiError::not_found("Keygen session not found"))?;

    let _encrypted_session_secret = match &session_status {
        keymeld_core::session::KeygenSessionStatus::CollectingParticipants(s) => {
            &s.encrypted_session_secret
        }
        keymeld_core::session::KeygenSessionStatus::Completed(s) => &s.encrypted_session_secret,
        keymeld_core::session::KeygenSessionStatus::Failed(_) => {
            return Err(ApiError::bad_request(
                "Cannot get status for failed session",
            ));
        }
    };

    debug!(
        "Keygen status check - Signature value: '{}'",
        session_signature.value()
    );

    // Use new session signature validation with database-stored public key
    validate_session_signature(&state.db, &keygen_session_id, session_signature.value()).await?;

    let participant_count = state
        .db
        .get_keygen_participant_count(&keygen_session_id)
        .await?;

    let (status, expected_participants, aggregate_public_key, expires_at) =
        session_status.extract_status_info();

    let response = KeygenSessionStatusResponse {
        keygen_session_id,
        status,
        expected_participants,
        registered_participants: participant_count,
        aggregate_public_key,
        expires_at,
    };

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/signing",
    tag = "signing",
    summary = "Create a new signing session",
    description = "Creates a new MuSig2 signing session for an existing completed keygen session. Requires X-Session-Signature header containing ECDSA signature in format 'nonce:signature' using seed-derived private key.",
    request_body = CreateSigningSessionRequest,
    security(
        ("SessionSignature" = [])
    ),
    responses(
        (status = 200, description = "Signing session created successfully", body = CreateSigningSessionResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-Session-Signature header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted", body = ErrorResponse),
        (status = 404, description = "Keygen session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn create_signing_session(
    State(state): State<AppState>,
    TypedHeader(session_signature): TypedHeader<SessionSignature>,
    Json(request): Json<CreateSigningSessionRequest>,
) -> ApiResult<Json<CreateSigningSessionResponse>> {
    info!("Creating signing session: {}", request.signing_session_id);

    validate_create_signing_session_request(&request)
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {e}")))?;

    // Refresh enclave public keys to prevent key mismatch errors
    info!("Refreshing enclave public keys before signing session creation");
    let key_refresh_start = std::time::Instant::now();
    state
        .enclave_manager
        .initialize_enclave_public_keys()
        .await
        .map_err(|e| {
            ApiError::enclave_communication(format!("Failed to refresh enclave public keys: {e}"))
        })?;
    info!(
        "Enclave public keys refreshed successfully in {:?} before signing session {}",
        key_refresh_start.elapsed(),
        request.signing_session_id
    );

    validate_session_signature(
        &state.db,
        &request.keygen_session_id,
        session_signature.value(),
    )
    .await?;

    let session_status = state
        .db
        .get_keygen_session_by_id(&request.keygen_session_id)
        .await?
        .ok_or(ApiError::not_found("Keygen session not found"))?;

    session_status
        .coordinator_enclave_id()
        .ok_or(ApiError::bad_request("Coordinator enclave not found"))?;

    // Session signature validation is now handled above

    if state
        .db
        .get_signing_session_by_id(&request.signing_session_id)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("Signing session already exists"));
    }

    let max_signing_sessions = state
        .db
        .get_keygen_session_max_signing_sessions(&request.keygen_session_id)
        .await?
        .unwrap_or(state.gateway_limits.default_max_signing_sessions as i64);

    let existing_signing_sessions_count = state
        .db
        .count_signing_sessions_for_keygen(&request.keygen_session_id)
        .await
        .unwrap_or(0);

    if existing_signing_sessions_count >= max_signing_sessions {
        warn!(
            "Quota violation: keygen session {} already has {} signing sessions (max: {})",
            request.keygen_session_id, existing_signing_sessions_count, max_signing_sessions
        );

        state
            .metrics
            .record_quota_violation(&request.keygen_session_id);

        return Err(ApiError::bad_request(format!(
            "Quota exceeded: maximum {max_signing_sessions} signing sessions allowed per keygen session"
        )));
    }

    if !matches!(session_status, KeygenSessionStatus::Completed(_)) {
        return Err(ApiError::bad_request(
            "Keygen session must be completed before creating signing session",
        ));
    }

    state.db.create_signing_session(&request).await?;

    info!(
        "Created signing session {} in database - enclave initialization will be handled by background coordinator",
        request.signing_session_id
    );

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let participants_count = state
        .db
        .get_keygen_participant_count(&request.keygen_session_id)
        .await? as usize;

    let response = CreateSigningSessionResponse {
        signing_session_id: request.signing_session_id.clone(),
        keygen_session_id: request.keygen_session_id.clone(),
        status: SigningStatusKind::CollectingParticipants,
        participants_count,
        expires_at: current_time + request.timeout_secs,
    };

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/signing/{signing_session_id}/approve/{user_id}",
    tag = "signing",
    summary = "Approve a signing session as a participant",
    description = "Approve a MuSig2 signing session as a participant. Requires X-User-Signature header containing ECDSA signature in format 'nonce:signature' using the user's private key.",
    params(
        ("signing_session_id" = SessionId, Path, description = "Signing session ID"),
        ("user_id" = UserId, Path, description = "User ID of the participant")
    ),
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Signing session approved successfully"),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-User-Signature header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn approve_signing_session(
    State(state): State<AppState>,
    Path((signing_session_id, user_id)): Path<(SessionId, UserId)>,
    TypedHeader(user_signature): TypedHeader<UserSignature>,
) -> ApiResult<StatusCode> {
    info!("Approving signing session: {}", signing_session_id);

    let keygen_session_id = state
        .db
        .get_keygen_session_id_from_signing_session(&signing_session_id)
        .await?
        .ok_or(ApiError::not_found("Signing session not found"))?;

    // Verify that session assignment exists for the signing session
    // This ensures that orchestrate_signing_session_initialization has completed
    let signing_assignment = state
        .enclave_manager
        .get_session_assignment(&signing_session_id)
        .map_err(|e| {
            ApiError::enclave_communication(format!(
                "Failed to get signing session assignment: {e}"
            ))
        })?;

    if signing_assignment.is_none() {
        return Err(ApiError::not_found(
            "Signing session not ready - session initialization still in progress",
        ));
    }

    validate_user_signature_with_session_auth(
        &state,
        &signing_session_id,
        &keygen_session_id,
        &user_id,
        user_signature.value(),
    )
    .await?;

    state
        .db
        .approve_signing_session(&signing_session_id, &user_id)
        .await?;

    info!(
        "Signing session {} approved by user {}",
        signing_session_id, user_id
    );

    Ok(StatusCode::OK)
}

/// Validate session signature using database-stored public key (new seed-based method)
async fn validate_session_signature(
    db: &Database,
    session_id: &SessionId,
    signature_header: &str,
) -> Result<(), ApiError> {
    let public_key = match db.get_session_public_key(session_id).await? {
        Some(key) => key,
        None => return Err(ApiError::not_found("Session not found")),
    };

    api_validate_session_signature(&session_id.as_string(), signature_header, &public_key)
        .map_err(|e| ApiError::bad_request(format!("Session signature validation failed: {e}")))
}

async fn validate_user_signature_with_session_auth(
    state: &AppState,
    signing_session_id: &SessionId,
    keygen_session_id: &SessionId,
    user_id: &UserId,
    signature_header: &str,
) -> Result<(), ApiError> {
    let auth_pubkey_bytes = state
        .db
        .get_participant_auth_pubkey(user_id, keygen_session_id)
        .await?;

    let auth_pubkey = PublicKey::from_slice(&auth_pubkey_bytes)
        .map_err(|e| ApiError::bad_request(format!("Invalid auth pubkey: {e}")))?;

    // Parse the signature header (format: "nonce:signature")
    let (nonce_hex, signature_hex) = signature_header
        .split_once(':')
        .ok_or(ApiError::bad_request("Invalid signature header format"))?;

    let nonce = hex::decode(nonce_hex)
        .map_err(|e| ApiError::bad_request(format!("Invalid nonce hex: {e}")))?;
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| ApiError::bad_request(format!("Invalid signature hex: {e}")))?;

    // Check nonce for replay protection (scoped to signing session)
    let nonce_key = format!("{}:{}", signing_session_id, nonce_hex);
    {
        let mut nonce_cache = state.nonce_cache.lock().unwrap();
        if !nonce_cache.check_and_insert(&nonce_key) {
            return Err(ApiError::bad_request("Nonce already used"));
        }
    }

    // Verify the signature using the session auth pubkey
    let is_valid = SecureCrypto::verify_auth_signature_with_session_key(
        &auth_pubkey,
        &signing_session_id.as_string(),
        &user_id.as_string(),
        &nonce,
        &signature_bytes,
    )
    .map_err(|e| ApiError::bad_request(format!("Signature verification failed: {e}")))?;

    if !is_valid {
        return Err(ApiError::bad_request("Invalid user signature"));
    }

    Ok(())
}

#[utoipa::path(
    get,
    path = "/signing/{signing_session_id}/status/{user_id}",
    tag = "signing",
    summary = "Get signing session status",
    description = "Retrieves the current status and details of a signing session, including approval information when in collecting_participants status. Requires X-User-Signature header containing ECDSA signature in format 'nonce:signature' using the user's private key.",
    security(
        ("UserSignature" = [])
    ),
    params(
        ("signing_session_id" = SessionId, Path, description = "Signing session ID"),
        ("user_id" = UserId, Path, description = "User ID of the participant")
    ),
    responses(
        (status = 200, description = "Signing session status retrieved successfully", body = SigningSessionStatusResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-User-Signature header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn get_signing_status(
    State(state): State<AppState>,
    Path((signing_session_id, user_id)): Path<(SessionId, UserId)>,
    TypedHeader(user_signature): TypedHeader<UserSignature>,
) -> ApiResult<Json<SigningSessionStatusResponse>> {
    debug!("Getting signing session status: {}", signing_session_id);

    let session_status = state
        .db
        .get_signing_session_by_id(&signing_session_id)
        .await?
        .ok_or(ApiError::not_found("Signing session not found"))?;

    let keygen_session_id = state
        .db
        .get_keygen_session_id_from_signing_session(&signing_session_id)
        .await?
        .ok_or(ApiError::not_found("Signing session not found"))?;

    validate_user_signature_with_session_auth(
        &state,
        &signing_session_id,
        &keygen_session_id,
        &user_id,
        user_signature.value(),
    )
    .await?;

    let participant_count = state
        .db
        .get_signing_participant_count(&signing_session_id)
        .await?;

    let (
        status,
        expected_participants,
        final_signature,
        expires_at,
        participants_requiring_approval,
        approved_participants,
        adaptor_signatures,
    ) = session_status.extract_status_info();

    let response = SigningSessionStatusResponse {
        signing_session_id,
        keygen_session_id,
        status,
        participants_registered: participant_count,
        expected_participants,
        final_signature,
        expires_at,
        participants_requiring_approval,
        approved_participants,
        adaptor_signatures,
    };

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/enclaves/{enclave_id}/public-key",
    tag = "enclaves",
    summary = "Get enclave public key",
    description = "Retrieves the public key for a specific enclave",
    params(
        ("enclave_id" = u32, Path, description = "Enclave ID")
    ),
    responses(
        (status = 200, description = "Public key retrieved successfully", body = EnclavePublicKeyResponse),
        (status = 404, description = "Enclave not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn get_enclave_public_key(
    State(state): State<AppState>,
    Path(enclave_id): Path<u32>,
) -> ApiResult<Json<EnclavePublicKeyResponse>> {
    debug!("Getting public key for enclave: {}", enclave_id);

    let health_info =
        state
            .db
            .get_enclave_health(enclave_id)
            .await?
            .ok_or(ApiError::enclave_communication(format!(
                "Enclave {enclave_id} not found"
            )))?;

    let (attestation_document, pcr_measurements) = if !health_info.attestation_document.is_empty() {
        match serde_json::from_str::<AttestationDocument>(&health_info.attestation_document) {
            Ok(attestation) => {
                let pcrs = attestation
                    .pcrs
                    .iter()
                    .map(|(k, v)| (k.clone(), hex::encode(v)))
                    .collect();
                (health_info.attestation_document.clone(), pcrs)
            }
            Err(_) => (health_info.attestation_document.clone(), HashMap::new()),
        }
    } else {
        (String::new(), HashMap::new())
    };

    let response = EnclavePublicKeyResponse {
        enclave_id,
        public_key: health_info.public_key,
        attestation_document,
        pcr_measurements,
        timestamp: health_info.cached_at as u64,
        healthy: health_info.is_healthy,
    };

    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/version",
    tag = "health",
    summary = "Get API version information",
    description = "Returns version and feature information for the KeyMeld Gateway API",
    responses(
        (status = 200, description = "Version information retrieved successfully", body = ApiVersionResponse),
    )
)]
pub async fn api_version() -> ApiResult<Json<ApiVersionResponse>> {
    let response = ApiVersionResponse {
        service: "KeyMeld Gateway".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: "v1".to_string(),
        features: ApiFeatures {
            service_participation: true,
            user_authentication: true,
            enclave_isolation: true,
        },
    };
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/keygen/{keygen_session_id}/slots",
    tag = "keygen",
    summary = "Get available slots for keygen session",
    description = "Returns available user slots for registration in a keygen session. Each slot has a deterministic signer index used for the signing process.",
    params(
        ("keygen_session_id" = SessionId, Path, description = "Keygen session ID")
    ),
    responses(
        (status = 200, description = "Available slots retrieved successfully", body = GetAvailableSlotsResponse),
        (status = 404, description = "Keygen session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn get_available_slots(
    State(state): State<AppState>,
    Path(keygen_session_id): Path<SessionId>,
) -> ApiResult<Json<GetAvailableSlotsResponse>> {
    debug!(
        "Getting available slots for keygen session: {}",
        keygen_session_id
    );

    let session_status = state
        .db
        .get_keygen_session_by_id(&keygen_session_id)
        .await?
        .ok_or(ApiError::not_found("Keygen session not found"))?;

    let (expected_participants, registered_participants) = match session_status {
        KeygenSessionStatus::CollectingParticipants(ref status) => (
            &status.expected_participants,
            &status.registered_participants,
        ),
        _ => {
            return Err(ApiError::bad_request(
                "Keygen session is not accepting new participants",
            ))
        }
    };

    // Get the session assignment to determine which enclaves participants should use
    let session_assignment = state
        .enclave_manager
        .get_session_assignment(&keygen_session_id)
        .map_err(|e| ApiError::Internal(format!("Failed to get session assignment: {e}")))?
        .ok_or(ApiError::Internal(
            "Session assignment not found".to_string(),
        ))?;

    let mut available_slots = Vec::new();
    let mut signer_index = 0;

    for expected_user_id in expected_participants {
        // Skip if this participant is already registered
        if registered_participants.contains_key(expected_user_id) {
            signer_index += 1;
            continue;
        }

        // Get the pre-assigned enclave for this participant
        let assigned_enclave_id = session_assignment
            .get_user_enclave(expected_user_id)
            .unwrap_or(session_assignment.coordinator_enclave);

        available_slots.push(AvailableUserSlot {
            user_id: expected_user_id.clone(),
            enclave_id: assigned_enclave_id,
            signer_index,
            claimed: false,
        });

        signer_index += 1;
    }

    let response = GetAvailableSlotsResponse {
        session_id: keygen_session_id
            .to_string()
            .try_into()
            .map_err(|e| ApiError::Internal(format!("Invalid session ID format: {e}")))?,
        available_slots,
        total_slots: expected_participants.len(),
        claimed_slots: registered_participants.len(),
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {

    use keymeld_core::{
        api::{
            validation::{
                decrypt_adaptor_configs, encrypt_adaptor_configs_for_client,
                validate_decrypted_adaptor_configs,
            },
            CreateSigningSessionRequest,
        },
        identifiers::SessionId,
        musig::{AdaptorConfig, AdaptorHint, AdaptorType},
    };
    use uuid::Uuid;

    #[test]
    fn test_client_side_privacy_architecture() {
        let adaptor_config = AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Single,
            adaptor_points: vec![
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
            ],
            hints: None,
        };

        let json = serde_json::to_string(&adaptor_config).expect("Should serialize");
        assert!(json.contains(&adaptor_config.adaptor_id.to_string()));
        assert!(json.contains("Single"));

        let deserialized: AdaptorConfig = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.adaptor_id, adaptor_config.adaptor_id);
        assert!(matches!(deserialized.adaptor_type, AdaptorType::Single));

        let request = CreateSigningSessionRequest {
            signing_session_id: SessionId::new_v7(),
            keygen_session_id: SessionId::new_v7(),
            message_hash: vec![0u8; 32],
            encrypted_message: Some("test_message".to_string()),
            timeout_secs: 3600,
            encrypted_adaptor_configs: serde_json::to_string(&serde_json::json!({
                "ciphertext": "a1b2c3d4e5f6...encrypted_blob",
                "nonce": "9f8e7d6c5b4a3210",
                "context": "adaptor_configs"
            }))
            .unwrap(),
        };

        let request_json = serde_json::to_string(&request).expect("Should serialize request");
        assert!(request_json.contains("encrypted_adaptor_configs"));
        assert!(request_json.contains("encrypted_blob"));
        assert!(!request_json.contains(&adaptor_config.adaptor_id.to_string()));
        assert!(!request_json.contains("oracle"));
    }

    #[test]
    fn test_empty_encrypted_adaptor_configs_default() {
        let request = CreateSigningSessionRequest {
            signing_session_id: SessionId::new_v7(),
            keygen_session_id: SessionId::new_v7(),
            message_hash: vec![0u8; 32],
            encrypted_message: None,
            timeout_secs: 3600,
            encrypted_adaptor_configs: String::new(),
        };

        assert!(request.encrypted_adaptor_configs.is_empty());

        let json = serde_json::to_string(&request).expect("Should serialize");
        let deserialized: CreateSigningSessionRequest =
            serde_json::from_str(&json).expect("Should deserialize");
        assert!(deserialized.encrypted_adaptor_configs.is_empty());
    }

    #[test]
    fn test_client_side_encryption_flow() {
        let session_secret = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678";

        let client_adaptor_configs = vec![
            AdaptorConfig {
                adaptor_id: Uuid::now_v7(),
                adaptor_type: AdaptorType::Single,
                adaptor_points: vec![
                    "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
                        .to_string(),
                ],
                hints: None,
            },
            AdaptorConfig {
                adaptor_id: Uuid::now_v7(),
                adaptor_type: AdaptorType::And,
                adaptor_points: vec![
                    "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
                        .to_string(),
                    "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66"
                        .to_string(),
                ],
                hints: None,
            },
        ];

        let encrypted = encrypt_adaptor_configs_for_client(&client_adaptor_configs, session_secret)
            .expect("Client should encrypt adaptor configs");

        assert!(!encrypted.is_empty());
        // The encrypted string is hex-encoded JSON, so decode and check the JSON structure
        let decoded_bytes = hex::decode(&encrypted).expect("Should decode hex");
        let decoded_json = String::from_utf8(decoded_bytes).expect("Should decode UTF-8");
        let json_value: serde_json::Value =
            serde_json::from_str(&decoded_json).expect("Should parse JSON");

        assert!(json_value.get("ciphertext").is_some());
        assert!(json_value.get("nonce").is_some());
        assert!(json_value.get("context").is_some());

        assert!(!encrypted.contains(&client_adaptor_configs[0].adaptor_id.to_string()));
        assert!(!encrypted.contains(&client_adaptor_configs[1].adaptor_id.to_string()));

        let enclave_decrypted = decrypt_adaptor_configs(&encrypted, session_secret)
            .expect("Enclave should decrypt adaptor configs");

        assert_eq!(enclave_decrypted.len(), 2);
        assert_eq!(
            enclave_decrypted[0].adaptor_id,
            client_adaptor_configs[0].adaptor_id
        );
        assert_eq!(
            enclave_decrypted[1].adaptor_id,
            client_adaptor_configs[1].adaptor_id
        );
        assert!(matches!(
            enclave_decrypted[0].adaptor_type,
            AdaptorType::Single
        ));
        assert!(matches!(
            enclave_decrypted[1].adaptor_type,
            AdaptorType::And
        ));

        validate_decrypted_adaptor_configs(&enclave_decrypted)
            .expect("Decrypted configs should be valid");

        let empty_encrypted = encrypt_adaptor_configs_for_client(&[], session_secret)
            .expect("Should handle empty configs");
        assert!(empty_encrypted.is_empty());

        let empty_decrypted = decrypt_adaptor_configs(&empty_encrypted, session_secret)
            .expect("Should decrypt empty configs");
        assert!(empty_decrypted.is_empty());
    }

    #[test]
    fn test_zero_knowledge_privacy_guarantees() {
        let session_secret = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678";

        let adaptor_config_1 = vec![AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Single,
            adaptor_points: vec![
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
            ],
            hints: None,
        }];

        let adaptor_config_2 = vec![AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::And,
            adaptor_points: vec![
                "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659".to_string(),
                "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66".to_string(),
            ],
            hints: None,
        }];

        let adaptor_config_3 = vec![AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Or,
            adaptor_points: vec![
                "02abc123def456789012345678901234567890123456789012345678901234567890".to_string(),
                "03def456789012345678901234567890123456789012345678901234567890123abc".to_string(),
            ],
            hints: Some(vec![
                AdaptorHint::Scalar(vec![1u8; 32]),
                AdaptorHint::Hash(vec![2u8; 32]),
            ]),
        }];

        let encrypted_config_1 =
            encrypt_adaptor_configs_for_client(&adaptor_config_1, session_secret)
                .expect("Should encrypt adaptor config 1");
        let encrypted_config_2 =
            encrypt_adaptor_configs_for_client(&adaptor_config_2, session_secret)
                .expect("Should encrypt adaptor config 2");
        let encrypted_config_3 =
            encrypt_adaptor_configs_for_client(&adaptor_config_3, session_secret)
                .expect("Should encrypt adaptor config 3");

        assert!(!encrypted_config_1.contains(&adaptor_config_2[0].adaptor_id.to_string()));
        assert!(!encrypted_config_2.contains(&adaptor_config_1[0].adaptor_id.to_string()));
        assert!(!encrypted_config_3.contains(&adaptor_config_3[0].adaptor_id.to_string()));

        // The encrypted strings are hex-encoded JSON, so decode and check the JSON structure
        let decoded_1 = hex::decode(&encrypted_config_1).expect("Should decode hex");
        let json_1 = String::from_utf8(decoded_1).expect("Should decode UTF-8");
        assert!(serde_json::from_str::<serde_json::Value>(&json_1).is_ok());

        let decoded_2 = hex::decode(&encrypted_config_2).expect("Should decode hex");
        let json_2 = String::from_utf8(decoded_2).expect("Should decode UTF-8");
        assert!(serde_json::from_str::<serde_json::Value>(&json_2).is_ok());

        let decoded_3 = hex::decode(&encrypted_config_3).expect("Should decode hex");
        let json_3 = String::from_utf8(decoded_3).expect("Should decode UTF-8");
        assert!(serde_json::from_str::<serde_json::Value>(&json_3).is_ok());

        assert_ne!(encrypted_config_1, encrypted_config_2);
        assert_ne!(encrypted_config_2, encrypted_config_3);
        assert_ne!(encrypted_config_1, encrypted_config_3);

        for encrypted in [
            &encrypted_config_1,
            &encrypted_config_2,
            &encrypted_config_3,
        ] {
            // The encrypted strings are hex-encoded JSON, so decode and check the JSON structure
            let decoded_bytes = hex::decode(encrypted).expect("Should decode hex");
            let decoded_json = String::from_utf8(decoded_bytes).expect("Should decode UTF-8");
            let json_value: serde_json::Value =
                serde_json::from_str(&decoded_json).expect("Should parse JSON");

            assert!(json_value.get("ciphertext").is_some());
            assert!(json_value.get("nonce").is_some());
            assert!(json_value.get("context").is_some());
        }

        println!("Zero-knowledge privacy verified: Gateway remains blind to all contract details");
    }
}
