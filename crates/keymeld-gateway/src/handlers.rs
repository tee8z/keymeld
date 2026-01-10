use crate::{
    auth::{validate_user_key_signature, SingleSigningAuth, UserKeyAuth},
    config::GatewayLimits,
    database::{CreateSingleSigningParams, Database},
    enclave::EnclaveManager,
    errors::{ApiError, ApiResult},
    headers::{SessionSignature, UserSignature},
    metrics::Metrics,
    session::keygen::KeygenSessionStatus,
};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Json, Response},
};
use axum_extra::TypedHeader;
use keymeld_core::{
    crypto::SecureCrypto,
    identifiers::{SessionId, UserId},
    protocol::{KeygenStatusKind, SigningStatusKind},
    AttestationDocument,
};
use keymeld_sdk::{
    validate_create_signing_session_request, validate_initialize_keygen_session_request,
    validate_register_keygen_participant_request, validate_reserve_keygen_session_request,
    ApiFeatures, ApiVersionResponse, AvailableUserSlot, CreateSigningSessionRequest,
    CreateSigningSessionResponse, DatabaseStats, DeleteUserKeyResponse, EnclaveHealthResponse,
    EnclaveId, EnclavePublicKeyResponse, ErrorResponse, GetAvailableSlotsResponse,
    HealthCheckResponse, ImportUserKeyRequest, ImportUserKeyResponse,
    InitializeKeygenSessionRequest, InitializeKeygenSessionResponse, KeyId,
    KeygenSessionStatusResponse, ListEnclavesResponse, ListUserKeysResponse,
    RegisterKeygenParticipantRequest, RegisterKeygenParticipantResponse, ReserveKeySlotRequest,
    ReserveKeySlotResponse, ReserveKeygenSessionRequest, ReserveKeygenSessionResponse,
    SignSingleRequest, SignSingleResponse, SigningSessionStatusResponse, SingleSigningStatus,
    SingleSigningStatusResponse, StoreKeyFromKeygenRequest, StoreKeyFromKeygenResponse,
};
use log::error;
use moka::sync::Cache;
use prometheus::Encoder;
use secp256k1::PublicKey;
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info, warn};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub enclave_manager: Arc<EnclaveManager>,
    pub metrics: Arc<Metrics>,
    pub gateway_limits: GatewayLimits,
    pub nonce_cache: NonceCache,
}

/// TTL-based nonce cache for replay protection.
#[derive(Clone)]
pub struct NonceCache {
    cache: Cache<String, ()>,
    time_window: Duration,
}

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceCache {
    pub fn new() -> Self {
        Self::with_config(Duration::from_secs(600), Duration::from_secs(300), 100_000)
    }

    pub fn with_config(ttl: Duration, time_window: Duration, max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .time_to_live(ttl)
            .max_capacity(max_capacity)
            .build();
        Self { cache, time_window }
    }

    pub fn check_and_insert_with_timestamp(
        &self,
        nonce_key: &str,
        timestamp_secs: u64,
    ) -> Result<(), &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "System time error")?
            .as_secs();

        if timestamp_secs.abs_diff(now) > self.time_window.as_secs() {
            return Err("Timestamp outside acceptable window");
        }

        if self.cache.contains_key(nonce_key) {
            return Err("Nonce already used");
        }

        self.cache.insert(nonce_key.to_string(), ());
        Ok(())
    }

    pub fn check_and_insert(&self, nonce_key: &str) -> bool {
        if self.cache.contains_key(nonce_key) {
            return false;
        }
        self.cache.insert(nonce_key.to_string(), ());
        true
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
            if current_time as i64 > health_info.startup_time {
                current_time.saturating_sub(health_info.startup_time as u64)
            } else {
                0
            }
        } else {
            0
        };

        let health_response = EnclaveHealthResponse {
            enclave_id: EnclaveId::from(health_info.enclave_id as u32),
            healthy: health_info.is_healthy,
            public_key: health_info.public_key,
            attestation_document: health_info.attestation_document,
            active_sessions: health_info.active_sessions as u32,
            uptime_seconds,
            key_epoch: health_info.key_epoch as u64,
            key_generation_time: health_info.key_generation_time as u64,
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
    path = "/keygen/reserve",
    tag = "keygen",
    summary = "Reserve a new keygen session",
    description = "Phase 1: Reserve a keygen session slot and get coordinator enclave assignment",
    request_body = ReserveKeygenSessionRequest,
    responses(
        (status = 200, description = "Keygen session reserved successfully", body = ReserveKeygenSessionResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn reserve_keygen_session(
    State(state): State<AppState>,
    Json(mut request): Json<ReserveKeygenSessionRequest>,
) -> ApiResult<Json<ReserveKeygenSessionResponse>> {
    info!("Reserving keygen session: {}", request.keygen_session_id);

    validate_reserve_keygen_session_request(&request)
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {e}")))?;

    // Sort expected_participants in descending order (newest UUIDv7 first) for consistency
    request
        .expected_participants
        .sort_by(|a: &UserId, b: &UserId| b.cmp(a));
    debug!(
        "After sorting expected_participants in gateway: {:?}",
        request.expected_participants
    );

    if state
        .db
        .get_keygen_session_by_id(&request.keygen_session_id)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("Keygen session already exists"));
    }

    // Create session assignment to determine coordinator enclave
    let session_assignment = state
        .enclave_manager
        .create_session_assignment_with_distributed_coordinator(
            request.keygen_session_id.clone(),
            &request.expected_participants,
            &request.coordinator_user_id,
        )
        .map_err(|e| {
            ApiError::enclave_communication(format!("Failed to create session assignment: {e}"))
        })?;

    let coordinator_enclave_id = session_assignment.coordinator_enclave;

    // Get coordinator enclave public key and epoch
    let coordinator_public_key = state
        .enclave_manager
        .get_enclave_public_key(&coordinator_enclave_id)
        .await
        .map_err(|e| {
            ApiError::EnclaveCommunication(format!(
                "Cannot get public key for coordinator enclave {}: {}",
                coordinator_enclave_id, e
            ))
        })?;

    debug!(
        "Retrieved coordinator public key for enclave {}: {}",
        coordinator_enclave_id, coordinator_public_key
    );

    let coordinator_key_epoch = state
        .enclave_manager
        .get_enclave_key_epoch(&coordinator_enclave_id)
        .ok_or(ApiError::EnclaveCommunication(format!(
            "Cannot get key epoch for coordinator enclave {}",
            coordinator_enclave_id
        )))?;

    // Reserve the session in database
    state
        .db
        .reserve_keygen_session(&request, coordinator_enclave_id)
        .await?;

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
        .as_secs();

    let response = ReserveKeygenSessionResponse {
        keygen_session_id: request.keygen_session_id,
        coordinator_enclave_id,
        coordinator_public_key,
        coordinator_key_epoch,
        expected_participants: request.expected_participants.len(),
        expires_at: current_time + request.timeout_secs,
    };

    info!(
        "Keygen session {} reserved with coordinator enclave {}",
        response.keygen_session_id,
        coordinator_enclave_id.as_u32()
    );

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/keygen/{session_id}/initialize",
    tag = "keygen",
    summary = "Initialize a reserved keygen session",
    description = "Phase 2: Initialize a reserved keygen session with encrypted data",
    request_body = InitializeKeygenSessionRequest,
    responses(
        (status = 200, description = "Keygen session initialized successfully", body = InitializeKeygenSessionResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn initialize_keygen_session(
    State(state): State<AppState>,
    Path(session_id): Path<SessionId>,
    Json(request): Json<InitializeKeygenSessionRequest>,
) -> ApiResult<Json<InitializeKeygenSessionResponse>> {
    info!("Initializing keygen session: {}", session_id);

    validate_initialize_keygen_session_request(&request)
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {e}")))?;

    // Get the reserved session to validate state and get coordinator enclave
    let session_status = state
        .db
        .get_keygen_session_by_id(&session_id)
        .await?
        .ok_or(ApiError::not_found("Keygen session not found"))?;

    let coordinator_enclave_id = match &session_status {
        crate::session::keygen::KeygenSessionStatus::Reserved(reserved) => {
            reserved.coordinator_enclave_id
        }
        _ => return Err(ApiError::bad_request(
            "Session is not in reserved state. It may have already been initialized or expired.",
        )),
    };

    // Validate that the client's epoch matches the current coordinator enclave epoch
    let current_epoch = state
        .enclave_manager
        .get_enclave_key_epoch(&coordinator_enclave_id)
        .ok_or(ApiError::EnclaveCommunication(format!(
            "Cannot get key epoch for coordinator enclave {}",
            coordinator_enclave_id
        )))?;

    if request.enclave_key_epoch != current_epoch {
        return Err(ApiError::bad_request(format!(
            "Encrypted session secret uses coordinator enclave {} epoch {}, but current epoch is {}. The enclave may have restarted. Please fetch the latest enclave public key and retry.",
            coordinator_enclave_id.as_u32(),
            request.enclave_key_epoch,
            current_epoch
        )));
    }

    debug!(
        "Validated keygen session {} coordinator enclave {} epoch: {}",
        session_id, coordinator_enclave_id, current_epoch
    );

    // Initialize the session with encrypted data
    let session_secret = state
        .db
        .initialize_keygen_session(&session_id, &request)
        .await?;

    let response = InitializeKeygenSessionResponse {
        keygen_session_id: session_id.clone(),
        status: KeygenStatusKind::CollectingParticipants,
        session_secret,
        session_public_key: request.session_public_key,
    };

    info!(
        "Keygen session {} initialized and moved to CollectingParticipants",
        session_id
    );

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

    // CRITICAL: Get both public key AND epoch from the same source (database) to ensure consistency
    // If we mix sources (public key from DB, epoch from EnclaveManager), they can be out of sync
    // during enclave restarts, causing decryption failures
    let (expected_public_key, enclave_key_epoch) = match state
        .db
        .get_enclave_health(assigned_enclave.as_u32())
        .await?
    {
        Some(health_info) => (health_info.public_key, health_info.key_epoch as u64),
        None => {
            return Err(ApiError::EnclaveCommunication(format!(
                "Assigned enclave {} is not healthy",
                assigned_enclave.as_u32()
            )));
        }
    };

    if expected_public_key != request.enclave_public_key {
        return Err(ApiError::bad_request(format!(
            "Participant {} must use assigned enclave {} (public key: {}, epoch: {}), but provided public key: {}",
            request.user_id,
            assigned_enclave.as_u32(),
            &expected_public_key[..16],
            enclave_key_epoch,
            &request.enclave_public_key[..16]
        )));
    }

    // CRITICAL: Validate that the client's epoch matches the server's epoch
    // This prevents decryption failures when an enclave restarts between client fetch and server processing
    if request.enclave_key_epoch != 0 && request.enclave_key_epoch != enclave_key_epoch {
        return Err(ApiError::bad_request(format!(
            "Participant {} encrypted data with enclave {} epoch {}, but current epoch is {}. The enclave may have restarted. Please fetch the latest enclave public key and retry.",
            request.user_id,
            assigned_enclave.as_u32(),
            request.enclave_key_epoch,
            enclave_key_epoch
        )));
    }

    debug!(
        "Validated participant {} assignment to enclave {} (public key: {}, epoch: {})",
        request.user_id,
        assigned_enclave,
        &request.enclave_public_key[..16],
        enclave_key_epoch
    );

    let session_encrypted = request.encrypted_session_data.clone();
    let enclave_encrypted = request.encrypted_private_key.clone();

    state
        .db
        .register_keygen_participant_with_encrypted_data(
            &keygen_session_id,
            &request,
            assigned_enclave,
            enclave_key_epoch,
            session_encrypted,
            enclave_encrypted,
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
        KeygenSessionStatus::Reserved(_) => {
            return Err(ApiError::bad_request(
                "Session is reserved but not yet initialized",
            ));
        }
        KeygenSessionStatus::CollectingParticipants(s) => &s.encrypted_session_secret,
        KeygenSessionStatus::Completed(s) => &s.encrypted_session_secret,
        KeygenSessionStatus::Failed(_) => {
            return Err(ApiError::bad_request(
                "Cannot get status for failed session",
            ));
        }
    };

    debug!(
        "Keygen status check - Signature value: '{}'",
        session_signature.value()
    );

    validate_session_signature(&state.db, &keygen_session_id, session_signature.value()).await?;

    let participant_count = state
        .db
        .get_keygen_participant_count(&keygen_session_id)
        .await?;

    let (status, expected_participants, aggregate_public_key, expires_at) =
        session_status.extract_status_info();

    // Get encrypted_subset_aggregates from Completed status
    let encrypted_subset_aggregates = match &session_status {
        KeygenSessionStatus::Completed(s) => s.encrypted_subset_aggregates.clone(),
        _ => std::collections::BTreeMap::new(),
    };

    let response = KeygenSessionStatusResponse {
        keygen_session_id,
        status,
        expected_participants,
        registered_participants: participant_count,
        aggregate_public_key,
        expires_at,
        encrypted_subset_aggregates,
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
        .unwrap_or(state.gateway_limits.default_max_signing_sessions);

    let existing_signing_sessions_count = state
        .db
        .count_signing_sessions_for_keygen(&request.keygen_session_id)
        .await
        .unwrap_or(0);

    if existing_signing_sessions_count >= max_signing_sessions as usize {
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

    // Copy session assignment from keygen to signing immediately so approval requests don't fail
    // with "session not ready" errors while waiting for the background coordinator to process.
    // This is a fast in-memory operation (no enclave network calls) - just copies between HashMaps.
    // This is idempotent - the coordinator's copy_session_assignment_for_signing will be a no-op.
    if let Err(e) = state.enclave_manager.copy_session_assignment_for_signing(
        &request.keygen_session_id,
        request.signing_session_id.clone(),
    ) {
        warn!(
            "Failed to copy session assignment for signing session {} (will retry in coordinator): {}",
            request.signing_session_id, e
        );
        // Don't fail the request - the coordinator will retry this
    }

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
        .await?;

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

/// Validate session signature using database-stored public key
async fn validate_session_signature(
    db: &Database,
    session_id: &SessionId,
    signature_header: &str,
) -> Result<(), ApiError> {
    let public_key = match db.get_session_public_key(session_id).await? {
        Some(key) => key,
        None => return Err(ApiError::not_found("Session not found")),
    };

    keymeld_core::validation::validate_session_signature(
        &session_id.as_string(),
        signature_header,
        &public_key,
    )
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
    if !state.nonce_cache.check_and_insert(&nonce_key) {
        return Err(ApiError::bad_request("Nonce already used"));
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
        expires_at,
        participants_requiring_approval,
        approved_participants,
    ) = session_status.extract_status_info();

    let batch_results = session_status
        .get_batch_results()
        .cloned()
        .unwrap_or_default();

    let response = SigningSessionStatusResponse {
        signing_session_id,
        keygen_session_id,
        status,
        participants_registered: participant_count,
        expected_participants,
        expires_at,
        participants_requiring_approval,
        approved_participants,
        batch_results,
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
        key_epoch: health_info.key_epoch as u64,
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
        KeygenSessionStatus::Reserved(_) => {
            return Err(ApiError::bad_request(
                "Keygen session is reserved but not yet initialized",
            ))
        }
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

// ============================================================================
// User Key Management Handlers (Stubbed)
// ============================================================================

/// Reserve a key slot for importing a user key
#[utoipa::path(
    post,
    path = "/keys/reserve",
    tag = "user_keys",
    summary = "Reserve a key slot",
    description = "Reserve a key slot and get assigned enclave info for key import",
    request_body = ReserveKeySlotRequest,
    responses(
        (status = 200, description = "Key slot reserved", body = ReserveKeySlotResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn reserve_key_slot(
    State(state): State<AppState>,
    Json(request): Json<ReserveKeySlotRequest>,
) -> ApiResult<Json<ReserveKeySlotResponse>> {
    info!("Reserving key slot for user: {}", request.user_id);

    // Get all healthy enclaves and pick one (round-robin or random)
    let enclave_ids = state.enclave_manager.get_all_enclave_ids();
    if enclave_ids.is_empty() {
        return Err(ApiError::enclave_communication("No enclaves available"));
    }

    // Simple selection: use first available healthy enclave
    // TODO: Could implement load balancing based on key count per enclave
    let enclave_id = enclave_ids[0];

    // Get enclave public key and epoch from database (cached health info)
    let health_info = state
        .db
        .get_enclave_health(enclave_id.as_u32())
        .await?
        .ok_or_else(|| {
            ApiError::enclave_communication(format!("Enclave {} not healthy", enclave_id.as_u32()))
        })?;

    // Generate a new key_id
    let key_id = KeyId::new_v7();

    // Calculate expiration (e.g., 10 minutes from now)
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
        .as_secs() as i64
        + 600; // 10 minutes

    // Reserve the slot in database
    state
        .db
        .reserve_key_slot(
            &key_id,
            &request.user_id,
            enclave_id,
            health_info.key_epoch as u64,
            expires_at,
        )
        .await?;

    info!(
        "Reserved key slot {} for user {} on enclave {}",
        key_id,
        request.user_id,
        enclave_id.as_u32()
    );

    let response = ReserveKeySlotResponse {
        key_id,
        user_id: request.user_id,
        enclave_id,
        enclave_public_key: health_info.public_key,
        enclave_key_epoch: health_info.key_epoch as u64,
    };

    Ok(Json(response))
}

/// Import a user key (async - poll status endpoint for completion)
#[utoipa::path(
    post,
    path = "/keys/import",
    tag = "user_keys",
    summary = "Import a user key",
    description = "Import a private key encrypted to the assigned enclave. The import is processed asynchronously - poll /keys/{user_id}/{key_id}/status to check completion. Requires X-User-Signature header signed with the private key corresponding to auth_pubkey.",
    request_body = ImportUserKeyRequest,
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Key import started", body = ImportUserKeyResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or invalid X-User-Signature header", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn import_user_key(
    State(state): State<AppState>,
    TypedHeader(user_signature): TypedHeader<UserSignature>,
    Json(request): Json<ImportUserKeyRequest>,
) -> ApiResult<Json<ImportUserKeyResponse>> {
    info!(
        "Starting key import {} for user {}",
        request.key_id, request.user_id
    );

    // Validate that the signature was made with the private key corresponding to auth_pubkey
    // This proves the caller owns the key pair before we store the auth_pubkey
    crate::auth::validate_signature_with_pubkey(
        &state.nonce_cache,
        &request.auth_pubkey,
        &request.key_id.as_string(),
        &request.user_id.as_string(),
        user_signature.value(),
    )?;

    // Validate the reserved key slot exists and matches
    let reserved_slot = state
        .db
        .get_reserved_key_slot(&request.key_id)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request(format!(
                "No reserved key slot found for key_id {}. Reserve a slot first.",
                request.key_id
            ))
        })?;

    // Validate the user matches
    if reserved_slot.user_id != request.user_id {
        return Err(ApiError::bad_request(format!(
            "Key slot {} was reserved for user {}, not {}",
            request.key_id, reserved_slot.user_id, request.user_id
        )));
    }

    let enclave_id = reserved_slot.enclave_id;

    // Get current enclave public key to validate the client used the correct one
    let health_info = state
        .db
        .get_enclave_health(enclave_id.as_u32())
        .await?
        .ok_or_else(|| {
            ApiError::enclave_communication(format!("Enclave {} not healthy", enclave_id.as_u32()))
        })?;

    // Validate the enclave public key matches (ensures client encrypted to correct enclave)
    if request.enclave_public_key != health_info.public_key {
        return Err(ApiError::bad_request(format!(
            "Encrypted private key uses wrong enclave public key. Expected: {}..., got: {}...",
            &health_info.public_key[..16.min(health_info.public_key.len())],
            &request.enclave_public_key[..16.min(request.enclave_public_key.len())]
        )));
    }

    // Validate the enclave epoch hasn't changed since reservation
    if health_info.key_epoch != reserved_slot.enclave_key_epoch {
        return Err(ApiError::bad_request(format!(
            "Enclave {} epoch changed from {} to {} since reservation. The enclave may have restarted. Please reserve a new slot.",
            enclave_id.as_u32(), reserved_slot.enclave_key_epoch, health_info.key_epoch
        )));
    }

    // Decode the encrypted private key to validate it's valid hex
    let encrypted_private_key_bytes = hex::decode(&request.encrypted_private_key)
        .map_err(|e| ApiError::bad_request(format!("Invalid encrypted_private_key hex: {}", e)))?;

    // Calculate expiration (10 minutes from now)
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
        .as_secs() as i64
        + 600;

    // Atomically move from reserved_key_slots to pending_key_imports
    // This ensures we don't have orphaned records if the operation fails
    // The coordinator will process the pending import and send ImportKeyCommand to the enclave
    state
        .db
        .move_reserved_to_pending_import(
            &request.key_id,
            &encrypted_private_key_bytes,
            &request.auth_pubkey,
            expires_at,
        )
        .await?;

    info!(
        "Key import {} for user {} queued for processing on enclave {}",
        request.key_id,
        request.user_id,
        enclave_id.as_u32()
    );

    let response = ImportUserKeyResponse {
        key_id: request.key_id,
        user_id: request.user_id,
        enclave_id,
    };

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
pub struct ListUserKeysQuery {
    pub key_id: String,
}

/// List keys for a user
#[utoipa::path(
    get,
    path = "/keys/{user_id}",
    tag = "user_keys",
    summary = "List user keys",
    description = "List all keys stored for a user. Requires X-User-Signature header signed with one of the user's keys (specified in key_id query param).",
    params(
        ("user_id" = String, Path, description = "User ID"),
        ("key_id" = String, Query, description = "Key ID to authenticate with")
    ),
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Key list", body = ListUserKeysResponse),
        (status = 401, description = "Missing or invalid X-User-Signature header", body = ErrorResponse),
        (status = 404, description = "Key not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn list_user_keys(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Query(query): Query<ListUserKeysQuery>,
    TypedHeader(user_signature): TypedHeader<UserSignature>,
) -> ApiResult<Json<ListUserKeysResponse>> {
    let user_id = UserId::parse(&user_id)
        .map_err(|e| ApiError::BadRequest(format!("Invalid user_id: {e}")))?;
    let key_id = KeyId::parse(&query.key_id)
        .map_err(|e| ApiError::BadRequest(format!("Invalid key_id: {e}")))?;

    // Validate signature with the provided key
    validate_user_key_signature(
        &state.db,
        &state.nonce_cache,
        &user_id,
        &key_id,
        user_signature.value(),
    )
    .await?;

    debug!("Listing keys for user: {}", user_id);

    let key_rows = state.db.list_user_keys(&user_id).await?;

    let keys: Vec<keymeld_core::protocol::UserKeyInfo> = key_rows
        .into_iter()
        .map(|row| keymeld_core::protocol::UserKeyInfo {
            user_id: row.user_id,
            key_id: row.key_id,
            created_at: row.created_at as u64,
            origin_keygen_session_id: row.origin_keygen_session_id,
        })
        .collect();

    let response = ListUserKeysResponse { user_id, keys };

    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/keys/{user_id}/{key_id}",
    tag = "user_keys",
    summary = "Delete a user key",
    description = "Delete a stored key. Requires X-User-Signature header.",
    params(
        ("user_id" = String, Path, description = "User ID"),
        ("key_id" = String, Path, description = "Key ID")
    ),
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Key deleted", body = DeleteUserKeyResponse),
        (status = 401, description = "Missing or invalid X-User-Signature header", body = ErrorResponse),
        (status = 404, description = "Key not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn delete_user_key(
    State(state): State<AppState>,
    UserKeyAuth((user_id, key_id)): UserKeyAuth,
) -> ApiResult<Json<DeleteUserKeyResponse>> {
    info!("Deleting key {} for user {}", key_id, user_id);

    // Delete from database only - do NOT call enclave directly
    // The enclave's in-memory copy will be orphaned but cannot be used:
    // - Signing requires looking up the key in the database first
    // - On enclave restart, only keys in the database are restored
    let deleted = state.db.delete_user_key(&user_id, &key_id).await?;

    if deleted {
        info!("Deleted key {} for user {}", key_id, user_id);
    } else {
        warn!("Key {} for user {} was already deleted", key_id, user_id);
    }

    let response = DeleteUserKeyResponse {
        key_id,
        user_id,
        deleted,
    };

    Ok(Json(response))
}

/// Get key operation status (for polling import/store progress)
#[utoipa::path(
    get,
    path = "/keys/{user_id}/{key_id}/status",
    tag = "user_keys",
    summary = "Get key operation status",
    description = "Get the status of a key import or store operation. Use this to poll for completion after calling /keys/import or /keys/{user_id}/keygen/{session_id}. Requires X-User-Signature header.",
    params(
        ("user_id" = String, Path, description = "User ID"),
        ("key_id" = String, Path, description = "Key ID")
    ),
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Key status", body = keymeld_sdk::KeyStatusResponse),
        (status = 401, description = "Missing or invalid X-User-Signature header", body = ErrorResponse),
        (status = 404, description = "Key not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn get_key_status(
    State(state): State<AppState>,
    UserKeyAuth((user_id, key_id)): UserKeyAuth,
) -> ApiResult<Json<keymeld_sdk::KeyStatusResponse>> {
    debug!("Getting key status for user {} key {}", user_id, key_id);

    let status = state
        .db
        .get_key_operation_status(&user_id, &key_id)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("Key {} not found for user {}", key_id, user_id))
        })?;

    let response = keymeld_sdk::KeyStatusResponse {
        key_id: status.key_id,
        user_id: status.user_id,
        status: status.status,
        error_message: status.error_message,
        created_at: status.created_at as u64,
    };

    Ok(Json(response))
}

/// Store a key from a completed keygen session (async - poll status endpoint)
#[utoipa::path(
    post,
    path = "/keys/{user_id}/keygen/{keygen_session_id}",
    tag = "user_keys",
    summary = "Store key from keygen",
    description = "Persist a key from a completed keygen session. The store is processed asynchronously - poll /keys/{user_id}/{key_id}/status to check completion.",
    params(
        ("user_id" = String, Path, description = "User ID"),
        ("keygen_session_id" = String, Path, description = "Keygen session ID")
    ),
    request_body = StoreKeyFromKeygenRequest,
    responses(
        (status = 200, description = "Key store started", body = StoreKeyFromKeygenResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn store_key_from_keygen(
    State(state): State<AppState>,
    Path((user_id, keygen_session_id)): Path<(String, String)>,
    Json(request): Json<StoreKeyFromKeygenRequest>,
) -> ApiResult<Json<StoreKeyFromKeygenResponse>> {
    let user_id = UserId::parse(&user_id)
        .map_err(|e| ApiError::BadRequest(format!("Invalid user_id: {e}")))?;
    let keygen_session_id = SessionId::parse(&keygen_session_id)
        .map_err(|e| ApiError::BadRequest(format!("Invalid keygen_session_id: {e}")))?;

    info!(
        "Starting key store {} from keygen session {} for user {}",
        request.key_id, keygen_session_id, user_id
    );

    // Validate keygen session exists and is completed
    let keygen_session = state
        .db
        .get_keygen_session_by_id(&keygen_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Keygen session not found"))?;

    // Verify session is completed
    if !matches!(keygen_session, KeygenSessionStatus::Completed(_)) {
        return Err(ApiError::bad_request(
            "Keygen session must be completed to store key",
        ));
    }

    // Verify the user was a participant in the keygen session
    let participant = state
        .db
        .get_keygen_participant(&keygen_session_id, &user_id)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request(format!(
                "User {} was not a participant in keygen session {}",
                user_id, keygen_session_id
            ))
        })?;

    // Get the enclave that has this user's key (their assigned enclave from keygen)
    let user_enclave_id = participant.enclave_id;

    // Verify the enclave is healthy before queuing
    let _health_info = state
        .db
        .get_enclave_health(user_enclave_id.as_u32())
        .await?
        .ok_or_else(|| {
            ApiError::enclave_communication(format!(
                "Enclave {} not healthy",
                user_enclave_id.as_u32()
            ))
        })?;

    // Calculate expiration (10 minutes from now)
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
        .as_secs() as i64
        + 600;

    // Write to pending_key_stores table for async processing by coordinator
    // The coordinator will send the StoreKeyFromKeygenCommand to the enclave
    state
        .db
        .create_pending_key_store(
            &request.key_id,
            &user_id,
            &keygen_session_id,
            user_enclave_id,
            expires_at,
        )
        .await?;

    info!(
        "Key store {} from keygen session {} for user {} queued for processing",
        request.key_id, keygen_session_id, user_id
    );

    let response = StoreKeyFromKeygenResponse {
        key_id: request.key_id,
        user_id,
        keygen_session_id,
    };

    Ok(Json(response))
}

// ============================================================================
// Single-Signer Signing Handlers
// ============================================================================

/// Create a single-signer signing session (async - poll status endpoint)
#[utoipa::path(
    post,
    path = "/sign/single",
    tag = "single_signing",
    summary = "Sign with stored key",
    description = "Create a single-signer signing session using a stored key. The signing is processed asynchronously - poll /sign/single/{session_id}/status/{user_id} to check completion. Requires X-User-Signature header.",
    request_body = SignSingleRequest,
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Signing session created", body = SignSingleResponse),
        (status = 401, description = "Missing or invalid X-User-Signature header", body = ErrorResponse),
        (status = 404, description = "Key not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn sign_single(
    State(state): State<AppState>,
    TypedHeader(user_signature): TypedHeader<UserSignature>,
    Json(request): Json<SignSingleRequest>,
) -> ApiResult<Json<SignSingleResponse>> {
    // Validate signature first
    validate_user_key_signature(
        &state.db,
        &state.nonce_cache,
        &request.user_id,
        &request.key_id,
        user_signature.value(),
    )
    .await?;

    info!(
        "Creating single signing session for user {} with key {}",
        request.user_id, request.key_id
    );

    // Verify the user key exists and get its database ID
    let user_key = state
        .db
        .get_user_key_by_user_and_key(&request.user_id, &request.key_id)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!(
                "Key {} not found for user {}",
                request.key_id, request.user_id
            ))
        })?;

    // Verify the assigned enclave is healthy
    let _health_info = state
        .db
        .get_enclave_health(user_key.enclave_id.as_u32())
        .await?
        .ok_or_else(|| {
            ApiError::enclave_communication(format!(
                "Enclave {} not healthy",
                user_key.enclave_id.as_u32()
            ))
        })?;

    // Decode the encrypted data to validate it's valid hex
    let encrypted_message_bytes = hex::decode(&request.encrypted_message)
        .map_err(|e| ApiError::bad_request(format!("Invalid encrypted_message hex: {}", e)))?;
    let encrypted_session_secret_bytes =
        hex::decode(&request.encrypted_session_secret).map_err(|e| {
            ApiError::bad_request(format!("Invalid encrypted_session_secret hex: {}", e))
        })?;

    // Generate a new signing session ID
    let signing_session_id = SessionId::new_v7();

    // Calculate expiration (10 minutes from now)
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {e}")))?
        .as_secs() as i64
        + 600;

    // Write to single_signing_sessions table for async processing by coordinator
    // The coordinator will send the SignSingleCommand to the enclave
    state
        .db
        .create_single_signing_session(CreateSingleSigningParams {
            signing_session_id: &signing_session_id,
            user_key_id: user_key.id,
            encrypted_message: &encrypted_message_bytes,
            encrypted_session_secret: &encrypted_session_secret_bytes,
            signature_type: request.signature_type.as_ref(),
            approval_signature: &request.approval_signature,
            approval_timestamp: request.approval_timestamp as i64,
            expires_at,
        })
        .await?;

    info!(
        "Single signing session {} for user {} with key {} queued for processing",
        signing_session_id, request.user_id, request.key_id
    );

    let response = SignSingleResponse {
        signing_session_id,
        user_id: request.user_id,
        key_id: request.key_id,
        status: SingleSigningStatus::Pending,
    };

    Ok(Json(response))
}

/// Get single-signer signing session status
#[utoipa::path(
    get,
    path = "/sign/single/{session_id}/status/{user_id}",
    tag = "single_signing",
    summary = "Get single signing status",
    description = "Get the status of a single-signer signing session (signature encrypted to session secret). Requires X-User-Signature header.",
    params(
        ("session_id" = String, Path, description = "Signing session ID"),
        ("user_id" = String, Path, description = "User ID")
    ),
    security(
        ("UserSignature" = [])
    ),
    responses(
        (status = 200, description = "Signing status", body = SingleSigningStatusResponse),
        (status = 401, description = "Missing or invalid X-User-Signature header", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal error", body = ErrorResponse),
    )
)]
pub async fn get_single_signing_status(
    State(state): State<AppState>,
    SingleSigningAuth((session_id, user_id, _key_id)): SingleSigningAuth,
) -> ApiResult<Json<SingleSigningStatusResponse>> {
    debug!(
        "Getting single signing session status: {} for user {}",
        session_id, user_id
    );

    // Get the signing session from database (already validated by extractor)
    let session = state
        .db
        .get_single_signing_session(&session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Single signing session not found"))?;

    // Convert status_name to SingleSigningStatus
    let status = match session.status_name.as_str() {
        "pending" => SingleSigningStatus::Pending,
        "processing" => SingleSigningStatus::Processing,
        "completed" => SingleSigningStatus::Completed,
        "failed" => SingleSigningStatus::Failed,
        _ => SingleSigningStatus::Pending,
    };

    // Parse signature type
    let signature_type = if status == SingleSigningStatus::Completed {
        Some(
            session
                .signature_type
                .parse()
                .unwrap_or(keymeld_core::protocol::SignatureType::SchnorrBip340),
        )
    } else {
        None
    };

    let response = SingleSigningStatusResponse {
        signing_session_id: session.signing_session_id,
        user_id: session.user_id,
        key_id: session.key_id,
        status,
        encrypted_signature: session.encrypted_signature,
        signature_type,
        error_message: session.error_message,
    };

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use keymeld_sdk::{
        types::{AdaptorConfig, AdaptorHint, AdaptorType},
        validation::{
            decrypt_adaptor_configs, encrypt_adaptor_configs_for_client,
            validate_decrypted_adaptor_configs,
        },
        CreateSigningSessionRequest, SessionId, SigningBatchItem, SigningMode,
    };

    #[test]
    fn test_client_side_privacy_architecture() {
        let adaptor_config = AdaptorConfig::single(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        );

        let json = serde_json::to_string(&adaptor_config).expect("Should serialize");
        assert!(json.contains(&adaptor_config.adaptor_id.to_string()));
        assert!(json.contains("Single"));

        let deserialized: AdaptorConfig = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.adaptor_id, adaptor_config.adaptor_id);
        assert!(matches!(deserialized.adaptor_type, AdaptorType::Single));

        // Use binary hex format for encrypted adaptor configs (EncryptedData::to_hex format)
        // Format: [context_len: 1 byte][context bytes][nonce: 12 bytes][ciphertext]
        // This is a mock hex-encoded encrypted data for testing serialization
        let mock_encrypted_hex =
            "0f6164617074 6f725f636f6e66696773000102030405060708090a0bdeadbeefcafebabe"
                .replace(" ", "");

        let batch_item = SigningBatchItem {
            batch_item_id: uuid::Uuid::now_v7(),
            message_hash: vec![0u8; 32],
            signing_mode: SigningMode::Adaptor {
                encrypted_message: "test_message".to_string(),
                encrypted_adaptor_configs: mock_encrypted_hex.clone(),
            },
            encrypted_taproot_tweak: "test_tweak".to_string(),
            subset_id: None,
        };

        let request = CreateSigningSessionRequest {
            signing_session_id: SessionId::new_v7(),
            keygen_session_id: SessionId::new_v7(),
            timeout_secs: 3600,
            batch_items: vec![batch_item],
        };

        let request_json = serde_json::to_string(&request).expect("Should serialize request");
        assert!(request_json.contains("encrypted_adaptor_configs"));
        // The encrypted data should be hex-encoded, not contain JSON structure
        assert!(!request_json.contains(&adaptor_config.adaptor_id.to_string()));
        assert!(!request_json.contains("oracle"));
    }

    #[test]
    fn test_regular_signing_mode() {
        let batch_item = SigningBatchItem {
            batch_item_id: uuid::Uuid::now_v7(),
            message_hash: vec![0u8; 32],
            signing_mode: SigningMode::Regular {
                encrypted_message: "test_message".to_string(),
            },
            encrypted_taproot_tweak: "test_tweak".to_string(),
            subset_id: None,
        };

        let request = CreateSigningSessionRequest {
            signing_session_id: SessionId::new_v7(),
            keygen_session_id: SessionId::new_v7(),
            timeout_secs: 3600,
            batch_items: vec![batch_item],
        };

        // Regular mode should not have adaptor configs
        assert!(request.batch_items[0]
            .signing_mode
            .encrypted_adaptor_configs()
            .is_none());

        let json = serde_json::to_string(&request).expect("Should serialize");
        let deserialized: CreateSigningSessionRequest =
            serde_json::from_str(&json).expect("Should deserialize");
        assert!(deserialized.batch_items[0]
            .signing_mode
            .encrypted_adaptor_configs()
            .is_none());
    }

    #[test]
    fn test_client_side_encryption_flow() {
        let session_secret = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678";

        let client_adaptor_configs = vec![
            AdaptorConfig::single(
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            ),
            AdaptorConfig::and(vec![
                "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659".to_string(),
                "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66".to_string(),
            ]),
        ];

        let encrypted = encrypt_adaptor_configs_for_client(&client_adaptor_configs, session_secret)
            .expect("Client should encrypt adaptor configs");

        assert!(!encrypted.is_empty());
        // The encrypted string is hex-encoded binary data (EncryptedData format)
        // Format: [context_len: 1 byte][context bytes][nonce: 12 bytes][ciphertext]
        let decoded_bytes = hex::decode(&encrypted).expect("Should decode hex");
        // Verify the format: first byte is context length
        assert!(decoded_bytes.len() > 13); // At least context_len + nonce + some ciphertext
        let context_len = decoded_bytes[0] as usize;
        assert!(context_len > 0);
        assert!(decoded_bytes.len() > 1 + context_len + 12); // context + nonce + ciphertext

        // Verify adaptor IDs are not visible in encrypted data
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

        let adaptor_config_1 = vec![AdaptorConfig::single(
            "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        )];

        let adaptor_config_2 = vec![AdaptorConfig::and(vec![
            "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659".to_string(),
            "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66".to_string(),
        ])];

        let adaptor_config_3 = vec![AdaptorConfig::or(vec![
            "02abc123def456789012345678901234567890123456789012345678901234567890".to_string(),
            "03def456789012345678901234567890123456789012345678901234567890123abc".to_string(),
        ])
        .with_hints(vec![
            AdaptorHint::Scalar(vec![1u8; 32]),
            AdaptorHint::Hash(vec![2u8; 32]),
        ])];

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

        // The encrypted strings are hex-encoded binary data (EncryptedData format)
        // Format: [context_len: 1 byte][context bytes][nonce: 12 bytes][ciphertext]
        for encrypted in [
            &encrypted_config_1,
            &encrypted_config_2,
            &encrypted_config_3,
        ] {
            let decoded_bytes = hex::decode(encrypted).expect("Should decode hex");
            // Verify the format: first byte is context length
            assert!(decoded_bytes.len() > 13); // At least context_len + nonce + some ciphertext
            let context_len = decoded_bytes[0] as usize;
            assert!(context_len > 0);
            assert!(decoded_bytes.len() > 1 + context_len + 12); // context + nonce + ciphertext
        }

        assert_ne!(encrypted_config_1, encrypted_config_2);
        assert_ne!(encrypted_config_2, encrypted_config_3);
        assert_ne!(encrypted_config_1, encrypted_config_3);

        println!("Zero-knowledge privacy verified: Gateway remains blind to all contract details");
    }
}
