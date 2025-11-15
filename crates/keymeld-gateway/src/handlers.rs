use crate::{
    database::Database,
    errors::{ApiError, ApiResult},
    headers::{SessionHmac, SigningHmac},
    metrics::Metrics,
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    Json,
};
use axum_extra::TypedHeader;
use keymeld_core::{
    api::{
        validation::{
            validate_create_keygen_session_request, validate_create_signing_session_request,
            validate_register_keygen_participant_request, validate_user_hmac,
        },
        ApiFeatures, ApiVersionResponse, AvailableUserSlot, CreateKeygenSessionRequest,
        CreateKeygenSessionResponse, CreateSigningSessionRequest, CreateSigningSessionResponse,
        DatabaseStats, EnclaveHealthResponse, EnclavePublicKeyResponse, ErrorResponse,
        GetAvailableSlotsResponse, HealthCheckResponse, KeygenSessionStatusResponse,
        ListEnclavesResponse, RegisterKeygenParticipantRequest, RegisterKeygenParticipantResponse,
        SigningSessionStatusResponse,
    },
    crypto::SecureCrypto,
    enclave::{AttestationResponse, EnclaveManager, InitKeygenSessionCommand},
    encrypted_data::{KeygenParticipantEnclaveData, KeygenParticipantSessionData},
    identifiers::{SessionId, UserId},
    resilience::GatewayLimits,
    session::{KeygenSessionStatus, KeygenStatusKind, SigningStatusKind},
};
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
        .map_err(|e| ApiError::Internal(format!("Failed to encode metrics: {}", e)))?;
    Response::builder()
        .header("Content-Type", encoder.format_type())
        .body(Body::from(buffer))
        .map_err(|e| ApiError::Internal(format!("Failed to build response: {}", e)))
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    summary = "Health check endpoint",
    description = "Returns the overall health status of the KeyMeld Gateway service",
    responses(
        (status = 200, description = "Service is healthy", body = HealthCheckResponse),
        (status = 500, description = "Service is unhealthy", body = ErrorResponse),
    )
)]
pub async fn health_check(State(state): State<AppState>) -> ApiResult<Json<HealthCheckResponse>> {
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
                .map_err(|e| ApiError::Internal(format!("System time error: {}", e)))?
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
            .map_err(|e| ApiError::Internal(format!("Invalid enclave count: {}", e)))?,
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
    Json(request): Json<CreateKeygenSessionRequest>,
) -> ApiResult<Json<CreateKeygenSessionResponse>> {
    info!("Creating keygen session: {}", request.keygen_session_id);

    validate_create_keygen_session_request(&request)
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {}", e)))?;

    if state
        .db
        .get_keygen_session_by_id(&request.keygen_session_id)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("Keygen session already exists"));
    }

    let session_secret = state.db.create_keygen_session(&request).await?;
    let session_assignment = state
        .enclave_manager
        .create_session_assignment_with_coordinator(
            request.keygen_session_id.clone(),
            &request.expected_participants,
            request.coordinator_enclave_id,
        )
        .map_err(|e| {
            ApiError::enclave_communication(format!("Failed to create session assignment: {}", e))
        })?;

    let assigned_enclaves = session_assignment.get_all_assigned_enclaves();
    for enclave_id in &assigned_enclaves {
        let is_coordinator = *enclave_id == request.coordinator_enclave_id;

        let init_cmd = InitKeygenSessionCommand {
            keygen_session_id: request.keygen_session_id.clone(),
            coordinator_encrypted_private_key: if is_coordinator {
                Some(request.coordinator_encrypted_private_key.clone())
            } else {
                None
            },
            encrypted_session_secret: if is_coordinator {
                Some(request.encrypted_session_secret.clone())
            } else {
                None
            },
            timeout_secs: request.timeout_secs,
            taproot_tweak: request.taproot_tweak_config.clone(),
            expected_participant_count: request.expected_participants.len(),
            enclave_public_keys: vec![],
        };

        state
            .enclave_manager
            .send_command_to_enclave(
                enclave_id,
                keymeld_core::enclave::EnclaveCommand::InitKeygenSession(init_cmd),
            )
            .await
            .map_err(|e| {
                ApiError::enclave_communication(format!(
                    "Failed to initialize keygen session on enclave {}: {}",
                    enclave_id, e
                ))
            })?;

        info!(
            "✅ Keygen session {} initialized on enclave {} (coordinator: {})",
            request.keygen_session_id, enclave_id, is_coordinator
        );
    }

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(format!("System time error: {}", e)))?
        .as_secs();

    let response = CreateKeygenSessionResponse {
        keygen_session_id: request.keygen_session_id,
        coordinator_enclave_id: request.coordinator_enclave_id,
        status: KeygenStatusKind::CollectingParticipants,
        expected_participants: request.expected_participants.len(),
        expires_at: current_time + request.timeout_secs,
        enclave_epochs: HashMap::new(),
        session_secret,
    };

    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/keygen/{keygen_session_id}/participants",
    tag = "keygen",
    summary = "Register participant in keygen session",
    description = "Registers a participant in a keygen session for distributed key generation",
    params(
        ("keygen_session_id" = SessionId, Path, description = "Keygen session ID")
    ),
    request_body = RegisterKeygenParticipantRequest,
    responses(
        (status = 200, description = "Participant registered successfully", body = RegisterKeygenParticipantResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn register_keygen_participant(
    State(state): State<AppState>,
    Path(keygen_session_id): Path<SessionId>,
    TypedHeader(session_hmac): TypedHeader<SessionHmac>,
    Json(request): Json<RegisterKeygenParticipantRequest>,
) -> ApiResult<Json<RegisterKeygenParticipantResponse>> {
    debug!(
        "Registering participant {} in keygen session {}",
        request.user_id, keygen_session_id
    );

    validate_register_keygen_participant_request(&request, session_hmac.value())
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {}", e)))?;

    let session_status = state
        .db
        .get_keygen_session_by_id(&keygen_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Keygen session not found"))?;

    let (coordinator_enclave_id, encrypted_session_secret) = match &session_status {
        KeygenSessionStatus::CollectingParticipants(status) => {
            let session_secret = state
                .db
                .get_keygen_encrypted_session_secret(&keygen_session_id)
                .await?
                .ok_or_else(|| ApiError::not_found("Session secret not found"))?;

            (status.coordinator_enclave_id, session_secret)
        }
        _ => {
            return Err(ApiError::bad_request(
                "Keygen session is not accepting new participants",
            ))
        }
    };

    state
        .enclave_manager
        .validate_keygen_participant_hmac(
            &coordinator_enclave_id,
            &keygen_session_id,
            &request.user_id,
            session_hmac.value(),
            &encrypted_session_secret,
        )
        .await
        .map_err(|e| {
            ApiError::enclave_communication(format!("Enclave HMAC validation failed: {}", e))
        })?;

    debug!(
        "HMAC validation SUCCESS for keygen participant {} in session {}",
        request.user_id, keygen_session_id
    );

    let current_count = state
        .db
        .get_keygen_participant_count(&keygen_session_id)
        .await?;

    let available_enclaves = state.enclave_manager.list_enclaves();
    if available_enclaves.is_empty() {
        return Err(ApiError::EnclaveCommunication(
            "No enclaves available".to_string(),
        ));
    }

    let assigned_enclave = available_enclaves[current_count % available_enclaves.len()];

    let enclave_key_epoch = state
        .enclave_manager
        .get_enclave_key_epoch(&assigned_enclave)
        .ok_or_else(|| {
            ApiError::EnclaveCommunication(format!(
                "Cannot get key epoch for enclave {}",
                assigned_enclave
            ))
        })?;

    let enclave_public_key = state
        .enclave_manager
        .get_enclave_public_key(&assigned_enclave)
        .await
        .map_err(|e| {
            ApiError::enclave_communication(format!("Failed to get enclave public key: {}", e))
        })?;

    let session_data = KeygenParticipantSessionData::new(request.public_key.clone());
    let session_encrypted_json = serde_json::to_string(&session_data)
        .map_err(|e| ApiError::Serialization(format!("Failed to serialize session data: {}", e)))?;

    let enclave_data = KeygenParticipantEnclaveData::new(request.encrypted_private_key.clone());
    let enclave_json = serde_json::to_string(&enclave_data)
        .map_err(|e| ApiError::Serialization(format!("Failed to serialize enclave data: {}", e)))?;

    let encrypted_enclave_data =
        SecureCrypto::ecies_encrypt_from_hex(&enclave_public_key, enclave_json.as_bytes())
            .map_err(|e| {
                ApiError::Serialization(format!("Failed to encrypt enclave data: {}", e))
            })?;

    let enclave_encrypted_hex = hex::encode(encrypted_enclave_data);

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
    description = "Retrieves the current status and details of a keygen session. Requires X-Session-HMAC header containing session HMAC in format 'nonce:hmac' using session secret.",
    security(
        ("SessionHmac" = [])
    ),
    params(
        ("keygen_session_id" = SessionId, Path, description = "Keygen session ID")
    ),
    responses(
        (status = 200, description = "Keygen status retrieved successfully", body = KeygenSessionStatusResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-Session-HMAC header", body = ErrorResponse),
        (status = 403, description = "Invalid HMAC or user not permitted", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn get_keygen_status(
    State(state): State<AppState>,
    Path(keygen_session_id): Path<SessionId>,
    TypedHeader(session_hmac): TypedHeader<SessionHmac>,
) -> ApiResult<Json<KeygenSessionStatusResponse>> {
    debug!("Getting keygen session status: {}", keygen_session_id);

    let encrypted_session_secret = state
        .db
        .get_keygen_encrypted_session_secret(&keygen_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Session secret not found"))?;

    debug!(
        "Keygen status check - HMAC value: '{}'",
        session_hmac.value()
    );
    let participants = state.db.get_keygen_participants(&keygen_session_id).await?;
    debug!("Found {} participants for validation", participants.len());

    let mut validation_successful = false;
    for participant in &participants {
        debug!("Trying validation for participant: {}", participant.user_id);
        match validate_keygen_session_hmac(
            &state,
            &keygen_session_id,
            &participant.user_id,
            session_hmac.value(),
            &encrypted_session_secret,
        )
        .await
        {
            Ok(()) => {
                debug!(
                    "Validation successful for participant: {}",
                    participant.user_id
                );
                validation_successful = true;
                break;
            }
            Err(e) => {
                debug!(
                    "Validation failed for participant {}: {}",
                    participant.user_id, e
                );
            }
        }
    }

    if !validation_successful {
        return Err(ApiError::bad_request("Session HMAC validation failed"));
    }

    let session_status = state
        .db
        .get_keygen_session_by_id(&keygen_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Keygen session not found"))?;

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
    description = "Creates a new MuSig2 signing session for an existing completed keygen session. Requires X-Session-HMAC header containing session HMAC in format 'nonce:hmac' using session secret.",
    request_body = CreateSigningSessionRequest,
    security(
        ("SessionHmac" = [])
    ),
    responses(
        (status = 200, description = "Signing session created successfully", body = CreateSigningSessionResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-Session-HMAC header", body = ErrorResponse),
        (status = 403, description = "Invalid HMAC or user not permitted", body = ErrorResponse),
        (status = 404, description = "Keygen session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn create_signing_session(
    State(state): State<AppState>,
    TypedHeader(session_hmac): TypedHeader<SessionHmac>,
    Json(request): Json<CreateSigningSessionRequest>,
) -> ApiResult<Json<CreateSigningSessionResponse>> {
    info!("Creating signing session: {}", request.signing_session_id);

    validate_create_signing_session_request(&request)
        .map_err(|e| ApiError::bad_request(format!("Invalid request: {}", e)))?;

    let encrypted_session_secret = state
        .db
        .get_keygen_encrypted_session_secret(&request.keygen_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Keygen session secret not found"))?;

    let participants = state
        .db
        .get_keygen_participants(&request.keygen_session_id)
        .await?;

    let mut validation_successful = false;
    for participant in &participants {
        if validate_keygen_session_hmac(
            &state,
            &request.keygen_session_id,
            &participant.user_id,
            session_hmac.value(),
            &encrypted_session_secret,
        )
        .await
        .is_ok()
        {
            validation_successful = true;
            break;
        }
    }

    if !validation_successful {
        return Err(ApiError::bad_request("Session HMAC validation failed"));
    }

    if state
        .db
        .get_signing_session_by_id(&request.signing_session_id)
        .await?
        .is_some()
    {
        return Err(ApiError::bad_request("Signing session already exists"));
    }

    let keygen_session_record = state
        .db
        .get_keygen_session_by_id(&request.keygen_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Keygen session not found"))?;

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
            "Quota exceeded: maximum {} signing sessions allowed per keygen session",
            max_signing_sessions
        )));
    }

    match keygen_session_record {
        KeygenSessionStatus::Completed(_) => {
            // Keygen session is completed, proceed
        }
        _ => {
            return Err(ApiError::bad_request(
                "Keygen session must be completed before creating signing session",
            ))
        }
    };

    state.db.create_signing_session(&request).await?;

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
    path = "/signing/{signing_session_id}",
    tag = "signing",
    summary = "Approve a signing session as a participant",
    description = "Approve a MuSig2 signing session as a participant. Requires X-Signing-HMAC header containing user_hmac in format 'user_id:nonce:signature' where signature is created with the user's private key.",
    security(
        ("SigningHmac" = [])
    ),
    responses(
        (status = 200, description = "Signing session approved successfully"),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed X-Signing-HMAC header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted to approve", body = ErrorResponse),
        (status = 404, description = "Signing session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn approve_signing_session(
    State(state): State<AppState>,
    Path(signing_session_id): Path<SessionId>,
    TypedHeader(user_hmac): TypedHeader<SigningHmac>,
) -> ApiResult<StatusCode> {
    info!("Approving signing session: {}", signing_session_id);

    if state
        .db
        .get_signing_session_by_id(&signing_session_id)
        .await?
        .is_none()
    {
        return Err(ApiError::not_found("Signing session not found"));
    }

    let user_id = extract_user_id_from_hmac(user_hmac.value())?;
    let keygen_session_id = state
        .db
        .get_keygen_session_id_from_signing_session(&signing_session_id)
        .await?
        .ok_or_else(|| ApiError::database("Could not find associated keygen session"))?;

    let user_public_key = state
        .db
        .get_user_public_key_from_keygen(&keygen_session_id, &user_id)
        .await?
        .ok_or_else(|| ApiError::bad_request("User is not a participant in this keygen session"))?;

    validate_user_hmac_against_public_key(&user_id, user_hmac.value(), &user_public_key)?;

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

fn extract_user_id_from_hmac(user_hmac: &str) -> Result<UserId, ApiError> {
    let parts: Vec<&str> = user_hmac.split(':').collect();
    if parts.len() != 3 {
        return Err(ApiError::bad_request(
            "Invalid user HMAC format, expected 'user_id:nonce:signature'",
        ));
    }

    let user_id_str = parts[0];
    UserId::parse(user_id_str).map_err(|_| ApiError::bad_request("Invalid user ID in HMAC"))
}

fn validate_user_hmac_against_public_key(
    expected_user_id: &UserId,
    user_hmac: &str,
    user_public_key: &[u8],
) -> Result<(), ApiError> {
    let parts: Vec<&str> = user_hmac.split(':').collect();
    if parts.len() != 3 {
        return Err(ApiError::bad_request(
            "Invalid user HMAC format, expected 'user_id:nonce:signature'",
        ));
    }

    let hmac_user_id = parts[0];
    if hmac_user_id != expected_user_id.as_str() {
        return Err(ApiError::bad_request(
            "User ID in HMAC does not match expected user ID",
        ));
    }

    validate_user_hmac(&expected_user_id.as_str(), user_hmac, user_public_key)
        .map_err(|e| ApiError::bad_request(format!("User HMAC validation failed: {}", e)))?;

    info!("User HMAC validated for user: {}", expected_user_id);
    Ok(())
}

async fn validate_keygen_session_hmac(
    state: &AppState,
    keygen_session_id: &SessionId,
    user_id: &UserId,
    session_hmac: &str,
    encrypted_session_secret: &str,
) -> Result<(), ApiError> {
    let participants = state.db.get_keygen_participants(keygen_session_id).await?;

    let participant_enclave = participants
        .iter()
        .find(|p| p.user_id == *user_id)
        .ok_or_else(|| ApiError::bad_request("User is not a participant in this keygen session"))?
        .enclave_id;

    state
        .enclave_manager
        .validate_keygen_participant_hmac(
            &participant_enclave,
            keygen_session_id,
            user_id,
            session_hmac,
            encrypted_session_secret,
        )
        .await
        .map_err(|e| ApiError::bad_request(format!("Session HMAC validation failed: {}", e)))?;

    Ok(())
}

#[utoipa::path(
    get,
    path = "/signing/{signing_session_id}/status",
    tag = "signing",
    summary = "Get signing session status",
    description = "Retrieves the current status and details of a signing session, including approval information when in collecting_participants status. Requires X-Signing-HMAC header containing user HMAC in format 'user_id:nonce:signature' signed with user's private key.",
    security(
        ("SigningHmac" = [])
    ),
    params(
        ("signing_session_id" = SessionId, Path, description = "Signing session ID")
    ),
    responses(
        (status = 200, description = "Signing status retrieved successfully", body = SigningSessionStatusResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 401, description = "Missing or malformed Authorization header", body = ErrorResponse),
        (status = 403, description = "Invalid signature or user not permitted", body = ErrorResponse),
        (status = 404, description = "Session not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn get_signing_status(
    State(state): State<AppState>,
    Path(signing_session_id): Path<SessionId>,
    TypedHeader(user_hmac): TypedHeader<SigningHmac>,
) -> ApiResult<Json<SigningSessionStatusResponse>> {
    debug!("Getting signing session status: {}", signing_session_id);

    let user_id = extract_user_id_from_hmac(user_hmac.value())?;

    let session_status = state
        .db
        .get_signing_session_by_id(&signing_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Signing session not found"))?;

    let keygen_session_id = state
        .db
        .get_keygen_session_id_from_signing_session(&signing_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Associated keygen session not found"))?;

    let user_public_key = state
        .db
        .get_user_public_key_from_keygen(&keygen_session_id, &user_id)
        .await?
        .ok_or_else(|| {
            ApiError::bad_request("User is not a participant in this signing session")
        })?;

    validate_user_hmac_against_public_key(&user_id, user_hmac.value(), &user_public_key)?;

    let participant_count = state
        .db
        .get_signing_participant_count(&signing_session_id)
        .await?;

    let keygen_session_id = state
        .db
        .get_keygen_session_id_from_signing_session(&signing_session_id)
        .await?
        .ok_or_else(|| ApiError::not_found("Signing session not found"))?;

    let (
        status,
        expected_participants,
        final_signature,
        expires_at,
        participants_requiring_approval,
        approved_participants,
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

    let health_info = state
        .db
        .get_enclave_health(enclave_id)
        .await?
        .ok_or_else(|| {
            ApiError::enclave_communication(format!("Enclave {} not found", enclave_id))
        })?;

    let (attestation_document, pcr_measurements) = if !health_info.attestation_document.is_empty() {
        match serde_json::from_str::<AttestationResponse>(&health_info.attestation_document) {
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
        .ok_or_else(|| ApiError::not_found("Keygen session not found"))?;

    let expected_participants = match session_status {
        KeygenSessionStatus::CollectingParticipants(ref status) => {
            status.expected_participants.len()
        }
        _ => {
            return Err(ApiError::bad_request(
                "Keygen session is not accepting new participants",
            ))
        }
    };

    let current_count = state
        .db
        .get_keygen_participant_count(&keygen_session_id)
        .await?;

    let available_enclaves = state.enclave_manager.list_enclaves();
    if available_enclaves.is_empty() {
        return Err(ApiError::EnclaveCommunication(
            "No enclaves available".to_string(),
        ));
    }

    let mut available_slots = Vec::new();
    for slot_index in current_count..expected_participants {
        let enclave_id = available_enclaves[slot_index % available_enclaves.len()];
        let user_id = UserId::new_v7();

        available_slots.push(AvailableUserSlot {
            user_id,
            enclave_id,
            signer_index: slot_index,
            claimed: false,
        });
    }

    let response = GetAvailableSlotsResponse {
        session_id: keygen_session_id
            .to_string()
            .try_into()
            .map_err(|e| ApiError::Internal(format!("Invalid session ID format: {}", e)))?,
        available_slots,
        total_slots: expected_participants,
        claimed_slots: current_count,
    };

    Ok(Json(response))
}
