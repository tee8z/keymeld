//! Authentication extractors for API endpoints
//!
//! This module provides Axum extractors for validating request signatures.
//! Extractors automatically validate headers and return authenticated context.

use crate::{
    database::Database,
    errors::ApiError,
    handlers::{AppState, NonceCache},
    headers::{SessionSignature, UserSignature},
};
use axum::{
    extract::{FromRef, FromRequestParts, Path},
    http::request::Parts,
    RequestPartsExt,
};
use axum_extra::TypedHeader;
use keymeld_core::{
    identifiers::SessionId,
    request_auth::{delete_key_scope, now_timestamp_secs, AuthKind, RequestAuth},
};
use keymeld_sdk::{KeyId, UserId};
use secp256k1::PublicKey;

// ============================================================================
// User Key Authentication Extractor
// ============================================================================

/// Authenticated user key context.
///
/// This extractor validates X-User-Signature header against the auth_pubkey
/// stored in the user_keys table. Use this for endpoints that operate on
/// a specific user's key (identified by user_id and key_id in the path).
///
/// # Path Parameters
/// Expects path to contain `(user_id, key_id)` tuple.
///
/// # Header
/// Requires `X-User-Signature: v1:timestamp:nonce:signature` where signature is
/// ECDSA proof over a versioned scope, user ID, timestamp, and nonce commitment.
///
/// # Example
/// ```ignore
/// pub async fn delete_user_key(
///     State(state): State<AppState>,
///     UserKeyAuth((user_id, key_id)): UserKeyAuth,
/// ) -> ApiResult<Json<Response>> {
///     // user_id and key_id are validated
/// }
/// ```
#[derive(Debug, Clone)]
pub struct UserKeyAuth(pub (UserId, KeyId));

impl<S> FromRequestParts<S> for UserKeyAuth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract path parameters (user_id, key_id)
        let Path((user_id_str, key_id_str)): Path<(String, String)> = parts
            .extract()
            .await
            .map_err(|_| ApiError::bad_request("Missing user_id or key_id in path"))?;

        let user_id = UserId::parse(&user_id_str)
            .map_err(|e| ApiError::bad_request(format!("Invalid user_id: {e}")))?;
        let key_id = KeyId::parse(&key_id_str)
            .map_err(|e| ApiError::bad_request(format!("Invalid key_id: {e}")))?;

        // Extract signature header
        let TypedHeader(signature): TypedHeader<UserSignature> = parts
            .extract()
            .await
            .map_err(|_| ApiError::unauthorized("Missing X-User-Signature header"))?;

        let auth_pubkey = if let Some(user_key) = app_state
            .db
            .get_user_key_by_user_and_key(&user_id, &key_id)
            .await?
        {
            user_key.auth_pubkey
        } else if parts.method == axum::http::Method::GET && parts.uri.path().ends_with("/status") {
            // Import failures and pending copies still belong to their authenticated
            // submitter. Only status polling may use these pending credentials.
            if let Some(import) = app_state
                .db
                .get_pending_key_import(&key_id)
                .await?
                .filter(|import| import.user_id == user_id)
            {
                import.auth_pubkey
            } else if let Some(store) = app_state
                .db
                .get_pending_key_store(&key_id)
                .await?
                .filter(|store| store.user_id == user_id)
            {
                app_state
                    .db
                    .get_participant_auth_pubkey(&user_id, &store.keygen_session_id)
                    .await?
            } else {
                return Err(ApiError::not_found("Key operation not found"));
            }
        } else {
            return Err(ApiError::not_found("Stored key not found"));
        };

        let scope = if parts.method == axum::http::Method::DELETE {
            delete_key_scope(&key_id.as_string())
        } else {
            key_id.as_string()
        };
        validate_signature(
            &app_state.db,
            &app_state.nonce_cache,
            &auth_pubkey,
            &scope,
            &user_id.as_string(),
            signature.value(),
        )
        .await?;

        Ok(UserKeyAuth((user_id, key_id)))
    }
}

// ============================================================================
// Session Authentication Extractor (for MuSig2 signing operations)
// ============================================================================

/// Authenticated signing session context.
///
/// This extractor validates X-User-Signature header against the auth_pubkey
/// stored for the participant in the keygen session. Use this for MuSig2
/// signing endpoints.
///
/// # Path Parameters
/// Expects path to contain `(signing_session_id, user_id)` tuple.
///
/// # Header
/// Requires `X-User-Signature: v1:timestamp:nonce:signature` where signature is
/// ECDSA proof over a versioned scope, user ID, timestamp, and nonce commitment.
#[derive(Debug, Clone)]
pub struct SigningSessionAuth {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
}

impl<S> FromRequestParts<S> for SigningSessionAuth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract path parameters (signing_session_id, user_id)
        let Path((signing_session_id, user_id)): Path<(SessionId, UserId)> = parts
            .extract()
            .await
            .map_err(|_| ApiError::bad_request("Missing signing_session_id or user_id in path"))?;

        // Extract signature header
        let TypedHeader(signature): TypedHeader<UserSignature> = parts
            .extract()
            .await
            .map_err(|_| ApiError::unauthorized("Missing X-User-Signature header"))?;

        // Get keygen_session_id from signing session
        let keygen_session_id = app_state
            .db
            .get_keygen_session_id_from_signing_session(&signing_session_id)
            .await?
            .ok_or(ApiError::not_found("Signing session not found"))?;

        // Get auth_pubkey from keygen participant
        let auth_pubkey_bytes = app_state
            .db
            .get_participant_auth_pubkey(&user_id, &keygen_session_id)
            .await?;

        validate_signature_with_pubkey(
            &app_state.db,
            &app_state.nonce_cache,
            &auth_pubkey_bytes,
            &signing_session_id.as_string(),
            &user_id.as_string(),
            signature.value(),
        )
        .await?;

        Ok(SigningSessionAuth {
            signing_session_id,
            keygen_session_id,
            user_id,
        })
    }
}

// ============================================================================
// Single Signing Session Authentication Extractor
// ============================================================================

/// Authenticated single signing session context.
///
/// This extractor validates X-User-Signature header for single-signer signing
/// status endpoints. It looks up the key_id from the signing session and
/// validates against the user's auth_pubkey.
///
/// # Path Parameters
/// Expects path to contain `(signing_session_id, user_id)` tuple.
///
/// # Header
/// Requires `X-User-Signature: v1:timestamp:nonce:signature`
#[derive(Debug, Clone)]
pub struct SingleSigningAuth(pub (SessionId, UserId, KeyId));

impl<S> FromRequestParts<S> for SingleSigningAuth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract path parameters (signing_session_id, user_id)
        let Path((session_id_str, user_id_str)): Path<(String, String)> = parts
            .extract()
            .await
            .map_err(|_| ApiError::bad_request("Missing session_id or user_id in path"))?;

        let session_id = SessionId::parse(&session_id_str)
            .map_err(|e| ApiError::bad_request(format!("Invalid session_id: {e}")))?;
        let user_id = UserId::parse(&user_id_str)
            .map_err(|e| ApiError::bad_request(format!("Invalid user_id: {e}")))?;

        // Extract signature header
        let TypedHeader(signature): TypedHeader<UserSignature> = parts
            .extract()
            .await
            .map_err(|_| ApiError::unauthorized("Missing X-User-Signature header"))?;

        // Get the signing session to find the key_id
        let session = app_state
            .db
            .get_single_signing_session(&session_id)
            .await?
            .ok_or_else(|| ApiError::not_found("Single signing session not found"))?;

        // Verify the user matches
        if session.user_id != user_id {
            return Err(ApiError::not_found("Single signing session not found"));
        }

        let key_id = session.key_id;

        // Get auth_pubkey from user_keys table
        let user_key = app_state
            .db
            .get_user_key_by_user_and_key(&user_id, &key_id)
            .await?
            .ok_or_else(|| {
                ApiError::not_found(format!("Key {} not found for user {}", key_id, user_id))
            })?;

        // Validate signature
        validate_signature(
            &app_state.db,
            &app_state.nonce_cache,
            &user_key.auth_pubkey,
            &key_id.as_string(),
            &user_id.as_string(),
            signature.value(),
        )
        .await?;

        Ok(SingleSigningAuth((session_id, user_id, key_id)))
    }
}

// ============================================================================
// Session Signature Extractor (for keygen operations)
// ============================================================================

/// Authenticated keygen session context.
///
/// This extractor validates X-Session-Signature header against the session
/// public key stored in the database.
///
/// # Path Parameters
/// Expects path to contain session_id.
///
/// # Header
/// Requires `X-Session-Signature: v1:timestamp:nonce:signature`
#[derive(Debug, Clone)]
pub struct KeygenSessionAuth {
    pub session_id: SessionId,
}

impl<S> FromRequestParts<S> for KeygenSessionAuth
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        // Extract session_id from path - try different path patterns
        let session_id: SessionId = if let Ok(Path(id)) = parts.extract::<Path<SessionId>>().await {
            id
        } else if let Ok(Path((id, _))) = parts.extract::<Path<(SessionId, String)>>().await {
            id
        } else {
            return Err(ApiError::bad_request("Missing session_id in path"));
        };

        // Extract signature header
        let TypedHeader(signature): TypedHeader<SessionSignature> = parts
            .extract()
            .await
            .map_err(|_| ApiError::unauthorized("Missing X-Session-Signature header"))?;

        // Validate session signature
        let public_key = app_state
            .db
            .get_session_public_key(&session_id)
            .await?
            .ok_or_else(|| ApiError::not_found("Session not found"))?;

        validate_session_signature_with_pubkey(
            &app_state.db,
            &app_state.nonce_cache,
            &public_key,
            &session_id.as_string(),
            signature.value(),
        )
        .await?;

        Ok(KeygenSessionAuth { session_id })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Verify first, then atomically claim the proof in durable storage. Invalid
/// signatures cannot consume another caller's nonce or force database writes.
async fn validate_signature(
    db: &Database,
    nonce_cache: &NonceCache,
    auth_pubkey_bytes: &[u8],
    scope_id: &str,
    user_id: &str,
    signature_header: &str,
) -> Result<(), ApiError> {
    validate_proof(
        db,
        nonce_cache,
        auth_pubkey_bytes,
        AuthKind::User,
        scope_id,
        user_id,
        signature_header,
    )
    .await
}

async fn validate_proof(
    db: &Database,
    nonce_cache: &NonceCache,
    auth_pubkey_bytes: &[u8],
    kind: AuthKind,
    scope_id: &str,
    user_id: &str,
    signature_header: &str,
) -> Result<(), ApiError> {
    let auth_pubkey = PublicKey::from_slice(auth_pubkey_bytes)
        .map_err(|e| ApiError::bad_request(format!("Invalid auth pubkey: {e}")))?;
    let proof =
        RequestAuth::parse(signature_header).map_err(|e| ApiError::unauthorized(e.to_string()))?;
    proof
        .verify(
            kind,
            scope_id,
            user_id,
            &auth_pubkey,
            now_timestamp_secs().map_err(|e| ApiError::unauthorized(e.to_string()))?,
        )
        .map_err(|e| ApiError::unauthorized(e.to_string()))?;
    nonce_cache
        .claim_verified(
            db,
            proof.replay_key(kind, scope_id, user_id, &auth_pubkey),
            proof.timestamp,
        )
        .await
}

/// Validate user authentication when the key ID is carried in the request body.
pub async fn validate_user_key_signature(
    db: &Database,
    nonce_cache: &NonceCache,
    user_id: &UserId,
    key_id: &KeyId,
    signature_header: &str,
) -> Result<(), ApiError> {
    let user_key = db
        .get_user_key_by_user_and_key(user_id, key_id)
        .await?
        .ok_or_else(|| {
            ApiError::not_found(format!("Key {} not found for user {}", key_id, user_id))
        })?;
    validate_signature(
        db,
        nonce_cache,
        &user_key.auth_pubkey,
        &key_id.as_string(),
        &user_id.as_string(),
        signature_header,
    )
    .await
}

pub async fn validate_signature_with_pubkey(
    db: &Database,
    nonce_cache: &NonceCache,
    auth_pubkey: &[u8],
    scope_id: &str,
    user_id: &str,
    signature_header: &str,
) -> Result<(), ApiError> {
    validate_signature(
        db,
        nonce_cache,
        auth_pubkey,
        scope_id,
        user_id,
        signature_header,
    )
    .await
}

pub async fn validate_session_signature_with_pubkey(
    db: &Database,
    nonce_cache: &NonceCache,
    session_pubkey: &[u8],
    scope_id: &str,
    signature_header: &str,
) -> Result<(), ApiError> {
    validate_proof(
        db,
        nonce_cache,
        session_pubkey,
        AuthKind::Session,
        scope_id,
        "",
        signature_header,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use secp256k1::{SecretKey, SECP256K1};
    use std::sync::Arc;

    fn config(path: &std::path::Path) -> DatabaseConfig {
        DatabaseConfig {
            path: path.to_string_lossy().into_owned(),
            max_connections: 5,
            connection_timeout_secs: 5,
            idle_timeout_secs: Some(60),
            enable_wal_mode: Some(true),
        }
    }

    #[tokio::test]
    async fn verified_proofs_are_consumed_atomically_and_survive_cache_loss_and_restart() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(&directory.path().join("replay.sqlite"));
        let db = Database::new(&config).await.unwrap();
        let cache = NonceCache::new();
        let private_key = SecretKey::from_byte_array([42; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key).serialize();
        let timestamp = now_timestamp_secs().unwrap();
        let proof = RequestAuth::sign(
            AuthKind::User,
            "key",
            "user",
            &private_key,
            timestamp,
            [3; 16],
        );
        let header = proof.to_header();

        // A forged proof with the same nonce must not poison the valid proof's claim.
        let forged = RequestAuth::sign(
            AuthKind::User,
            "key",
            "user",
            &SecretKey::from_byte_array([43; 32]).unwrap(),
            timestamp,
            [3; 16],
        )
        .to_header();
        assert!(
            validate_signature_with_pubkey(&db, &cache, &public_key, "key", "user", &forged)
                .await
                .is_err()
        );

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let (db, cache, header) = (db.clone(), cache.clone(), header.clone());
            tasks.spawn(async move {
                validate_signature_with_pubkey(&db, &cache, &public_key, "key", "user", &header)
                    .await
                    .is_ok()
            });
        }
        let mut accepted = 0;
        while let Some(result) = tasks.join_next().await {
            accepted += usize::from(result.unwrap());
        }
        assert_eq!(accepted, 1);

        // Cache eviction and an independent process opening the persisted database
        // must not make a still-fresh consumed proof usable again.
        let cache = NonceCache::new();
        assert!(
            validate_signature_with_pubkey(&db, &cache, &public_key, "key", "user", &header)
                .await
                .is_err()
        );
        drop(db);
        let restarted = Database::new(&config).await.unwrap();
        assert!(validate_signature_with_pubkey(
            &restarted,
            &NonceCache::new(),
            &public_key,
            "key",
            "user",
            &header.to_uppercase().replacen("V1:", "v1:", 1)
        )
        .await
        .is_err());

        let fresh = RequestAuth::sign(
            AuthKind::User,
            "key",
            "user",
            &private_key,
            timestamp,
            [4; 16],
        )
        .to_header();
        validate_signature_with_pubkey(&restarted, &cache, &public_key, "key", "user", &fresh)
            .await
            .unwrap();

        let session_proof = RequestAuth::sign(
            AuthKind::Session,
            "session",
            "",
            &private_key,
            timestamp,
            [5; 16],
        )
        .to_header();
        assert!(validate_signature_with_pubkey(
            &restarted,
            &cache,
            &public_key,
            "session",
            "",
            &session_proof
        )
        .await
        .is_err());
        validate_session_signature_with_pubkey(
            &restarted,
            &cache,
            &public_key,
            "session",
            &session_proof,
        )
        .await
        .unwrap();
        assert!(validate_session_signature_with_pubkey(
            &restarted,
            &NonceCache::new(),
            &public_key,
            "session",
            &session_proof
        )
        .await
        .is_err());
    }

    #[derive(Clone)]
    struct HttpTestState {
        db: Arc<Database>,
        cache: NonceCache,
        public_key: [u8; 33],
    }

    async fn authenticated_test_route(
        axum::extract::State(state): axum::extract::State<HttpTestState>,
        method: axum::http::Method,
        headers: axum::http::HeaderMap,
    ) -> Result<axum::http::StatusCode, ApiError> {
        let header = headers
            .get("x-user-signature")
            .and_then(|header| header.to_str().ok())
            .ok_or_else(|| ApiError::unauthorized("Missing authentication"))?;
        let scope = if method == axum::http::Method::DELETE {
            delete_key_scope("key")
        } else {
            "key".to_owned()
        };
        validate_signature_with_pubkey(
            &state.db,
            &state.cache,
            &state.public_key,
            &scope,
            "user",
            header,
        )
        .await?;
        Ok(axum::http::StatusCode::NO_CONTENT)
    }

    async fn send_http(address: std::net::SocketAddr, method: &str, proof: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(format!("{method} /key HTTP/1.1\r\nHost: localhost\r\nX-User-Signature: {proof}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        std::str::from_utf8(&response)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn http_rejects_timeless_expired_future_cross_action_and_replayed_proofs() {
        let directory = tempfile::tempdir().unwrap();
        let db = Database::new(&config(&directory.path().join("http.sqlite")))
            .await
            .unwrap();
        let private_key = SecretKey::from_byte_array([42; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key).serialize();
        let state = HttpTestState {
            db: Arc::new(db),
            cache: NonceCache::new(),
            public_key,
        };
        let router = axum::Router::new()
            .route(
                "/key",
                axum::routing::get(authenticated_test_route).delete(authenticated_test_route),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let now = now_timestamp_secs().unwrap();
        let proof = |scope: &str, timestamp: u64, nonce: u8| {
            RequestAuth::sign(
                AuthKind::User,
                scope,
                "user",
                &private_key,
                timestamp,
                [nonce; 16],
            )
            .to_header()
        };
        let read = proof("key", now, 1);
        let legacy = read.split(':').skip(2).collect::<Vec<_>>().join(":");
        assert_eq!(send_http(address, "GET", "").await, 401);
        assert_eq!(send_http(address, "GET", &legacy).await, 401);
        assert_eq!(
            send_http(address, "GET", &proof("key", now - 601, 2)).await,
            401
        );
        assert_eq!(
            send_http(address, "GET", &proof("key", now + 600, 3)).await,
            401
        );
        assert_eq!(send_http(address, "DELETE", &read).await, 401);
        assert_eq!(send_http(address, "GET", &read).await, 204);
        assert_eq!(send_http(address, "GET", &read).await, 401);
        assert_eq!(
            send_http(address, "DELETE", &proof(&delete_key_scope("key"), now, 4)).await,
            204
        );
        server.abort();
    }
}
