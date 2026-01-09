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
use keymeld_core::{crypto::SecureCrypto, identifiers::SessionId};
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
/// Requires `X-User-Signature: nonce:signature` where signature is
/// ECDSA signature over SHA256(key_id + user_id + nonce).
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
            &app_state.nonce_cache,
            &user_key.auth_pubkey,
            &key_id.as_string(),
            &user_id.as_string(),
            signature.value(),
        )?;

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
/// Requires `X-User-Signature: nonce:signature` where signature is
/// ECDSA signature over SHA256(signing_session_id + user_id + nonce).
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

        let auth_pubkey = PublicKey::from_slice(&auth_pubkey_bytes)
            .map_err(|e| ApiError::bad_request(format!("Invalid auth pubkey: {e}")))?;

        // Parse and validate signature
        let (nonce_hex, signature_hex) = signature
            .value()
            .split_once(':')
            .ok_or(ApiError::bad_request("Invalid signature header format"))?;

        let nonce = hex::decode(nonce_hex)
            .map_err(|e| ApiError::bad_request(format!("Invalid nonce hex: {e}")))?;
        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| ApiError::bad_request(format!("Invalid signature hex: {e}")))?;

        // Check nonce for replay protection
        let nonce_key = format!("{}:{}", signing_session_id, nonce_hex);
        if !app_state.nonce_cache.check_and_insert(&nonce_key) {
            return Err(ApiError::bad_request("Nonce already used"));
        }

        // Verify signature
        let is_valid = SecureCrypto::verify_auth_signature_with_session_key(
            &auth_pubkey,
            &signing_session_id.as_string(),
            &user_id.as_string(),
            &nonce,
            &signature_bytes,
        )
        .map_err(|e| ApiError::bad_request(format!("Signature verification failed: {e}")))?;

        if !is_valid {
            return Err(ApiError::unauthorized("Invalid signature"));
        }

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
/// Requires `X-User-Signature: nonce:signature`
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
            &app_state.nonce_cache,
            &user_key.auth_pubkey,
            &key_id.as_string(),
            &user_id.as_string(),
            signature.value(),
        )?;

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
/// Requires `X-Session-Signature: nonce:signature`
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

        keymeld_core::validation::validate_session_signature(
            &session_id.as_string(),
            signature.value(),
            &public_key,
        )
        .map_err(|e| ApiError::bad_request(format!("Session signature validation failed: {e}")))?;

        Ok(KeygenSessionAuth { session_id })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Validate a signature against a public key
fn validate_signature(
    nonce_cache: &NonceCache,
    auth_pubkey_bytes: &[u8],
    scope_id: &str,
    user_id: &str,
    signature_header: &str,
) -> Result<(), ApiError> {
    let auth_pubkey = PublicKey::from_slice(auth_pubkey_bytes)
        .map_err(|e| ApiError::bad_request(format!("Invalid auth pubkey: {e}")))?;

    // Parse the signature header (format: "nonce:signature")
    let (nonce_hex, signature_hex) =
        signature_header
            .split_once(':')
            .ok_or(ApiError::bad_request(
                "Invalid signature header format. Expected 'nonce:signature'",
            ))?;

    let nonce = hex::decode(nonce_hex)
        .map_err(|e| ApiError::bad_request(format!("Invalid nonce hex: {e}")))?;
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| ApiError::bad_request(format!("Invalid signature hex: {e}")))?;

    // Check nonce for replay protection
    let nonce_key = format!("{}:{}:{}", scope_id, user_id, nonce_hex);
    if !nonce_cache.check_and_insert(&nonce_key) {
        return Err(ApiError::bad_request("Nonce already used"));
    }

    // Verify signature
    let is_valid = SecureCrypto::verify_auth_signature_with_session_key(
        &auth_pubkey,
        scope_id,
        user_id,
        &nonce,
        &signature_bytes,
    )
    .map_err(|e| ApiError::bad_request(format!("Signature verification failed: {e}")))?;

    if !is_valid {
        return Err(ApiError::unauthorized("Invalid signature"));
    }

    Ok(())
}

/// Validate user signature for single-signer operations.
/// Use this when the extractor pattern doesn't fit (e.g., key_id in request body).
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
        nonce_cache,
        &user_key.auth_pubkey,
        &key_id.as_string(),
        &user_id.as_string(),
        signature_header,
    )
}

/// Validate signature against a provided auth_pubkey.
/// Use this for import_user_key where the auth_pubkey is in the request body
/// and we need to verify the caller owns the corresponding private key.
pub fn validate_signature_with_pubkey(
    nonce_cache: &NonceCache,
    auth_pubkey: &[u8],
    scope_id: &str,
    user_id: &str,
    signature_header: &str,
) -> Result<(), ApiError> {
    validate_signature(
        nonce_cache,
        auth_pubkey,
        scope_id,
        user_id,
        signature_header,
    )
}
