use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use keymeld_core::KeyMeldError;
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("KeyMeld core error: {0}")]
    KeyMeld(#[from] KeyMeldError),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Configuration error: {0}")]
    Configuration(#[from] anyhow::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Enclave communication error: {0}")]
    EnclaveCommunication(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub fn is_retryable_error(error: &KeyMeldError) -> bool {
    matches!(
        error,
        KeyMeldError::EnclaveError(_) | KeyMeldError::DistributionError(_)
    )
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn database(msg: impl Into<String>) -> Self {
        Self::Database(sqlx::Error::Configuration(msg.into().into()))
    }

    pub fn enclave_communication(msg: impl Into<String>) -> Self {
        Self::EnclaveCommunication(msg.into())
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::KeyMeld(e) => match e {
                KeyMeldError::InvalidConfiguration(_) => StatusCode::BAD_REQUEST,
                KeyMeldError::DistributionError(_) => StatusCode::BAD_REQUEST,
                KeyMeldError::KeyNotFound(_) => StatusCode::NOT_FOUND,
                KeyMeldError::SessionTooLarge(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Configuration(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::EnclaveCommunication(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_type(&self) -> &'static str {
        match self {
            ApiError::KeyMeld(_) => "keymeld_error",
            ApiError::Database(_) => "database_error",
            ApiError::BadRequest(_) => "bad_request",
            ApiError::NotFound(_) => "not_found",
            ApiError::Configuration(_) => "configuration_error",
            ApiError::Serialization(_) => "serialization_error",
            ApiError::EnclaveCommunication(_) => "enclave_communication_error",
            ApiError::Internal(_) => "internal_error",
        }
    }

    pub fn should_log_as_error(&self) -> bool {
        matches!(
            self,
            ApiError::Database(_)
                | ApiError::Configuration(_)
                | ApiError::EnclaveCommunication(_)
                | ApiError::Internal(_)
        ) || matches!(self, ApiError::KeyMeld(e) if !is_retryable_error(e))
    }

    pub fn client_message(&self) -> String {
        match self {
            ApiError::BadRequest(msg) => msg.clone(),
            ApiError::NotFound(msg) => msg.clone(),

            ApiError::Database(_) => "Database operation failed".to_string(),
            ApiError::Configuration(_) => "Server configuration error".to_string(),
            ApiError::Serialization(_) => "Data serialization error".to_string(),
            ApiError::EnclaveCommunication(_) => "Enclave communication failed".to_string(),
            ApiError::Internal(_) => "Internal server error".to_string(),
            ApiError::KeyMeld(e) => match e {
                KeyMeldError::InvalidConfiguration(_) => {
                    "Invalid request configuration".to_string()
                }
                KeyMeldError::DistributionError(msg) => msg.clone(),
                KeyMeldError::KeyNotFound(msg) => msg.clone(),
                KeyMeldError::SessionTooLarge(msg) => msg.clone(),
                _ => "KeyMeld operation failed".to_string(),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_type = self.error_type();
        let client_message = self.client_message();

        if self.should_log_as_error() {
            error!(
                error_type = error_type,
                status_code = %status,
                error = %self,
                "API error occurred"
            );
        } else {
            tracing::warn!(
                error_type = error_type,
                status_code = %status,
                error = %self,
                "API warning occurred"
            );
        }

        let body = Json(json!({
            "error": {
                "type": error_type,
                "message": client_message,
                "code": status.as_u16()
            },
            "timestamp": time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "timestamp_unavailable".to_string())
        }));

        (status, body).into_response()
    }
}

impl From<hex::FromHexError> for ApiError {
    fn from(e: hex::FromHexError) -> Self {
        ApiError::KeyMeld(KeyMeldError::SerializationError(format!(
            "Invalid hex encoding: {}",
            e
        )))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::KeyMeld(KeyMeldError::SerializationError(format!(
            "JSON serialization error: {}",
            e
        )))
    }
}

impl From<uuid::Error> for ApiError {
    fn from(e: uuid::Error) -> Self {
        ApiError::KeyMeld(KeyMeldError::InvalidConfiguration(format!(
            "Invalid UUID: {}",
            e
        )))
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            ApiError::bad_request("test").status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiError::not_found("test").status_code(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_error_types() {
        assert_eq!(ApiError::bad_request("test").error_type(), "bad_request");
        assert_eq!(ApiError::not_found("test").error_type(), "not_found");
        assert_eq!(
            ApiError::Database(sqlx::Error::PoolClosed).error_type(),
            "database_error"
        );
    }

    #[test]
    fn test_should_log_as_error() {
        assert!(ApiError::Database(sqlx::Error::PoolClosed).should_log_as_error());
        assert!(!ApiError::bad_request("test").should_log_as_error());
        assert!(!ApiError::not_found("test").should_log_as_error());
    }

    #[test]
    fn test_client_message_sanitization() {
        assert_eq!(
            ApiError::bad_request("detailed error").client_message(),
            "detailed error"
        );

        assert_eq!(
            ApiError::Database(sqlx::Error::PoolClosed).client_message(),
            "Database operation failed"
        );
    }
}
