use super::Database;
use crate::errors::ApiError;
use keymeld_core::request_auth::{now_timestamp_secs, validate_timestamp, MAX_AUTH_AGE_SECS};

impl Database {
    /// Atomically consume a verified proof. A persistent unique constraint is the
    /// replay authority; an in-memory cache is only an optimization.
    pub(crate) async fn claim_request_auth_nonce(
        &self,
        nonce_key: String,
        timestamp: u64,
    ) -> Result<(), ApiError> {
        self.writer.execute(self.pool.clone(), move |pool| async move {
            let now = now_timestamp_secs()
                .map_err(|e| ApiError::unauthorized(e.to_string()))?;
            validate_timestamp(timestamp, now)
                .map_err(|e| ApiError::unauthorized(e.to_string()))?;
            let expires_at = i64::try_from(timestamp.saturating_add(MAX_AUTH_AGE_SECS))
                .map_err(|_| ApiError::unauthorized("Invalid authentication expiry"))?;
            let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
            sqlx::query("DELETE FROM request_auth_nonces WHERE expires_at < ?")
                .bind(now as i64)
                .execute(&mut *transaction).await?;
            let claim = sqlx::query(
                "INSERT INTO request_auth_nonces (nonce_key, expires_at) VALUES (?, ?) ON CONFLICT DO NOTHING",
            )
                .bind(nonce_key)
                .bind(expires_at)
                .execute(&mut *transaction).await?;
            if claim.rows_affected() != 1 {
                return Err(ApiError::unauthorized("Authentication proof already used"));
            }
            transaction.commit().await?;
            Ok(())
        }).await
    }
}
