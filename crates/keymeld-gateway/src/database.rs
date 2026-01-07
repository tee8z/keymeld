use crate::{
    config::DatabaseConfig,
    encrypted_data::{SigningEnclaveData, SigningSessionData},
    errors::ApiError,
    session::{
        keygen::{KeygenCollectingParticipants, KeygenReserved, KeygenSessionStatus},
        signing::{SigningCollectingParticipants, SigningSessionStatus},
        types::ParticipantData,
        SessionKind,
    },
};
use anyhow::{Context, Result};
use keymeld_core::{
    identifiers::{EnclaveId, SessionId, UserId},
    protocol::{KeygenStatusKind, SigningStatusKind},
};
use keymeld_sdk::{
    CreateSigningSessionRequest, InitializeKeygenSessionRequest, RegisterKeygenParticipantRequest,
    ReserveKeygenSessionRequest,
};
use secp256k1::PublicKey;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow},
    FromRow, Row,
};
use std::{collections::BTreeMap, future::Future, str::FromStr, time::Duration};
use time::OffsetDateTime;
use tokio::{
    fs::create_dir_all,
    sync::{mpsc, oneshot},
};
use tracing::{debug, info, warn};

pub struct DbUtils;

impl DbUtils {
    pub fn current_timestamp() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }
}

type WriteOperation = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Debug)]
pub struct DatabaseWriter {
    write_tx: mpsc::UnboundedSender<WriteOperation>,
    _handle: tokio::task::JoinHandle<()>,
}

impl Default for DatabaseWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl DatabaseWriter {
    pub fn new() -> Self {
        let (write_tx, mut write_rx) = mpsc::unbounded_channel::<WriteOperation>();

        let handle = tokio::spawn(async move {
            while let Some(future) = write_rx.recv().await {
                future.await;
            }
        });

        Self {
            write_tx,
            _handle: handle,
        }
    }

    pub async fn execute<T, F, Fut>(&self, pool: SqlitePool, operation: F) -> Result<T, ApiError>
    where
        T: Send + 'static,
        F: FnOnce(SqlitePool) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, ApiError>> + Send + 'static,
    {
        let (result_tx, result_rx) = oneshot::channel::<Result<T, ApiError>>();

        let write_op = Box::pin(async move {
            let result = operation(pool).await;
            let _ = result_tx.send(result);
        });

        self.write_tx
            .send(write_op)
            .map_err(|_| ApiError::database("Database writer channel closed".to_string()))?;

        result_rx
            .await
            .map_err(|_| ApiError::database("Failed to receive write result".to_string()))?
    }
}

#[derive(Debug)]
pub struct Database {
    pool: SqlitePool,
    path: String,
    writer: DatabaseWriter,
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            path: self.path.clone(),
            writer: DatabaseWriter::new(),
        }
    }
}

impl Database {
    pub async fn new(config: &DatabaseConfig) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(&config.path).parent() {
            create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create database directory: {parent:?}"))?;
        }

        let mut options = SqliteConnectOptions::from_str(&format!("sqlite:{}", config.path))?
            .create_if_missing(true);

        if config.enable_wal_mode.unwrap_or(true) {
            options = options.pragma("journal_mode", "WAL");
        }

        options = options
            .pragma("synchronous", "NORMAL")
            .pragma("busy_timeout", "5000")
            .pragma("cache_size", "-64000")
            .pragma("foreign_keys", "ON")
            .pragma("temp_store", "MEMORY");

        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(config.connection_timeout_secs))
            .idle_timeout(config.idle_timeout_secs.map(Duration::from_secs))
            .connect_with(options)
            .await
            .context("Failed to create database connection pool")?;

        let db = Self {
            pool,
            path: config.path.clone(),
            writer: DatabaseWriter::new(),
        };

        db.run_migrations().await?;

        info!("Database initialized successfully at: {}", config.path);

        Ok(db)
    }

    async fn run_migrations(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .context("Failed to run database migrations")?;

        Ok(())
    }

    pub async fn get_stats(&self) -> Result<DatabaseStats, ApiError> {
        let keygen_session_count: i64 =
            sqlx::query_scalar!("SELECT COUNT(keygen_session_id) as count FROM keygen_sessions")
                .fetch_one(&self.pool)
                .await?;

        let signing_session_count: i64 =
            sqlx::query_scalar!("SELECT COUNT(signing_session_id) as count FROM signing_sessions")
                .fetch_one(&self.pool)
                .await?;

        let active_keygen_sessions: i64 = sqlx::query_scalar!(
            "SELECT COUNT(keygen_session_id) as count FROM keygen_sessions WHERE status_name NOT IN ('completed', 'failed')"
        )
        .fetch_one(&self.pool)
        .await?;

        let active_signing_sessions: i64 = sqlx::query_scalar!(
            "SELECT COUNT(signing_session_id) as count FROM signing_sessions WHERE status_name NOT IN ('completed', 'failed')"
        )
        .fetch_one(&self.pool)
        .await?;

        let total_participants: i64 =
            sqlx::query_scalar!("SELECT COUNT(id) as count FROM keygen_participants")
                .fetch_one(&self.pool)
                .await?;

        let database_size = std::fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);

        Ok(DatabaseStats {
            total_sessions: keygen_session_count + signing_session_count,
            active_sessions: active_keygen_sessions + active_signing_sessions,
            total_participants,
            database_size_bytes: Some(database_size),
        })
    }

    pub async fn health_check(&self) -> Result<(), ApiError> {
        sqlx::query!("SELECT 1 as health_check")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ApiError::database(format!("Database health check failed: {e}")))?;

        Ok(())
    }

    pub async fn cleanup_expired_keygen_sessions(&self) -> Result<usize, ApiError> {
        self.writer
            .execute(self.pool.clone(), |pool| async move {
                let current_time = OffsetDateTime::now_utc().unix_timestamp();

                let deleted_sessions = sqlx::query!(
                    "DELETE FROM keygen_sessions WHERE expires_at < $1",
                    current_time
                )
                .execute(&pool)
                .await?
                .rows_affected();

                if deleted_sessions > 0 {
                    debug!("Cleaned up {} expired keygen sessions", deleted_sessions);
                }

                Ok(deleted_sessions as usize)
            })
            .await
    }

    pub async fn cleanup_old_completed_keygen_sessions(
        &self,
        retention_hours: u64,
    ) -> Result<usize, ApiError> {
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = OffsetDateTime::now_utc().unix_timestamp();
                let cutoff_time = current_time - (retention_hours as i64 * 3600);

                let deleted_sessions = sqlx::query!(
                    r#"DELETE FROM keygen_sessions
                     WHERE status_name IN ('completed', 'failed')
                     AND (completed_at < $1 OR failed_at < $2)"#,
                    cutoff_time,
                    cutoff_time
                )
                .execute(&pool)
                .await?
                .rows_affected();

                if deleted_sessions > 0 {
                    debug!(
                        "Cleaned up {} old completed/failed keygen sessions",
                        deleted_sessions
                    );
                }

                Ok(deleted_sessions as usize)
            })
            .await
    }

    pub async fn cleanup_expired_signing_sessions(&self) -> Result<usize, ApiError> {
        self.writer
            .execute(self.pool.clone(), |pool| async move {
                let current_time = OffsetDateTime::now_utc().unix_timestamp();

                let deleted_sessions = sqlx::query!(
                    "DELETE FROM signing_sessions WHERE expires_at < $1",
                    current_time
                )
                .execute(&pool)
                .await?
                .rows_affected();

                if deleted_sessions > 0 {
                    debug!("Cleaned up {} expired signing sessions", deleted_sessions);
                }

                Ok(deleted_sessions as usize)
            })
            .await
    }

    pub async fn cleanup_old_completed_signing_sessions(
        &self,
        retention_hours: u64,
    ) -> Result<usize, ApiError> {
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = OffsetDateTime::now_utc().unix_timestamp();
                let cutoff_time = current_time - (retention_hours as i64 * 3600);

                let deleted_sessions = sqlx::query!(
                    r#"DELETE FROM signing_sessions
                     WHERE status_name IN ('completed', 'failed')
                     AND (completed_at < $1 OR failed_at < $2)"#,
                    cutoff_time,
                    cutoff_time
                )
                .execute(&pool)
                .await?
                .rows_affected();

                if deleted_sessions > 0 {
                    debug!(
                        "Cleaned up {} old completed/failed signing sessions",
                        deleted_sessions
                    );
                }

                Ok(deleted_sessions as usize)
            })
            .await
    }

    pub async fn count_signing_sessions_for_keygen(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<usize, ApiError> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) as count FROM signing_sessions WHERE keygen_session_id = $1",
            keygen_session_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    pub async fn get_keygen_session_max_signing_sessions(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Option<u32>, ApiError> {
        let row = sqlx::query!(
            "SELECT max_signing_sessions FROM keygen_sessions WHERE keygen_session_id = $1",
            keygen_session_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.and_then(|r| r.max_signing_sessions.map(|s| s as u32)))
    }

    pub async fn reserve_keygen_session(
        &self,
        request: &ReserveKeygenSessionRequest,
        coordinator_enclave_id: EnclaveId,
    ) -> Result<(), ApiError> {
        let request = request.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = DbUtils::current_timestamp();
                let expires_at = current_time + request.timeout_secs as i64;

                let status = KeygenSessionStatus::Reserved(KeygenReserved {
                    keygen_session_id: request.keygen_session_id.clone(),
                    coordinator_user_id: request.coordinator_user_id.clone(),
                    coordinator_enclave_id,
                    expected_participants: request.expected_participants.clone(),
                    created_at: current_time as u64,
                    expires_at: expires_at as u64,
                    max_signing_sessions: request.max_signing_sessions,
                    encrypted_taproot_tweak: request.encrypted_taproot_tweak.clone(),
                });

                let status_json = serde_json::to_string(&status).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize keygen status: {e}"))
                })?;

                let status_name = status.kind().to_string();
                let keygen_session_id = &request.keygen_session_id;
                let coordinator_enclave_id_i64 = coordinator_enclave_id.as_u32() as i64;
                let max_signing_sessions = request.max_signing_sessions.map(|max| max as i64);
                let expected_participants_json =
                    serde_json::to_string(&request.expected_participants)?;

                sqlx::query!(
                    r#"INSERT INTO keygen_sessions (
                        keygen_session_id, status_name, coordinator_enclave_id, created_at,
                        expires_at, updated_at, retry_count, max_signing_sessions,
                        expected_participants, status, session_encrypted_data, enclave_encrypted_data,
                        session_public_key
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, NULL, NULL)"#,
                    keygen_session_id,
                    status_name,
                    coordinator_enclave_id_i64,
                    current_time,
                    expires_at,
                    current_time,
                    0i32,
                    max_signing_sessions,
                    expected_participants_json,
                    status_json
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    pub async fn initialize_keygen_session(
        &self,
        session_id: &SessionId,
        request: &InitializeKeygenSessionRequest,
    ) -> Result<String, ApiError> {
        let session_id = session_id.clone();
        let request = request.clone();

        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                // First get the existing reserved session
                let existing_row = sqlx::query!(
                    "SELECT status, coordinator_enclave_id FROM keygen_sessions WHERE keygen_session_id = $1",
                    session_id
                )
                .fetch_optional(&pool)
                .await?;

                let existing_row = existing_row.ok_or_else(|| {
                    ApiError::NotFound("Keygen session not found".to_string())
                })?;

                let status_json: String = existing_row.status;
                let existing_status: KeygenSessionStatus = serde_json::from_str(&status_json)
                    .map_err(|e| ApiError::Internal(format!("Failed to deserialize session status: {e}")))?;

                // Validate that session is in Reserved state
                let reserved_session = match existing_status {
                    KeygenSessionStatus::Reserved(reserved) => reserved,
                    _ => return Err(ApiError::BadRequest("Session is not in reserved state".to_string())),
                };

                let coordinator_pubkey = match PublicKey::from_slice(&request.coordinator_pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(e) => {
                        return Err(ApiError::bad_request(format!(
                            "Invalid coordinator public key: {e}"
                        )))
                    }
                };

                // Create the new CollectingParticipants status
                let new_status = KeygenSessionStatus::CollectingParticipants(KeygenCollectingParticipants {
                    keygen_session_id: reserved_session.keygen_session_id,
                    coordinator_pubkey,
                    coordinator_encrypted_private_key: request.coordinator_encrypted_private_key.clone(),
                    session_public_key: request.session_public_key.clone(),
                    encrypted_session_secret: request.encrypted_session_secret.clone(),
                    coordinator_enclave_id: reserved_session.coordinator_enclave_id,
                    expected_participants: reserved_session.expected_participants,
                    registered_participants: BTreeMap::new(),
                    created_at: reserved_session.created_at,
                    expires_at: reserved_session.expires_at,
                    required_enclave_epochs: BTreeMap::new(),
                    encrypted_taproot_tweak: reserved_session.encrypted_taproot_tweak,
                });

                let status_json = serde_json::to_string(&new_status).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize keygen status: {e}"))
                })?;

                let status_name = new_status.kind().to_string();
                let current_time = DbUtils::current_timestamp();
                let session_encrypted_data = request.encrypted_session_data.clone();
                let enclave_encrypted_data = request.encrypted_enclave_data.clone();
                let session_public_key = request.session_public_key.as_slice();

                // Update the session with encrypted data and new status
                sqlx::query!(
                    r#"UPDATE keygen_sessions SET
                        status_name = $1,
                        status = $2,
                        session_encrypted_data = $3,
                        enclave_encrypted_data = $4,
                        session_public_key = $5,
                        updated_at = $6
                    WHERE keygen_session_id = $7"#,
                    status_name,
                    status_json,
                    session_encrypted_data,
                    enclave_encrypted_data,
                    session_public_key,
                    current_time,
                    session_id
                )
                .execute(&pool)
                .await?;

                Ok(request.encrypted_session_secret.clone())
            })
            .await
    }

    pub async fn get_keygen_session_by_id(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Option<KeygenSessionStatus>, ApiError> {
        let row = sqlx::query!(
            "SELECT status FROM keygen_sessions WHERE keygen_session_id = $1",
            keygen_session_id
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let status_json: String = row.status;
                let mut status: KeygenSessionStatus =
                    serde_json::from_str(&status_json).map_err(|e| {
                        ApiError::Serialization(format!("Failed to deserialize keygen status: {e}"))
                    })?;

                // Load and merge participants from the keygen_participants table
                let participants = self.get_keygen_participants(keygen_session_id).await?;

                let participants_map: BTreeMap<UserId, ParticipantData> = participants
                    .into_iter()
                    .map(|p| (p.user_id.clone(), p))
                    .collect();
                if let Err(e) = status.merge_participants(participants_map) {
                    warn!("Failed to merge participants: {}", e);
                }

                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    pub async fn get_session_public_key(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let row = sqlx::query!(
            "SELECT session_public_key FROM keygen_sessions WHERE keygen_session_id = $1",
            keygen_session_id
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(row.session_public_key),
            None => Ok(None),
        }
    }

    pub async fn register_keygen_participant_with_encrypted_data(
        &self,
        keygen_session_id: &SessionId,
        request: &RegisterKeygenParticipantRequest,
        enclave_id: EnclaveId,
        enclave_key_epoch: u64,
        session_encrypted_data: String,
        enclave_encrypted_data: String,
    ) -> Result<(), ApiError> {
        let keygen_session_id = keygen_session_id.clone();
        let request = request.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = DbUtils::current_timestamp();
                let user_id = &request.user_id;
                let enclave_id_i64 = enclave_id.as_u32() as i64;
                let enclave_key_epoch_i64 = enclave_key_epoch as i64;
                let auth_pubkey = request.auth_pubkey.as_slice();

                sqlx::query!(
                    r#"INSERT OR REPLACE INTO keygen_participants (
                        keygen_session_id, user_id, assigned_enclave_id, enclave_key_epoch,
                        registered_at, require_signing_approval, auth_pubkey,
                        session_encrypted_data, enclave_encrypted_data
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
                    keygen_session_id,
                    user_id,
                    enclave_id_i64,
                    enclave_key_epoch_i64,
                    current_time,
                    request.require_signing_approval,
                    auth_pubkey,
                    session_encrypted_data,
                    enclave_encrypted_data
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    /// Note: We use `query_as::<_, T>()` (runtime) instead of `query_as!()` (macro) here
    /// because `KeygenParticipantRow` has custom types (`UserId`, `EnclaveId`) that require
    /// a `FromRow` implementation for proper type conversion from SQLite primitives.
    /// The `query_as!` macro generates its own mapping code and doesn't use `FromRow`,
    /// so it can't handle custom type conversions. If sqlx adds support for custom type
    /// mappings in macros in the future, this could be converted to use `query_as!`.
    async fn get_keygen_participants(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<ParticipantData>, ApiError> {
        let rows = sqlx::query_as::<_, KeygenParticipantRow>(
            r#"SELECT user_id, assigned_enclave_id as enclave_id, enclave_key_epoch, registered_at,
                    require_signing_approval, auth_pubkey, session_encrypted_data, enclave_encrypted_data
             FROM keygen_participants
             WHERE keygen_session_id = ?
             ORDER BY registered_at ASC"#,
        )
        .bind(keygen_session_id)
        .fetch_all(&self.pool)
        .await?;

        let participants: Vec<ParticipantData> =
            rows.into_iter().filter_map(|row| row.into()).collect();

        Ok(participants)
    }

    pub async fn get_keygen_participant_count(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<usize, ApiError> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) as count FROM keygen_participants WHERE keygen_session_id = $1",
            keygen_session_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    pub async fn get_participant_auth_pubkey(
        &self,
        user_id: &UserId,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<u8>, ApiError> {
        let auth_pubkey: Vec<u8> = sqlx::query_scalar!(
            r#"SELECT auth_pubkey FROM keygen_participants
             WHERE user_id = $1 AND keygen_session_id = $2"#,
            user_id,
            keygen_session_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(auth_pubkey)
    }

    pub async fn update_keygen_session_status(
        &self,
        keygen_session_id: &SessionId,
        status: &KeygenSessionStatus,
    ) -> Result<(), ApiError> {
        let keygen_session_id = keygen_session_id.clone();
        let status = status.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let status_json = serde_json::to_string(&status).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize keygen status: {e}"))
                })?;

                let status_name = status.kind().to_string();
                let current_time = DbUtils::current_timestamp();

                sqlx::query!(
                    r#"UPDATE keygen_sessions
                     SET status = $1, status_name = $2, updated_at = $3,
                         completed_at = CASE WHEN $4 = 'completed' THEN $5 ELSE completed_at END,
                         failed_at = CASE WHEN $6 = 'failed' THEN $7 ELSE failed_at END
                     WHERE keygen_session_id = $8"#,
                    status_json,
                    status_name,
                    current_time,
                    status_name,
                    current_time,
                    status_name,
                    current_time,
                    keygen_session_id
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    pub async fn create_signing_session(
        &self,
        request: &CreateSigningSessionRequest,
    ) -> Result<(), ApiError> {
        let request = request.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                // First get the keygen session status
                let keygen_session_id = &request.keygen_session_id;
                let keygen_row = sqlx::query!(
                    "SELECT status FROM keygen_sessions WHERE keygen_session_id = $1",
                    keygen_session_id
                )
                .fetch_optional(&pool)
                .await?
                .ok_or(ApiError::not_found("Keygen session not found"))?;

                let status_json: String = keygen_row.status;
                let keygen_status: KeygenSessionStatus =
                    serde_json::from_str(&status_json).map_err(|e| {
                        ApiError::Serialization(format!("Failed to deserialize keygen status: {e}"))
                    })?;

                let (encrypted_session_secret, coordinator_encrypted_private_key, taproot_tweak) =
                    match &keygen_status {
                        KeygenSessionStatus::Completed(completed) => (
                            completed.encrypted_session_secret.clone(),
                            completed.coordinator_encrypted_private_key.clone(),
                            completed.encrypted_taproot_tweak.clone(),
                        ),
                        _ => {
                            return Err(ApiError::bad_request(
                                "Keygen session must be completed before signing",
                            ))
                        }
                    };

                let keygen_participants_rows = sqlx::query_as::<_, KeygenParticipantRow>(
                    r#"SELECT user_id, assigned_enclave_id as enclave_id, enclave_key_epoch, registered_at,
                            require_signing_approval, auth_pubkey, session_encrypted_data, enclave_encrypted_data
                     FROM keygen_participants
                     WHERE keygen_session_id = ?
                     ORDER BY registered_at ASC"#,
                )
                .bind(keygen_session_id)
                .fetch_all(&pool)
                .await?;

                let keygen_participants: Vec<ParticipantData> = keygen_participants_rows
                    .into_iter()
                    .filter_map(|row| row.into())
                    .collect();

                let expected_participants: Vec<UserId> = keygen_participants
                    .iter()
                    .map(|p| p.user_id.clone())
                    .collect();

                let current_time = DbUtils::current_timestamp();
                let expires_at = current_time + request.timeout_secs as i64;

                let participants_requiring_approval: Vec<UserId> = sqlx::query_scalar!(
                    r#"SELECT user_id as "user_id: UserId" FROM keygen_participants
                     WHERE keygen_session_id = $1 AND require_signing_approval = true"#,
                    keygen_session_id
                )
                .fetch_all(&pool)
                .await?;

                // Convert keygen participants to registered participants map
                let registered_participants: BTreeMap<UserId, ParticipantData> = keygen_participants
                    .into_iter()
                    .map(|p| (p.user_id.clone(), p))
                    .collect();

                // Create initial signing session status - CollectingParticipants
                let status = SigningSessionStatus::CollectingParticipants(SigningCollectingParticipants {
                    signing_session_id: request.signing_session_id.clone(),
                    keygen_session_id: request.keygen_session_id.clone(),
                    message_hash: request.message_hash.clone(),
                    encrypted_message: request.encrypted_message.clone().unwrap_or_default(),
                    expected_participants: expected_participants.clone(),
                    registered_participants,
                    coordinator_encrypted_private_key: Some(coordinator_encrypted_private_key.clone()),
                    encrypted_session_secret: Some(encrypted_session_secret.clone()),
                    created_at: current_time as u64,
                    expires_at: expires_at as u64,
                    required_enclave_epochs: BTreeMap::new(),
                    encrypted_taproot_tweak: taproot_tweak.clone(),
                    encrypted_adaptor_configs: request.encrypted_adaptor_configs.clone(),
                    participants_requiring_approval,
                    approved_participants: Vec::new(),
                });

                let status_json = serde_json::to_string(&status).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize signing status: {e}"))
                })?;
                let status_name = status.kind().to_string();
                let correlation_id_bytes: Option<Vec<u8>> = None;

                // Create initial empty signing session data (will be populated after enclave initialization)
                let session_data = SigningSessionData {
                    message: Vec::new(), // Will be populated after decryption in enclave
                    message_hash: request.message_hash.clone(),
                    signed_message: None,
                    adaptor_configs: Vec::new(), // Will be populated after decryption in enclave
                    adaptor_signatures: None,
                };
                let session_encrypted = serde_json::to_string(&session_data).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize session data: {e}"))
                })?;

                // Create enclave data with coordinator private key and session secret
                let enclave_data = SigningEnclaveData {
                    coordinator_private_key: coordinator_encrypted_private_key.clone(),
                    session_secret: encrypted_session_secret.clone(),
                };
                let enclave_encrypted = serde_json::to_string(&enclave_data).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize enclave data: {e}"))
                })?;

                let signing_session_id = &request.signing_session_id;
                let message_hash = request.message_hash.as_slice();
                let expected_participants_json = serde_json::to_string(&expected_participants)?;

                sqlx::query!(
                    r#"INSERT INTO signing_sessions (
                        signing_session_id, keygen_session_id, status_name, created_at,
                        expires_at, updated_at, retry_count, correlation_id, message_hash,
                        expected_participants, status, session_encrypted_data, enclave_encrypted_data
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
                    signing_session_id,
                    keygen_session_id,
                    status_name,
                    current_time,
                    expires_at,
                    current_time,
                    0i32,
                    correlation_id_bytes,
                    message_hash,
                    expected_participants_json,
                    status_json,
                    session_encrypted,
                    enclave_encrypted
                )
                .execute(&pool)
                .await?;

                // Get fresh keygen participants for database insertion (uses runtime query_as for custom FromRow types)
                let keygen_participants_for_db_rows = sqlx::query_as::<_, KeygenParticipantRow>(
                    r#"SELECT user_id, assigned_enclave_id as enclave_id, enclave_key_epoch, registered_at,
                            require_signing_approval, auth_pubkey, session_encrypted_data, enclave_encrypted_data
                     FROM keygen_participants
                     WHERE keygen_session_id = ?
                     ORDER BY registered_at ASC"#,
                )
                .bind(keygen_session_id)
                .fetch_all(&pool)
                .await?;

                let keygen_participants_for_db: Vec<ParticipantData> = keygen_participants_for_db_rows
                    .into_iter()
                    .filter_map(|row| row.into())
                    .collect();

                for participant in &keygen_participants_for_db {
                    let participant_session_encrypted = &participant.session_encrypted_data;
                    let participant_enclave_encrypted = &participant.enclave_encrypted_data;
                    let user_id = &participant.user_id;
                    let enclave_id_i64 = participant.enclave_id.as_u32() as i64;
                    let enclave_key_epoch_i64 = participant.enclave_key_epoch as i64;

                    sqlx::query!(
                        r#"INSERT INTO signing_participants (
                            signing_session_id, user_id, assigned_enclave_id, enclave_key_epoch,
                            registered_at, session_encrypted_data, enclave_encrypted_data
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
                        signing_session_id,
                        user_id,
                        enclave_id_i64,
                        enclave_key_epoch_i64,
                        current_time,
                        participant_session_encrypted,
                        participant_enclave_encrypted
                    )
                    .execute(&pool)
                    .await?;
                }

                Ok(())
            })
            .await
    }

    pub async fn get_signing_session_by_id(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<Option<SigningSessionStatus>, ApiError> {
        tracing::debug!("Loading signing session {}", signing_session_id);

        // Force WAL checkpoint to ensure we see recent writes
        // PRAGMA returns columns with NULL type that sqlx macros can't map
        let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to checkpoint WAL before signing session load: {}",
                    e
                );
            });

        let row = sqlx::query!(
            "SELECT status FROM signing_sessions WHERE signing_session_id = $1",
            signing_session_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to fetch signing session {} from database: {}",
                signing_session_id,
                e
            );
            ApiError::database(format!("Failed to fetch signing session: {e}"))
        })?;

        match row {
            Some(row) => {
                let status_json: String = row.status;
                tracing::debug!(
                    "Deserializing signing session {} status JSON",
                    signing_session_id
                );

                let mut status: SigningSessionStatus =
                    serde_json::from_str(&status_json).map_err(|e| {
                        tracing::error!(
                            "Failed to deserialize signing session {} status: {}",
                            signing_session_id,
                            e
                        );
                        ApiError::Serialization(format!(
                            "Failed to deserialize signing status for session {}: {e}",
                            signing_session_id
                        ))
                    })?;

                // Status loaded successfully - participants should already be populated during creation

                if let SigningSessionStatus::CollectingParticipants(ref mut collecting) = status {
                    tracing::debug!(
                        "Loading approval data for signing session {} (keygen: {})",
                        signing_session_id,
                        collecting.keygen_session_id
                    );

                    let participants_requiring_approval = self
                        .get_participants_requiring_approval(&collecting.keygen_session_id)
                        .await
                        .map_err(|e| {
                            tracing::error!("Failed to get participants requiring approval for signing session {}: {}",
                                signing_session_id, e);
                            e
                        })?;

                    let approved_participants = self
                        .get_signing_session_approvals(signing_session_id)
                        .await
                        .map_err(|e| {
                            tracing::error!(
                                "Failed to get approved participants for signing session {}: {}",
                                signing_session_id,
                                e
                            );
                            e
                        })?;

                    tracing::debug!(
                        "Signing session {} loaded: {} requiring approval, {} approved",
                        signing_session_id,
                        participants_requiring_approval.len(),
                        approved_participants.len()
                    );

                    collecting.participants_requiring_approval = participants_requiring_approval;
                    collecting.approved_participants = approved_participants;
                }

                tracing::debug!("Loaded signing session {}", signing_session_id);
                Ok(Some(status))
            }
            None => {
                tracing::debug!(
                    "Signing session {} not found in database",
                    signing_session_id
                );
                Ok(None)
            }
        }
    }

    pub async fn get_signing_participant_count(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<usize, ApiError> {
        let count: i64 = sqlx::query_scalar!(
            "SELECT COUNT(*) as count FROM signing_participants WHERE signing_session_id = $1",
            signing_session_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    pub async fn update_signing_session_status(
        &self,
        signing_session_id: &SessionId,
        status: &SigningSessionStatus,
    ) -> Result<(), ApiError> {
        let signing_session_id = signing_session_id.clone();
        let status = status.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let status_json = serde_json::to_string(&status).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize signing status: {e}"))
                })?;

                let status_name = status.kind().to_string();
                let current_time = DbUtils::current_timestamp();

                sqlx::query!(
                    r#"UPDATE signing_sessions
                     SET status = $1, status_name = $2, updated_at = $3,
                         completed_at = CASE WHEN $4 = 'completed' THEN $5 ELSE completed_at END,
                         failed_at = CASE WHEN $6 = 'failed' THEN $7 ELSE failed_at END
                     WHERE signing_session_id = $8"#,
                    status_json,
                    status_name,
                    current_time,
                    status_name,
                    current_time,
                    status_name,
                    current_time,
                    signing_session_id
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    pub async fn get_keygen_session_id_from_signing_session(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<Option<SessionId>, ApiError> {
        let row: Option<SessionId> = sqlx::query_scalar!(
            r#"SELECT keygen_session_id as "keygen_session_id: SessionId" FROM signing_sessions WHERE signing_session_id = $1"#,
            signing_session_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Note: This function uses dynamic SQL building instead of `sqlx::query!` macros because
    /// SQLite does not support binding arrays to `IN` clauses. The sqlx macros require all
    /// query parameters to be known at compile time, but the number of `active_states` varies
    /// at runtime. PostgreSQL supports `= ANY($1)` with array binding as an alternative, but
    /// SQLite has no equivalent. If sqlx adds support for array parameter expansion in macros
    /// for SQLite in the future, this could be converted to use compile-time checked queries.
    /// See: https://github.com/launchbadge/sqlx/blob/main/FAQ.md
    pub async fn get_processable_keygen_sessions_cursor(
        &self,
        active_states: &[KeygenStatusKind],
        batch_size: u32,
        cursor: Option<&SessionId>,
        processing_timeout_mins: u64,
        max_retries: u16,
    ) -> Result<Vec<ProcessableSessionRecord>, ApiError> {
        let current_time = DbUtils::current_timestamp();
        let timeout_seconds = processing_timeout_mins * 60;

        let placeholders = active_states
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");

        let cursor_condition = if cursor.is_some() {
            "AND keygen_session_id > ?"
        } else {
            ""
        };

        let query = format!(
            r#"
            SELECT keygen_session_id as session_id, 'keygen' as session_kind
            FROM keygen_sessions
            WHERE status_name IN ({placeholders})
              AND expires_at > ?
              AND (
                  processing_started_at IS NULL
                  OR processing_started_at < ? - ?
                  OR last_processing_attempt IS NULL
                  OR last_processing_attempt < ? - ?
              )
              AND retry_count < ?
              {cursor_condition}
            ORDER BY keygen_session_id ASC
            LIMIT ?
            "#
        );

        let mut query_builder = sqlx::query_as::<_, ProcessableSessionRecord>(&query);

        for status in active_states {
            query_builder = query_builder.bind(status.as_ref());
        }

        query_builder = query_builder
            .bind(current_time) // expires_at > ?
            .bind(current_time) // processing_started_at < ? - ?
            .bind(timeout_seconds as i64)
            .bind(current_time) // last_processing_attempt < ? - ?
            .bind(timeout_seconds as i64)
            .bind(max_retries);

        if let Some(cursor) = cursor {
            query_builder = query_builder.bind(cursor);
        }

        query_builder = query_builder.bind(batch_size as i32);

        let records = query_builder.fetch_all(&self.pool).await.map_err(|e| {
            ApiError::database(format!(
                "Failed to fetch processable keygen sessions with cursor: {e}"
            ))
        })?;

        Ok(records)
    }

    pub async fn get_processable_signing_sessions_cursor(
        &self,
        active_states: &[SigningStatusKind],
        batch_size: u32,
        cursor: Option<&SessionId>,
        processing_timeout_mins: u64,
        max_retries: u16,
    ) -> Result<Vec<ProcessableSessionRecord>, ApiError> {
        let current_time = DbUtils::current_timestamp();
        let timeout_seconds = processing_timeout_mins * 60;

        let placeholders = active_states
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");

        let cursor_condition = if cursor.is_some() {
            "AND signing_session_id > ?"
        } else {
            ""
        };

        let query = format!(
            r#"
            SELECT signing_session_id as session_id, 'signing' as session_kind
            FROM signing_sessions
            WHERE status_name IN ({placeholders})
              AND expires_at > ?
              AND (
                  processing_started_at IS NULL
                  OR processing_started_at < ? - ?
                  OR last_processing_attempt IS NULL
                  OR last_processing_attempt < ? - ?
              )
              AND retry_count < ?
              {cursor_condition}
            ORDER BY signing_session_id ASC
            LIMIT ?
            "#
        );

        let mut query_builder = sqlx::query_as::<_, ProcessableSessionRecord>(&query);

        for status in active_states {
            query_builder = query_builder.bind(status.as_ref());
        }

        query_builder = query_builder
            .bind(current_time) // expires_at > ?
            .bind(current_time) // processing_started_at < ? - ?
            .bind(timeout_seconds as i64)
            .bind(current_time) // last_processing_attempt < ? - ?
            .bind(timeout_seconds as i64)
            .bind(max_retries);

        if let Some(cursor) = cursor {
            query_builder = query_builder.bind(cursor);
        }

        query_builder = query_builder.bind(batch_size as i32);

        let records = query_builder.fetch_all(&self.pool).await.map_err(|e| {
            tracing::error!("Database query failed for signing sessions cursor: {}", e);
            ApiError::database(format!(
                "Failed to fetch processable signing sessions with cursor: {e}"
            ))
        })?;

        tracing::debug!(
            "Found {} processable signing sessions (cursor: {:?}, batch_size: {})",
            records.len(),
            cursor,
            batch_size
        );

        Ok(records)
    }

    /// Get all COMPLETED, non-expired keygen sessions where this enclave participates
    /// (either as coordinator or has participants assigned).
    /// These are long-lived sessions that need to be restored after gateway/enclave restart.
    pub async fn get_restorable_keygen_sessions_for_enclave(
        &self,
        enclave_id: u32,
    ) -> Result<Vec<KeygenSessionStatus>, ApiError> {
        // Get sessions where this enclave is either:
        // 1. The coordinator enclave, OR
        // 2. Has participants assigned to it
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT ks.keygen_session_id, ks.status
            FROM keygen_sessions ks
            LEFT JOIN keygen_participants kp ON ks.keygen_session_id = kp.keygen_session_id
            WHERE ks.status_name = 'completed'
              AND (ks.coordinator_enclave_id = ? OR kp.assigned_enclave_id = ?)
            "#,
        )
        .bind(enclave_id as i64)
        .bind(enclave_id as i64)
        .fetch_all(&self.pool)
        .await?;

        let mut sessions = Vec::new();
        for row in rows {
            let session_id_bytes: Vec<u8> = row.try_get("keygen_session_id")?;
            let session_id = SessionId::try_from(session_id_bytes)
                .map_err(|e| ApiError::Serialization(format!("Invalid session ID: {e:?}")))?;
            let status_json: String = row.try_get("status")?;

            let mut status: KeygenSessionStatus =
                serde_json::from_str(&status_json).map_err(|e| {
                    ApiError::Serialization(format!("Failed to deserialize keygen status: {e}"))
                })?;

            // Load and merge participants
            let participants = self.get_keygen_participants(&session_id).await?;
            let participants_map: BTreeMap<UserId, ParticipantData> = participants
                .into_iter()
                .map(|p| (p.user_id.clone(), p))
                .collect();

            if let Err(e) = status.merge_participants(participants_map) {
                warn!(
                    "Failed to merge participants for session {}: {}",
                    session_id, e
                );
            }

            sessions.push(status);
        }

        debug!(
            "Found {} restorable keygen sessions for enclave {}",
            sessions.len(),
            enclave_id
        );

        Ok(sessions)
    }

    /// Get all ACTIVE (non-completed, non-failed) signing sessions for an enclave.
    /// These sessions will be reset and re-run from the beginning after restart.
    pub async fn get_active_signing_sessions_for_enclave(
        &self,
        enclave_id: u32,
    ) -> Result<Vec<SigningSessionStatus>, ApiError> {
        // Get signing sessions where this enclave has participants assigned
        // and the session is still active (not completed or failed)
        let enclave_id_i64 = enclave_id as i64;
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT ss.signing_session_id, ss.status
            FROM signing_sessions ss
            INNER JOIN signing_participants sp ON ss.signing_session_id = sp.signing_session_id
            WHERE ss.status_name NOT IN ('completed', 'failed')
              AND sp.assigned_enclave_id = $1
            "#,
            enclave_id_i64
        )
        .fetch_all(&self.pool)
        .await?;

        let mut sessions = Vec::new();
        for row in rows {
            let status: SigningSessionStatus = serde_json::from_str(&row.status).map_err(|e| {
                ApiError::Serialization(format!("Failed to deserialize signing status: {e}"))
            })?;

            sessions.push(status);
        }

        debug!(
            "Found {} active signing sessions for enclave {}",
            sessions.len(),
            enclave_id
        );

        Ok(sessions)
    }

    /// Reset a signing session to CollectingParticipants state so it can be re-run.
    /// Called after enclave restart to allow the coordinator to re-process the session.
    pub async fn reset_signing_session_to_collecting(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<(), ApiError> {
        let signing_session_id = signing_session_id.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                // First get the current session to extract needed data
                let row = sqlx::query!(
                    "SELECT status FROM signing_sessions WHERE signing_session_id = $1",
                    signing_session_id
                )
                .fetch_optional(&pool)
                .await?;

                let row = row.ok_or_else(|| {
                    ApiError::NotFound(format!("Signing session {} not found", signing_session_id))
                })?;

                let status_json: String = row.status;
                let current_status: SigningSessionStatus = serde_json::from_str(&status_json)
                    .map_err(|e| {
                        ApiError::Serialization(format!(
                            "Failed to deserialize signing status: {e}"
                        ))
                    })?;

                // Extract the data we need to create a new CollectingParticipants state
                // Note: Later states lose some fields, so we query approval data separately
                let new_status = match current_status {
                    SigningSessionStatus::CollectingParticipants(collecting) => {
                        // Already in collecting state - just clear enclave epochs
                        SigningSessionStatus::CollectingParticipants(
                            SigningCollectingParticipants {
                                required_enclave_epochs: std::collections::BTreeMap::new(),
                                ..collecting
                            },
                        )
                    }
                    SigningSessionStatus::InitializingSession(init) => {
                        // InitializingSession has encrypted_session_secret but not approval fields
                        // Query approval data from signing_approvals table
                        let approved_participants: Vec<UserId> = sqlx::query_scalar!(
                            r#"SELECT user_id as "user_id: UserId" FROM signing_approvals WHERE signing_session_id = $1"#,
                            signing_session_id
                        )
                        .fetch_all(&pool)
                        .await?;

                        // Get participants requiring approval from keygen session
                        let keygen_session_id = &init.keygen_session_id;
                        let participants_requiring_approval: Vec<UserId> = sqlx::query_scalar!(
                            r#"SELECT user_id as "user_id: UserId" FROM keygen_participants
                             WHERE keygen_session_id = $1 AND require_signing_approval = true"#,
                            keygen_session_id
                        )
                        .fetch_all(&pool)
                        .await?;

                        SigningSessionStatus::CollectingParticipants(
                            SigningCollectingParticipants {
                                signing_session_id: init.signing_session_id,
                                keygen_session_id: init.keygen_session_id,
                                message_hash: init.message_hash,
                                encrypted_message: init.encrypted_message,
                                expected_participants: init.expected_participants,
                                registered_participants: init.registered_participants,
                                coordinator_encrypted_private_key: init.coordinator_encrypted_private_key,
                                encrypted_session_secret: init.encrypted_session_secret,
                                created_at: init.created_at,
                                expires_at: init.expires_at,
                                required_enclave_epochs: std::collections::BTreeMap::new(),
                                encrypted_taproot_tweak: init.encrypted_taproot_tweak,
                                encrypted_adaptor_configs: init.encrypted_adaptor_configs,
                                participants_requiring_approval,
                                approved_participants,
                            },
                        )
                    }
                    SigningSessionStatus::DistributingNonces(_)
                    | SigningSessionStatus::FinalizingSignature(_) => {
                        // These states don't have encrypted_session_secret - need to query from
                        // the original signing session's enclave_encrypted_data
                        // For now, fail these sessions as they can't be safely reset
                        return Err(ApiError::BadRequest(format!(
                            "Cannot reset signing session {} from state {}. Session data lost during state transition.",
                            signing_session_id,
                            current_status.kind()
                        )));
                    }
                    SigningSessionStatus::Completed(_) | SigningSessionStatus::Failed(_) => {
                        // Should not be called for completed/failed sessions
                        return Err(ApiError::BadRequest(format!(
                            "Cannot reset completed or failed signing session {}",
                            signing_session_id
                        )));
                    }
                };

                let status_json = serde_json::to_string(&new_status).map_err(|e| {
                    ApiError::Serialization(format!("Failed to serialize signing status: {e}"))
                })?;

                let current_time = DbUtils::current_timestamp();

                sqlx::query!(
                    r#"UPDATE signing_sessions
                     SET status = $1, status_name = 'collecting_participants', updated_at = $2
                     WHERE signing_session_id = $3"#,
                    status_json,
                    current_time,
                    signing_session_id
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update_enclave_health(
        &self,
        enclave_id: u32,
        is_healthy: bool,
        public_key: Option<String>,
        cache_duration_secs: i64,
        attestation_document: Option<String>,
        key_epoch: Option<u64>,
        key_generation_time: Option<u64>,
        startup_time: Option<u64>,
        active_sessions: Option<u32>,
    ) -> Result<(), ApiError> {
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = DbUtils::current_timestamp();
                let expires_at = current_time + cache_duration_secs;
                let public_key_value = public_key.unwrap_or_else(|| "unavailable".to_string());
                let enclave_id_i32 = enclave_id as i32;
                let attestation_doc = attestation_document.unwrap_or_default();
                let key_epoch_i64 = key_epoch.unwrap_or(1) as i64;
                let key_gen_time_i64 = key_generation_time.unwrap_or(0) as i64;
                let startup_time_i64 = startup_time.unwrap_or(current_time as u64) as i64;
                let active_sessions_i32 = active_sessions.unwrap_or(0) as i32;

                sqlx::query!(
                    r#"INSERT INTO enclave_public_keys (enclave_id, public_key, cached_at, expires_at, is_healthy,
                                                    attestation_document, key_epoch, key_generation_time, startup_time, active_sessions)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                     ON CONFLICT(enclave_id) DO UPDATE SET
                         public_key = CASE WHEN excluded.public_key != 'unavailable' THEN excluded.public_key ELSE enclave_public_keys.public_key END,
                         cached_at = excluded.cached_at,
                         expires_at = excluded.expires_at,
                         is_healthy = excluded.is_healthy,
                         attestation_document = COALESCE(excluded.attestation_document, enclave_public_keys.attestation_document),
                         key_epoch = COALESCE(excluded.key_epoch, enclave_public_keys.key_epoch),
                         key_generation_time = COALESCE(excluded.key_generation_time, enclave_public_keys.key_generation_time),
                         startup_time = COALESCE(excluded.startup_time, enclave_public_keys.startup_time),
                         active_sessions = COALESCE(excluded.active_sessions, enclave_public_keys.active_sessions)"#,
                    enclave_id_i32,
                    public_key_value,
                    current_time,
                    expires_at,
                    is_healthy,
                    attestation_doc,
                    key_epoch_i64,
                    key_gen_time_i64,
                    startup_time_i64,
                    active_sessions_i32
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    pub async fn get_enclave_health(
        &self,
        enclave_id: u32,
    ) -> Result<Option<EnclaveHealthInfo>, ApiError> {
        let row = sqlx::query_as::<_, EnclaveHealthInfo>(
            r#"SELECT enclave_id, public_key, cached_at, expires_at, is_healthy,
                    COALESCE(attestation_document, '') as attestation_document,
                    COALESCE(key_epoch, 1) as key_epoch,
                    COALESCE(key_generation_time, 0) as key_generation_time,
                    COALESCE(startup_time, 0) as startup_time,
                    COALESCE(active_sessions, 0) as active_sessions
             FROM enclave_public_keys
             WHERE enclave_id = ?"#,
        )
        .bind(enclave_id as i32)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_all_enclave_health(&self) -> Result<Vec<EnclaveHealthInfo>, ApiError> {
        let rows = sqlx::query_as::<_, EnclaveHealthInfo>(
            r#"SELECT enclave_id, public_key, cached_at, expires_at, is_healthy,
                    COALESCE(attestation_document, '') as attestation_document,
                    COALESCE(key_epoch, 1) as key_epoch,
                    COALESCE(key_generation_time, 0) as key_generation_time,
                    COALESCE(startup_time, 0) as startup_time,
                    COALESCE(active_sessions, 0) as active_sessions
             FROM enclave_public_keys
             ORDER BY enclave_id"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn invalidate_enclave_cache(&self, enclave_id: u32) -> Result<(), ApiError> {
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = DbUtils::current_timestamp();
                let enclave_id_i32 = enclave_id as i32;

                sqlx::query!(
                    r#"UPDATE enclave_public_keys
                     SET expires_at = $1
                     WHERE enclave_id = $2"#,
                    current_time,
                    enclave_id_i32
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    pub async fn approve_signing_session(
        &self,
        signing_session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<(), ApiError> {
        let signing_session_id = signing_session_id.clone();
        let user_id = user_id.clone();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let current_time = DbUtils::current_timestamp();

                sqlx::query!(
                    r#"INSERT OR REPLACE INTO signing_approvals (
                        signing_session_id, user_id, approved_at, user_signature_validated, session_signature_validated
                    ) VALUES ($1, $2, $3, $4, $5)"#,
                    signing_session_id,
                    user_id,
                    current_time,
                    true,
                    true
                )
                .execute(&pool)
                .await?;
                Ok(())
            })
            .await
    }

    async fn get_participants_requiring_approval(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<UserId>, ApiError> {
        let user_ids: Vec<UserId> = sqlx::query_scalar!(
            r#"SELECT user_id as "user_id: UserId" FROM keygen_participants
             WHERE keygen_session_id = $1 AND require_signing_approval = true"#,
            keygen_session_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(user_ids)
    }

    async fn get_signing_session_approvals(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<Vec<UserId>, ApiError> {
        // Force WAL checkpoint to ensure we see recent approval writes
        // PRAGMA returns columns with NULL type that sqlx macros can't map
        let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!("Failed to checkpoint WAL before approval query: {}", e);
            });

        let user_ids: Vec<UserId> = sqlx::query_scalar!(
            r#"SELECT user_id as "user_id: UserId" FROM signing_approvals
             WHERE signing_session_id = $1"#,
            signing_session_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(user_ids)
    }

    pub async fn store_enclave_master_key(
        &self,
        enclave_id: EnclaveId,
        kms_encrypted_dek: &[u8],
        encrypted_private_key: &[u8],
        kms_key_id: &str,
    ) -> Result<(), ApiError> {
        let kms_encrypted_dek = kms_encrypted_dek.to_vec();
        let encrypted_private_key = encrypted_private_key.to_vec();
        let kms_key_id = kms_key_id.to_string();
        self.writer
            .execute(self.pool.clone(), move |pool| async move {
                let enclave_id_i64 = enclave_id.as_u32() as i64;

                sqlx::query!(
                    r#"INSERT INTO enclave_master_keys (
                        enclave_id, kms_encrypted_dek, encrypted_private_key, kms_key_id
                    ) VALUES ($1, $2, $3, $4)
                    ON CONFLICT(enclave_id) DO UPDATE SET
                        kms_encrypted_dek = excluded.kms_encrypted_dek,
                        encrypted_private_key = excluded.encrypted_private_key,
                        kms_key_id = excluded.kms_key_id,
                        key_epoch = key_epoch + 1"#,
                    enclave_id_i64,
                    kms_encrypted_dek,
                    encrypted_private_key,
                    kms_key_id
                )
                .execute(&pool)
                .await?;

                Ok(())
            })
            .await
    }

    /// Uses runtime query_as for custom FromRow type
    pub async fn get_enclave_master_key(
        &self,
        enclave_id: EnclaveId,
    ) -> Result<Option<EnclaveMasterKeyRecord>, ApiError> {
        let row = sqlx::query_as::<_, EnclaveMasterKeyRecord>(
            r#"SELECT kms_encrypted_dek, encrypted_private_key, kms_key_id, key_epoch
             FROM enclave_master_keys
             WHERE enclave_id = ?"#,
        )
        .bind(enclave_id.as_u32() as i64)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }
}

#[derive(Debug, Clone)]
pub struct KeygenParticipantRow {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_key_epoch: u64,
    pub registered_at: i64,
    pub require_signing_approval: bool,
    pub auth_pubkey: Vec<u8>,
    pub session_encrypted_data: String,
    pub enclave_encrypted_data: String,
}

impl FromRow<'_, SqliteRow> for KeygenParticipantRow {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        let user_id: UserId = row.try_get("user_id")?;

        let enclave_id: EnclaveId = row.try_get("enclave_id")?;

        let enclave_key_epoch_i64: i64 = row.try_get("enclave_key_epoch")?;
        let registered_at: i64 = row.try_get("registered_at")?;
        let require_signing_approval: bool = row.try_get("require_signing_approval")?;
        let auth_pubkey: Vec<u8> = row.try_get("auth_pubkey")?;
        let session_encrypted_data: String = row.try_get("session_encrypted_data")?;
        let enclave_encrypted_data: String = row.try_get("enclave_encrypted_data")?;

        Ok(KeygenParticipantRow {
            user_id,
            enclave_id,
            enclave_key_epoch: enclave_key_epoch_i64 as u64,
            registered_at,
            require_signing_approval,
            auth_pubkey,
            session_encrypted_data,
            enclave_encrypted_data,
        })
    }
}

impl From<KeygenParticipantRow> for Option<ParticipantData> {
    fn from(row: KeygenParticipantRow) -> Self {
        Some(ParticipantData {
            user_id: row.user_id,
            enclave_id: row.enclave_id,
            enclave_key_epoch: row.enclave_key_epoch,
            session_encrypted_data: row.session_encrypted_data,
            enclave_encrypted_data: row.enclave_encrypted_data,
        })
    }
}

#[derive(Clone)]
pub struct ProcessableSessionRecord {
    pub session_id: SessionId,
    pub session_kind: SessionKind,
}

impl FromRow<'_, SqliteRow> for ProcessableSessionRecord {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        let session_kind: SessionKind = row.try_get("session_kind")?;
        let session_id: SessionId = row.try_get("session_id")?;

        Ok(ProcessableSessionRecord {
            session_id,
            session_kind,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EnclaveMasterKeyRecord {
    pub kms_encrypted_dek: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub kms_key_id: String,
    pub key_epoch: i64,
}

impl FromRow<'_, SqliteRow> for EnclaveMasterKeyRecord {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(EnclaveMasterKeyRecord {
            kms_encrypted_dek: row.try_get("kms_encrypted_dek")?,
            encrypted_private_key: row.try_get("encrypted_private_key")?,
            kms_key_id: row.try_get("kms_key_id")?,
            key_epoch: row.try_get("key_epoch")?,
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EnclaveHealthInfo {
    pub enclave_id: u32,
    pub public_key: String,
    pub cached_at: i64,
    pub expires_at: i64,
    pub is_healthy: bool,
    pub attestation_document: String,
    pub key_epoch: u64,
    pub key_generation_time: u64,
    pub startup_time: u64,
    pub active_sessions: u32,
}

impl FromRow<'_, SqliteRow> for EnclaveHealthInfo {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(EnclaveHealthInfo {
            enclave_id: row.try_get::<i32, _>("enclave_id")? as u32,
            public_key: row.try_get("public_key")?,
            cached_at: row.try_get("cached_at")?,
            expires_at: row.try_get("expires_at")?,
            is_healthy: row.try_get("is_healthy")?,
            attestation_document: row.try_get("attestation_document")?,
            key_epoch: row.try_get::<i64, _>("key_epoch")? as u64,
            key_generation_time: row.try_get::<i64, _>("key_generation_time")? as u64,
            startup_time: row.try_get::<i64, _>("startup_time")? as u64,
            active_sessions: row.try_get::<i32, _>("active_sessions")? as u32,
        })
    }
}

#[derive(Debug)]
pub struct DatabaseStats {
    pub total_sessions: i64,
    pub active_sessions: i64,
    pub total_participants: i64,
    pub database_size_bytes: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    use tempfile::TempDir;

    async fn create_test_db() -> (Database, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory for tests");
        let db_path = temp_dir.path().join("test.db");

        let config = DatabaseConfig {
            path: db_path.to_string_lossy().to_string(),
            max_connections: 5,
            connection_timeout_secs: 5,
            idle_timeout_secs: Some(60),
            enable_wal_mode: Some(false),
        };

        let db = Database::new(&config)
            .await
            .expect("Failed to create test database");
        (db, temp_dir)
    }

    #[tokio::test]
    async fn test_session_storage() {
        let (db, _temp_dir) = create_test_db().await;
        db.health_check()
            .await
            .expect("Database health check should pass");
    }

    #[tokio::test]
    async fn test_database_stats() {
        let (db, _temp_dir) = create_test_db().await;

        let stats = db
            .get_stats()
            .await
            .expect("Should be able to get database stats");

        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.total_participants, 0);
    }
}
