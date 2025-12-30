use crate::{config::DatabaseConfig, errors::ApiError};
use anyhow::{Context, Result};
use keymeld_core::{
    api::{
        CreateKeygenSessionRequest, CreateSigningSessionRequest, RegisterKeygenParticipantRequest,
    },
    encrypted_data::{SigningEnclaveData, SigningSessionData},
    identifiers::{EnclaveId, UserId},
    session::{KeygenStatusKind, SigningStatusKind},
    KeygenCollectingParticipants, KeygenSessionStatus, ParticipantData, SessionId,
    SigningCollectingParticipants, SigningSessionStatus,
};
use secp256k1::PublicKey;
use sqlx::{
    query_scalar,
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow},
    FromRow, Row,
};
use std::{collections::BTreeMap, str::FromStr};
use time::OffsetDateTime;
use tokio::fs::create_dir_all;
use tracing::{debug, info, warn};

pub struct DbUtils;

impl DbUtils {
    pub fn current_timestamp() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }
}

#[derive(Clone, Debug)]
pub struct Database {
    pool: SqlitePool,
    path: String,
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
            .pragma("cache_size", "-64000")
            .pragma("foreign_keys", "ON")
            .pragma("temp_store", "MEMORY");

        let pool = SqlitePoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(std::time::Duration::from_secs(
                config.connection_timeout_secs,
            ))
            .idle_timeout(config.idle_timeout_secs.map(std::time::Duration::from_secs))
            .connect_with(options)
            .await
            .context("Failed to create database connection pool")?;

        let db = Self {
            pool,
            path: config.path.clone(),
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
            query_scalar!("SELECT COUNT(keygen_session_id) FROM keygen_sessions")
                .fetch_one(&self.pool)
                .await?;

        let signing_session_count: i64 =
            query_scalar!("SELECT COUNT(signing_session_id) FROM signing_sessions")
                .fetch_one(&self.pool)
                .await?;

        let session_count = keygen_session_count + signing_session_count;

        let active_keygen_count: i64 = query_scalar!(
            "SELECT COUNT(keygen_session_id) FROM keygen_sessions WHERE status_name NOT IN ('completed', 'failed')",
        )
        .fetch_one(&self.pool)
        .await?;

        let active_signing_count: i64 = query_scalar!(
            "SELECT COUNT(signing_session_id) FROM signing_sessions WHERE status_name NOT IN ('completed', 'failed')",
        )
        .fetch_one(&self.pool)
        .await?;

        let active_session_count = active_keygen_count + active_signing_count;

        let participant_count: i64 = query_scalar!("SELECT COUNT(id) FROM keygen_participants")
            .fetch_one(&self.pool)
            .await?;

        let db_size = match tokio::fs::metadata(&self.path).await {
            Ok(metadata) => Some(metadata.len()),
            Err(e) => {
                warn!("Failed to get database file size: {}", e);
                None
            }
        };

        Ok(DatabaseStats {
            total_sessions: session_count,
            active_sessions: active_session_count,
            total_participants: participant_count,
            database_size_bytes: db_size,
        })
    }

    pub async fn health_check(&self) -> Result<(), ApiError> {
        sqlx::query!("SELECT 1 as health_check")
            .fetch_one(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn cleanup_expired_keygen_sessions(&self) -> Result<usize, ApiError> {
        let current_time = OffsetDateTime::now_utc().unix_timestamp();

        let deleted_sessions = sqlx::query("DELETE FROM keygen_sessions WHERE expires_at < ?")
            .bind(current_time)
            .execute(&self.pool)
            .await?
            .rows_affected();

        if deleted_sessions > 0 {
            debug!("Cleaned up {} expired keygen sessions", deleted_sessions);
        }

        Ok(deleted_sessions as usize)
    }

    pub async fn cleanup_old_completed_keygen_sessions(
        &self,
        older_than_secs: u64,
    ) -> Result<usize, ApiError> {
        let cutoff_time = OffsetDateTime::now_utc().unix_timestamp() - older_than_secs as i64;

        let deleted_sessions = sqlx::query(
            "DELETE FROM keygen_sessions
             WHERE status_name IN ('completed', 'failed')
             AND (completed_at < ? OR failed_at < ?)",
        )
        .bind(cutoff_time)
        .bind(cutoff_time)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if deleted_sessions > 0 {
            debug!(
                "Cleaned up {} old completed keygen sessions",
                deleted_sessions
            );
        }

        Ok(deleted_sessions as usize)
    }

    pub async fn cleanup_expired_signing_sessions(&self) -> Result<usize, ApiError> {
        let current_time = OffsetDateTime::now_utc().unix_timestamp();

        let deleted_sessions = sqlx::query(
            "DELETE FROM signing_sessions
             WHERE expires_at < ?",
        )
        .bind(current_time)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if deleted_sessions > 0 {
            debug!("Cleaned up {} expired signing sessions", deleted_sessions);
        }

        Ok(deleted_sessions as usize)
    }

    pub async fn cleanup_old_completed_signing_sessions(
        &self,
        older_than_secs: u64,
    ) -> Result<usize, ApiError> {
        let cutoff_time = OffsetDateTime::now_utc().unix_timestamp() - older_than_secs as i64;

        let deleted_sessions = sqlx::query(
            "DELETE FROM signing_sessions
             WHERE status_name IN ('completed', 'failed')
             AND (completed_at < ? OR failed_at < ?)",
        )
        .bind(cutoff_time)
        .bind(cutoff_time)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if deleted_sessions > 0 {
            debug!(
                "Cleaned up {} old completed signing sessions",
                deleted_sessions
            );
        }

        Ok(deleted_sessions as usize)
    }

    pub async fn count_signing_sessions_for_keygen(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<i64, ApiError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM signing_sessions WHERE keygen_session_id = ?")
                .bind(keygen_session_id.as_string())
                .fetch_one(&self.pool)
                .await?;

        Ok(count)
    }

    pub async fn get_keygen_session_max_signing_sessions(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Option<i64>, ApiError> {
        let max_signing_sessions: Option<i64> = sqlx::query_scalar(
            "SELECT max_signing_sessions FROM keygen_sessions WHERE keygen_session_id = ?",
        )
        .bind(keygen_session_id.as_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(max_signing_sessions)
    }

    pub async fn create_keygen_session(
        &self,
        request: &CreateKeygenSessionRequest,
    ) -> Result<String, ApiError> {
        let current_time = DbUtils::current_timestamp();
        let expires_at = current_time + request.timeout_secs as i64;

        let coordinator_pubkey = match PublicKey::from_slice(&request.coordinator_pubkey) {
            Ok(pubkey) => pubkey,
            Err(e) => {
                return Err(ApiError::bad_request(format!(
                    "Invalid coordinator public key: {e}"
                )))
            }
        };

        let status = KeygenSessionStatus::CollectingParticipants(KeygenCollectingParticipants {
            keygen_session_id: request.keygen_session_id.clone(),
            coordinator_pubkey,
            coordinator_encrypted_private_key: request.coordinator_encrypted_private_key.clone(),
            session_public_key: request.session_public_key.clone(),
            coordinator_enclave_id: request.coordinator_enclave_id,
            expected_participants: request.expected_participants.clone(),
            encrypted_session_secret: request.encrypted_session_secret.clone(),
            registered_participants: BTreeMap::new(),
            created_at: current_time as u64,
            expires_at: expires_at as u64,
            required_enclave_epochs: BTreeMap::new(),
            taproot_tweak_config: request.taproot_tweak_config.clone(),
        });

        let status_json = serde_json::to_string(&status).map_err(|e| {
            ApiError::Serialization(format!("Failed to serialize keygen status: {e}"))
        })?;

        let status_name = status.kind();

        let session_encrypted = request.encrypted_session_data.clone();
        let enclave_encrypted = request.encrypted_enclave_data.clone();

        sqlx::query(
            "INSERT INTO keygen_sessions (
                keygen_session_id, status_name, coordinator_enclave_id, created_at,
                expires_at, updated_at, retry_count, max_signing_sessions,
                expected_participants, status, session_encrypted_data, enclave_encrypted_data,
                session_public_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(request.keygen_session_id.as_string())
        .bind(status_name.to_string())
        .bind(request.coordinator_enclave_id.as_u32() as i64)
        .bind(current_time)
        .bind(expires_at)
        .bind(current_time)
        .bind(0)
        .bind(request.max_signing_sessions.map(|max| max as i64))
        .bind(serde_json::to_string(&request.expected_participants)?)
        .bind(status_json)
        .bind(session_encrypted)
        .bind(enclave_encrypted)
        .bind(request.session_public_key.as_slice())
        .execute(&self.pool)
        .await?;

        Ok(request.encrypted_session_secret.clone())
    }

    pub async fn get_keygen_session_by_id(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Option<KeygenSessionStatus>, ApiError> {
        let row = sqlx::query("SELECT status FROM keygen_sessions WHERE keygen_session_id = ?")
            .bind(keygen_session_id.as_string())
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => {
                let status_json: String = row.get("status");
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
        let row = sqlx::query(
            "SELECT session_public_key FROM keygen_sessions WHERE keygen_session_id = ?",
        )
        .bind(keygen_session_id.as_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => {
                let public_key: Option<Vec<u8>> = row.get("session_public_key");
                Ok(public_key)
            }
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
        let current_time = DbUtils::current_timestamp();

        sqlx::query(
            "INSERT INTO keygen_participants (
                keygen_session_id, user_id, assigned_enclave_id, enclave_key_epoch,
                registered_at, require_signing_approval, auth_pubkey, session_encrypted_data, enclave_encrypted_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(keygen_session_id.as_string())
        .bind(request.user_id.as_str())
        .bind(enclave_id.as_u32() as i64)
        .bind(enclave_key_epoch as i64)
        .bind(current_time)
        .bind(request.require_signing_approval)
        .bind(&request.auth_pubkey)
        .bind(session_encrypted_data)
        .bind(enclave_encrypted_data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_keygen_participants(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<ParticipantData>, ApiError> {
        let rows = sqlx::query_as::<_, KeygenParticipantRow>(
            "SELECT user_id, assigned_enclave_id, enclave_key_epoch, registered_at,
                    require_signing_approval, auth_pubkey, session_encrypted_data, enclave_encrypted_data
             FROM keygen_participants
             WHERE keygen_session_id = ?
             ORDER BY registered_at ASC",
        )
        .bind(keygen_session_id.as_string())
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
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM keygen_participants WHERE keygen_session_id = ?",
        )
        .bind(keygen_session_id.as_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    /// Get participant's session-specific auth pubkey for authorization
    pub async fn get_participant_auth_pubkey(
        &self,
        user_id: &UserId,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<u8>, ApiError> {
        let auth_pubkey: Vec<u8> = sqlx::query_scalar(
            "SELECT auth_pubkey FROM keygen_participants
             WHERE user_id = ? AND keygen_session_id = ?",
        )
        .bind(user_id.as_str())
        .bind(keygen_session_id.as_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(auth_pubkey)
    }

    pub async fn update_keygen_session_status(
        &self,
        keygen_session_id: &SessionId,
        status: &KeygenSessionStatus,
    ) -> Result<(), ApiError> {
        let status_json = serde_json::to_string(status).map_err(|e| {
            ApiError::Serialization(format!("Failed to serialize keygen status: {e}"))
        })?;

        let status_name = status.kind().to_string();
        let current_time = DbUtils::current_timestamp();

        sqlx::query(
            "UPDATE keygen_sessions
             SET status = ?, status_name = ?, updated_at = ?,
                 completed_at = CASE WHEN ? = 'completed' THEN ? ELSE completed_at END,
                 failed_at = CASE WHEN ? = 'failed' THEN ? ELSE failed_at END
             WHERE keygen_session_id = ?",
        )
        .bind(status_json)
        .bind(status_name.clone())
        .bind(current_time)
        .bind(status_name.clone())
        .bind(current_time)
        .bind(status_name)
        .bind(current_time)
        .bind(keygen_session_id.as_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_signing_session(
        &self,
        request: &CreateSigningSessionRequest,
    ) -> Result<(), ApiError> {
        let keygen_status = self
            .get_keygen_session_by_id(&request.keygen_session_id)
            .await?
            .ok_or(ApiError::not_found("Keygen session not found"))?;

        let (encrypted_session_secret, coordinator_encrypted_private_key, taproot_tweak) =
            match &keygen_status {
                KeygenSessionStatus::Completed(completed) => (
                    completed.encrypted_session_secret.clone(),
                    completed.coordinator_encrypted_private_key.clone(),
                    completed.taproot_tweak_config.clone(),
                ),
                _ => {
                    return Err(ApiError::bad_request(
                        "Keygen session must be completed before signing",
                    ))
                }
            };

        let keygen_participants = self
            .get_keygen_participants(&request.keygen_session_id)
            .await?;
        let expected_participants: Vec<UserId> = keygen_participants
            .iter()
            .map(|p| p.user_id.clone())
            .collect();

        let current_time = DbUtils::current_timestamp();
        let expires_at = current_time + request.timeout_secs as i64;

        let participants_requiring_approval = sqlx::query_scalar(
            "SELECT user_id FROM keygen_participants
             WHERE keygen_session_id = ? AND require_signing_approval = true",
        )
        .bind(request.keygen_session_id.as_string())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|user_id_str: String| UserId::parse(&user_id_str))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::database(format!("Invalid user ID in database: {e}")))?;

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
            taproot_tweak: taproot_tweak.clone(),
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

        sqlx::query(
            "INSERT INTO signing_sessions (
                signing_session_id, keygen_session_id, status_name, created_at,
                expires_at, updated_at, retry_count, correlation_id, message_hash,
                expected_participants, status, session_encrypted_data, enclave_encrypted_data
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(request.signing_session_id.as_string())
        .bind(request.keygen_session_id.as_string())
        .bind(status_name.to_string())
        .bind(current_time)
        .bind(expires_at)
        .bind(current_time)
        .bind(0)
        .bind(correlation_id_bytes)
        .bind(request.message_hash.as_slice())
        .bind(serde_json::to_string(&expected_participants)?)
        .bind(status_json)
        .bind(session_encrypted)
        .bind(enclave_encrypted)
        .execute(&self.pool)
        .await?;

        // Get fresh keygen participants for database insertion
        let keygen_participants_for_db = self
            .get_keygen_participants(&request.keygen_session_id)
            .await?;
        for participant in &keygen_participants_for_db {
            let session_encrypted = &participant.session_encrypted_data;
            let enclave_encrypted = &participant.enclave_encrypted_data;

            sqlx::query(
                "INSERT INTO signing_participants (
                    signing_session_id, user_id, assigned_enclave_id, enclave_key_epoch,
                    registered_at, session_encrypted_data, enclave_encrypted_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(request.signing_session_id.as_string())
            .bind(participant.user_id.as_str())
            .bind(participant.enclave_id.as_u32() as i64)
            .bind(participant.enclave_key_epoch as i64)
            .bind(current_time)
            .bind(session_encrypted)
            .bind(enclave_encrypted)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_signing_session_by_id(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<Option<keymeld_core::session::SigningSessionStatus>, ApiError> {
        let row = sqlx::query("SELECT status FROM signing_sessions WHERE signing_session_id = ?")
            .bind(signing_session_id.as_string())
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(row) => {
                let status_json: String = row.get("status");
                let mut status: SigningSessionStatus =
                    serde_json::from_str(&status_json).map_err(|e| {
                        ApiError::Serialization(format!(
                            "Failed to deserialize signing status: {e}"
                        ))
                    })?;

                // Status loaded successfully

                // Only merge keygen participants if registered_participants is empty (fallback for old sessions)
                if let SigningSessionStatus::CollectingParticipants(ref collecting) = status {
                    if collecting.registered_participants.is_empty() {
                        debug!(
                            "Signing session {} has empty registered_participants, merging from keygen",
                            collecting.signing_session_id
                        );
                        if let Ok(keygen_participants) = self
                            .get_keygen_participants(&collecting.keygen_session_id)
                            .await
                        {
                            let keygen_map: BTreeMap<UserId, ParticipantData> = keygen_participants
                                .into_iter()
                                .map(|p| (p.user_id.clone(), p))
                                .collect();
                            debug!(
                                "Merging {} keygen participants into signing session",
                                keygen_map.len()
                            );
                            let _ = status.merge_participants_from_keygen(&keygen_map);
                        }
                    } else {
                        debug!(
                            "Signing session {} already has {} registered_participants, no merge needed",
                            collecting.signing_session_id,
                            collecting.registered_participants.len()
                        );
                    }
                }

                if let SigningSessionStatus::CollectingParticipants(ref mut collecting) = status {
                    let participants_requiring_approval = self
                        .get_participants_requiring_approval(&collecting.keygen_session_id)
                        .await?;

                    let approved_participants = self
                        .get_signing_session_approvals(signing_session_id)
                        .await?;

                    collecting.participants_requiring_approval = participants_requiring_approval;
                    collecting.approved_participants = approved_participants;
                }

                Ok(Some(status))
            }
            None => Ok(None),
        }
    }

    pub async fn get_signing_participant_count(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<usize, ApiError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM signing_participants WHERE signing_session_id = ?",
        )
        .bind(signing_session_id.as_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(count as usize)
    }

    pub async fn update_signing_session_status(
        &self,
        signing_session_id: &SessionId,
        status: &keymeld_core::session::SigningSessionStatus,
    ) -> Result<(), ApiError> {
        let status_json = serde_json::to_string(status).map_err(|e| {
            ApiError::Serialization(format!("Failed to serialize signing status: {e}"))
        })?;

        let status_name = status.kind().to_string();
        let current_time = DbUtils::current_timestamp();

        sqlx::query(
            "UPDATE signing_sessions
             SET status = ?, status_name = ?, updated_at = ?,
                 completed_at = CASE WHEN ? = 'completed' THEN ? ELSE completed_at END,
                 failed_at = CASE WHEN ? = 'failed' THEN ? ELSE failed_at END
             WHERE signing_session_id = ?",
        )
        .bind(status_json)
        .bind(status_name.clone())
        .bind(current_time)
        .bind(status_name.clone())
        .bind(current_time)
        .bind(status_name)
        .bind(current_time)
        .bind(signing_session_id.as_string())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_keygen_session_id_from_signing_session(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<Option<SessionId>, ApiError> {
        let row = sqlx::query_scalar::<_, String>(
            "SELECT keygen_session_id FROM signing_sessions WHERE signing_session_id = ?",
        )
        .bind(signing_session_id.as_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(keygen_session_id_str) => {
                let keygen_session_id = keygen_session_id_str.try_into().map_err(|e| {
                    ApiError::Serialization(format!("Invalid keygen session ID: {e:?}"))
                })?;
                Ok(Some(keygen_session_id))
            }
            None => Ok(None),
        }
    }

    pub async fn get_processable_keygen_sessions_batch(
        &self,
        active_states: &[KeygenStatusKind],
        batch_size: u32,
        offset: u32,
        _processing_timeout_mins: u64,
        max_retries: u16,
    ) -> Result<Vec<ProcessableSessionRecord>, ApiError> {
        let current_time = DbUtils::current_timestamp();

        debug!("Querying processable keygen sessions - states: {:?}, current_time: {}, max_retries: {}, batch_size: {}, offset: {}",
               active_states.iter().map(|s| s.as_ref()).collect::<Vec<_>>(), current_time, max_retries, batch_size, offset);

        let all_sessions = sqlx::query("SELECT keygen_session_id, status_name, expires_at, retry_count FROM keygen_sessions ORDER BY updated_at ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| ApiError::database(format!("Failed to fetch all keygen sessions for debugging: {e}")))?;

        debug!("Total keygen sessions in database: {}", all_sessions.len());
        for row in all_sessions {
            let session_id: String = row.get("keygen_session_id");
            let status_name: String = row.get("status_name");
            let expires_at: i64 = row.get("expires_at");
            let retry_count: i64 = row.get("retry_count");
            debug!(
                "Session: {} | Status: {} | Expires: {} | Retries: {} | Current: {}",
                session_id, status_name, expires_at, retry_count, current_time
            );
        }

        let placeholders = active_states
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r#"
            SELECT keygen_session_id as session_id
            FROM keygen_sessions
            WHERE status_name IN ({placeholders})
              AND expires_at > ?
              AND retry_count < ?
            ORDER BY updated_at ASC
            LIMIT ? OFFSET ?
            "#
        );

        debug!("Executing query: {}", query);

        let mut query_builder = sqlx::query_as::<_, ProcessableSessionRecord>(&query);

        for status in active_states {
            query_builder = query_builder.bind(status.as_ref());
        }

        query_builder = query_builder
            .bind(current_time)
            .bind(max_retries)
            .bind(batch_size as i32)
            .bind(offset as i32);

        let records = query_builder.fetch_all(&self.pool).await.map_err(|e| {
            ApiError::database(format!(
                "Failed to fetch processable keygen sessions batch: {e}"
            ))
        })?;

        debug!(
            "Found {} processable keygen sessions matching criteria",
            records.len()
        );

        Ok(records)
    }

    pub async fn get_processable_signing_sessions_batch(
        &self,
        active_states: &[SigningStatusKind],
        batch_size: u32,
        offset: u32,
        processing_timeout_mins: u64,
        max_retries: u16,
    ) -> Result<Vec<ProcessableSessionRecord>, ApiError> {
        let timeout_seconds = (processing_timeout_mins * 60) as i64;
        let current_time = DbUtils::current_timestamp();

        let placeholders = active_states
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(
            r#"
            SELECT signing_session_id as session_id
            FROM signing_sessions
            WHERE status_name IN ({placeholders})
              AND expires_at > ?
              AND (processing_started_at IS NULL
                   OR processing_started_at < ? - ?)
              AND (last_processing_attempt IS NULL
                   OR last_processing_attempt < ? - (retry_count * retry_count * 2))
              AND retry_count < ?
            ORDER BY updated_at ASC
            LIMIT ? OFFSET ?
            "#
        );

        let mut query_builder = sqlx::query_as::<_, ProcessableSessionRecord>(&query);

        for status in active_states {
            query_builder = query_builder.bind(status.as_ref());
        }

        query_builder = query_builder
            .bind(current_time)
            .bind(current_time)
            .bind(timeout_seconds)
            .bind(current_time)
            .bind(max_retries)
            .bind(batch_size as i32)
            .bind(offset as i32);

        let records = query_builder.fetch_all(&self.pool).await.map_err(|e| {
            ApiError::database(format!(
                "Failed to fetch processable signing sessions batch: {e}"
            ))
        })?;

        Ok(records)
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
        let current_time = DbUtils::current_timestamp();
        let expires_at = current_time + cache_duration_secs;
        let public_key_value = public_key.unwrap_or_else(|| "unavailable".to_string());

        sqlx::query(
            "INSERT INTO enclave_public_keys (enclave_id, public_key, cached_at, expires_at, is_healthy,
                                            attestation_document, key_epoch, key_generation_time, startup_time, active_sessions)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(enclave_id) DO UPDATE SET
                 public_key = CASE WHEN excluded.public_key != 'unavailable' THEN excluded.public_key ELSE enclave_public_keys.public_key END,
                 cached_at = excluded.cached_at,
                 expires_at = excluded.expires_at,
                 is_healthy = excluded.is_healthy,
                 attestation_document = COALESCE(excluded.attestation_document, enclave_public_keys.attestation_document),
                 key_epoch = COALESCE(excluded.key_epoch, enclave_public_keys.key_epoch),
                 key_generation_time = COALESCE(excluded.key_generation_time, enclave_public_keys.key_generation_time),
                 startup_time = COALESCE(excluded.startup_time, enclave_public_keys.startup_time),
                 active_sessions = COALESCE(excluded.active_sessions, enclave_public_keys.active_sessions)"
        )
        .bind(enclave_id as i32)
        .bind(public_key_value)
        .bind(current_time)
        .bind(expires_at)
        .bind(is_healthy)
        .bind(attestation_document.unwrap_or_default())
        .bind(key_epoch.unwrap_or(1) as i64)
        .bind(key_generation_time.unwrap_or(0) as i64)
        .bind(startup_time.unwrap_or(current_time as u64) as i64)
        .bind(active_sessions.unwrap_or(0) as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_enclave_health(
        &self,
        enclave_id: u32,
    ) -> Result<Option<EnclaveHealthInfo>, ApiError> {
        let row = sqlx::query_as::<_, EnclaveHealthInfo>(
            "SELECT enclave_id, public_key, cached_at, expires_at, is_healthy,
                    COALESCE(attestation_document, '') as attestation_document,
                    COALESCE(key_epoch, 1) as key_epoch,
                    COALESCE(key_generation_time, 0) as key_generation_time,
                    COALESCE(startup_time, 0) as startup_time,
                    COALESCE(active_sessions, 0) as active_sessions
             FROM enclave_public_keys
             WHERE enclave_id = ?",
        )
        .bind(enclave_id as i32)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    pub async fn get_all_enclave_health(&self) -> Result<Vec<EnclaveHealthInfo>, ApiError> {
        let rows = sqlx::query_as::<_, EnclaveHealthInfo>(
            "SELECT enclave_id, public_key, cached_at, expires_at, is_healthy,
                    COALESCE(attestation_document, '') as attestation_document,
                    COALESCE(key_epoch, 1) as key_epoch,
                    COALESCE(key_generation_time, 0) as key_generation_time,
                    COALESCE(startup_time, 0) as startup_time,
                    COALESCE(active_sessions, 0) as active_sessions
             FROM enclave_public_keys
             ORDER BY enclave_id",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    pub async fn invalidate_enclave_cache(&self, enclave_id: u32) -> Result<(), ApiError> {
        // Force cache expiration by setting expires_at to current time
        let current_time = DbUtils::current_timestamp();

        sqlx::query(
            "UPDATE enclave_public_keys
             SET expires_at = ?
             WHERE enclave_id = ?",
        )
        .bind(current_time)
        .bind(enclave_id as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn approve_signing_session(
        &self,
        signing_session_id: &SessionId,
        user_id: &UserId,
    ) -> Result<(), ApiError> {
        let current_time = DbUtils::current_timestamp();

        sqlx::query(
            "INSERT OR REPLACE INTO signing_approvals (
                signing_session_id, user_id, approved_at, user_signature_validated, session_signature_validated
            ) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(signing_session_id.as_string())
        .bind(user_id.as_str())
        .bind(current_time)
        .bind(true)
        .bind(true)
        .execute(&self.pool)
        .await?;

        let mut session_status = self
            .get_signing_session_by_id(signing_session_id)
            .await?
            .ok_or(ApiError::not_found("Signing session not found"))?;

        if let SigningSessionStatus::CollectingParticipants(ref mut collecting) = session_status {
            if !collecting.approved_participants.contains(user_id) {
                collecting.approved_participants.push(user_id.clone());
            }
        }

        self.update_signing_session_status(signing_session_id, &session_status)
            .await?;

        Ok(())
    }

    pub async fn get_participants_requiring_approval(
        &self,
        keygen_session_id: &SessionId,
    ) -> Result<Vec<UserId>, ApiError> {
        let rows = sqlx::query(
            "SELECT user_id FROM keygen_participants
             WHERE keygen_session_id = ? AND require_signing_approval = true",
        )
        .bind(keygen_session_id.as_string())
        .fetch_all(&self.pool)
        .await?;

        let mut user_ids = Vec::new();
        for row in rows {
            let user_id_str: String = row.try_get("user_id")?;
            user_ids
                .push(UserId::parse(&user_id_str).map_err(|e| {
                    ApiError::database(format!("Invalid user ID in database: {e}"))
                })?);
        }

        Ok(user_ids)
    }

    pub async fn get_signing_session_approvals(
        &self,
        signing_session_id: &SessionId,
    ) -> Result<Vec<UserId>, ApiError> {
        let rows = sqlx::query(
            "SELECT user_id FROM signing_approvals
             WHERE signing_session_id = ?",
        )
        .bind(signing_session_id.as_string())
        .fetch_all(&self.pool)
        .await?;

        let mut user_ids = Vec::new();
        for row in rows {
            let user_id_str: String = row.try_get("user_id")?;
            user_ids
                .push(UserId::parse(&user_id_str).map_err(|e| {
                    ApiError::database(format!("Invalid user ID in database: {e}"))
                })?);
        }

        Ok(user_ids)
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
        let user_id_str: String = row.try_get("user_id")?;
        let user_id = UserId::parse(user_id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "user_id".to_string(),
            source: Box::new(e),
        })?;

        let enclave_id_i64: i64 = row.try_get("assigned_enclave_id")?;
        let enclave_id = EnclaveId::new(enclave_id_i64 as u32);

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

#[derive(Debug)]
pub struct SigningParticipantRow {
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_key_epoch: u64,
    pub registered_at: i64,
    pub session_encrypted_data: String,
    pub enclave_encrypted_data: String,
}

impl FromRow<'_, SqliteRow> for SigningParticipantRow {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        let user_id_str: String = row.try_get("user_id")?;
        let user_id = UserId::parse(user_id_str).map_err(|e| sqlx::Error::ColumnDecode {
            index: "user_id".to_string(),
            source: Box::new(e),
        })?;

        let enclave_id_i64: i64 = row.try_get("assigned_enclave_id")?;
        let enclave_id = EnclaveId::new(enclave_id_i64 as u32);

        let enclave_key_epoch_i64: i64 = row.try_get("enclave_key_epoch")?;
        let registered_at: i64 = row.try_get("registered_at")?;
        let session_encrypted_data: String = row.try_get("session_encrypted_data")?;
        let enclave_encrypted_data: String = row.try_get("enclave_encrypted_data")?;

        Ok(SigningParticipantRow {
            user_id,
            enclave_id,
            enclave_key_epoch: enclave_key_epoch_i64 as u64,
            registered_at,
            session_encrypted_data,
            enclave_encrypted_data,
        })
    }
}

impl From<SigningParticipantRow> for ParticipantData {
    fn from(row: SigningParticipantRow) -> Self {
        ParticipantData {
            user_id: row.user_id,
            enclave_id: row.enclave_id,
            enclave_key_epoch: row.enclave_key_epoch,
            session_encrypted_data: row.session_encrypted_data,
            enclave_encrypted_data: row.enclave_encrypted_data,
        }
    }
}

pub struct ProcessableSessionRecord {
    pub session_id: SessionId,
}

impl FromRow<'_, SqliteRow> for ProcessableSessionRecord {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(ProcessableSessionRecord {
            session_id: SessionId::new(row.try_get::<String, _>("session_id")?),
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
