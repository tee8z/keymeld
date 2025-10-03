use crate::{
    config::CoordinatorConfig,
    database::{Database, ProcessableSessionRecord},
    errors::ApiError,
    metrics::{Metrics, MetricsTimer},
};
use keymeld_core::{
    enclave::EnclaveManager,
    session::{KeygenSessionStatus, KeygenStatusKind, SigningSessionStatus, SigningStatusKind},
    Advanceable,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::oneshot::{Receiver, Sender},
    task::JoinHandle,
    time::interval,
};
use tracing::{debug, error, info, warn};

pub struct Coordinator {
    db: Arc<Database>,
    enclave_manager: Arc<EnclaveManager>,
    config: CoordinatorConfig,
    metrics: Arc<Metrics>,
}

impl Coordinator {
    pub fn new(
        db: Arc<Database>,
        enclave_manager: Arc<EnclaveManager>,
        config: Option<CoordinatorConfig>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            db,
            enclave_manager,
            config: config.unwrap_or_default(),
            metrics,
        }
    }

    pub async fn process_sessions(&self) -> Result<u32, ApiError> {
        let timer = MetricsTimer::start((*self.metrics).clone(), "all", "process_sessions");

        let keygen_processed = match self.process_keygen_sessions().await {
            Ok(count) => count,
            Err(e) => {
                self.metrics
                    .record_session_error("coordinator", "keygen_processing_failed");
                return Err(e);
            }
        };

        let signing_processed = match self.process_signing_sessions().await {
            Ok(count) => count,
            Err(e) => {
                self.metrics
                    .record_session_error("coordinator", "signing_processing_failed");
                return Err(e);
            }
        };

        let total_processed = keygen_processed + signing_processed;

        timer.finish();

        if total_processed > 0 {
            info!(
                "Processed {} total sessions (keygen: {}, signing: {})",
                total_processed, keygen_processed, signing_processed
            );
        }

        Ok(total_processed)
    }

    pub async fn run_continuous(&self, mut shutdown_rx: Receiver<()>) -> Result<(), ApiError> {
        let mut processing_interval_ms = interval(Duration::from_millis(
            self.config.processing_interval_ms.unwrap_or(1000),
        ));

        let mut cleanup_interval = interval(Duration::from_secs(
            self.config.cleanup_interval_secs.unwrap_or(300),
        ));
        let mut metrics_interval = interval(Duration::from_secs(
            self.config.metric_record_interval_secs.unwrap_or(30),
        ));

        info!(
            "Starting session coordinator with {}ms interval",
            self.config.processing_interval_ms.unwrap_or(1000)
        );

        loop {
            tokio::select! {
                _ = processing_interval_ms.tick() => {
                    match self.process_sessions().await {
                        Ok(count) => {
                            if count > 0 {
                                debug!("Session processing cycle completed: {} sessions processed", count);
                            }
                        }
                        Err(e) => {
                            error!("Session processing cycle failed: {}", e);
                            self.metrics.record_session_error("coordinator", "processing_cycle_failed");
                        }
                    }
                }
                _ = cleanup_interval.tick() => {
                    match self.cleanup_expired_sessions().await {
                        Ok(_) => {
                        }
                        Err(e) => {
                            error!("Session cleanup failed: {}", e);
                            self.metrics.record_session_error("coordinator", "cleanup_failed");
                        }
                    }
                }
                _ = metrics_interval.tick() => {
                    if let Err(e) = self.update_session_metrics().await {
                        error!("Session metrics update failed: {}", e);
                    }

                    if let Err(e) = self.update_enclave_health_metrics().await {
                        error!("Enclave health metrics update failed: {}", e);
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Session coordinator received shutdown signal");
                    break;
                }
            }
        }

        info!("Session coordinator shut down gracefully");
        Ok(())
    }

    pub fn start_background_task(self) -> (JoinHandle<Result<(), ApiError>>, Sender<()>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let handle = tokio::spawn(async move { self.run_continuous(shutdown_rx).await });

        (handle, shutdown_tx)
    }

    async fn process_keygen_sessions(&self) -> Result<u32, ApiError> {
        let timer = MetricsTimer::start((*self.metrics).clone(), "keygen", "batch_processing");
        let active_states = vec![KeygenStatusKind::CollectingParticipants];

        let batch_size = self.config.batch_size.unwrap_or(50);
        let max_retries = self.config.max_retries.unwrap_or(3) as u16;
        let processing_timeout = self.config.processing_timeout_mins.unwrap_or(5);

        let mut total_processed_count = 0;
        let mut offset = 0;

        loop {
            match self
                .db
                .get_processable_keygen_sessions_batch(
                    &active_states,
                    batch_size,
                    offset,
                    processing_timeout,
                    max_retries,
                )
                .await
            {
                Ok(sessions) => {
                    if sessions.is_empty() {
                        break; // No more sessions to process
                    }

                    let mut batch_processed_count = 0;
                    for session_record in sessions {
                        match self.advance_keygen_session(session_record).await {
                            Ok(advanced) => {
                                if advanced {
                                    batch_processed_count += 1;
                                    total_processed_count += 1;
                                }
                            }
                            Err(e) => {
                                error!("Failed to advance keygen session: {}", e);
                                self.metrics
                                    .record_session_error("keygen", "advance_failed");
                            }
                        }
                    }

                    offset += batch_size;

                    // If we processed fewer than batch_size sessions, we've reached the end
                    if batch_processed_count < batch_size {
                        break;
                    }
                }
                Err(e) => {
                    timer.finish();
                    error!(
                        "Failed to get keygen sessions batch at offset {}: {}",
                        offset, e
                    );
                    self.metrics
                        .record_session_error("keygen", "batch_fetch_failed");
                    return Err(e);
                }
            }
        }

        timer.finish();

        if total_processed_count > 0 {
            info!(
                "Processed {} keygen sessions across all batches",
                total_processed_count
            );
        }

        Ok(total_processed_count)
    }

    async fn process_signing_sessions(&self) -> Result<u32, ApiError> {
        let timer = MetricsTimer::start((*self.metrics).clone(), "signing", "batch_processing");
        let active_states = vec![
            SigningStatusKind::CollectingParticipants,
            SigningStatusKind::SessionFull,
            SigningStatusKind::GeneratingNonces,
            SigningStatusKind::CollectingNonces,
            SigningStatusKind::AggregatingNonces,
            SigningStatusKind::GeneratingPartialSignatures,
            SigningStatusKind::CollectingPartialSignatures,
            SigningStatusKind::FinalizingSignature,
        ];

        let batch_size = self.config.batch_size.unwrap_or(50);
        let max_retries = self.config.max_retries.unwrap_or(3) as u16;
        let processing_timeout = self.config.processing_timeout_mins.unwrap_or(5);

        let mut total_processed_count = 0;
        let mut offset = 0;

        loop {
            match self
                .db
                .get_processable_signing_sessions_batch(
                    &active_states,
                    batch_size,
                    offset,
                    processing_timeout,
                    max_retries,
                )
                .await
            {
                Ok(sessions) => {
                    if sessions.is_empty() {
                        break; // No more sessions to process
                    }

                    let mut batch_processed_count = 0;
                    for session_record in sessions {
                        match self.advance_signing_session(session_record).await {
                            Ok(advanced) => {
                                if advanced {
                                    batch_processed_count += 1;
                                    total_processed_count += 1;
                                }
                            }
                            Err(e) => {
                                error!("Failed to advance signing session: {}", e);
                                self.metrics
                                    .record_session_error("signing", "advance_failed");
                            }
                        }
                    }

                    offset += batch_size;

                    // If we processed fewer than batch_size sessions, we've reached the end
                    if batch_processed_count < batch_size {
                        break;
                    }
                }
                Err(e) => {
                    timer.finish();
                    error!(
                        "Failed to get signing sessions batch at offset {}: {}",
                        offset, e
                    );
                    self.metrics
                        .record_session_error("signing", "batch_fetch_failed");
                    return Err(e);
                }
            }
        }

        timer.finish();

        if total_processed_count > 0 {
            info!(
                "Processed {} signing sessions across all batches",
                total_processed_count
            );
        }

        Ok(total_processed_count)
    }

    async fn update_session_metrics(&self) -> Result<(), ApiError> {
        match self.db.get_stats().await {
            Ok(stats) => {
                self.metrics.update_active_session_count(
                    "sessions",
                    "active",
                    stats.active_sessions as f64,
                );
                self.metrics.update_active_session_count(
                    "sessions",
                    "total",
                    stats.total_sessions as f64,
                );
                self.metrics.update_active_session_count(
                    "participants",
                    "total",
                    stats.total_participants as f64,
                );

                debug!(
                    "Updated session metrics: {} total sessions, {} active sessions, {} participants",
                    stats.total_sessions, stats.active_sessions, stats.total_participants
                );
            }
            Err(e) => {
                warn!("Failed to get database stats for metrics: {}", e);
            }
        }

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), ApiError> {
        match self.db.cleanup_expired_keygen_sessions().await {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} expired keygen sessions", count);
            }
            Ok(_) => {
                debug!("No expired keygen sessions to clean up");
            }
            Err(e) => {
                error!("Failed to cleanup expired keygen sessions: {}", e);
                self.metrics
                    .record_session_error("keygen", "cleanup_failed");
                return Err(e);
            }
        }

        match self.db.cleanup_expired_signing_sessions().await {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} expired signing sessions", count);
            }
            Ok(_) => {
                debug!("No expired signing sessions to clean up");
            }
            Err(e) => {
                error!("Failed to cleanup expired signing sessions: {}", e);
                self.metrics
                    .record_session_error("signing", "cleanup_failed");
                return Err(e);
            }
        }

        match self
            .db
            .cleanup_old_completed_keygen_sessions(
                self.config.delete_sessions_older_than_secs.unwrap_or(86400),
            )
            .await
        {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} old completed keygen sessions", count);
            }
            Ok(_) => {
                debug!("No old completed keygen sessions to clean up");
            }
            Err(e) => {
                error!("Failed to cleanup old completed keygen sessions: {}", e);
                self.metrics
                    .record_session_error("keygen", "old_cleanup_failed");
                return Err(e);
            }
        }

        match self
            .db
            .cleanup_old_completed_signing_sessions(
                self.config.delete_sessions_older_than_secs.unwrap_or(86400),
            )
            .await
        {
            Ok(count) if count > 0 => {
                info!("Cleaned up {} old completed signing sessions", count);
            }
            Ok(_) => {
                debug!("No old completed signing sessions to clean up");
            }
            Err(e) => {
                error!("Failed to cleanup old completed signing sessions: {}", e);
                self.metrics
                    .record_session_error("signing", "old_cleanup_failed");
                return Err(e);
            }
        }

        Ok(())
    }

    async fn update_enclave_health_metrics(&self) -> Result<(), ApiError> {
        let enclaves = self.enclave_manager.health_check().await;
        for (enclave_id, health) in enclaves {
            // Update in-memory metrics
            self.metrics
                .update_enclave_health(enclave_id.as_u32(), health);

            // Check if this enclave already exists in database to determine if we need to set startup_time
            let existing_enclave = self.db.get_enclave_health(enclave_id.as_u32()).await?;
            let current_time = crate::database::DbUtils::current_timestamp();

            // Set startup_time for new enclaves or preserve existing startup_time
            let startup_time = if existing_enclave.is_none() && health {
                Some(current_time as u64)
            } else {
                existing_enclave.map(|e| e.startup_time)
            };

            // Get complete enclave info if healthy
            let (public_key, attestation_document, key_epoch, key_generation_time, active_sessions) =
                if health {
                    match self
                        .enclave_manager
                        .get_enclave_public_info(&enclave_id)
                        .await
                    {
                        Ok((key, attestation, sessions, _uptime, epoch, key_time)) => (
                            Some(key),
                            attestation.map(|att| serde_json::to_string(&att).unwrap_or_default()),
                            Some(epoch),
                            Some(key_time),
                            Some(sessions),
                        ),
                        Err(_) => (None, None, None, None, None),
                    }
                } else {
                    (None, None, None, None, None)
                };

            // Update database with complete health status and enclave info
            self.db
                .update_enclave_health(
                    enclave_id.as_u32(),
                    health,
                    public_key,
                    300, // Cache for 5 minutes
                    attestation_document,
                    key_epoch,
                    key_generation_time,
                    startup_time,
                    active_sessions,
                )
                .await?;
        }

        Ok(())
    }

    async fn advance_keygen_session(
        &self,
        session_record: ProcessableSessionRecord,
    ) -> Result<bool, ApiError> {
        let session_id = session_record.session_id.clone();
        let timer = MetricsTimer::start((*self.metrics).clone(), "keygen", "advance_session");

        debug!("Advancing keygen session: {}", session_id);

        let current_status: KeygenSessionStatus =
            match self.db.get_keygen_session_by_id(&session_id).await {
                Ok(Some(status)) => status,
                Ok(None) => {
                    error!("Keygen session {} not found", session_id);
                    self.metrics
                        .record_session_error("keygen", "session_not_found");
                    timer.finish();
                    return Ok(false);
                }
                Err(e) => {
                    error!(
                        "Failed to load keygen session status for {}: {}",
                        session_id, e
                    );
                    self.metrics.record_session_error("keygen", "load_failed");
                    timer.finish();
                    return Ok(false);
                }
            };

        let current_state_name = format!("{:?}", current_status);

        self.metrics.record_session_state_transition(
            "keygen",
            &current_state_name,
            "processing",
            true,
        );

        match current_status.process(&self.enclave_manager).await {
            Ok(next_status) => {
                let next_state_name = format!("{:?}", next_status);

                self.metrics.record_musig_operation("keygen_advance", true);

                if let Err(e) = self
                    .db
                    .update_keygen_session_status(&session_id, &next_status)
                    .await
                {
                    error!(
                        "Failed to update keygen session status for {}: {}",
                        session_id, e
                    );
                    self.metrics.record_session_error("keygen", "update_failed");
                    timer.finish();
                    return Err(e);
                }

                self.metrics.record_session_state_transition(
                    "keygen",
                    &current_state_name,
                    &next_state_name,
                    true,
                );

                timer.finish();
                info!(
                    "Keygen session {} advanced from {} to {}",
                    session_id, current_state_name, next_state_name
                );
                Ok(true)
            }
            Err(e) => {
                error!("Failed to process keygen session {}: {}", session_id, e);

                self.metrics.record_musig_operation("keygen_advance", false);
                self.metrics.record_session_state_transition(
                    "keygen",
                    &current_state_name,
                    "failed",
                    false,
                );
                self.metrics
                    .record_session_error("keygen", "process_failed");

                timer.finish();
                Ok(false)
            }
        }
    }

    async fn advance_signing_session(
        &self,
        session_record: crate::database::ProcessableSessionRecord,
    ) -> Result<bool, ApiError> {
        let session_id = session_record.session_id.clone();
        let timer = MetricsTimer::start((*self.metrics).clone(), "signing", "advance_session");

        debug!("Advancing signing session: {}", session_id);

        let current_status: SigningSessionStatus =
            match self.db.get_signing_session_by_id(&session_id).await {
                Ok(Some(status)) => status,
                Ok(None) => {
                    error!("Signing session {} not found", session_id);
                    self.metrics
                        .record_session_error("signing", "session_not_found");
                    timer.finish();
                    return Ok(false);
                }
                Err(e) => {
                    error!(
                        "Failed to load signing session status for {}: {}",
                        session_id, e
                    );
                    self.metrics.record_session_error("signing", "load_failed");
                    timer.finish();
                    return Ok(false);
                }
            };

        let current_state_name = format!("{:?}", current_status);
        self.metrics.record_session_state_transition(
            "signing",
            &current_state_name,
            "processing",
            true,
        );

        match current_status.process(&self.enclave_manager).await {
            Ok(next_status) => {
                let next_state_name = format!("{:?}", next_status);

                self.metrics.record_musig_operation("signing_advance", true);
                if let Err(e) = self
                    .db
                    .update_signing_session_status(&session_id, &next_status)
                    .await
                {
                    error!(
                        "Failed to update signing session status for {}: {}",
                        session_id, e
                    );
                    self.metrics
                        .record_session_error("signing", "update_failed");
                    timer.finish();
                    return Err(e);
                }

                // Update participant data (nonces, signatures) if available
                if let Some(participants) = next_status.registered_participants() {
                    for (user_id, participant) in participants {
                        if participant.public_nonces.is_some()
                            || participant.partial_signature.is_some()
                        {
                            if let Err(e) = self
                                .db
                                .update_signing_participant(
                                    &session_id,
                                    user_id,
                                    participant.public_nonces.as_ref(),
                                    participant.partial_signature.as_ref(),
                                )
                                .await
                            {
                                warn!(
                                    "Failed to update participant data for user {} in session {}: {}",
                                    user_id, session_id, e
                                );
                                // Continue processing other participants
                            } else {
                                debug!(
                                    "✅ Updated participant data for user {} in session {}",
                                    user_id, session_id
                                );
                            }
                        }
                    }
                }

                self.metrics.record_session_state_transition(
                    "signing",
                    &current_state_name,
                    &next_state_name,
                    true,
                );

                timer.finish();
                info!(
                    "Signing session {} advanced from {} to {}",
                    session_id, current_state_name, next_state_name
                );
                Ok(true)
            }
            Err(e) => {
                error!("Failed to process signing session {}: {}", session_id, e);
                self.metrics
                    .record_musig_operation("signing_advance", false);
                self.metrics.record_session_state_transition(
                    "signing",
                    &current_state_name,
                    "failed",
                    false,
                );
                self.metrics
                    .record_session_error("signing", "process_failed");

                timer.finish();
                Ok(false)
            }
        }
    }
}
