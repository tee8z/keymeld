use crate::{
    config::CoordinatorConfig,
    database::{Database, DbUtils, ProcessableSessionRecord},
    errors::ApiError,
    metrics::{Metrics, MetricsTimer},
};
use keymeld_core::{
    enclave::EnclaveManager,
    identifiers::EnclaveId,
    session::{Session, SessionKind, SigningSessionStatus},
    Advanceable, KeygenSessionStatus,
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

        let keygen_processed = match self.process_sessions_by_kind(SessionKind::Keygen).await {
            Ok(count) => count,
            Err(e) => {
                self.metrics
                    .record_session_error("coordinator", "keygen_processing_failed");
                return Err(e);
            }
        };

        let signing_processed = match self.process_sessions_by_kind(SessionKind::Signing).await {
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

    async fn process_sessions_by_kind(&self, kind: SessionKind) -> Result<u32, ApiError> {
        let kind_str = kind.to_string();
        let timer = MetricsTimer::start((*self.metrics).clone(), &kind_str, "batch_processing");

        let batch_size = self.config.batch_size.unwrap_or(50);
        let max_retries = self.config.max_retries.unwrap_or(3) as u16;
        let processing_timeout = self.config.processing_timeout_mins.unwrap_or(5);

        let mut total_processed_count = 0;
        let mut offset = 0u32;

        loop {
            let sessions = self
                .get_processable_sessions(kind, batch_size, offset, processing_timeout, max_retries)
                .await;

            match sessions {
                Ok(sessions) => {
                    if sessions.is_empty() {
                        break;
                    }

                    let mut batch_advanced_count = 0;
                    let mut batch_failed_count = 0;

                    for session_record in sessions {
                        let session_id = session_record.session_id.clone();

                        match self.advance_session(session_record, kind).await {
                            Ok(advanced) => {
                                if advanced {
                                    batch_advanced_count += 1;
                                }
                                // Record successful processing regardless of advancement
                                self.metrics
                                    .record_musig_operation("session_batch_process", true);
                            }
                            Err(e) => {
                                batch_failed_count += 1;
                                error!(
                                    "Failed to advance {} session {}: {}",
                                    kind_str, session_id, e
                                );
                                self.metrics
                                    .record_session_error(&kind_str, "advance_failed");
                                self.metrics
                                    .record_musig_operation("session_batch_process", false);
                            }
                        }
                    }

                    total_processed_count += batch_advanced_count;
                    offset += batch_size;

                    self.metrics
                        .record_musig_operation("session_batch_complete", batch_failed_count == 0);
                }
                Err(e) => {
                    error!("Failed to fetch processable {} sessions: {}", kind_str, e);
                    self.metrics.record_session_error(&kind_str, "fetch_failed");
                    self.metrics
                        .record_musig_operation("session_batch_fetch", false);
                    break;
                }
            }
        }

        timer.finish();

        self.metrics
            .record_musig_operation("session_batch_complete", true);

        Ok(total_processed_count)
    }

    async fn advance_session(
        &self,
        session_record: ProcessableSessionRecord,
        kind: SessionKind,
    ) -> Result<bool, ApiError> {
        let session_id = session_record.session_id.clone();
        let kind_str = kind.to_string();
        let timer = MetricsTimer::start((*self.metrics).clone(), &kind_str, "advance_session");

        let current_session = match self.load_session(&session_id, kind).await {
            Ok(Some(session)) => session,
            Ok(None) => {
                error!("{} session {} not found", kind_str, session_id);
                self.metrics
                    .record_session_error(&kind_str, "session_not_found");
                timer.finish();
                return Ok(false);
            }
            Err(e) => {
                error!(
                    "Failed to load {} session status for {}: {}",
                    kind_str, session_id, e
                );
                self.metrics.record_session_error(&kind_str, "load_failed");
                timer.finish();
                return Ok(false);
            }
        };

        let current_state_name = current_session.as_ref().to_string();

        self.metrics.record_session_state_transition(
            &kind_str,
            &current_state_name,
            "processing",
            true,
        );

        match current_session.process(&self.enclave_manager).await {
            Ok(next_session) => {
                let next_state_name = next_session.as_ref();
                let advanced = current_state_name != next_state_name;

                self.metrics.record_musig_operation("session_process", true);

                if advanced {
                    self.record_advancement_metrics(&next_session);
                    self.metrics.record_session_state_transition(
                        &kind_str,
                        &current_state_name,
                        next_state_name,
                        true,
                    );
                } else {
                    self.check_stuck_session(&next_session);
                }

                self.update_session_status(&session_id, &next_session)
                    .await?;

                timer.finish();
                Ok(advanced)
            }
            Err(e) => {
                error!(
                    "Failed to advance {} session {}: {}",
                    kind_str, session_id, e
                );
                self.metrics
                    .record_session_error(&kind_str, "advance_failed");
                self.metrics.record_session_state_transition(
                    &kind_str,
                    &current_state_name,
                    "error",
                    false,
                );
                timer.finish();
                Ok(false)
            }
        }
    }

    async fn load_session(
        &self,
        session_id: &keymeld_core::SessionId,
        kind: SessionKind,
    ) -> Result<Option<Session>, ApiError> {
        match kind {
            SessionKind::Keygen => self
                .db
                .get_keygen_session_by_id(session_id)
                .await
                .map(|opt| opt.map(Session::Keygen)),
            SessionKind::Signing => self
                .db
                .get_signing_session_by_id(session_id)
                .await
                .map(|opt| opt.map(Session::Signing)),
        }
    }

    async fn update_session_status(
        &self,
        session_id: &keymeld_core::SessionId,
        session: &Session,
    ) -> Result<(), ApiError> {
        match session {
            Session::Keygen(keygen_status) => self
                .db
                .update_keygen_session_status(session_id, keygen_status)
                .await
                .map_err(|e| {
                    error!(
                        "Failed to update keygen session {} status in database: {}",
                        session_id, e
                    );
                    self.metrics
                        .record_session_error("keygen", "db_update_failed");
                    e
                }),
            Session::Signing(signing_status) => self
                .db
                .update_signing_session_status(session_id, signing_status)
                .await
                .map_err(|e| {
                    error!(
                        "Failed to update signing session {} status in database: {}",
                        session_id, e
                    );
                    self.metrics
                        .record_session_error("signing", "db_update_failed");
                    e
                }),
        }
    }

    fn record_advancement_metrics(&self, session: &Session) {
        match session {
            Session::Keygen(keygen_status) => {
                if let KeygenSessionStatus::Completed(_) = keygen_status {
                    self.metrics.record_musig_operation("keygen_complete", true);
                }
            }
            Session::Signing(signing_status) => match signing_status {
                SigningSessionStatus::SessionFull(_) => {
                    self.metrics
                        .record_musig_operation("session_initialization", true);
                }
                SigningSessionStatus::GeneratingNonces(_) => {
                    self.metrics
                        .record_musig_operation("nonce_generation_start", true);
                }
                SigningSessionStatus::CollectingNonces(_) => {
                    self.metrics
                        .record_musig_operation("nonce_generation_complete", true);
                }
                SigningSessionStatus::GeneratingPartialSignatures(_) => {
                    self.metrics
                        .record_musig_operation("nonce_aggregation_complete", true);
                }
                SigningSessionStatus::CollectingPartialSignatures(_) => {
                    self.metrics
                        .record_musig_operation("partial_signature_generation", true);
                }
                SigningSessionStatus::FinalizingSignature(_) => {
                    self.metrics
                        .record_musig_operation("signature_aggregation_start", true);
                }
                SigningSessionStatus::Completed(_) => {
                    self.metrics
                        .record_musig_operation("signature_finalization", true);
                }
                _ => {}
            },
        }
    }

    fn check_stuck_session(&self, session: &Session) {
        match session {
            Session::Keygen(KeygenSessionStatus::CollectingParticipants(_)) => {
                // Keygen sessions that stay in collecting_participants might be waiting for participants
                // This is normal, so no failure metric needed
            }
            Session::Signing(SigningSessionStatus::SessionFull(_))
            | Session::Signing(SigningSessionStatus::GeneratingNonces(_))
            | Session::Signing(SigningSessionStatus::CollectingNonces(_))
            | Session::Signing(SigningSessionStatus::GeneratingPartialSignatures(_))
            | Session::Signing(SigningSessionStatus::CollectingPartialSignatures(_))
            | Session::Signing(SigningSessionStatus::FinalizingSignature(_)) => {
                // Signing sessions that don't advance might indicate processing issues
                self.metrics.record_musig_operation("session_stuck", false);
            }
            _ => {}
        }
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

        // Fast health check interval for epoch change detection (every 5 seconds)
        let mut fast_health_interval = interval(Duration::from_secs(5));

        info!(
            "Starting session coordinator with {}ms interval and 5s epoch detection",
            self.config.processing_interval_ms.unwrap_or(1000)
        );

        self.perform_startup_enclave_health_check().await;

        loop {
            tokio::select! {
                _ = processing_interval_ms.tick() => {
                    match self.process_sessions().await {
                        Ok(_count) => {

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
                _ = fast_health_interval.tick() => {
                    // Fast epoch detection - only check epoch changes, not full health
                    let _ = self.fast_epoch_detection().await;
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

    async fn get_processable_sessions(
        &self,
        kind: SessionKind,
        batch_size: u32,
        offset: u32,
        processing_timeout: u64,
        max_retries: u16,
    ) -> Result<Vec<crate::database::ProcessableSessionRecord>, ApiError> {
        match kind {
            SessionKind::Keygen => {
                let active_states = Session::active_keygen_states();
                self.db
                    .get_processable_keygen_sessions_batch(
                        &active_states,
                        batch_size,
                        offset,
                        processing_timeout,
                        max_retries,
                    )
                    .await
            }
            SessionKind::Signing => {
                let active_states = Session::active_signing_states();
                self.db
                    .get_processable_signing_sessions_batch(
                        &active_states,
                        batch_size,
                        offset,
                        processing_timeout,
                        max_retries,
                    )
                    .await
            }
        }
    }

    pub fn start_background_task(self) -> (JoinHandle<Result<(), ApiError>>, Sender<()>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let handle = tokio::spawn(async move { self.run_continuous(shutdown_rx).await });

        (handle, shutdown_tx)
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
            Ok(_) => {}
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
            Ok(_) => {}
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
            self.metrics
                .update_enclave_health(enclave_id.as_u32(), health);

            // Check if this enclave already exists in database to determine if we need to set startup_time
            let existing_enclave = self.db.get_enclave_health(enclave_id.as_u32()).await?;
            let current_time = DbUtils::current_timestamp();

            // Set startup_time for new enclaves or preserve existing startup_time
            let startup_time = if existing_enclave.is_none() && health {
                Some(current_time as u64)
            } else {
                existing_enclave.map(|e| e.startup_time)
            };

            let (
                actual_health,
                public_key,
                attestation_document,
                key_epoch,
                key_generation_time,
                active_sessions,
            ) = if health {
                // First validate epochs to detect any enclave restarts
                let epoch_check_result = self
                    .enclave_manager
                    .validate_enclave_epoch(&enclave_id)
                    .await;

                match epoch_check_result {
                    Ok(true) => {
                        warn!("Enclave {} restart detected during health check - marking as unhealthy until epoch stabilizes", enclave_id);
                        // Force immediate cache refresh by invalidating current cache
                        if let Err(e) = self.db.invalidate_enclave_cache(enclave_id.as_u32()).await
                        {
                            warn!(
                                "Failed to invalidate cache for enclave {}: {}",
                                enclave_id, e
                            );
                        }
                        // Mark as unhealthy until the epoch stabilizes
                        (false, None, None, None, None, None)
                    }
                    Ok(false) => {
                        // No restart detected, get fresh public info
                        match self
                            .enclave_manager
                            .get_enclave_public_info(&enclave_id)
                            .await
                        {
                            Ok((key, attestation, sessions, _uptime, epoch, key_time)) => {
                                info!(
                                    "Successfully retrieved public key for enclave {} (epoch {}): {} chars",
                                    enclave_id,
                                    epoch,
                                    key.len()
                                );
                                (
                                    true,
                                    Some(key),
                                    attestation
                                        .map(|att| serde_json::to_string(&att).unwrap_or_default()),
                                    Some(epoch),
                                    Some(key_time),
                                    Some(sessions),
                                )
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to get public info for healthy enclave {}: {}",
                                    enclave_id, e
                                );
                                (false, None, None, None, None, None)
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to validate epoch for enclave {}: {}", enclave_id, e);
                        // If we can't validate epoch, don't mark as healthy
                        (false, None, None, None, None, None)
                    }
                }
            } else {
                debug!(
                    "Enclave {} is not healthy, skipping public key retrieval",
                    enclave_id
                );
                (false, None, None, None, None, None)
            };

            self.db
                .update_enclave_health(
                    enclave_id.as_u32(),
                    actual_health,
                    public_key,
                    30, // Cache for 30 seconds to quickly detect epoch changes
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

    /// Fast epoch detection - checks for epoch changes without full health check
    async fn fast_epoch_detection(&self) -> Result<(), ApiError> {
        let enclave_ids = self.enclave_manager.get_enclave_ids();

        for enclave_id in enclave_ids {
            // Only validate epochs - don't do full health check
            match self
                .enclave_manager
                .validate_enclave_epoch(&enclave_id)
                .await
            {
                Ok(had_restart) => {
                    if had_restart {
                        info!("Fast epoch detection: Enclave {} restart detected, forcing cache refresh", enclave_id);

                        // Immediately invalidate cache for this enclave
                        if let Err(e) = self.db.invalidate_enclave_cache(enclave_id.as_u32()).await
                        {
                            warn!(
                                "Failed to invalidate cache for enclave {}: {}",
                                enclave_id, e
                            );
                        }

                        // Trigger immediate health check to refresh with new keys
                        if let Err(e) = self
                            .update_single_enclave_health_immediate(enclave_id)
                            .await
                        {
                            warn!(
                                "Failed to update enclave {} health after epoch change: {}",
                                enclave_id, e
                            );
                        }
                    }
                }
                Err(e) => {
                    // Don't log as error since this runs frequently
                    debug!(
                        "Fast epoch validation failed for enclave {}: {}",
                        enclave_id, e
                    );
                }
            }
        }

        Ok(())
    }

    /// Immediately update health for a single enclave after epoch change detection
    async fn update_single_enclave_health_immediate(
        &self,
        enclave_id: EnclaveId,
    ) -> Result<(), ApiError> {
        let health = self
            .enclave_manager
            .health_check()
            .await
            .get(&enclave_id)
            .copied()
            .unwrap_or(false);

        if !health {
            warn!(
                "Enclave {} is not healthy during immediate update",
                enclave_id
            );
            return Ok(());
        }

        // Get fresh public info after epoch change
        let (public_key, attestation_document, key_epoch, key_generation_time, active_sessions) =
            match self
                .enclave_manager
                .get_enclave_public_info(&enclave_id)
                .await
            {
                Ok((key, attestation, sessions, _uptime, epoch, key_time)) => {
                    info!(
                        "Fast update: Retrieved fresh public key for enclave {} (epoch {})",
                        enclave_id, epoch
                    );
                    (
                        Some(key),
                        attestation.map(|att| serde_json::to_string(&att).unwrap_or_default()),
                        Some(epoch),
                        Some(key_time),
                        Some(sessions),
                    )
                }
                Err(e) => {
                    warn!(
                        "Failed to get public info for enclave {} during immediate update: {}",
                        enclave_id, e
                    );
                    return Err(e.into());
                }
            };

        // Get existing startup time
        let existing_enclave = self.db.get_enclave_health(enclave_id.as_u32()).await?;
        let startup_time = existing_enclave.map(|e| e.startup_time);

        // Update database with fresh keys and short TTL for immediate availability
        self.db
            .update_enclave_health(
                enclave_id.as_u32(),
                health,
                public_key,
                30, // 30 second cache TTL
                attestation_document,
                key_epoch,
                key_generation_time,
                startup_time,
                active_sessions,
            )
            .await?;

        info!(
            "Successfully updated enclave {} health after epoch change",
            enclave_id
        );
        Ok(())
    }

    async fn perform_startup_enclave_health_check(&self) {
        info!("Performing initial enclave health check with epoch validation...");
        let mut retry_count = 0;
        const MAX_STARTUP_RETRIES: u32 = 10;
        const STARTUP_RETRY_DELAY_MS: u64 = 2000;

        while retry_count < MAX_STARTUP_RETRIES {
            match self.update_enclave_health_metrics().await {
                Ok(()) => {
                    // Verify that all enclaves are healthy with epoch-validated keys
                    let mut healthy_enclaves_count = 0;
                    let mut epoch_validated_count = 0;
                    let enclave_ids = self.enclave_manager.get_enclave_ids();

                    info!(
                        "Validating {} enclaves for startup readiness",
                        enclave_ids.len()
                    );

                    for enclave_id in &enclave_ids {
                        match self.db.get_enclave_health(enclave_id.as_u32()).await {
                            Ok(Some(health_info))
                                if health_info.is_healthy
                                    && health_info.public_key != "unavailable"
                                    && !health_info.public_key.is_empty() =>
                            {
                                healthy_enclaves_count += 1;

                                // Additional check: validate that epoch is synchronized
                                match self
                                    .enclave_manager
                                    .validate_enclave_epoch(enclave_id)
                                    .await
                                {
                                    Ok(false) => {
                                        // No restart detected, epoch is synchronized
                                        epoch_validated_count += 1;
                                        info!(
                                            "Enclave {} is healthy and epoch-synchronized",
                                            enclave_id
                                        );
                                    }
                                    Ok(true) => {
                                        info!("Enclave {} detected restart, needs more time to stabilize", enclave_id);
                                    }
                                    Err(e) => {
                                        warn!(
                                            "Failed to validate epoch for enclave {}: {}",
                                            enclave_id, e
                                        );
                                    }
                                }
                            }
                            Ok(Some(health_info)) => {
                                info!(
                                    "Enclave {} not ready - healthy: {}, public_key: {}",
                                    enclave_id,
                                    health_info.is_healthy,
                                    if health_info.public_key.is_empty() {
                                        "empty"
                                    } else {
                                        "available"
                                    }
                                );
                            }
                            Ok(None) => {
                                info!("Enclave {} not found in health check", enclave_id);
                            }
                            Err(e) => {
                                warn!("Failed to get health for enclave {}: {}", enclave_id, e);
                            }
                        }
                    }

                    info!(
                        "Startup check: {}/{} enclaves healthy, {}/{} epoch-validated",
                        healthy_enclaves_count,
                        enclave_ids.len(),
                        epoch_validated_count,
                        enclave_ids.len()
                    );

                    // Require all enclaves to be both healthy and epoch-validated
                    if epoch_validated_count == enclave_ids.len() && epoch_validated_count > 0 {
                        info!("All {} enclaves are healthy and epoch-synchronized - startup complete!", enclave_ids.len());
                        break;
                    } else if retry_count + 1 >= MAX_STARTUP_RETRIES {
                        warn!(
                            "Startup failed after {} retries: only {}/{} enclaves epoch-validated",
                            MAX_STARTUP_RETRIES,
                            epoch_validated_count,
                            enclave_ids.len()
                        );
                        break;
                    } else {
                        retry_count += 1;
                        info!(
                            "Waiting for epoch synchronization (attempt {}/{}), retrying in {}ms",
                            retry_count, MAX_STARTUP_RETRIES, STARTUP_RETRY_DELAY_MS
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            STARTUP_RETRY_DELAY_MS,
                        ))
                        .await;
                    }
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= MAX_STARTUP_RETRIES {
                        warn!(
                            "Initial enclave health check failed after {} retries: {}",
                            MAX_STARTUP_RETRIES, e
                        );
                        break;
                    } else {
                        warn!("Initial enclave health check failed (attempt {}/{}): {}, retrying in {}ms",
                              retry_count, MAX_STARTUP_RETRIES, e, STARTUP_RETRY_DELAY_MS);
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            STARTUP_RETRY_DELAY_MS,
                        ))
                        .await;
                    }
                }
            }
        }
    }
}
