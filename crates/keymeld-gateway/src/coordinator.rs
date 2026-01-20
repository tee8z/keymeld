use crate::{
    config::{CoordinatorConfig, KmsConfig},
    database::{Database, DbUtils, ProcessableSessionRecord},
    enclave::EnclaveManager,
    errors::ApiError,
    metrics::{Metrics, MetricsTimer},
    session::{Session, SessionKind, SigningSessionStatus},
    Advanceable, KeygenSessionStatus,
};
use dashmap::DashSet;
use futures::stream::{FuturesUnordered, StreamExt};
use keymeld_core::identifiers::{EnclaveId, SessionId};
use keymeld_core::protocol::{KeygenStatusKind, SigningStatusKind};
use log::trace;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::{
    sync::{
        mpsc,
        oneshot::{Receiver, Sender},
    },
    task::JoinHandle,
    time::interval,
};
use tracing::{debug, error, info, warn};

/// Message sent to the database writer task
struct DbWriteRequest {
    session_id: keymeld_core::SessionId,
    session: Session,
}

/// Circuit breaker for coordinator database operations
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_count: Arc<AtomicU32>,
    last_failure_time: Arc<std::sync::Mutex<Option<Instant>>>,
    failure_threshold: u32,
    reset_timeout: Duration,
}

const MAX_RETRIES_DEFAULT: u32 = 3;
const PROCESSING_TIMEOUT_DEFAULT: u64 = 10;
const DEFAULT_BATCH_SIZE: u32 = 20;
/// Threshold in seconds to log a warning about slow session processing
const SLOW_SESSION_THRESHOLD_SECS: u64 = 30;

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failure_count: Arc::new(AtomicU32::new(0)),
            last_failure_time: Arc::new(std::sync::Mutex::new(None)),
            failure_threshold,
            reset_timeout,
        }
    }

    pub fn is_open(&self) -> bool {
        let failure_count = self.failure_count.load(Ordering::Relaxed);
        if failure_count < self.failure_threshold {
            return false;
        }

        // Check if enough time has passed to reset
        if let Ok(last_failure) = self.last_failure_time.lock() {
            if let Some(last_time) = *last_failure {
                if last_time.elapsed() >= self.reset_timeout {
                    self.failure_count.store(0, Ordering::Relaxed);
                    return false;
                }
            }
        }

        true
    }

    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last_failure) = self.last_failure_time.lock() {
            *last_failure = Some(Instant::now());
        }
    }
}

#[derive(Clone)]
pub struct Coordinator {
    db: Arc<Database>,
    enclave_manager: Arc<EnclaveManager>,
    config: CoordinatorConfig,
    kms_config: KmsConfig,
    metrics: Arc<Metrics>,
    circuit_breaker: CircuitBreaker,
    /// Sessions currently being processed - prevents concurrent processing of the same session
    processing_sessions: Arc<DashSet<keymeld_core::SessionId>>,
    /// Channel to send session updates to the database writer
    db_write_tx: mpsc::Sender<DbWriteRequest>,
}

impl Coordinator {
    pub fn new(
        db: Arc<Database>,
        enclave_manager: Arc<EnclaveManager>,
        config: Option<CoordinatorConfig>,
        kms_config: KmsConfig,
        metrics: Arc<Metrics>,
    ) -> Self {
        let config = config.unwrap_or_default();

        let circuit_breaker = CircuitBreaker::new(
            config.circuit_breaker_failure_threshold.unwrap_or(5),
            Duration::from_secs(config.circuit_breaker_reset_timeout_secs.unwrap_or(60)),
        );

        // Create channel for database writes
        // Size based on batch_size * number of batches we could process in ~10 seconds
        // This ensures the channel can buffer all writes if the DB is temporarily slow
        let batch_size = config.batch_size.unwrap_or(DEFAULT_BATCH_SIZE) as usize;
        let processing_interval_ms = config.processing_interval_ms.unwrap_or(200);
        let batches_per_10_secs = (10_000 / processing_interval_ms) as usize;
        let db_writer_channel_size = batch_size * batches_per_10_secs;
        let (db_write_tx, db_write_rx) = mpsc::channel(db_writer_channel_size);
        info!(
            "Database writer channel capacity: {} (batch_size={}, interval={}ms, batches_per_10s={})",
            db_writer_channel_size, batch_size, processing_interval_ms, batches_per_10_secs
        );

        // Spawn the database writer task
        let db_for_writer = Arc::clone(&db);
        let metrics_for_writer = Arc::clone(&metrics);
        tokio::spawn(Self::run_db_writer(
            db_for_writer,
            metrics_for_writer,
            db_write_rx,
        ));

        Self {
            db,
            enclave_manager,
            config,
            kms_config,
            metrics,
            circuit_breaker,
            processing_sessions: Arc::new(DashSet::new()),
            db_write_tx,
        }
    }

    /// Background task that processes database write requests
    async fn run_db_writer(
        db: Arc<Database>,
        metrics: Arc<Metrics>,
        mut rx: mpsc::Receiver<DbWriteRequest>,
    ) {
        info!("Database writer task started");

        while let Some(request) = rx.recv().await {
            let session_id = request.session_id;
            let result = match &request.session {
                Session::Keygen(keygen_status) => {
                    db.update_keygen_session_status(&session_id, keygen_status)
                        .await
                }
                Session::Signing(signing_status) => {
                    db.update_signing_session_status(&session_id, signing_status)
                        .await
                }
            };

            if let Err(e) = result {
                let kind = match &request.session {
                    Session::Keygen(_) => "keygen",
                    Session::Signing(_) => "signing",
                };
                error!(
                    "Database writer failed to update {} session {}: {}",
                    kind, session_id, e
                );
                metrics.record_session_error(kind, "db_write_failed");
            }
        }

        info!("Database writer task stopped");
    }

    /// Monitor database pool health using actual database health check
    async fn monitor_db_pool_health(&self) -> Result<(), ApiError> {
        // Use the existing database health check method
        self.db.health_check().await?;

        // Log that health check passed
        debug!("Database health check passed");

        Ok(())
    }

    pub async fn process_sessions(&self) -> Result<u32, ApiError> {
        let timer = MetricsTimer::start((*self.metrics).clone(), "all", "process_sessions");

        // Check circuit breaker before processing
        if self.circuit_breaker.is_open() {
            warn!("Coordinator circuit breaker is OPEN - skipping processing cycle");
            return Ok(0);
        }

        // Monitor DB pool health before processing
        if let Err(e) = self.monitor_db_pool_health().await {
            warn!("Database health check failed: {}", e);
        }

        // Process keygen, signing, and single-signer operations in parallel
        debug!("Starting parallel processing of keygen, signing, and single-signer operations");
        let parallel_start = Instant::now();
        let (keygen_result, signing_result, single_signer_result) = tokio::join!(
            self.process_sessions_by_kind_with_recovery(SessionKind::Keygen),
            self.process_sessions_by_kind_with_recovery(SessionKind::Signing),
            self.process_single_signer_operations()
        );
        let parallel_duration = parallel_start.elapsed();
        debug!(
            "Completed parallel session processing in {:?}",
            parallel_duration
        );

        let keygen_processed = match keygen_result {
            Ok(count) => {
                self.circuit_breaker.record_success();
                count
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.metrics
                    .record_session_error("coordinator", "keygen_processing_failed");
                warn!("Keygen processing failed, continuing with signing: {}", e);
                0 // Continue with signing sessions instead of failing entirely
            }
        };

        let signing_processed = match signing_result {
            Ok(count) => {
                self.circuit_breaker.record_success();
                count
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.metrics
                    .record_session_error("coordinator", "signing_processing_failed");
                warn!("Signing processing failed: {}", e);
                0 // Don't fail the entire cycle
            }
        };

        let single_signer_processed = match single_signer_result {
            Ok(count) => {
                if count > 0 {
                    self.circuit_breaker.record_success();
                }
                count
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.metrics
                    .record_session_error("coordinator", "single_signer_processing_failed");
                warn!("Single-signer processing failed: {}", e);
                0
            }
        };

        let total_processed = keygen_processed + signing_processed + single_signer_processed;

        timer.finish();

        if total_processed > 0 {
            info!(
                "Processed {} total sessions (keygen: {}, signing: {}, single-signer: {}) in parallel in {:?}",
                total_processed, keygen_processed, signing_processed, single_signer_processed, parallel_duration
            );
        } else {
            debug!("No sessions processed this cycle");
        }

        Ok(total_processed)
    }

    /// Process sessions with recovery - no artificial limits
    async fn process_sessions_by_kind_with_recovery(
        &self,
        kind: SessionKind,
    ) -> Result<u32, ApiError> {
        let kind_str = kind.to_string();
        let timer = MetricsTimer::start((*self.metrics).clone(), &kind_str, "batch_processing");

        let batch_size = self.config.batch_size.unwrap_or(DEFAULT_BATCH_SIZE);
        let max_retries = self.config.max_retries.unwrap_or(MAX_RETRIES_DEFAULT) as u16;
        let processing_timeout = self
            .config
            .processing_timeout_mins
            .unwrap_or(PROCESSING_TIMEOUT_DEFAULT);

        // Use cursor-based pagination to handle concurrent session creation
        // UUIDv7 IDs are naturally ordered by creation time
        let mut total_processed_count = 0;
        let mut cursor: Option<SessionId> = None;
        let mut batch_count = 0;

        loop {
            // Get next batch using cursor pagination
            let sessions = match self
                .get_processable_sessions_cursor(
                    kind,
                    batch_size,
                    cursor.as_ref(),
                    processing_timeout,
                    max_retries,
                )
                .await
            {
                Ok(sessions) => sessions,
                Err(e) => {
                    error!(
                        "Failed to get processable {} sessions (cursor-based): {}",
                        kind_str, e
                    );
                    break;
                }
            };

            if sessions.is_empty() {
                trace!("No more {} sessions to process", kind_str);
                break;
            }

            batch_count += 1;
            info!(
                "Processing batch {} with {} {} sessions",
                batch_count,
                sessions.len(),
                kind_str
            );

            // Update cursor to last session ID for next batch
            cursor = sessions.last().map(|s| s.session_id.clone());

            // Process this batch
            match self.process_batch_sessions(sessions).await {
                Ok(count) => {
                    total_processed_count += count;
                    info!("Batch {} processed {} sessions", batch_count, count);
                }
                Err(e) => {
                    warn!("Batch {} failed: {}", batch_count, e);
                    self.metrics.record_session_error(&kind_str, "batch_failed");
                }
            }
        }

        trace!(
            "Completed cursor-based processing: {} batches, {} sessions processed",
            batch_count,
            total_processed_count
        );

        timer.finish();
        Ok(total_processed_count)
    }

    async fn process_batch_sessions(
        &self,
        sessions: Vec<ProcessableSessionRecord>,
    ) -> Result<u32, ApiError> {
        let kind_str = "session"; // Generic since this processes any session type

        info!("Processing batch of {} sessions", sessions.len());

        // Filter out sessions that are already being processed by another batch
        let sessions_to_process: Vec<_> = sessions
            .into_iter()
            .filter(|session_record| {
                // Atomically try to insert the session into the processing set
                if self
                    .processing_sessions
                    .insert(session_record.session_id.clone())
                {
                    true
                } else {
                    debug!(
                        "Session {} already being processed, skipping",
                        session_record.session_id
                    );
                    false
                }
            })
            .collect();

        if sessions_to_process.is_empty() {
            debug!("All sessions in batch already being processed, skipping");
            return Ok(0);
        }

        let session_timeout = Duration::from_secs(10 * 60); // 10 minutes default
        let mut session_futures: FuturesUnordered<_> = sessions_to_process
            .into_iter()
            .map(|session_record| {
                let session_id = session_record.session_id.clone();
                let processing_sessions = Arc::clone(&self.processing_sessions);
                let coordinator = self.clone();

                async move {
                    let _session_start = Instant::now();
                    debug!("Starting parallel processing for session {}", session_id);

                    let slow_threshold = Duration::from_secs(SLOW_SESSION_THRESHOLD_SECS);
                    let session_id_for_warning = session_id.clone();
                    let warning_task = tokio::spawn(async move {
                        tokio::time::sleep(slow_threshold).await;
                        warn!("Session {} is taking longer than {:?} - still processing", session_id_for_warning, slow_threshold);
                    });

                    // Use session_kind from ProcessableSessionRecord
                    let kind = session_record.session_kind;

                    let result = match tokio::time::timeout(
                        session_timeout,
                        coordinator.advance_session(session_record, kind)
                    ).await {
                        Ok(result) => result,
                        Err(_) => {
                            error!("Session {} ABANDONED after {:?} - possible deadlock or stuck enclave call", session_id, session_timeout);
                            Err(ApiError::Internal(format!("Session {} abandoned after {:?}", session_id, session_timeout)))
                        }
                    };

                    warning_task.abort();
                    processing_sessions.remove(&session_id);
                    (session_id, result)
                }
            })
            .collect();

        let mut batch_processed_count = 0;
        let mut batch_failed_count = 0;

        while let Some((session_id, result)) = session_futures.next().await {
            match result {
                Ok(advanced) => {
                    if advanced {
                        batch_processed_count += 1;
                    }
                    self.metrics
                        .record_musig_operation("session_batch_process", true);
                }
                Err(e) => {
                    batch_failed_count += 1;
                    warn!("Failed to process session {}: {}", session_id, e);
                    self.metrics
                        .record_session_error(kind_str, "advance_failed");
                    self.metrics
                        .record_musig_operation("session_batch_process", false);
                }
            }
        }

        self.metrics
            .record_musig_operation("session_batch_complete", batch_failed_count == 0);
        Ok(batch_processed_count)
    }

    async fn get_processable_sessions_cursor(
        &self,
        kind: SessionKind,
        batch_size: u32,
        cursor: Option<&SessionId>,
        processing_timeout: u64,
        max_retries: u16,
    ) -> Result<Vec<ProcessableSessionRecord>, ApiError> {
        match kind {
            SessionKind::Keygen => {
                let active_states = vec![KeygenStatusKind::CollectingParticipants];
                self.db
                    .get_processable_keygen_sessions_cursor(
                        &active_states,
                        batch_size,
                        cursor,
                        processing_timeout,
                        max_retries,
                    )
                    .await
            }
            SessionKind::Signing => {
                let active_states = vec![
                    SigningStatusKind::CollectingParticipants,
                    SigningStatusKind::InitializingSession,
                    SigningStatusKind::DistributingNonces,
                    SigningStatusKind::FinalizingSignature,
                ];
                self.db
                    .get_processable_signing_sessions_cursor(
                        &active_states,
                        batch_size,
                        cursor,
                        processing_timeout,
                        max_retries,
                    )
                    .await
            }
        }
    }

    async fn advance_session(
        &self,
        session_record: ProcessableSessionRecord,
        kind: SessionKind,
    ) -> Result<bool, ApiError> {
        let session_id = session_record.session_id.clone();
        let kind_str = kind.to_string();
        let timer = MetricsTimer::start((*self.metrics).clone(), &kind_str, "advance_session");

        debug!("Attempting to advance {} session: {}", kind_str, session_id);

        // Load session from database with timeout protection
        let current_session = match self.load_session(&session_id, kind).await {
            Ok(Some(session)) => {
                debug!("Loaded {} session: {}", kind_str, session_id);
                session
            }
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

        debug!(
            "Processing {} session {} from state: {}",
            kind_str, session_id, current_state_name
        );

        self.metrics.record_session_state_transition(
            &kind_str,
            &current_state_name,
            "processing",
            true,
        );

        // Process session with enclave (this involves network calls, not DB operations)
        match current_session.process(&self.enclave_manager).await {
            Ok(next_session) => {
                let next_state_name = next_session.as_ref();
                let advanced = current_state_name != next_state_name;

                self.metrics.record_musig_operation("session_process", true);

                if advanced {
                    info!(
                        "{} session {} advanced: {} -> {}",
                        kind_str, session_id, current_state_name, next_state_name
                    );
                    self.record_advancement_metrics(&next_session);
                    self.metrics.record_session_state_transition(
                        &kind_str,
                        &current_state_name,
                        next_state_name,
                        true,
                    );
                } else {
                    debug!(
                        "{} session {} stayed in state: {}",
                        kind_str, session_id, current_state_name
                    );
                    self.check_stuck_session(&next_session);
                }

                // Send session update to database writer (non-blocking)
                if let Err(e) = self.db_write_tx.try_send(DbWriteRequest {
                    session_id: session_id.clone(),
                    session: next_session,
                }) {
                    error!(
                        "Failed to queue {} session {} for database update: {}",
                        kind_str, session_id, e
                    );
                    self.metrics
                        .record_session_error(&kind_str, "db_queue_full");
                }

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

    fn record_advancement_metrics(&self, session: &Session) {
        match session {
            Session::Keygen(keygen_status) => {
                if let KeygenSessionStatus::Completed(_) = keygen_status {
                    self.metrics.record_musig_operation("keygen_complete", true);
                }
            }
            Session::Signing(signing_status) => match signing_status {
                SigningSessionStatus::InitializingSession(_) => {
                    self.metrics
                        .record_musig_operation("session_initialization", true);
                }
                SigningSessionStatus::DistributingNonces(_) => {
                    self.metrics
                        .record_musig_operation("nonce_distribution", true);
                }
                SigningSessionStatus::FinalizingSignature(_) => {
                    self.metrics
                        .record_musig_operation("signature_finalization_start", true);
                }
                SigningSessionStatus::Completed(_) => {
                    self.metrics
                        .record_musig_operation("signature_complete", true);
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
            Session::Signing(SigningSessionStatus::InitializingSession(_))
            | Session::Signing(SigningSessionStatus::DistributingNonces(_))
            | Session::Signing(SigningSessionStatus::FinalizingSignature(_)) => {
                // Signing sessions that don't advance might indicate processing issues
                self.metrics.record_musig_operation("session_stuck", false);
            }
            _ => {}
        }
    }

    pub async fn run_continuous(&self, mut shutdown_rx: Receiver<()>) -> Result<(), ApiError> {
        let mut processing_interval_ms = interval(Duration::from_millis(
            self.config.processing_interval_ms.unwrap_or(200),
        ));

        let mut cleanup_interval = interval(Duration::from_secs(
            self.config.cleanup_interval_secs.unwrap_or(300),
        ));
        let mut metrics_interval = interval(Duration::from_secs(
            self.config.metric_record_interval_secs.unwrap_or(30),
        ));

        // Stats logging interval (every 60 seconds)
        let mut stats_logging_interval = interval(Duration::from_secs(60));

        // Fast health check interval for epoch change detection (every 5 seconds)
        let mut fast_health_interval = interval(Duration::from_secs(5));

        // Heartbeat interval for coordinator health monitoring
        let mut heartbeat_interval = interval(Duration::from_secs(
            self.config.health_check_interval_secs.unwrap_or(10),
        ));

        info!(
            "Coordinator background task starting with {}ms processing interval and {}s heartbeat",
            self.config.processing_interval_ms.unwrap_or(200),
            self.config.health_check_interval_secs.unwrap_or(10)
        );

        self.perform_startup_enclave_health_check().await;

        loop {
            tokio::select! {
                _ = processing_interval_ms.tick() => {
                    let cycle_start = Instant::now();
                    debug!("Coordinator processing cycle starting");

                    // Monitor DB health before processing
                    if let Err(e) = self.monitor_db_pool_health().await {
                        warn!("DB pool health check failed: {}", e);
                    }

                    match self.process_sessions().await {
                        Ok(count) => {
                            let duration = cycle_start.elapsed();
                            if duration > Duration::from_secs(1) {
                                warn!("Slow coordinator processing: {} sessions in {:?}", count, duration);
                            } else if count > 0 {
                                debug!("Processed {} sessions in {:?}", count, duration);
                            } else {
                                debug!("No sessions processed this cycle (duration: {:?})", duration);
                            }
                        }
                        Err(e) => {
                            error!("Session processing cycle failed: {}", e);
                            self.metrics.record_session_error("coordinator", "processing_cycle_failed");
                            // Continue processing instead of crashing
                        }
                    }
                }
                _ = heartbeat_interval.tick() => {
                    info!("Coordinator heartbeat - task alive, DB pool healthy");
                    self.log_coordinator_stats().await;
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
                _ = stats_logging_interval.tick() => {
                    self.log_operational_stats().await;
                    self.update_prometheus_stats().await;
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

    /// Log coordinator statistics for monitoring
    async fn log_coordinator_stats(&self) {
        // Get actual database stats using existing method
        match self.db.get_stats().await {
            Ok(stats) => {
                debug!(
                    "Coordinator stats: {} active sessions, {} total sessions, {} participants, DB size: {} bytes",
                    stats.active_sessions, stats.total_sessions, stats.total_participants, stats.database_size_bytes.unwrap_or_default()
                );
            }
            Err(e) => {
                warn!("Failed to get coordinator stats: {}", e);
            }
        }

        // Log circuit breaker status
        if self.circuit_breaker.is_open() {
            warn!("Circuit breaker is OPEN - coordinator degraded");
        } else {
            debug!("Circuit breaker is CLOSED - coordinator healthy");
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

        let connection_stats = self.enclave_manager.get_connection_stats();

        for (enclave_id, health) in enclaves {
            let connection_health = connection_stats
                .get(&enclave_id)
                .map(|stats| stats.health_status)
                .unwrap_or(false);

            let overall_health = health && connection_health;

            self.metrics
                .update_enclave_health(enclave_id.as_u32(), overall_health);

            if let Some(stats) = connection_stats.get(&enclave_id) {
                if !overall_health {
                    warn!(
                        "Enclave {} health issue - enclave_health: {}, connection_health: {}, failure_rate: {:.1}%",
                        enclave_id.as_u32(), health, connection_health, stats.prometheus_metrics.failure_rate
                    );
                }
            }

            let existing_enclave = self.db.get_enclave_health(enclave_id.as_u32()).await?;
            let current_time = DbUtils::current_timestamp();

            let startup_time = if existing_enclave.is_none() && health {
                Some(current_time)
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
                // Use validate_enclave_epoch_with_kms to ensure the enclave gets its KMS keys
                // back on restart, which is required for session restoration
                let epoch_check_result = self
                    .enclave_manager
                    .validate_enclave_epoch_with_kms(
                        &enclave_id,
                        Some(&self.db),
                        Some(&self.kms_config),
                    )
                    .await;

                match epoch_check_result {
                    Ok(true) => {
                        warn!(
                            "Enclave {} restart detected during health check - restoring sessions",
                            enclave_id
                        );
                        // Force immediate cache refresh by invalidating current cache
                        if let Err(e) = self.db.invalidate_enclave_cache(enclave_id.as_u32()).await
                        {
                            warn!(
                                "Failed to invalidate cache for enclave {}: {}",
                                enclave_id, e
                            );
                        }

                        // Restore sessions for this enclave after restart detection
                        // This is critical - without restoration, completed keygen sessions
                        // will be lost and signing will fail with "Session not found"
                        info!(
                            "Restoring sessions for restarted enclave {} (via health check)",
                            enclave_id
                        );
                        match self
                            .enclave_manager
                            .restore_sessions_for_enclave(&enclave_id, &self.db)
                            .await
                        {
                            Ok(stats) => {
                                if stats.keygen_restored > 0 || stats.signing_reset > 0 {
                                    info!(
                                        "Restored sessions for enclave {} (health check): {} keygen, {} signing reset",
                                        enclave_id, stats.keygen_restored, stats.signing_reset
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to restore sessions for enclave {} (health check): {}",
                                    enclave_id, e
                                );
                            }
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
                                debug!(
                                    "Retrieved public key for enclave {} (epoch {})",
                                    enclave_id, epoch
                                );
                                (
                                    true,
                                    Some(key),
                                    attestation
                                        .map(|att| serde_json::to_string(&att).unwrap_or_default()),
                                    Some(epoch as i64),
                                    Some(key_time as i64),
                                    Some(sessions as i32),
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
            // Validate epochs with full KMS reconfiguration on restart
            match self
                .enclave_manager
                .validate_enclave_epoch_with_kms(
                    &enclave_id,
                    Some(&self.db),
                    Some(&self.kms_config),
                )
                .await
            {
                Ok(had_restart) => {
                    if had_restart {
                        info!("Fast epoch detection: Enclave {} restart detected, reconfigured with KMS", enclave_id);

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

                        // Restore sessions after enclave restart detection
                        info!("Restoring sessions for restarted enclave {}", enclave_id);
                        match self
                            .enclave_manager
                            .restore_sessions_for_enclave(&enclave_id, &self.db)
                            .await
                        {
                            Ok(stats) => {
                                if stats.keygen_restored > 0 || stats.signing_reset > 0 {
                                    info!(
                                        "Restored sessions for enclave {}: {} keygen, {} signing reset",
                                        enclave_id, stats.keygen_restored, stats.signing_reset
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to restore sessions for enclave {}: {}",
                                    enclave_id, e
                                );
                            }
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
                        Some(epoch as i64),
                        Some(key_time as i64),
                        Some(sessions as i32),
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

        info!("Updated enclave {} health after epoch change", enclave_id);
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
                                // Use validate_enclave_epoch_with_kms to ensure KMS keys are restored on restart
                                match self
                                    .enclave_manager
                                    .validate_enclave_epoch_with_kms(
                                        enclave_id,
                                        Some(&self.db),
                                        Some(&self.kms_config),
                                    )
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
                        info!(
                            "All {} enclaves are healthy and epoch-synchronized",
                            enclave_ids.len()
                        );

                        // Restore sessions to all enclaves
                        info!("Restoring sessions to enclaves after startup...");
                        for enclave_id in &enclave_ids {
                            match self
                                .enclave_manager
                                .restore_sessions_for_enclave(enclave_id, &self.db)
                                .await
                            {
                                Ok(stats) => {
                                    if stats.keygen_restored > 0 || stats.signing_reset > 0 {
                                        info!(
                                            "Restored sessions for enclave {}: {} keygen, {} signing reset",
                                            enclave_id, stats.keygen_restored, stats.signing_reset
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to restore sessions for enclave {}: {}",
                                        enclave_id, e
                                    );
                                }
                            }
                        }

                        info!("Startup complete!");
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

    async fn log_operational_stats(&self) {
        let enclave_stats = self.enclave_manager.get_connection_stats();
        for (enclave_id, stats) in enclave_stats {
            // For dynamic pools, measure load as percentage of threshold (10 requests per connection)
            let load_percent = (stats.avg_load_per_connection / 10.0) * 100.0;

            info!(
                "Connection Stats [Enclave {}]: connections={}, avg_load={:.1} ({:.1}% of threshold), healthy={}, req/min={:.1}, success={:.1}/min, fail={:.1}/min, failure_rate={:.1}%",
                enclave_id.as_u32(),
                stats.active_connections,
                stats.avg_load_per_connection,
                load_percent,
                stats.health_status,
                stats.prometheus_metrics.requests_per_minute,
                stats.prometheus_metrics.successful_requests_per_minute,
                stats.prometheus_metrics.failed_requests_per_minute,
                stats.prometheus_metrics.failure_rate
            );

            // Warn if average load exceeds threshold (connections are overloaded)
            if stats.avg_load_per_connection > 10.0 {
                warn!(
                    "Enclave {} connections overloaded: avg load {:.1} (threshold: 10)",
                    enclave_id.as_u32(),
                    stats.avg_load_per_connection
                );
            }
            if stats.prometheus_metrics.failure_rate > 10.0 {
                warn!(
                    "Enclave {} high failure rate: {:.1}%",
                    enclave_id.as_u32(),
                    stats.prometheus_metrics.failure_rate
                );
            }
        }

        match self.db.get_stats().await {
            Ok(db_stats) => {
                info!(
                    "Database Stats: total_sessions={}, active_sessions={}, total_participants={}, size={}MB",
                    db_stats.total_sessions,
                    db_stats.active_sessions,
                    db_stats.total_participants,
                    db_stats.database_size_bytes.unwrap_or_default() / (1024 * 1024)
                );
            }
            Err(e) => {
                debug!("Failed to get database stats: {}", e);
            }
        }

        info!("Operational stats logged successfully");
    }

    async fn update_prometheus_stats(&self) {
        let enclave_stats = self.enclave_manager.get_connection_stats();
        for (enclave_id, stats) in enclave_stats {
            self.metrics
                .update_enclave_connection_stats(enclave_id.as_u32(), &stats);
        }

        debug!("Prometheus connection stats updated successfully");
    }

    // ============================================================
    // Single-Signer Operations Processing
    // ============================================================

    /// Process all single-signer operations (key imports, key stores, single signing)
    async fn process_single_signer_operations(&self) -> Result<u32, ApiError> {
        let (imports_result, stores_result, signing_result) = tokio::join!(
            self.process_pending_key_imports(),
            self.process_pending_key_stores(),
            self.process_single_signing_sessions()
        );

        let imports_count = imports_result.unwrap_or_else(|e| {
            warn!("Failed to process pending key imports: {}", e);
            0
        });

        let stores_count = stores_result.unwrap_or_else(|e| {
            warn!("Failed to process pending key stores: {}", e);
            0
        });

        let signing_count = signing_result.unwrap_or_else(|e| {
            warn!("Failed to process single signing sessions: {}", e);
            0
        });

        let total = imports_count + stores_count + signing_count;
        if total > 0 {
            debug!(
                "Single-signer operations: {} imports, {} stores, {} signings",
                imports_count, stores_count, signing_count
            );
        }

        Ok(total)
    }

    /// Process pending key imports - send ImportUserKeyCommand to enclaves
    async fn process_pending_key_imports(&self) -> Result<u32, ApiError> {
        let pending = self.db.get_processable_pending_key_imports(20).await?;
        if pending.is_empty() {
            return Ok(0);
        }

        debug!("Processing {} pending key imports", pending.len());
        let mut processed = 0;

        for record in pending {
            // Mark as processing
            if let Err(e) = self
                .db
                .mark_pending_key_import_processing(&record.key_id)
                .await
            {
                warn!(
                    "Failed to mark key import {} as processing: {}",
                    record.key_id, e
                );
                continue;
            }

            // Build the command
            let command = keymeld_core::protocol::EnclaveCommand::UserKey(
                keymeld_core::protocol::UserKeyCommand::ImportKey(
                    keymeld_core::protocol::ImportUserKeyCommand {
                        user_id: record.user_id.clone(),
                        key_id: record.key_id.clone(),
                        encrypted_private_key: hex::encode(&record.encrypted_private_key),
                        auth_pubkey: record.auth_pubkey.clone(),
                    },
                ),
            );

            // Send to enclave
            match self
                .enclave_manager
                .send_command_to_enclave(&record.enclave_id, command.into())
                .await
            {
                Ok(outcome) => {
                    // Check outcome type
                    match outcome.response {
                        keymeld_core::protocol::EnclaveOutcome::UserKey(
                            keymeld_core::protocol::UserKeyOutcome::KeyImported(_info),
                        ) => {
                            info!(
                                "Key {} imported successfully for user {}",
                                record.key_id, record.user_id
                            );
                            // Complete the import - moves to user_keys table
                            if let Err(e) =
                                self.db.complete_pending_key_import(&record.key_id).await
                            {
                                error!("Failed to complete key import {}: {}", record.key_id, e);
                            } else {
                                processed += 1;
                            }
                        }
                        other => {
                            let error_msg = format!("Unexpected outcome: {:?}", other);
                            warn!("Key import {} failed: {}", record.key_id, error_msg);
                            let _ = self
                                .db
                                .fail_pending_key_import(&record.key_id, &error_msg)
                                .await;
                        }
                    }
                }
                Err(e) => {
                    let error_msg = format!("Enclave error: {}", e);
                    warn!("Key import {} failed: {}", record.key_id, error_msg);
                    let _ = self
                        .db
                        .fail_pending_key_import(&record.key_id, &error_msg)
                        .await;
                }
            }
        }

        Ok(processed)
    }

    /// Process pending key stores - send StoreKeyFromKeygenCommand to enclaves
    async fn process_pending_key_stores(&self) -> Result<u32, ApiError> {
        let pending = self.db.get_processable_pending_key_stores(20).await?;
        if pending.is_empty() {
            return Ok(0);
        }

        debug!("Processing {} pending key stores", pending.len());
        let mut processed = 0;

        for record in pending {
            // Mark as processing
            if let Err(e) = self
                .db
                .mark_pending_key_store_processing(&record.key_id)
                .await
            {
                warn!(
                    "Failed to mark key store {} as processing: {}",
                    record.key_id, e
                );
                continue;
            }

            // Get the keygen participant data to retrieve auth_pubkey and enclave_key_epoch
            let participant = match self
                .db
                .get_keygen_participant(&record.keygen_session_id, &record.user_id)
                .await
            {
                Ok(Some(p)) => p,
                Ok(None) => {
                    let error_msg = "Keygen participant not found";
                    warn!("Key store {} failed: {}", record.key_id, error_msg);
                    let _ = self
                        .db
                        .fail_pending_key_store(&record.key_id, error_msg)
                        .await;
                    continue;
                }
                Err(e) => {
                    let error_msg = format!("Failed to get keygen participant: {}", e);
                    warn!("Key store {} failed: {}", record.key_id, error_msg);
                    let _ = self
                        .db
                        .fail_pending_key_store(&record.key_id, &error_msg)
                        .await;
                    continue;
                }
            };

            // Build the command
            let command = keymeld_core::protocol::EnclaveCommand::UserKey(
                keymeld_core::protocol::UserKeyCommand::StoreKeyFromKeygen(
                    keymeld_core::protocol::StoreKeyFromKeygenCommand {
                        user_id: record.user_id.clone(),
                        key_id: record.key_id.clone(),
                        keygen_session_id: record.keygen_session_id.clone(),
                    },
                ),
            );

            // Send to enclave
            match self
                .enclave_manager
                .send_command_to_enclave(&record.enclave_id, command.into())
                .await
            {
                Ok(outcome) => {
                    match outcome.response {
                        keymeld_core::protocol::EnclaveOutcome::UserKey(
                            keymeld_core::protocol::UserKeyOutcome::KeyStoredFromKeygen(result),
                        ) => {
                            info!(
                                "Key {} stored from keygen {} for user {}",
                                record.key_id, record.keygen_session_id, record.user_id
                            );
                            // Complete the store - creates user_keys entry with encrypted key from enclave
                            // auth_pubkey and enclave_key_epoch come from the keygen participant
                            let encrypted_key_bytes = hex::decode(&result.encrypted_private_key)
                                .unwrap_or_else(|_| {
                                    result.encrypted_private_key.as_bytes().to_vec()
                                });
                            if let Err(e) = self
                                .db
                                .complete_pending_key_store(
                                    &record.key_id,
                                    &encrypted_key_bytes,
                                    &participant.auth_pubkey,
                                    participant.enclave_key_epoch,
                                )
                                .await
                            {
                                error!("Failed to complete key store {}: {}", record.key_id, e);
                            } else {
                                processed += 1;
                            }
                        }
                        other => {
                            let error_msg = format!("Unexpected outcome: {:?}", other);
                            warn!("Key store {} failed: {}", record.key_id, error_msg);
                            let _ = self
                                .db
                                .fail_pending_key_store(&record.key_id, &error_msg)
                                .await;
                        }
                    }
                }
                Err(e) => {
                    let error_msg = format!("Enclave error: {}", e);
                    warn!("Key store {} failed: {}", record.key_id, error_msg);
                    let _ = self
                        .db
                        .fail_pending_key_store(&record.key_id, &error_msg)
                        .await;
                }
            }
        }

        Ok(processed)
    }

    /// Process single signing sessions - send SignSingleCommand to enclaves
    async fn process_single_signing_sessions(&self) -> Result<u32, ApiError> {
        let pending = self.db.get_processable_single_signing_sessions(20).await?;
        if pending.is_empty() {
            return Ok(0);
        }

        debug!("Processing {} single signing sessions", pending.len());
        let mut processed = 0;

        for record in pending {
            // Mark as processing
            if let Err(e) = self
                .db
                .mark_single_signing_processing(&record.signing_session_id)
                .await
            {
                warn!(
                    "Failed to mark single signing {} as processing: {}",
                    record.signing_session_id, e
                );
                continue;
            }

            // Get the encrypted message and session secret
            let encrypted_message = match &record.encrypted_message {
                Some(msg) => hex::encode(msg),
                None => {
                    let _ = self
                        .db
                        .update_single_signing_result(
                            &record.signing_session_id,
                            None,
                            Some("Missing encrypted message"),
                        )
                        .await;
                    continue;
                }
            };

            let encrypted_session_secret = match &record.encrypted_session_secret {
                Some(secret) => hex::encode(secret),
                None => {
                    let _ = self
                        .db
                        .update_single_signing_result(
                            &record.signing_session_id,
                            None,
                            Some("Missing encrypted session secret"),
                        )
                        .await;
                    continue;
                }
            };

            // Parse signature type
            let signature_type: keymeld_core::protocol::SignatureType =
                match record.signature_type.parse() {
                    Ok(st) => st,
                    Err(e) => {
                        let _ = self
                            .db
                            .update_single_signing_result(
                                &record.signing_session_id,
                                None,
                                Some(&format!("Invalid signature type: {}", e)),
                            )
                            .await;
                        continue;
                    }
                };

            // Build the command with approval signature from DB
            let command = keymeld_core::protocol::EnclaveCommand::UserKey(
                keymeld_core::protocol::UserKeyCommand::SignSingle(
                    keymeld_core::protocol::SignSingleCommand {
                        user_id: record.user_id.clone(),
                        key_id: record.key_id.clone(),
                        encrypted_message,
                        signature_type,
                        encrypted_session_secret,
                        approval_signature: record.approval_signature.clone(),
                        approval_timestamp: record.approval_timestamp as u64,
                    },
                ),
            );

            // Send to enclave
            match self
                .enclave_manager
                .send_command_to_enclave(&record.enclave_id, command.into())
                .await
            {
                Ok(outcome) => match outcome.response {
                    keymeld_core::protocol::EnclaveOutcome::UserKey(
                        keymeld_core::protocol::UserKeyOutcome::SingleSignature(result),
                    ) => {
                        info!(
                            "Single signing {} completed for user {}",
                            record.signing_session_id, record.user_id
                        );
                        if let Err(e) = self
                            .db
                            .update_single_signing_result(
                                &record.signing_session_id,
                                Some(&result.encrypted_signature),
                                None,
                            )
                            .await
                        {
                            error!(
                                "Failed to update signing result {}: {}",
                                record.signing_session_id, e
                            );
                        } else {
                            processed += 1;
                        }
                    }
                    other => {
                        let error_msg = format!("Unexpected outcome: {:?}", other);
                        warn!(
                            "Single signing {} failed: {}",
                            record.signing_session_id, error_msg
                        );
                        let _ = self
                            .db
                            .update_single_signing_result(
                                &record.signing_session_id,
                                None,
                                Some(&error_msg),
                            )
                            .await;
                    }
                },
                Err(e) => {
                    let error_msg = format!("Enclave error: {}", e);
                    warn!(
                        "Single signing {} failed: {}",
                        record.signing_session_id, error_msg
                    );
                    let _ = self
                        .db
                        .update_single_signing_result(
                            &record.signing_session_id,
                            None,
                            Some(&error_msg),
                        )
                        .await;
                }
            }
        }

        Ok(processed)
    }
}
