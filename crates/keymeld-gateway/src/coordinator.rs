use crate::{
    config::{CoordinatorConfig, KmsConfig},
    database::{Database, DbUtils, ProcessableSessionRecord},
    enclave::EnclaveManager,
    errors::ApiError,
    metrics::{Metrics, MetricsTimer},
    session::{Session, SessionKind, SigningSessionStatus},
    Advanceable, KeygenSessionStatus,
};
use anyhow::anyhow;
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
    completed: Sender<Result<Session, ApiError>>,
    // The writer owns the lease after enqueueing, even if the processing task
    // times out or is canceled while the database operation is still pending.
    _lease: SessionLease,
}

struct SessionLease {
    session_id: SessionId,
    processing_sessions: Arc<DashSet<SessionId>>,
}

impl SessionLease {
    fn acquire(
        session_id: SessionId,
        processing_sessions: &Arc<DashSet<SessionId>>,
    ) -> Option<Self> {
        processing_sessions
            .insert(session_id.clone())
            .then(|| Self {
                session_id,
                processing_sessions: Arc::clone(processing_sessions),
            })
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        self.processing_sessions.remove(&self.session_id);
    }
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
const SESSION_WRITE_QUEUE_CAPACITY: usize = 1024;
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

pub struct CoordinatorWriter {
    db: Arc<Database>,
    metrics: Arc<Metrics>,
    receiver: mpsc::Receiver<DbWriteRequest>,
}

impl CoordinatorWriter {
    async fn persist(&self, request: DbWriteRequest) -> Result<(), ApiError> {
        let session_id = request.session_id;
        let result = match &request.session {
            Session::Keygen(status) => {
                self.db
                    .update_keygen_session_status(&session_id, status)
                    .await
            }
            Session::Signing(status) => {
                self.db
                    .update_signing_session_status(&session_id, status)
                    .await
            }
        };
        let failure = result.as_ref().err().map(|error| {
            let kind = match &request.session {
                Session::Keygen(_) => "keygen",
                Session::Signing(_) => "signing",
            };
            error!(
                "Failed to persist {} session {}: {}",
                kind, session_id, error
            );
            self.metrics.record_session_error(kind, "db_write_failed");
            ApiError::Internal(format!(
                "Session persistence failed for {session_id}: {error}"
            ))
        });
        let _ = request.completed.send(result.map(|()| request.session));
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn run(mut self, mut shutdown: Receiver<()>) -> Result<(), ApiError> {
        info!("Session persistence task started");
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    self.receiver.close();
                    break;
                }
                request = self.receiver.recv() => {
                    let request = request.ok_or_else(|| ApiError::Internal(
                        "Session persistence queue closed unexpectedly".into()
                    ))?;
                    self.persist(request).await?;
                }
            }
        }
        // Processing has stopped. Reject new work and persist every accepted
        // transition before the application's database writer can be stopped.
        while let Some(request) = self.receiver.recv().await {
            self.persist(request).await?;
        }
        info!("Session persistence task drained");
        Ok(())
    }
}

impl Coordinator {
    pub fn new(
        db: Arc<Database>,
        enclave_manager: Arc<EnclaveManager>,
        config: Option<CoordinatorConfig>,
        kms_config: KmsConfig,
        metrics: Arc<Metrics>,
    ) -> Result<(Self, CoordinatorWriter), ApiError> {
        let config = config.unwrap_or_default();
        Self::validate_config(&config)?;

        let circuit_breaker = CircuitBreaker::new(
            config.circuit_breaker_failure_threshold.unwrap_or(5),
            Duration::from_secs(config.circuit_breaker_reset_timeout_secs.unwrap_or(60)),
        );

        let (db_write_tx, receiver) = mpsc::channel(SESSION_WRITE_QUEUE_CAPACITY);
        let writer = CoordinatorWriter {
            db: Arc::clone(&db),
            metrics: Arc::clone(&metrics),
            receiver,
        };
        Ok((
            Self {
                db,
                enclave_manager,
                config,
                kms_config,
                metrics,
                circuit_breaker,
                processing_sessions: Arc::new(DashSet::new()),
                db_write_tx,
            },
            writer,
        ))
    }

    fn validate_config(config: &CoordinatorConfig) -> Result<(), ApiError> {
        let batch_size = config.batch_size.unwrap_or(DEFAULT_BATCH_SIZE);
        if batch_size == 0 || batch_size as usize > SESSION_WRITE_QUEUE_CAPACITY {
            return Err(ApiError::Configuration(anyhow!(
                "Coordinator batch_size must be between 1 and {SESSION_WRITE_QUEUE_CAPACITY}"
            )));
        }
        for (name, duration) in [
            (
                "processing_interval_ms",
                Duration::from_millis(config.processing_interval_ms.unwrap_or(200)),
            ),
            (
                "cleanup_interval_secs",
                Duration::from_secs(config.cleanup_interval_secs.unwrap_or(300)),
            ),
            (
                "metric_record_interval_secs",
                Duration::from_secs(config.metric_record_interval_secs.unwrap_or(30)),
            ),
            (
                "health_check_interval_secs",
                Duration::from_secs(config.health_check_interval_secs.unwrap_or(10)),
            ),
        ] {
            if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
                return Err(ApiError::Configuration(anyhow!(
                    "Coordinator {name} must be positive and fit the monotonic clock"
                )));
            }
        }
        Ok(())
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
            .filter_map(|session_record| {
                if let Some(lease) = SessionLease::acquire(
                    session_record.session_id.clone(),
                    &self.processing_sessions,
                ) {
                    Some((session_record, lease))
                } else {
                    debug!(
                        "Session {} already being processed, skipping",
                        session_record.session_id
                    );
                    None
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
            .map(|(session_record, lease)| {
                let session_id = session_record.session_id.clone();
                let coordinator = self.clone();

                async move {
                    let _session_start = Instant::now();
                    debug!("Starting parallel processing for session {}", session_id);

                    let slow_threshold = Duration::from_secs(SLOW_SESSION_THRESHOLD_SECS);
                    let kind = session_record.session_kind;
                    let advancing = tokio::time::timeout(
                        session_timeout,
                        coordinator.advance_session(session_record, kind, lease),
                    );
                    tokio::pin!(advancing);
                    let completion = tokio::select! {
                        result = &mut advancing => result,
                        _ = tokio::time::sleep(slow_threshold) => {
                            warn!("Session {} is taking longer than {:?} - still processing", session_id, slow_threshold);
                            advancing.await
                        }
                    };
                    let result = match completion {
                        Ok(result) => result,
                        Err(_) => {
                            error!("Session {} ABANDONED after {:?} - possible deadlock or stuck enclave call", session_id, session_timeout);
                            Err(ApiError::Internal(format!("Session {} abandoned after {:?}", session_id, session_timeout)))
                        }
                    };

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
        lease: SessionLease,
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
        match self
            .process_and_persist(
                session_id.clone(),
                lease,
                current_session.process(&self.enclave_manager),
            )
            .await
        {
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
                Err(e)
            }
        }
    }

    async fn process_and_persist(
        &self,
        session_id: SessionId,
        lease: SessionLease,
        process: impl std::future::Future<Output = Result<Session, keymeld_core::KeyMeldError>> + Send,
    ) -> Result<Session, ApiError> {
        // Reserve writer capacity before polling any enclave work. Cancellation
        // under backpressure is safe because that work has not started yet.
        let write_permit = self
            .db_write_tx
            .reserve()
            .await
            .map_err(|_| ApiError::DatabaseUnavailable)?;
        let next_session = process.await?;
        let (completed, persisted) = tokio::sync::oneshot::channel();
        // No await between receiving a transition and transferring its lease to
        // the writer. A canceled caller cannot release a queued transition's lease.
        write_permit.send(DbWriteRequest {
            session_id,
            session: next_session,
            completed,
            _lease: lease,
        });
        persisted
            .await
            .map_err(|_| ApiError::DatabaseOutcomeUnknown)?
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
            if !matches!(
                shutdown_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ) {
                break;
            }
            tokio::select! {
                _ = &mut shutdown_rx => {
                    info!("Session coordinator received shutdown signal");
                    break;
                }
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
            }
        }

        info!("Session coordinator stopped processing");
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

    async fn supervise_persistence(
        processing: impl std::future::Future<Output = Result<(), ApiError>>,
        writer: CoordinatorWriter,
    ) -> Result<(), ApiError> {
        let (shutdown, writer_shutdown) = tokio::sync::oneshot::channel();
        let persistence = writer.run(writer_shutdown);
        tokio::pin!(processing, persistence);
        tokio::select! {
            result = &mut processing => {
                let _ = shutdown.send(());
                let drained = persistence.await;
                result.and(drained)
            }
            result = &mut persistence => {
                result.and(Err(ApiError::Internal(
                    "Session persistence stopped before processing".into()
                )))
            }
        }
    }

    pub fn start_background_task(
        self,
        writer: CoordinatorWriter,
    ) -> (JoinHandle<Result<(), ApiError>>, Sender<()>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            Self::supervise_persistence(self.run_continuous(shutdown_rx), writer).await
        });
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
                        authorization: record.authorization.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::DatabaseConfig, enclave::channel::ChannelCredentials, session::KeygenFailed,
    };
    use keymeld_core::managed_socket::{config::TimeoutConfig, SocketConnector};

    struct Fixture {
        coordinator: Coordinator,
        pool: sqlx::SqlitePool,
        receiver: Option<mpsc::Receiver<DbWriteRequest>>,
        database_task: Option<JoinHandle<anyhow::Result<()>>>,
        database_shutdown: Option<Sender<()>>,
        record: ProcessableSessionRecord,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("coordinator.sqlite");
            let (db, writer) = Database::open(&DatabaseConfig {
                path: path.to_string_lossy().into_owned(),
                ..DatabaseConfig::default()
            })
            .await
            .unwrap();
            let (shutdown, requested) = tokio::sync::oneshot::channel();
            let database_task = tokio::spawn(writer.run(requested));
            let db = Arc::new(db);
            let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
                .await
                .unwrap();
            let session_id = SessionId::new_v7();
            // A terminal fixture exercises dispatch/persistence without needing a
            // live enclave. Its unchanged state is still persisted by advance_session.
            let status = KeygenSessionStatus::Failed(KeygenFailed {
                keygen_session_id: session_id.clone(),
                coordinator_pubkey: None,
                coordinator_encrypted_private_key: None,
                session_public_key: None,
                coordinator_enclave_id: None,
                expected_participants: Vec::new(),
                registered_participants: Default::default(),
                created_at: 0,
                failed_at: 0,
                error: "fixture".into(),
                failed_due_to_enclave_restart: None,
            });
            sqlx::query("INSERT INTO keygen_sessions (keygen_session_id, status_name, created_at, expires_at, expected_participants, status, updated_at) VALUES (?, 'failed', 0, 1, '[]', ?, 0)")
                .bind(&session_id).bind(serde_json::to_string(&status).unwrap())
                .execute(&pool).await.unwrap();
            let manager = EnclaveManager::new_with_credentials(
                vec![crate::enclave::EnclaveConfig {
                    id: 1,
                    cid: 3,
                    port: 9,
                    connector: SocketConnector::tcp("127.0.0.1", 9),
                }],
                TimeoutConfig::default(),
                Arc::new(
                    ChannelCredentials::dangerous_trust_unattested_enclaves([42; 32]).unwrap(),
                ),
            )
            .unwrap();
            let (mut coordinator, _writer) = Coordinator::new(
                db,
                Arc::new(manager),
                None,
                KmsConfig::default(),
                Arc::new(Metrics),
            )
            .unwrap();
            // Keep writes queued until the test deliberately starts the real writer.
            let (sender, receiver) = mpsc::channel(1);
            coordinator.db_write_tx = sender;
            Self {
                coordinator,
                pool,
                receiver: Some(receiver),
                database_task: Some(database_task),
                database_shutdown: Some(shutdown),
                record: ProcessableSessionRecord {
                    session_id,
                    session_kind: SessionKind::Keygen,
                },
                _directory: directory,
            }
        }

        fn take_writer(&mut self) -> CoordinatorWriter {
            CoordinatorWriter {
                db: self.coordinator.db.clone(),
                metrics: self.coordinator.metrics.clone(),
                receiver: self.receiver.take().unwrap(),
            }
        }

        async fn close(mut self) {
            self.pool.close().await;
            self.database_shutdown.take().unwrap().send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(5), self.database_task.take().unwrap())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(task) = &self.database_task {
                task.abort();
            }
        }
    }

    #[tokio::test]
    async fn session_lease_blocks_duplicate_dispatch_until_persisted_even_after_cancellation() {
        let mut fixture = Fixture::new().await;
        let coordinator = fixture.coordinator.clone();
        let record = fixture.record.clone();
        let processing =
            tokio::spawn(async move { coordinator.process_batch_sessions(vec![record]).await });
        let request = tokio::time::timeout(
            Duration::from_secs(5),
            fixture.receiver.as_mut().unwrap().recv(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            !processing.is_finished(),
            "dispatch returned before the writer acknowledged persistence"
        );
        assert!(fixture
            .coordinator
            .processing_sessions
            .contains(&fixture.record.session_id));
        assert_eq!(
            fixture
                .coordinator
                .process_batch_sessions(vec![fixture.record.clone()])
                .await
                .unwrap(),
            0
        );
        assert!(
            fixture.receiver.as_mut().unwrap().try_recv().is_err(),
            "stale state was dispatched a second time"
        );

        processing.abort();
        assert!(processing.await.unwrap_err().is_cancelled());
        assert!(
            fixture
                .coordinator
                .processing_sessions
                .contains(&fixture.record.session_id),
            "canceling the caller released a queued write's lease"
        );

        let (sender, receiver) = mpsc::channel(1);
        sender
            .send(request)
            .await
            .unwrap_or_else(|_| panic!("writer receiver dropped"));
        drop(sender);
        let (shutdown, requested) = tokio::sync::oneshot::channel();
        shutdown.send(()).unwrap();
        CoordinatorWriter {
            db: fixture.coordinator.db.clone(),
            metrics: fixture.coordinator.metrics.clone(),
            receiver,
        }
        .run(requested)
        .await
        .unwrap();
        let updated_at: i64 = sqlx::query_scalar(
            "SELECT updated_at FROM keygen_sessions WHERE keygen_session_id = ?",
        )
        .bind(&fixture.record.session_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert!(
            updated_at > 0,
            "lease was released without persisting the transition"
        );
        assert!(SessionLease::acquire(
            fixture.record.session_id.clone(),
            &fixture.coordinator.processing_sessions
        )
        .is_some());
        fixture.close().await;
    }

    #[tokio::test]
    async fn cancellation_under_writer_backpressure_does_not_start_enclave_work() {
        let fixture = Fixture::new().await;
        let occupied_capacity = fixture.coordinator.db_write_tx.reserve().await.unwrap();
        let calls = Arc::new(AtomicU32::new(0));
        let calls_for_process = calls.clone();
        let lease = SessionLease::acquire(
            fixture.record.session_id.clone(),
            &fixture.coordinator.processing_sessions,
        )
        .unwrap();
        let next = fixture
            .coordinator
            .db
            .get_keygen_session_by_id(&fixture.record.session_id)
            .await
            .unwrap()
            .unwrap();
        let mut waiting = Box::pin(fixture.coordinator.process_and_persist(
            fixture.record.session_id.clone(),
            lease,
            async move {
                calls_for_process.fetch_add(1, Ordering::SeqCst);
                Ok(Session::Keygen(next))
            },
        ));
        assert!(futures::poll!(&mut waiting).is_pending());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(waiting);
        assert!(!fixture
            .coordinator
            .processing_sessions
            .contains(&fixture.record.session_id));
        drop(occupied_capacity);
        assert!(
            fixture.receiver.as_ref().unwrap().is_empty(),
            "a canceled operation queued a transition"
        );
        fixture.close().await;
    }

    #[tokio::test]
    async fn failed_and_unavailable_writes_are_reported_to_session_processing() {
        let mut fixture = Fixture::new().await;
        sqlx::query("CREATE TRIGGER reject_session_update BEFORE UPDATE ON keygen_sessions BEGIN SELECT RAISE(FAIL, 'write rejected'); END")
            .execute(&fixture.pool).await.unwrap();
        let (_shutdown, requested) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(fixture.take_writer().run(requested));
        let lease = SessionLease::acquire(
            fixture.record.session_id.clone(),
            &fixture.coordinator.processing_sessions,
        )
        .unwrap();
        let error = fixture
            .coordinator
            .advance_session(fixture.record.clone(), SessionKind::Keygen, lease)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("write rejected"), "{error}");
        assert!(writer.await.unwrap().is_err());

        let lease = SessionLease::acquire(
            fixture.record.session_id.clone(),
            &fixture.coordinator.processing_sessions,
        )
        .unwrap();
        let error = fixture
            .coordinator
            .advance_session(fixture.record.clone(), SessionKind::Keygen, lease)
            .await
            .unwrap_err();
        assert!(matches!(error, ApiError::DatabaseUnavailable), "{error}");
        assert!(!fixture
            .coordinator
            .processing_sessions
            .contains(&fixture.record.session_id));
        fixture.close().await;
    }

    #[tokio::test]
    async fn shutdown_drains_accepted_transitions_before_the_owned_task_returns() {
        let mut fixture = Fixture::new().await;
        let mut transaction = fixture.pool.begin().await.unwrap();
        sqlx::query("UPDATE keygen_sessions SET updated_at = 0")
            .execute(&mut *transaction)
            .await
            .unwrap();
        let session = fixture
            .coordinator
            .db
            .get_keygen_session_by_id(&fixture.record.session_id)
            .await
            .unwrap()
            .unwrap();
        let (completed, persisted) = tokio::sync::oneshot::channel();
        let lease = SessionLease::acquire(
            fixture.record.session_id.clone(),
            &fixture.coordinator.processing_sessions,
        )
        .unwrap();
        fixture
            .coordinator
            .db_write_tx
            .send(DbWriteRequest {
                session_id: fixture.record.session_id.clone(),
                session: Session::Keygen(session),
                completed,
                _lease: lease,
            })
            .await
            .unwrap_or_else(|_| panic!("session persistence receiver dropped"));
        let writer = fixture.take_writer();
        let (processing_stopped, stopped) = tokio::sync::oneshot::channel();
        let processing = async move {
            processing_stopped.send(()).unwrap();
            Ok(())
        };
        let running = tokio::spawn(Coordinator::supervise_persistence(processing, writer));
        // Processing has returned. An already-dequeued write may still hold
        // persistence inside its SQL call, so receiver closure is not readiness.
        tokio::time::timeout(Duration::from_secs(5), stopped)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !running.is_finished(),
            "shutdown abandoned an accepted write"
        );
        assert!(fixture
            .coordinator
            .processing_sessions
            .contains(&fixture.record.session_id));
        transaction.commit().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        persisted.await.unwrap().unwrap();
        assert!(fixture.coordinator.db_write_tx.try_reserve().is_err());
        let updated_at: i64 = sqlx::query_scalar(
            "SELECT updated_at FROM keygen_sessions WHERE keygen_session_id = ?",
        )
        .bind(&fixture.record.session_id)
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
        assert!(updated_at > 0);
        assert!(fixture.coordinator.processing_sessions.is_empty());
        fixture.close().await;
    }

    #[tokio::test]
    async fn unexpected_persistence_exit_stops_its_owned_processing_future() {
        let fixture = Fixture::new().await;
        let (sender, receiver) = mpsc::channel(1);
        drop(sender);
        let writer = CoordinatorWriter {
            db: fixture.coordinator.db.clone(),
            metrics: fixture.coordinator.metrics.clone(),
            receiver,
        };
        let (processing_owner, dropped) = tokio::sync::oneshot::channel::<()>();
        let processing = async move {
            let _owner = processing_owner;
            std::future::pending::<Result<(), ApiError>>().await
        };
        let running = tokio::spawn(Coordinator::supervise_persistence(processing, writer));
        let error = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("queue closed unexpectedly"));
        assert!(
            tokio::time::timeout(Duration::from_secs(5), dropped)
                .await
                .unwrap()
                .is_err(),
            "processing was detached after failure"
        );
        fixture.close().await;
    }

    #[test]
    fn coordinator_configuration_rejects_unbounded_batches_and_zero_timers() {
        for batch_size in [0, SESSION_WRITE_QUEUE_CAPACITY as u32 + 1, u32::MAX] {
            let config = CoordinatorConfig {
                batch_size: Some(batch_size),
                ..CoordinatorConfig::default()
            };
            assert!(Coordinator::validate_config(&config).is_err());
        }
        let invalid = [
            CoordinatorConfig {
                processing_interval_ms: Some(0),
                ..CoordinatorConfig::default()
            },
            CoordinatorConfig {
                cleanup_interval_secs: Some(0),
                ..CoordinatorConfig::default()
            },
            CoordinatorConfig {
                metric_record_interval_secs: Some(0),
                ..CoordinatorConfig::default()
            },
            CoordinatorConfig {
                health_check_interval_secs: Some(0),
                ..CoordinatorConfig::default()
            },
            CoordinatorConfig {
                cleanup_interval_secs: Some(u64::MAX),
                ..CoordinatorConfig::default()
            },
        ];
        for config in invalid {
            assert!(Coordinator::validate_config(&config).is_err());
        }
        let slow = CoordinatorConfig {
            processing_interval_ms: Some(20_000),
            ..CoordinatorConfig::default()
        };
        assert!(Coordinator::validate_config(&slow).is_ok());
        assert!(Coordinator::validate_config(&CoordinatorConfig::default()).is_ok());
    }
}
