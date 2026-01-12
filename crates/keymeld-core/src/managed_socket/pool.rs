use super::config::TimeoutConfig;
use super::transport::{SocketConnector, SocketStream};
use crate::KeyMeldError;
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::connection::{create_client_with_wrapper, Client, Request};
use super::metrics::{
    ConnectionMetrics, HistogramData, RequestRateTracker, LATENCY_HISTOGRAM_BUCKETS,
};

/// Trait for command/response types that support health checking
pub trait HealthCheckable {
    type Command;
    type Response;

    /// Create a ping command for health checking
    fn ping_command() -> Self::Command;

    /// Check if a response is a valid pong response
    fn is_pong_response(response: &Self::Response) -> bool;
}

pub struct SocketPool<C, R> {
    connector: SocketConnector,
    connection_timeout: Duration,
    health_state: Arc<AtomicBool>,
    timeout_config: TimeoutConfig,
    // Multiple connections with metadata (load tracking, health, etc.)
    connections: Arc<DashMap<Uuid, Arc<ConnectionMetadata<C, R>>>>,
    // Mutex to serialize connection creation (prevents thundering herd)
    connection_creation_lock: Arc<Mutex<()>>,
    // Phantom data to hold the type parameters
    _phantom: std::marker::PhantomData<(C, R)>,
}

struct MultiplexedConnection<C, R> {
    client: Client<C, R>,
}

impl<C, R> MultiplexedConnection<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    fn new(stream: SocketStream, timeout_config: TimeoutConfig) -> Self {
        let active_connections = Arc::new(AtomicU32::new(0));
        let request_rate_tracker = Arc::new(RequestRateTracker::new());

        let (connection_handler, client) =
            create_client_with_wrapper::<C, R>(active_connections.clone(), &timeout_config);

        let timeout_config_clone = timeout_config.clone();

        tokio::spawn(async move {
            if let Err(e) = connection_handler
                .handle(stream, request_rate_tracker, timeout_config_clone)
                .await
            {
                error!("Client handler error: {}", e);
            }
        });

        Self { client }
    }

    async fn send_request(&self, request: Request<C>) -> Result<R, KeyMeldError> {
        self.client
            .send_request(request)
            .await
            .map_err(|e| KeyMeldError::EnclaveError(e.to_string()))
    }

    pub fn get_metrics(&self) -> ConnectionMetrics {
        self.client.get_metrics()
    }
}

impl<C, R> From<MultiplexedConnection<C, R>> for ConnectionMetadata<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    fn from(val: MultiplexedConnection<C, R>) -> Self {
        let id = Uuid::now_v7();
        ConnectionMetadata::new(id, Arc::new(val))
    }
}

/// Metadata wrapper for a multiplexed connection
/// Uses existing MetricsTracker for load information
struct ConnectionMetadata<C, R> {
    id: Uuid,
    connection: Arc<MultiplexedConnection<C, R>>,
    created_at: Instant,
}

/// Connection recycling configuration
/// Based on research: VSock connections benefit from recycling but use longer timeouts than TCP
const MAX_CONNECTION_LIFETIME_SECS: u64 = 3600; // 1 hour - conservative for VSock
const IDLE_TIMEOUT_SECS: u64 = 900; // 15 minutes

impl<C, R> ConnectionMetadata<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    fn new(id: Uuid, connection: Arc<MultiplexedConnection<C, R>>) -> Self {
        Self {
            id,
            connection,
            created_at: Instant::now(),
        }
    }

    /// Get current load (active requests in current window)
    fn active_count(&self) -> u32 {
        self.connection.get_metrics().requests_in_current_window
    }

    /// Calculate load score for selection (lower is better)
    /// Combines active requests, failure rate, and average latency
    fn load_score(&self) -> f64 {
        let metrics = self.connection.get_metrics();
        let base_load = metrics.requests_in_current_window as f64;

        // Penalty for high failure rate (0-100%)
        // Weight: 0.5 means 10% failure rate adds 5 points to score
        let failure_penalty = metrics.failure_rate * 0.5;

        // Penalty for high average latency
        // Calculate average latency in milliseconds from histogram
        let avg_latency_ms = if metrics.latency_histogram.total_count > 0 {
            metrics.latency_histogram.total_sum as f64
                / metrics.latency_histogram.total_count as f64
        } else {
            0.0
        };
        // Weight: 0.1 means 10ms average adds 1 point to score
        let latency_penalty = avg_latency_ms * 0.1;

        base_load + failure_penalty + latency_penalty
    }

    fn is_healthy(&self) -> bool {
        self.connection.get_metrics().is_healthy()
    }

    fn get_metrics(&self) -> ConnectionMetrics {
        self.connection.get_metrics()
    }

    /// Check if connection has exceeded maximum lifetime
    fn is_too_old(&self) -> bool {
        self.created_at.elapsed().as_secs() > MAX_CONNECTION_LIFETIME_SECS
    }

    /// Check if connection has been idle too long
    fn is_idle_too_long(&self) -> bool {
        let metrics = self.connection.get_metrics();
        // Consider idle if no active requests and connection age > idle timeout
        metrics.requests_in_current_window == 0
            && self.created_at.elapsed().as_secs() > IDLE_TIMEOUT_SECS
    }

    /// Check if connection should be recycled
    fn should_recycle(&self) -> bool {
        self.is_too_old() || self.is_idle_too_long()
    }
}

impl<C, R> SocketPool<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de> + 'static,
{
    pub fn new(
        connector: SocketConnector,
        timeout_config: &TimeoutConfig,
    ) -> Result<Self, KeyMeldError> {
        let health_state = Arc::new(AtomicBool::new(true));

        debug!("Creating SocketPool for {}", connector.address_string());

        Ok(Self {
            connector,
            connection_timeout: timeout_config.pool_acquire_timeout(),
            health_state,
            timeout_config: timeout_config.clone(),
            connections: Arc::new(DashMap::new()),
            connection_creation_lock: Arc::new(Mutex::new(())),
            _phantom: std::marker::PhantomData,
        })
    }

    pub async fn send_command(&self, command: C) -> Result<R, KeyMeldError>
    where
        C: Into<Request<C>>,
    {
        const MAX_RETRY_ATTEMPTS: usize = 3;
        const RETRY_DELAY_MS: u64 = 500;

        let request: Request<C> = command.into();
        let mut last_error = None;

        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            let metadata = match self.acquire_connection().await {
                Ok(meta) => meta,
                Err(e) => {
                    warn!(
                        "Failed to acquire connection on attempt {}/{}: {}",
                        attempt, MAX_RETRY_ATTEMPTS, e
                    );
                    last_error = Some(e);
                    if attempt < MAX_RETRY_ATTEMPTS {
                        tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS))
                            .await;
                        continue;
                    } else {
                        return Err(last_error.unwrap());
                    }
                }
            };

            debug!(
                "Sending request {} via connection {} (attempt {}/{}, load: {}, pool: {} connections)",
                request.request_id,
                metadata.id,
                attempt,
                MAX_RETRY_ATTEMPTS,
                metadata.active_count(),
                self.connections.len()
            );

            let request_id = request.request_id;
            match metadata.connection.send_request(request.clone()).await {
                Ok(response) => {
                    debug!(
                        "Request {} completed via connection {} (attempt {}, load: {})",
                        request_id,
                        metadata.id,
                        attempt,
                        metadata.active_count()
                    );
                    return Ok(response);
                }
                Err(e) => {
                    let is_retriable = self.is_retriable_connection_error(&e);
                    warn!(
                        "Connection {} failed: {}, removing from pool (had load: {}, retriable: {}, attempt: {}/{})",
                        metadata.id,
                        e,
                        metadata.active_count(),
                        is_retriable,
                        attempt,
                        MAX_RETRY_ATTEMPTS
                    );

                    // Remove the failed connection from the pool
                    self.connections.remove(&metadata.id);
                    last_error = Some(e);

                    // Only retry if it's a retriable error and we have attempts left
                    if is_retriable && attempt < MAX_RETRY_ATTEMPTS {
                        debug!(
                            "Retrying request {} (attempt {}/{})",
                            request_id,
                            attempt + 1,
                            MAX_RETRY_ATTEMPTS
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS))
                            .await;
                        continue;
                    } else {
                        // Before final failure, try health recovery if needed
                        if self.needs_health_intervention() {
                            warn!(
                                "Pool health intervention triggered for request {}",
                                request_id
                            );
                            if let Err(e) = self.health_check_and_recover().await {
                                warn!("Health recovery failed: {}", e);
                            }
                        }
                        return Err(last_error.unwrap());
                    }
                }
            }
        }

        // Should never reach here due to loop logic
        Err(last_error
            .unwrap_or_else(|| KeyMeldError::EnclaveError("Unknown connection error".to_string())))
    }

    fn needs_health_intervention(&self) -> bool {
        let stats = self.get_connection_stats();

        // No active connections but we've had activity before indicates a problem
        if stats.active_connections == 0 && stats.pending_requests_count > 0 {
            return true;
        }

        // High load with unhealthy status
        if stats.avg_load_per_connection > self.timeout_config.connection_load_threshold as f64
            && !stats.health_status
        {
            return true;
        }

        // High failure rate indicates persistent connection issues
        if stats.prometheus_metrics.failure_rate > 50.0
            && stats.prometheus_metrics.requests_in_current_window > 5
        {
            return true;
        }

        false
    }

    async fn health_check_and_recover(&self) -> Result<usize, KeyMeldError> {
        let cleaned = self.cleanup_unhealthy_connections().await;

        let stats = self.get_connection_stats();
        if stats.active_connections == 0 {
            self.health_state.store(false, Ordering::Release);
            return Ok(cleaned);
        }

        match self.create_recovery_connection().await {
            Ok(_) => {
                self.health_state.store(true, Ordering::Release);
                Ok(cleaned + 1)
            }
            Err(e) => {
                warn!("Health recovery failed: {}", e);
                self.health_state.store(false, Ordering::Release);
                Err(KeyMeldError::EnclaveError(format!(
                    "Health recovery failed: {}",
                    e
                )))
            }
        }
    }

    async fn create_recovery_connection(&self) -> Result<uuid::Uuid, KeyMeldError> {
        // Check file descriptor limits before creating new connection
        self.check_fd_limits();

        // Use existing connection creation method
        let metadata = self.create_connection().await?;
        let connection_id = metadata.id;

        Ok(connection_id)
    }

    fn is_retriable_connection_error(&self, error: &KeyMeldError) -> bool {
        match error {
            KeyMeldError::EnclaveError(msg) => {
                // Retry on connection-related errors that indicate the enclave might be recoverable
                msg.contains("Broken pipe")
                    || msg.contains("broken pipe")
                    || msg.contains("Connection reset")
                    || msg.contains("connection reset")
                    || msg.contains("Connection refused")
                    || msg.contains("connection refused")
                    || msg.contains("Connection closed")
                    || msg.contains("connection closed")
                    || msg.contains("Response channel closed")
                    || msg.contains("Failed to write message")
                    || msg.contains("Network is unreachable")
                    || msg.contains("Host is unreachable")
            }
            _ => false,
        }
    }

    /// Acquire a connection from the pool, creating a new one if needed
    ///
    /// Strategy:
    /// 1. Try to find an existing connection with load below threshold
    /// 2. If all connections are overloaded, create a new one
    /// 3. Monitor file descriptor usage and warn if approaching limits
    async fn acquire_connection(&self) -> Result<Arc<ConnectionMetadata<C, R>>, KeyMeldError> {
        // First, try to select an existing healthy connection with acceptable load
        if let Some(metadata) = self.select_available_connection() {
            debug!(
                "Reusing connection {} (load: {}, pool: {} connections)",
                metadata.id,
                metadata.active_count(),
                self.connections.len()
            );
            return Ok(metadata);
        }

        // All connections are overloaded or none exist - create a new one
        // Use a lock to prevent thundering herd when many requests arrive simultaneously
        let _lock = self.connection_creation_lock.lock().await;

        // Double-check after acquiring lock - another thread might have created one
        if let Some(metadata) = self.select_available_connection() {
            debug!(
                "Found available connection {} after lock (load: {}, pool: {} connections)",
                metadata.id,
                metadata.active_count(),
                self.connections.len()
            );
            return Ok(metadata);
        }

        // Check file descriptor limits before creating new connection
        self.check_fd_limits();

        // Create new connection
        let metadata = self.create_connection().await?;

        info!(
            "Created new connection {} (pool now has {} connections)",
            metadata.id,
            self.connections.len()
        );

        Ok(metadata)
    }

    /// Select an available connection (healthy, not recycling, and below load threshold)
    /// Returns the least-loaded connection that meets criteria, or None if all are overloaded
    fn select_available_connection(&self) -> Option<Arc<ConnectionMetadata<C, R>>> {
        let candidates: Vec<Arc<ConnectionMetadata<C, R>>> = self
            .connections
            .iter()
            .map(|entry| entry.value().clone())
            .filter(|metadata| {
                metadata.is_healthy()
                    && !metadata.should_recycle()
                    && metadata.active_count() < self.timeout_config.connection_load_threshold
            })
            .collect();

        if candidates.is_empty() {
            let total_connections = self.connections.len();
            if total_connections > 0 {
                debug!(
                    "All {} connections are at or above load threshold ({}), will create new connection",
                    total_connections, self.timeout_config.connection_load_threshold
                );
            }
            return None;
        }

        // Find connection with minimum load score (considers active requests, failure rate, and latency)
        let least_loaded = candidates.into_iter().min_by(|a, b| {
            a.load_score()
                .partial_cmp(&b.load_score())
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;

        debug!(
            "Selected connection {} with load: {}/{} (score: {:.2})",
            least_loaded.id,
            least_loaded.active_count(),
            self.timeout_config.connection_load_threshold,
            least_loaded.load_score()
        );

        Some(least_loaded)
    }

    /// Create a new socket connection
    async fn create_connection(&self) -> Result<Arc<ConnectionMetadata<C, R>>, KeyMeldError> {
        debug!(
            "Creating new connection to {} (current pool size: {})",
            self.connector.address_string(),
            self.connections.len()
        );

        // Create stream using the connector
        let stream = self.connector.connect(self.connection_timeout).await?;

        // Create multiplexed connection wrapper
        let multiplexed_conn =
            MultiplexedConnection::<C, R>::new(stream, self.timeout_config.clone());

        let conn: ConnectionMetadata<C, R> = multiplexed_conn.into();
        let metadata = Arc::new(conn);

        self.connections.insert(metadata.id, metadata.clone());

        debug!(
            "Connection {} created and added to pool (pool size: {})",
            metadata.id,
            self.connections.len()
        );

        Ok(metadata)
    }

    /// Check file descriptor limits and warn if approaching capacity
    fn check_fd_limits(&self) {
        // Try to read current and max file descriptor limits from /proc
        if let Ok(limits) = std::fs::read_to_string("/proc/self/limits") {
            for line in limits.lines() {
                if line.starts_with("Max open files") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        if let (Ok(soft), Ok(hard)) =
                            (parts[3].parse::<u64>(), parts[4].parse::<u64>())
                        {
                            // Get current open file count
                            if let Ok(fd_dir) = std::fs::read_dir("/proc/self/fd") {
                                let current_fds = fd_dir.count() as u64;
                                let usage_percent = (current_fds as f64 / soft as f64) * 100.0;

                                if usage_percent > 90.0 {
                                    error!(
                                        "CRITICAL: File descriptor usage at {:.1}% ({}/{} soft limit, {} hard limit). \
                                        Increase ulimit or system limits immediately!",
                                        usage_percent, current_fds, soft, hard
                                    );
                                } else if usage_percent > 75.0 {
                                    warn!(
                                        "High file descriptor usage: {:.1}% ({}/{} soft limit). \
                                        Consider increasing ulimit -n or system limits.",
                                        usage_percent, current_fds, soft
                                    );
                                } else if usage_percent > 50.0 {
                                    info!(
                                        "File descriptor usage: {:.1}% ({}/{} soft limit)",
                                        usage_percent, current_fds, soft
                                    );
                                }

                                return;
                            }
                        }
                    }
                }
            }
        }

        // Fallback: just log pool size if we can't read limits
        debug!(
            "Could not read file descriptor limits, pool has {} connections",
            self.connections.len()
        );
    }

    pub fn get_connection_stats(&self) -> ConnectionStats {
        let active_connections = self.connections.len();
        let mut total_pending = 0usize;
        let mut total_successful_rpm = 0.0;
        let mut total_failed_rpm = 0.0;
        let mut total_requests_in_window = 0u32;
        let mut healthy_connections = 0;

        // Initialize aggregated histogram
        let mut aggregated_histogram = HistogramData {
            buckets: LATENCY_HISTOGRAM_BUCKETS.to_vec(),
            bucket_counts: vec![0; LATENCY_HISTOGRAM_BUCKETS.len()],
            total_count: 0,
            total_sum: 0,
        };

        // Aggregate metrics from all multiplexed connections
        for conn_ref in self.connections.iter() {
            let conn_metrics = conn_ref.value().get_metrics();
            total_pending += conn_metrics.requests_in_current_window as usize;
            total_successful_rpm += conn_metrics.successful_requests_per_minute;
            total_failed_rpm += conn_metrics.failed_requests_per_minute;
            total_requests_in_window += conn_metrics.requests_in_current_window;

            if conn_metrics.is_healthy() {
                healthy_connections += 1;
            }

            // Aggregate histogram data from this connection
            for (i, &count) in conn_metrics
                .latency_histogram
                .bucket_counts
                .iter()
                .enumerate()
            {
                if i < aggregated_histogram.bucket_counts.len() {
                    aggregated_histogram.bucket_counts[i] += count;
                }
            }
            aggregated_histogram.total_count += conn_metrics.latency_histogram.total_count;
            aggregated_histogram.total_sum += conn_metrics.latency_histogram.total_sum;
        }

        // Create aggregated metrics
        let metrics = ConnectionMetrics {
            requests_per_minute: total_successful_rpm + total_failed_rpm,
            successful_requests_per_minute: total_successful_rpm,
            failed_requests_per_minute: total_failed_rpm,
            requests_in_current_window: total_requests_in_window,
            latency_histogram: aggregated_histogram,
            failure_rate: if total_successful_rpm + total_failed_rpm > 0.0 {
                (total_failed_rpm / (total_successful_rpm + total_failed_rpm)) * 100.0
            } else {
                0.0
            },
        };

        // Pool is healthy if at least 50% of connections are healthy
        let pool_healthy = if active_connections > 0 {
            (healthy_connections as f64 / active_connections as f64) >= 0.5
        } else {
            true // No connections yet, consider healthy
        };

        self.health_state.store(pool_healthy, Ordering::Release);

        let avg_load = if active_connections > 0 {
            total_requests_in_window as f64 / active_connections as f64
        } else {
            0.0
        };

        ConnectionStats {
            active_connections,
            health_status: pool_healthy,
            prometheus_metrics: metrics,
            pending_requests_count: total_pending,
            avg_load_per_connection: avg_load,
        }
    }

    /// Get detailed pool health information
    pub fn get_pool_health(&self) -> PoolHealth {
        let stats = self.get_connection_stats();

        PoolHealth {
            is_healthy: stats.health_status,
            active_connections: stats.active_connections,
            avg_load_per_connection: stats.avg_load_per_connection,
            failure_rate: stats.prometheus_metrics.failure_rate,
            requests_per_minute: stats.prometheus_metrics.requests_per_minute,
        }
    }

    /// Check if pool is under high load (average load per connection exceeds threshold)
    pub fn is_saturated(&self) -> bool {
        let health = self.get_pool_health();
        health.avg_load_per_connection > self.timeout_config.connection_load_threshold as f64
    }

    /// Remove unhealthy connections from the pool
    pub async fn cleanup_unhealthy_connections(&self) -> usize {
        let mut removed_count = 0;
        let conn_ids_to_remove: Vec<(Uuid, &str)> = self
            .connections
            .iter()
            .filter_map(|entry| {
                let metadata = entry.value();
                let metrics = metadata.get_metrics();

                // Remove if unhealthy, too old, or idle too long
                if !metrics.is_healthy() {
                    Some((*entry.key(), "unhealthy"))
                } else if metadata.is_too_old() {
                    Some((*entry.key(), "exceeded max lifetime"))
                } else if metadata.is_idle_too_long() {
                    Some((*entry.key(), "idle timeout"))
                } else {
                    None
                }
            })
            .collect();

        for (conn_id, reason) in conn_ids_to_remove {
            if self.connections.remove(&conn_id).is_some() {
                removed_count += 1;
                debug!("Removed connection {} (reason: {})", conn_id, reason);
            }
        }

        if removed_count > 0 {
            info!(
                "Cleaned up {} connections (unhealthy, aged, or idle)",
                removed_count
            );
        }

        removed_count
    }
}

impl<C, R> SocketPool<C, R>
where
    C: Clone + Send + Sync + for<'de> serde::Deserialize<'de> + serde::Serialize + 'static,
    R: Clone
        + Send
        + Sync
        + serde::Serialize
        + for<'de> serde::Deserialize<'de>
        + 'static
        + std::fmt::Debug,
{
    pub async fn health_check_with<H>(&self) -> Result<(), KeyMeldError>
    where
        H: HealthCheckable<Command = C, Response = R>,
        C: Into<Request<C>>,
    {
        // First check pool-level health
        let stats = self.get_connection_stats();
        if !stats.health_status {
            return Err(KeyMeldError::EnclaveError(format!(
                "Pool unhealthy: {} connections, avg load: {:.1}",
                stats.active_connections, stats.avg_load_per_connection
            )));
        }

        let command = H::ping_command();
        match self.send_command(command).await {
            Ok(response) if H::is_pong_response(&response) => {
                debug!(
                    "Pool health check passed (Ping/Pong) - {} connections active, avg load: {:.1}",
                    stats.active_connections, stats.avg_load_per_connection
                );
                self.health_state.store(true, Ordering::Release);
                Ok(())
            }
            Ok(response) => {
                warn!("Unexpected health check response: {response:?}");
                self.health_state.store(false, Ordering::Release);
                Err(KeyMeldError::EnclaveError(format!(
                    "Unexpected health check response: {response:?}"
                )))
            }
            Err(e) => {
                warn!(
                    "Health check failed: {} (connections: {}, avg load: {:.1})",
                    e, stats.active_connections, stats.avg_load_per_connection
                );
                self.health_state.store(false, Ordering::Release);
                Err(e)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub active_connections: usize,
    pub health_status: bool,
    pub prometheus_metrics: ConnectionMetrics,
    pub pending_requests_count: usize,
    /// Average load per connection (requests / connections)
    pub avg_load_per_connection: f64,
}

#[derive(Debug, Clone)]
pub struct PoolHealth {
    pub is_healthy: bool,
    pub active_connections: usize,
    /// Average load per connection
    pub avg_load_per_connection: f64,
    pub failure_rate: f64,
    pub requests_per_minute: f64,
}
