use super::config::{RetryConfig, TimeoutConfig};
use super::transport::SocketConnector;
use crate::KeyMeldError;

use super::connection::ConnectionState;
use super::connection::{Request, Response};
use super::metrics::ConnectionMetrics;
use super::pool::{ConnectionStats, SocketPool};

use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::time::Duration;
use tracing::{debug, error, warn};

pub struct SocketClient<C, R>
where
    C: Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + 'static,
    R: Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + 'static,
{
    pool: Arc<SocketPool<C, R>>,
    retry_config: RetryConfig,
    commands_sent: Arc<AtomicU64>,
    commands_successful: Arc<AtomicU64>,
    commands_failed: Arc<AtomicU64>,
    shutdown_signal: Arc<AtomicBool>,
}

impl<C, R> SocketClient<C, R>
where
    C: Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + 'static,
    R: Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + 'static,
{
    /// Create a new SocketClient for vsock connections
    pub fn vsock(cid: u32, port: u32) -> Self {
        Self::with_config(
            SocketConnector::vsock(cid, port),
            &TimeoutConfig::default(),
            &RetryConfig::default(),
        )
    }

    /// Create a new SocketClient for TCP connections
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self::with_config(
            SocketConnector::tcp(host, port),
            &TimeoutConfig::default(),
            &RetryConfig::default(),
        )
    }

    pub fn with_config(
        connector: SocketConnector,
        timeout_config: &TimeoutConfig,
        retry_config: &RetryConfig,
    ) -> Self {
        let pool = SocketPool::new(connector.clone(), timeout_config)
            .expect("Failed to create SocketPool");

        let shutdown_signal = Arc::new(AtomicBool::new(false));
        let commands_sent = Arc::new(AtomicU64::new(0));
        let commands_successful = Arc::new(AtomicU64::new(0));
        let commands_failed = Arc::new(AtomicU64::new(0));

        debug!(
            "SocketClient initialized for {} (load threshold: {})",
            connector.address_string(),
            timeout_config.connection_load_threshold
        );

        Self {
            pool: Arc::new(pool),
            retry_config: retry_config.clone(),
            commands_sent: commands_sent.clone(),
            commands_successful: commands_successful.clone(),
            commands_failed: commands_failed.clone(),
            shutdown_signal: shutdown_signal.clone(),
        }
    }

    pub async fn send_command(&self, request: Request<C>) -> Result<Response<R>, KeyMeldError> {
        self.commands_sent.fetch_add(1, Ordering::AcqRel);

        for attempt in 0..self.retry_config.max_attempts {
            match self.pool.send_command(request.command.clone()).await {
                Ok(response) => {
                    self.commands_successful.fetch_add(1, Ordering::AcqRel);

                    return Ok(Response::<R>::from_with_id(request.request_id, response));
                }
                Err(e)
                    if attempt < self.retry_config.max_attempts - 1
                        && self.is_retriable_error(&e) =>
                {
                    let delay = self.retry_config.delay_for_attempt(attempt);
                    warn!(
                        "Command failed (attempt {}/{}), retrying in {:?}: {}",
                        attempt + 1,
                        self.retry_config.max_attempts,
                        delay,
                        e
                    );
                    tokio::time::sleep(delay).await;
                    // Continue to next attempt - permit still held
                }
                Err(e) => {
                    self.commands_failed.fetch_add(1, Ordering::AcqRel);

                    // Log session failure for persistent connection issues
                    if self.is_persistent_failure(&e) {
                        error!(
                            "Persistent enclave failure detected: {}. Session should be marked as failed.",
                            e
                        );

                        // Check if enclave needs health intervention
                        if self.needs_health_intervention(&e) {
                            warn!("Enclave appears to need health intervention due to: {}", e);
                        }
                    }

                    return Err(e);
                }
            }
        }

        // This should never be reached due to the loop logic above
        unreachable!("Retry loop should always return or error")
    }

    pub async fn send_raw_command(&self, command: C) -> Result<Response<R>, KeyMeldError>
    where
        C: Into<Request<C>>,
    {
        self.send_command(command.into()).await
    }

    /// Determine if an error is retriable
    fn is_retriable_error(&self, error: &KeyMeldError) -> bool {
        match error {
            KeyMeldError::EnclaveError(msg) => {
                // Retry on connection-related errors
                msg.contains("Connection")
                    || msg.contains("connection")
                    || msg.contains("Timeout")
                    || msg.contains("timeout")
                    || msg.contains("closed")
                    || msg.contains("broken")
                    || msg.contains("refused")
                    || msg.contains("unreachable")
                    || msg.contains("reset")
                    || msg.contains("aborted")
            }
            // Add other retriable error patterns as needed
            _ => false,
        }
    }

    /// Determine if an error indicates a persistent failure that should mark sessions as failed
    fn is_persistent_failure(&self, error: &KeyMeldError) -> bool {
        match error {
            KeyMeldError::EnclaveError(msg) => {
                // These errors suggest the enclave or session is in a bad state
                msg.contains("State inconsistency")
                    || msg.contains("Session not found")
                    || msg.contains("Invalid session state")
                    || msg.contains("Musig processor not found")
                    || msg.contains("Key aggregation context")
                    || msg.contains("Session secret not initialized")
                    || (msg.contains("Broken pipe") && msg.contains("after retries"))
                    || msg.contains("Enclave appears unresponsive")
            }
            _ => false,
        }
    }

    /// Determine if an error indicates the enclave needs health intervention
    fn needs_health_intervention(&self, error: &KeyMeldError) -> bool {
        match error {
            KeyMeldError::EnclaveError(msg) => {
                // These errors suggest the enclave process itself is problematic
                msg.contains("Broken pipe")
                    || msg.contains("Connection refused")
                    || msg.contains("No route to host")
                    || msg.contains("Network is unreachable")
                    || (msg.contains("Timeout") && msg.contains("consecutive"))
            }
            _ => false,
        }
    }

    pub async fn check_connection_health<H>(&self) -> Result<Duration, KeyMeldError>
    where
        H: super::pool::HealthCheckable<Command = C, Response = R>,
        C: Into<super::connection::Request<C>>,
    {
        let start = Instant::now();
        match self.pool.health_check_with::<H>().await {
            Ok(_) => Ok(start.elapsed()),
            Err(e) => {
                warn!("Connection health check failed: {}", e);
                Err(e)
            }
        }
    }

    pub fn get_retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    pub fn get_client_metrics(&self) -> ClientMetrics {
        let total_sent = self.commands_sent.load(Ordering::Acquire);
        let successful = self.commands_successful.load(Ordering::Acquire);
        let failed = self.commands_failed.load(Ordering::Acquire);

        let success_rate = if total_sent > 0 {
            (successful as f64 / total_sent as f64) * 100.0
        } else {
            0.0
        };

        ClientMetrics {
            commands_sent: total_sent,
            commands_successful: successful,
            commands_failed: failed,
            success_rate_percent: success_rate,
            connection_state: self.get_connection_state(),
            metrics: self.get_metrics(),
        }
    }

    /// Get connection statistics for monitoring
    pub fn get_connection_stats(&self) -> ConnectionStats {
        self.pool.get_connection_stats()
    }

    /// Get enhanced metrics from the connection system
    pub fn get_metrics(&self) -> ConnectionMetrics {
        let stats = self.pool.get_connection_stats();
        stats.prometheus_metrics
    }

    /// Check if the client connection is healthy based on metrics
    pub fn is_healthy(&self) -> bool {
        let stats = self.pool.get_connection_stats();
        stats.health_status && stats.prometheus_metrics.is_healthy()
    }

    /// Get detailed pool health information
    pub fn get_pool_health(&self) -> super::pool::PoolHealth {
        self.pool.get_pool_health()
    }

    /// Check if the connection pool is saturated (near limit)
    pub fn is_pool_saturated(&self) -> bool {
        self.pool.is_saturated()
    }

    /// Check if the client is in a failed state that requires intervention
    pub fn requires_intervention(&self) -> bool {
        let metrics = self.get_client_metrics();

        // High failure rate indicates persistent issues
        let high_failure_rate = metrics.success_rate_percent < 50.0 && metrics.commands_sent > 10;

        // Pool health issues
        let pool_unhealthy = !self.is_healthy();

        high_failure_rate || pool_unhealthy
    }

    /// Cleanup unhealthy connections and return count removed
    pub async fn cleanup_unhealthy_connections(&self) -> usize {
        self.pool.cleanup_unhealthy_connections().await
    }

    pub async fn comprehensive_health_check<H>(
        &self,
    ) -> Result<super::pool::PoolHealth, KeyMeldError>
    where
        H: super::pool::HealthCheckable<Command = C, Response = R>,
        C: Into<super::connection::Request<C>>,
    {
        let cleaned_up = self.cleanup_unhealthy_connections().await;
        if cleaned_up > 0 {
            debug!(
                "Cleaned up {} unhealthy connections during health check",
                cleaned_up
            );
        }

        self.pool.health_check_with::<H>().await?;

        Ok(self.get_pool_health())
    }

    /// Check if the pool is saturated (all connections are being used)
    pub fn is_saturated(&self) -> bool {
        self.pool.is_saturated()
    }

    pub async fn health_check<H>(&self) -> Result<bool, KeyMeldError>
    where
        H: super::pool::HealthCheckable<Command = C, Response = R>,
        C: Into<super::connection::Request<C>>,
    {
        self.pool
            .health_check_with::<H>()
            .await
            .map(|_| true)
            .or(Ok(false))
    }

    pub fn shutdown(&self) {
        self.shutdown_signal.store(true, Ordering::Release);
    }

    pub fn get_connection_state(&self) -> ConnectionState {
        let metrics = self.get_metrics();
        if !self.is_healthy() {
            ConnectionState::Failed
        } else if metrics.requests_in_current_window > 0 {
            ConnectionState::Active
        } else {
            ConnectionState::Idle
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientMetrics {
    pub commands_sent: u64,
    pub commands_successful: u64,
    pub commands_failed: u64,
    pub success_rate_percent: f64,
    pub connection_state: ConnectionState,
    pub metrics: ConnectionMetrics,
}

impl ClientMetrics {
    pub fn is_performing_well(&self) -> bool {
        self.success_rate_percent > 95.0 && self.metrics.failure_rate < 5.0
    }

    pub fn status_summary(&self) -> String {
        format!(
            "State: {:?}, Success: {:.1}%, RPM: {:.1}, Failure Rate: {:.1}%",
            self.connection_state,
            self.success_rate_percent,
            self.metrics.requests_per_minute,
            self.metrics.failure_rate,
        )
    }
}

impl<C, R> Drop for SocketClient<C, R>
where
    C: Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + 'static,
    R: Clone
        + Send
        + Sync
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug
        + 'static,
{
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use crate::managed_socket::pool::HealthCheckable;

    use super::*;
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    enum TestCommand {
        Ping,
        Echo(String),
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    enum TestResponse {
        Pong,
        Echo(String),
        Error(String),
    }

    // Health checkable implementation for tests
    #[allow(dead_code)]
    struct TestHealthCheck;

    impl HealthCheckable for TestHealthCheck {
        type Command = TestCommand;
        type Response = TestResponse;

        fn ping_command() -> Self::Command {
            TestCommand::Ping
        }

        fn is_pong_response(response: &Self::Response) -> bool {
            matches!(response, TestResponse::Pong)
        }
    }

    type TestClient = SocketClient<TestCommand, TestResponse>;

    fn init_test() {
        let _ = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_retry_config_integration() {
        init_test();
        let retry_config = RetryConfig {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 1000,
            backoff_multiplier: 2.0,
        };

        let client: TestClient = SocketClient::with_config(
            SocketConnector::vsock(1, 5000),
            &TimeoutConfig::default(),
            &retry_config,
        );

        assert_eq!(client.get_retry_config().max_attempts, 3);
        assert_eq!(client.get_retry_config().initial_delay_ms, 100);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_is_retriable_error() {
        init_test();
        let client: TestClient = SocketClient::vsock(1, 5000);

        // Connection-related errors should be retriable
        assert!(
            client.is_retriable_error(&KeyMeldError::EnclaveError("Connection failed".to_string()))
        );
        assert!(client.is_retriable_error(&KeyMeldError::EnclaveError(
            "Timeout connecting".to_string()
        )));
        assert!(
            client.is_retriable_error(&KeyMeldError::EnclaveError("Connection closed".to_string()))
        );
        assert!(client.is_retriable_error(&KeyMeldError::EnclaveError(
            "Connection refused".to_string()
        )));

        // Other errors should not be retriable
        assert!(
            !client.is_retriable_error(&KeyMeldError::EnclaveError("Invalid command".to_string()))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_metrics() {
        init_test();
        let client: TestClient = SocketClient::vsock(1, 5000);
        let metrics = client.get_client_metrics();

        assert_eq!(metrics.commands_sent, 0);
        assert_eq!(metrics.commands_successful, 0);
        assert_eq!(metrics.commands_failed, 0);
        assert_eq!(metrics.success_rate_percent, 0.0);
        assert_eq!(metrics.connection_state, ConnectionState::Idle);
        assert_eq!(metrics.metrics.requests_per_minute, 0.0);
    }

    #[tokio::test]
    async fn test_retry_delay_calculation() {
        let retry_config = RetryConfig {
            max_attempts: 5,
            initial_delay_ms: 100,
            max_delay_ms: 2000,
            backoff_multiplier: 2.0,
        };

        // Test exponential backoff
        assert_eq!(
            retry_config.delay_for_attempt(0),
            Duration::from_millis(100)
        );
        assert_eq!(
            retry_config.delay_for_attempt(1),
            Duration::from_millis(200)
        );
        assert_eq!(
            retry_config.delay_for_attempt(2),
            Duration::from_millis(400)
        );
        assert_eq!(
            retry_config.delay_for_attempt(3),
            Duration::from_millis(800)
        );
        assert_eq!(
            retry_config.delay_for_attempt(4),
            Duration::from_millis(1600)
        );

        // Should cap at max_delay_ms
        assert_eq!(
            retry_config.delay_for_attempt(10),
            Duration::from_millis(2000)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_client_metrics_performance_check() {
        init_test();
        let client: TestClient = SocketClient::vsock(1, 5000);
        let metrics = client.get_client_metrics();

        // Initial metrics should not indicate good performance (no data)
        assert!(!metrics.is_performing_well());

        // Status summary should include all key metrics
        let summary = metrics.status_summary();
        assert!(summary.contains("State:"));
        assert!(summary.contains("Success:"));
        assert!(summary.contains("RPM:"));
        assert!(summary.contains("Failure Rate:"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_pool_health_methods() {
        init_test();
        let client: TestClient = SocketClient::vsock(1, 5000);

        // Pool should start as healthy
        assert!(client.is_healthy());

        // Should not be saturated initially
        assert!(!client.is_pool_saturated());

        // Pool health should be available
        let pool_health = client.get_pool_health();
        assert_eq!(pool_health.active_connections, 0);
        assert!(pool_health.is_healthy);
    }
}
