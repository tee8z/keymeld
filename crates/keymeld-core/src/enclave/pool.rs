use crate::{resilience::TimeoutConfig, KeyMeldError};
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::{debug, error, warn};

use super::protocol::{EnclaveCommand, EnclaveResponse};

pub struct PooledVsockStream {
    stream: VsockStream,
    last_used: Instant,
}

impl PooledVsockStream {
    fn new(stream: VsockStream) -> Self {
        Self {
            stream,
            last_used: Instant::now(),
        }
    }

    fn update_last_used(&mut self) {
        self.last_used = Instant::now();
    }

    fn idle_duration(&self) -> Duration {
        self.last_used.elapsed()
    }

    fn get_mut(&mut self) -> &mut VsockStream {
        &mut self.stream
    }
}

pub struct VsockConnectionManager {
    address: VsockAddr,
    /// Minimum idle time before health check is performed (default: 5 seconds)
    health_check_idle_threshold: Duration,
    /// Timeout for Ping/Pong health check (default: 1 second)
    health_check_timeout: Duration,
}

impl VsockConnectionManager {
    pub fn new(cid: u32, port: u32) -> Self {
        Self {
            address: VsockAddr::new(cid, port),
            health_check_idle_threshold: Duration::from_secs(5),
            health_check_timeout: Duration::from_secs(1),
        }
    }

    async fn health_check(&self, stream: &mut VsockStream) -> Result<(), KeyMeldError> {
        // Send Ping command
        let ping_command = EnclaveCommand::Ping;
        let command_data = serde_json::to_vec(&ping_command)
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to serialize Ping: {e}")))?;

        let length_bytes = u32::try_from(command_data.len())
            .map_err(|_| KeyMeldError::EnclaveError("Ping command too large".to_string()))?
            .to_be_bytes();

        // Write with timeout
        timeout(self.health_check_timeout, stream.write_all(&length_bytes))
            .await
            .map_err(|_| KeyMeldError::EnclaveError("Timeout writing Ping length".to_string()))?
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to write Ping length: {e}")))?;

        timeout(self.health_check_timeout, stream.write_all(&command_data))
            .await
            .map_err(|_| KeyMeldError::EnclaveError("Timeout writing Ping data".to_string()))?
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to write Ping data: {e}")))?;

        // Read Pong response
        let mut length_buffer = [0u8; 4];
        timeout(
            self.health_check_timeout,
            stream.read_exact(&mut length_buffer),
        )
        .await
        .map_err(|_| KeyMeldError::EnclaveError("Timeout reading Pong length".to_string()))?
        .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to read Pong length: {e}")))?;

        let response_length = u32::from_be_bytes(length_buffer) as usize;
        if response_length > 1024 {
            // Sanity check
            return Err(KeyMeldError::EnclaveError(format!(
                "Pong response too large: {response_length} bytes"
            )));
        }

        let mut response_buffer = vec![0u8; response_length];
        timeout(
            self.health_check_timeout,
            stream.read_exact(&mut response_buffer),
        )
        .await
        .map_err(|_| KeyMeldError::EnclaveError("Timeout reading Pong data".to_string()))?
        .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to read Pong data: {e}")))?;

        let response: EnclaveResponse = serde_json::from_slice(&response_buffer)
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to deserialize Pong: {e}")))?;

        match response {
            EnclaveResponse::Pong => {
                debug!("Health check passed (Ping/Pong)");
                Ok(())
            }
            _ => Err(KeyMeldError::EnclaveError(
                "Expected Pong response for health check".to_string(),
            )),
        }
    }
}

impl Manager for VsockConnectionManager {
    type Type = PooledVsockStream;
    type Error = KeyMeldError;

    fn create(&self) -> impl Future<Output = Result<Self::Type, Self::Error>> + Send {
        let address = self.address;
        async move {
            debug!(
                "Creating new VSock connection to CID {}:{}",
                address.cid(),
                address.port()
            );

            let stream = VsockStream::connect(address)
                .await
                .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to connect: {e}")))?;

            Ok(PooledVsockStream::new(stream))
        }
    }

    fn recycle(
        &self,
        conn: &mut Self::Type,
        _metrics: &Metrics,
    ) -> impl Future<Output = RecycleResult<Self::Error>> + Send {
        let idle_duration = conn.idle_duration();
        let health_check_idle_threshold = self.health_check_idle_threshold;
        let should_health_check = idle_duration >= health_check_idle_threshold;

        async move {
            // Only perform health check if connection has been idle for > threshold
            if should_health_check {
                debug!(
                    "Connection idle for {:?}, performing Ping/Pong health check",
                    idle_duration
                );

                if let Err(e) = self.health_check(conn.get_mut()).await {
                    warn!("Health check failed, discarding connection: {}", e);
                    return Err(RecycleError::message(format!("Health check failed: {e}")));
                }
            } else {
                debug!(
                    "Connection idle for {:?} (< {:?}), skipping health check",
                    idle_duration, health_check_idle_threshold
                );
            }

            conn.update_last_used();
            Ok(())
        }
    }
}

pub struct VsockPool {
    pool: Pool<VsockConnectionManager>,
    timeout: Duration,
    network_write_timeout: Duration,
    network_read_timeout: Duration,
    max_message_size: usize,
}

impl VsockPool {
    pub fn new(
        cid: u32,
        port: u32,
        max_size: usize,
        timeout_config: &TimeoutConfig,
    ) -> Result<Self, KeyMeldError> {
        let manager = VsockConnectionManager::new(cid, port);

        let pool = Pool::builder(manager)
            .max_size(max_size)
            .build()
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to create pool: {e}")))?;

        Ok(Self {
            pool,
            timeout: timeout_config.vsock_timeout(),
            network_write_timeout: timeout_config.network_write_timeout(),
            network_read_timeout: timeout_config.network_read_timeout(),
            max_message_size: timeout_config.max_message_size_bytes,
        })
    }

    pub async fn send_command(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        let result = timeout(self.timeout, self.send_command_inner(command))
            .await
            .map_err(|_| {
                error!("Command timeout");
                KeyMeldError::EnclaveError("Command timeout".to_string())
            })?;

        if let Err(e) = &result {
            error!("Command failed: {}", e);
        }

        result
    }

    async fn send_command_inner(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        let mut pooled_conn = self.pool.get().await.map_err(|e| {
            KeyMeldError::EnclaveError(format!("Failed to get connection from pool: {e}"))
        })?;

        pooled_conn.update_last_used();
        let conn = pooled_conn.get_mut();

        let command_data = serde_json::to_vec(&command)
            .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to serialize command: {e}")))?;

        let length_bytes = u32::try_from(command_data.len())
            .map_err(|_| KeyMeldError::EnclaveError("Command data too large".to_string()))?
            .to_be_bytes();

        timeout(self.network_write_timeout, conn.write_all(&length_bytes))
            .await
            .map_err(|_| KeyMeldError::EnclaveError("Timeout writing command length".to_string()))?
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to write command length: {e}"))
            })?;

        timeout(self.network_write_timeout, conn.write_all(&command_data))
            .await
            .map_err(|_| KeyMeldError::EnclaveError("Timeout writing command data".to_string()))?
            .map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to write command data: {e}"))
            })?;

        let mut length_buffer = [0u8; 4];
        timeout(
            self.network_read_timeout,
            conn.read_exact(&mut length_buffer),
        )
        .await
        .map_err(|_| KeyMeldError::EnclaveError("Timeout reading response length".to_string()))?
        .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to read response length: {e}")))?;

        let response_length = u32::from_be_bytes(length_buffer) as usize;
        if response_length > self.max_message_size {
            return Err(KeyMeldError::EnclaveError(format!(
                "Response too large: {response_length} bytes"
            )));
        }

        let mut response_buffer = vec![0u8; response_length];
        timeout(
            self.network_read_timeout,
            conn.read_exact(&mut response_buffer),
        )
        .await
        .map_err(|_| KeyMeldError::EnclaveError("Timeout reading response data".to_string()))?
        .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to read response data: {e}")))?;

        let response: EnclaveResponse = serde_json::from_slice(&response_buffer).map_err(|e| {
            KeyMeldError::EnclaveError(format!("Failed to deserialize response: {e}"))
        })?;

        Ok(response)
    }
}
