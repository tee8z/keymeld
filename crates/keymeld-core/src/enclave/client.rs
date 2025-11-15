use crate::{resilience::TimeoutConfig, KeyMeldError};

use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::error;

use super::protocol::{EnclaveCommand, EnclaveResponse};

#[derive(Debug, Clone)]
pub struct VsockClient {
    address: VsockAddr,
    timeout: Duration,
    use_tcp_fallback: bool,
    tcp_host: Option<String>,
    tcp_port: u32,
    network_write_timeout: Duration,
    network_read_timeout: Duration,
    max_message_size: usize,
}

impl VsockClient {
    pub fn new(cid: u32, port: u32) -> Self {
        Self::with_config(cid, port, &TimeoutConfig::default())
    }

    pub fn with_config(cid: u32, port: u32, timeout_config: &TimeoutConfig) -> Self {
        let use_tcp_fallback = std::env::var("TEST_MODE").unwrap_or_default() == "true";
        let tcp_host = if use_tcp_fallback {
            let env_key = format!("ENCLAVE_{}_HOST", cid);
            let hostname = std::env::var(&env_key).unwrap_or_else(|_| "localhost".to_string());
            Some(hostname)
        } else {
            None
        };

        Self {
            address: VsockAddr::new(cid, port),
            timeout: timeout_config.vsock_timeout(),
            use_tcp_fallback,
            tcp_host,
            tcp_port: port,
            network_write_timeout: timeout_config.network_write_timeout(),
            network_read_timeout: timeout_config.network_read_timeout(),
            max_message_size: timeout_config.max_message_size_bytes,
        }
    }

    pub async fn send_command(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        let result = timeout(self.timeout, self.send_command_inner(command))
            .await
            .map_err(|_| {
                error!(
                    "Command timeout to CID {}:{}",
                    self.address.cid(),
                    self.address.port()
                );
                KeyMeldError::EnclaveError("Command timeout".to_string())
            })?;

        if let Err(e) = &result {
            error!(
                "Command failed to CID {}:{}: {}",
                self.address.cid(),
                self.address.port(),
                e
            );
        }

        result
    }

    async fn send_command_inner(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        let command_data = serde_json::to_vec(&command).map_err(|e| {
            KeyMeldError::EnclaveError(format!("Failed to serialize command: {}", e))
        })?;

        if self.use_tcp_fallback {
            if let Some(ref host) = self.tcp_host {
                let tcp_addr = format!("{}:{}", host, self.tcp_port);

                let mut stream = TcpStream::connect(&tcp_addr).await.map_err(|e| {
                    error!("Failed to connect to {}: {}", tcp_addr, e);
                    KeyMeldError::EnclaveError(format!("Failed to connect to {}: {}", tcp_addr, e))
                })?;

                let command_length = u32::try_from(command_data.len())
                    .map_err(|_| KeyMeldError::EnclaveError("Command data too large".to_string()))?
                    .to_be_bytes();

                // Write command length with timeout
                match timeout(
                    self.network_write_timeout,
                    stream.write_all(&command_length),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to write command length: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Timeout writing command length to {}",
                            tcp_addr
                        )));
                    }
                }

                // Write command data with timeout
                match timeout(self.network_write_timeout, stream.write_all(&command_data)).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to write command data: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Timeout writing command data to {}",
                            tcp_addr
                        )));
                    }
                }

                // Flush the stream to ensure data is sent
                match timeout(self.network_write_timeout, stream.flush()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to flush stream: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Timeout flushing stream to {}",
                            tcp_addr
                        )));
                    }
                }

                let mut length_buffer = [0u8; 4];

                // Use longer timeout for reading response length to handle slow crypto operations
                match timeout(
                    self.network_read_timeout,
                    stream.read_exact(&mut length_buffer),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to read response length: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Timeout reading response length from {} (waited 5 minutes)",
                            tcp_addr
                        )));
                    }
                }

                let response_length = u32::from_be_bytes(length_buffer) as usize;

                if response_length > self.max_message_size {
                    return Err(KeyMeldError::EnclaveError(format!(
                        "Response too large: {} bytes",
                        response_length
                    )));
                }

                let mut response_buffer = vec![0u8; response_length];

                // Use timeout for reading response data to prevent hanging
                match timeout(
                    self.network_read_timeout,
                    stream.read_exact(&mut response_buffer),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Failed to read response data: {}",
                            e
                        )));
                    }
                    Err(_) => {
                        return Err(KeyMeldError::EnclaveError(format!(
                            "Timeout reading response data from {} (waited 5 minutes)",
                            tcp_addr
                        )));
                    }
                }

                let response: EnclaveResponse =
                    serde_json::from_slice(&response_buffer).map_err(|e| {
                        KeyMeldError::EnclaveError(format!("Failed to deserialize response: {}", e))
                    })?;

                Ok(response)
            } else {
                Err(KeyMeldError::EnclaveError(
                    "TCP fallback enabled but no host configured".to_string(),
                ))
            }
        } else {
            let mut stream = VsockStream::connect(self.address)
                .await
                .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to connect: {}", e)))?;

            let length_bytes = u32::try_from(command_data.len())
                .map_err(|_| KeyMeldError::EnclaveError("Command data too large".to_string()))?
                .to_be_bytes();
            stream.write_all(&length_bytes).await.map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to write command length: {}", e))
            })?;
            stream.write_all(&command_data).await.map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to write command data: {}", e))
            })?;

            let mut length_buffer = [0u8; 4];
            stream.read_exact(&mut length_buffer).await.map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to read response length: {}", e))
            })?;

            let response_length = u32::from_be_bytes(length_buffer) as usize;
            if response_length > self.max_message_size {
                return Err(KeyMeldError::EnclaveError(format!(
                    "Response too large: {} bytes",
                    response_length
                )));
            }

            let mut response_buffer = vec![0u8; response_length];
            stream.read_exact(&mut response_buffer).await.map_err(|e| {
                KeyMeldError::EnclaveError(format!("Failed to read response data: {}", e))
            })?;

            let response: EnclaveResponse =
                serde_json::from_slice(&response_buffer).map_err(|e| {
                    KeyMeldError::EnclaveError(format!("Failed to deserialize response: {}", e))
                })?;

            Ok(response)
        }
    }

    pub async fn ping(&self) -> Result<(), KeyMeldError> {
        match self.send_command(EnclaveCommand::Ping).await? {
            EnclaveResponse::Pong => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(err.to_string())),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response to ping: {:?}",
                response
            ))),
        }
    }

    pub async fn configure(
        &self,
        region: String,
        enclave_id: crate::identifiers::EnclaveId,
    ) -> Result<(), KeyMeldError> {
        let command = super::protocol::ConfigureCommand { region, enclave_id };
        match self
            .send_command(EnclaveCommand::Configure(command))
            .await?
        {
            EnclaveResponse::Success(_) => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(err.to_string())),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response to configure: {:?}",
                response
            ))),
        }
    }

    pub async fn health_check(&self) -> Result<bool, KeyMeldError> {
        self.ping().await.map(|_| true).or(Ok(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_vsock_client_timeout_configuration() {
        let custom_timeout_config = TimeoutConfig {
            vsock_timeout_secs: 120,
            network_write_timeout_secs: 10,
            network_read_timeout_secs: 600,
            max_message_size_bytes: 2 * 1024 * 1024,
            ..Default::default()
        };

        let client = VsockClient::with_config(3, 8000, &custom_timeout_config);

        // Verify that the client uses the configured timeouts
        assert_eq!(client.timeout, Duration::from_secs(120));
        assert_eq!(client.network_write_timeout, Duration::from_secs(10));
        assert_eq!(client.network_read_timeout, Duration::from_secs(600));
        assert_eq!(client.max_message_size, 2 * 1024 * 1024);
    }
}
