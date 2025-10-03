use crate::KeyMeldError;

use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_vsock::{VsockAddr, VsockStream};

use super::protocol::{EnclaveCommand, EnclaveResponse};

#[derive(Debug)]
pub struct VsockClient {
    address: VsockAddr,
    timeout: Duration,
    use_tcp_fallback: bool,
    tcp_host: Option<String>,
    tcp_port: u32,
}

impl VsockClient {
    pub fn new(cid: u32, port: u32) -> Self {
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
            //TODO(@tee8z): make configurable
            timeout: Duration::from_secs(30),
            use_tcp_fallback,
            tcp_host,
            tcp_port: port,
        }
    }

    pub fn with_timeout(cid: u32, port: u32, timeout: Duration) -> Self {
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
            timeout,
            use_tcp_fallback,
            tcp_host,
            tcp_port: port,
        }
    }

    pub async fn send_command(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        timeout(self.timeout, self.send_command_inner(command))
            .await
            .map_err(|_| KeyMeldError::EnclaveError("Command timeout".to_string()))?
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
                    KeyMeldError::EnclaveError(format!("Failed to connect to {}: {}", tcp_addr, e))
                })?;

                let length_bytes = (command_data.len() as u32).to_be_bytes();
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
                if response_length > 1024 * 1024 {
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
            } else {
                Err(KeyMeldError::EnclaveError(
                    "TCP fallback enabled but no host configured".to_string(),
                ))
            }
        } else {
            let mut stream = VsockStream::connect(self.address)
                .await
                .map_err(|e| KeyMeldError::EnclaveError(format!("Failed to connect: {}", e)))?;

            let length_bytes = (command_data.len() as u32).to_be_bytes();
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
            if response_length > 1024 * 1024 {
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
