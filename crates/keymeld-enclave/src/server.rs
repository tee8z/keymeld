use crate::{create_enclave_operator, init_enclave_logging, operator::EnclaveOperator};
use anyhow::{anyhow, Result};
use keymeld_core::{
    enclave::{EnclaveCommand, EnclaveError, EnclaveResponse, ErrorResponse},
    resilience::TimeoutConfig,
    EnclaveId,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{io::ErrorKind, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
    time::{sleep, timeout},
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};
use tracing::{debug, error, info, warn};

const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
const HEADER_SIZE: usize = 4;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u32,
    pub max_connections: usize,
    pub use_tcp_fallback: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 5000,
            max_connections: 50,
            use_tcp_fallback: std::env::var("TEST_MODE").unwrap_or_default() == "true",
        }
    }
}

pub async fn run_vsock_server(port: u32, enclave_id: u32) -> Result<()> {
    run_vsock_server_with_config(port, enclave_id, TimeoutConfig::default()).await
}

pub async fn run_vsock_server_with_config(
    port: u32,
    enclave_id: u32,
    timeout_config: TimeoutConfig,
) -> Result<()> {
    init_enclave_logging();

    let enclave_id = EnclaveId::new(enclave_id);
    info!("Starting KeyMeld Enclave (ID: {})", enclave_id);

    let use_tcp_fallback = std::env::var("TEST_MODE").unwrap_or_default() == "true";

    if use_tcp_fallback {
        info!("Enclave will use TCP fallback (Development Mode)");
    } else {
        info!("Enclave will use VSock");
    }

    let state = create_enclave_operator(enclave_id)?;

    let config = ServerConfig {
        port,
        use_tcp_fallback,
        ..Default::default()
    };

    let server = SimpleVsockServer::new(config, state, timeout_config).await?;
    info!("KeyMeld Enclave server starting...");

    server.start().await
}

pub struct SimpleVsockServer {
    config: ServerConfig,
    operator: Arc<EnclaveOperator>,
    active_connections: Arc<RwLock<u32>>,
    shutdown_signal: Arc<RwLock<bool>>,
    timeout_config: TimeoutConfig,
}

impl SimpleVsockServer {
    pub async fn new(
        config: ServerConfig,
        operator: EnclaveOperator,
        timeout_config: TimeoutConfig,
    ) -> Result<Self> {
        Ok(Self {
            config,
            operator: Arc::new(operator),
            active_connections: Arc::new(RwLock::new(0)),
            shutdown_signal: Arc::new(RwLock::new(false)),
            timeout_config,
        })
    }

    pub async fn start(self) -> Result<()> {
        if self.config.use_tcp_fallback {
            info!(
                "Starting TCP Server on port {} (max connections: {}) - Development Mode",
                self.config.port, self.config.max_connections
            );
            self.start_tcp_server().await
        } else {
            info!(
                "Starting VSock Server on port {} (max connections: {})",
                self.config.port, self.config.max_connections
            );
            self.start_vsock_server().await
        }
    }

    async fn start_vsock_server(&self) -> Result<()> {
        let addr = VsockAddr::new(VMADDR_CID_ANY, self.config.port);
        let mut listener = VsockListener::bind(addr)
            .map_err(|e| anyhow!("Failed to bind VSock listener: {}", e))?;

        info!(
            "VSock server listening on CID ANY, port {}",
            self.config.port
        );

        loop {
            if *self.shutdown_signal.read().await {
                info!("VSock server shutting down");
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    let current_connections = *self.active_connections.read().await;
                    if current_connections >= self.config.max_connections as u32 {
                        warn!(
                            "Connection limit reached, rejecting connection from {:?}",
                            addr
                        );
                        continue;
                    }

                    let handler = VsockConnectionHandler::new(
                        stream,
                        self.operator.clone(),
                        self.active_connections.clone(),
                        &self.timeout_config,
                    );

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle().await {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept VSock connection: {}", e);
                    sleep(self.timeout_config.connection_retry_delay()).await;
                }
            }
        }

        Ok(())
    }

    async fn start_tcp_server(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| anyhow!("Failed to bind TCP listener on {}: {}", addr, e))?;

        info!("TCP server listening on {}", addr);

        loop {
            if *self.shutdown_signal.read().await {
                info!("TCP server shutting down");
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    let current_connections = *self.active_connections.read().await;
                    if current_connections >= self.config.max_connections as u32 {
                        warn!(
                            "Connection limit reached, rejecting connection from {:?}",
                            addr
                        );
                        continue;
                    }

                    let handler = TcpConnectionHandler::new(
                        stream,
                        self.operator.clone(),
                        self.active_connections.clone(),
                        &self.timeout_config,
                    );

                    tokio::spawn(async move {
                        if let Err(e) = handler.handle().await {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                    sleep(self.timeout_config.connection_retry_delay()).await;
                }
            }
        }

        Ok(())
    }

    pub async fn shutdown(&self) {
        info!("Shutting down server...");
        let mut signal = self.shutdown_signal.write().await;
        *signal = true;
    }

    pub async fn get_stats(&self) -> ServerStats {
        ServerStats {
            active_connections: *self.active_connections.read().await,
            max_connections: self.config.max_connections as u32,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub active_connections: u32,
    pub max_connections: u32,
}

struct VsockConnectionHandler {
    stream: VsockStream,
    operator: Arc<EnclaveOperator>,
    active_connections: Arc<RwLock<u32>>,
    timeout_config: TimeoutConfig,
}

struct TcpConnectionHandler {
    stream: TcpStream,
    operator: Arc<EnclaveOperator>,
    active_connections: Arc<RwLock<u32>>,
    timeout_config: TimeoutConfig,
}

impl VsockConnectionHandler {
    fn new(
        stream: VsockStream,
        operator: Arc<EnclaveOperator>,
        active_connections: Arc<RwLock<u32>>,
        timeout_config: &TimeoutConfig,
    ) -> Self {
        Self {
            stream,
            operator,
            active_connections,
            timeout_config: timeout_config.clone(),
        }
    }

    async fn handle(mut self) -> Result<()> {
        {
            let mut connections = self.active_connections.write().await;
            *connections += 1;
        }

        let result = self.handle_connection().await;

        {
            let mut connections = self.active_connections.write().await;
            *connections -= 1;
        }

        result
    }

    async fn handle_connection(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; HEADER_SIZE];

        loop {
            match timeout(
                self.timeout_config.network_read_timeout(),
                self.stream.read_exact(&mut buffer),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let message_len =
                        u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

                    if message_len > self.timeout_config.max_message_size_bytes {
                        return Err(anyhow!("Message too large: {} bytes", message_len));
                    }

                    let mut message_buffer = vec![0u8; message_len];
                    match timeout(
                        self.timeout_config.network_read_timeout(),
                        self.stream.read_exact(&mut message_buffer),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let command: EnclaveCommand =
                                serde_json::from_slice(&message_buffer)
                                    .map_err(|e| anyhow!("Failed to deserialize command: {}", e))?;

                            let response = self.process_command(command).await;
                            self.send_response(response).await?;
                        }
                        Ok(Err(e)) => return Err(anyhow!("Failed to read message body: {}", e)),
                        Err(_) => return Err(anyhow!("Timeout reading message body")),
                    }
                }
                Ok(Err(e)) => {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        return Ok(());
                    }
                    return Err(anyhow!("Failed to read message header: {}", e));
                }
                Err(_) => return Err(anyhow!("Timeout reading message header")),
            }
        }
    }

    async fn send_response(&mut self, response: EnclaveResponse) -> Result<()> {
        let response_data = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;

        let length_bytes = (response_data.len() as u32).to_be_bytes();

        timeout(
            self.timeout_config.network_write_timeout(),
            self.stream.write_all(&length_bytes),
        )
        .await
        .map_err(|_| anyhow!("Timeout writing response length"))?
        .map_err(|e| anyhow!("Failed to write response length: {}", e))?;

        timeout(
            self.timeout_config.network_write_timeout(),
            self.stream.write_all(&response_data),
        )
        .await
        .map_err(|_| anyhow!("Timeout writing response data"))?
        .map_err(|e| anyhow!("Failed to write response data: {}", e))?;

        Ok(())
    }

    async fn process_command(&self, command: EnclaveCommand) -> EnclaveResponse {
        match self.operator.handle_command(command).await {
            Ok(response) => response,
            Err(e) => {
                error!("Error processing command: {}", e);
                EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::Internal(format!("Command processing failed: {}", e)),
                })
            }
        }
    }
}

impl TcpConnectionHandler {
    fn new(
        stream: TcpStream,
        operator: Arc<EnclaveOperator>,
        active_connections: Arc<RwLock<u32>>,
        timeout_config: &TimeoutConfig,
    ) -> Self {
        Self {
            stream,
            operator,
            active_connections,
            timeout_config: timeout_config.clone(),
        }
    }

    async fn handle(mut self) -> Result<()> {
        {
            let mut connections = self.active_connections.write().await;
            *connections += 1;
        }

        let result = self.handle_connection().await;

        {
            let mut connections = self.active_connections.write().await;
            *connections -= 1;
        }

        result
    }

    async fn handle_connection(&mut self) -> Result<()> {
        let mut buffer = vec![0u8; HEADER_SIZE];

        loop {
            match timeout(
                self.timeout_config.network_read_timeout(),
                self.stream.read_exact(&mut buffer),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let message_len =
                        u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

                    if message_len > self.timeout_config.max_message_size_bytes {
                        return Err(anyhow!("Message too large: {} bytes", message_len));
                    }

                    let mut message_buffer = vec![0u8; message_len];
                    match timeout(
                        self.timeout_config.network_read_timeout(),
                        self.stream.read_exact(&mut message_buffer),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            let command: EnclaveCommand =
                                serde_json::from_slice(&message_buffer)
                                    .map_err(|e| anyhow!("Failed to deserialize command: {}", e))?;

                            let response = self.process_command(command).await;
                            self.send_response(response).await?;
                        }
                        Ok(Err(e)) => return Err(anyhow!("Failed to read message body: {}", e)),
                        Err(_) => return Err(anyhow!("Timeout reading message body")),
                    }
                }
                Ok(Err(e)) => {
                    if e.kind() == ErrorKind::UnexpectedEof {
                        debug!("Connection closed by client (health check ping)");
                        return Ok(());
                    }
                    return Err(anyhow!("Failed to read message header: {}", e));
                }
                Err(_) => return Err(anyhow!("Timeout reading message header")),
            }
        }
    }

    async fn send_response(&mut self, response: EnclaveResponse) -> Result<()> {
        let response_data = serde_json::to_vec(&response)
            .map_err(|e| anyhow!("Failed to serialize response: {}", e))?;
        debug!("Serialized response, {} bytes", response_data.len());

        let length_bytes = (response_data.len() as u32).to_be_bytes();

        timeout(
            self.timeout_config.network_write_timeout(),
            self.stream.write_all(&length_bytes),
        )
        .await
        .map_err(|_| anyhow!("Timeout writing response length"))?
        .map_err(|e| anyhow!("Failed to write response length: {}", e))?;

        timeout(
            self.timeout_config.network_write_timeout(),
            self.stream.write_all(&response_data),
        )
        .await
        .map_err(|_| anyhow!("Timeout writing response data"))?
        .map_err(|e| anyhow!("Failed to write response data: {}", e))?;

        Ok(())
    }

    async fn process_command(&self, command: EnclaveCommand) -> EnclaveResponse {
        match self.operator.handle_command(command).await {
            Ok(response) => response,
            Err(e) => {
                error!("Error processing command: {}", e);
                EnclaveResponse::Error(ErrorResponse {
                    error: EnclaveError::Internal(format!("Command processing failed: {}", e)),
                })
            }
        }
    }
}
