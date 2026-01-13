use crate::{
    create_enclave_operator, init_enclave_logging,
    operator::{EnclaveCommandHandler, EnclaveOperator},
};
use anyhow::{anyhow, Result};
use keymeld_core::{
    managed_socket::{create_server_handler, RequestRateTracker, SocketStream, TimeoutConfig},
    protocol::{Command, Outcome},
    EnclaveId,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_vsock::{VsockAddr, VsockListener};
use tracing::{error, info, warn};

const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

/// Transport mode for the enclave server
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportMode {
    #[default]
    Vsock,
    Tcp,
}

impl TransportMode {
    /// Parse from environment variable TRANSPORT_MODE
    /// Returns Vsock by default, Tcp if "tcp" (case-insensitive)
    pub fn from_env() -> Self {
        std::env::var("TRANSPORT_MODE")
            .map(|v| {
                if v.eq_ignore_ascii_case("tcp") {
                    TransportMode::Tcp
                } else {
                    TransportMode::Vsock
                }
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u32,
    pub max_connections: usize,
    pub transport_mode: TransportMode,
    pub tcp_host: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 5000,
            max_connections: 500,
            transport_mode: TransportMode::default(),
            tcp_host: "0.0.0.0".to_string(),
        }
    }
}

pub async fn run_until_stopped(
    port: u32,
    enclave_id: u32,
    timeout_config: TimeoutConfig,
) -> Result<()> {
    init_enclave_logging();

    let enclave_id = EnclaveId::new(enclave_id);
    info!("Starting KeyMeld Enclave (ID: {})", enclave_id);

    let state = create_enclave_operator(enclave_id)?;

    let transport_mode = TransportMode::from_env();
    let tcp_host = std::env::var("TCP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

    let config = ServerConfig {
        port,
        transport_mode,
        tcp_host,
        ..Default::default()
    };

    let server = EnclaveServer::new(config, state, timeout_config).await?;
    info!("KeyMeld Enclave server starting...");

    server.start().await
}

pub struct EnclaveServer {
    config: ServerConfig,
    operator: Arc<EnclaveOperator>,
    active_connections: Arc<AtomicU32>,
    shutdown_signal: Arc<AtomicBool>,
    timeout_config: TimeoutConfig,
}

impl EnclaveServer {
    pub async fn new(
        config: ServerConfig,
        operator: EnclaveOperator,
        timeout_config: TimeoutConfig,
    ) -> Result<Self> {
        Ok(Self {
            config,
            operator: Arc::new(operator),
            active_connections: Arc::new(AtomicU32::new(0)),
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            timeout_config,
        })
    }

    pub async fn start(self) -> Result<()> {
        match self.config.transport_mode {
            TransportMode::Vsock => self.start_vsock().await,
            TransportMode::Tcp => self.start_tcp().await,
        }
    }

    async fn start_vsock(self) -> Result<()> {
        info!(
            "Starting VSock Server on port {} (max connections: {})",
            self.config.port, self.config.max_connections
        );

        let addr = VsockAddr::new(VMADDR_CID_ANY, self.config.port);
        let listener =
            VsockListener::bind(addr).map_err(|e| anyhow!("Failed to bind VSock listener: {e}"))?;

        info!(
            "VSock server listening on CID ANY, port {} (multiplexed protocol)",
            self.config.port
        );

        let server = Arc::new(self);
        server.clone().spawn_stats_task();

        loop {
            if server.shutdown_signal.load(Ordering::Acquire) {
                info!("VSock server shutting down");
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    if !server.can_accept_connection() {
                        warn!(
                            "Connection limit reached, rejecting connection from {:?}",
                            addr
                        );
                        continue;
                    }
                    server
                        .clone()
                        .handle_connection(SocketStream::Vsock(stream));
                }
                Err(e) => {
                    error!("Failed to accept VSock connection: {}", e);
                    sleep(server.timeout_config.connection_retry_delay()).await;
                }
            }
        }

        Ok(())
    }

    async fn start_tcp(self) -> Result<()> {
        let addr = format!("{}:{}", self.config.tcp_host, self.config.port);
        info!(
            "Starting TCP Server on {} (max connections: {})",
            addr, self.config.max_connections
        );

        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| anyhow!("Failed to bind TCP listener on {}: {e}", addr))?;

        info!("TCP server listening on {} (multiplexed protocol)", addr);

        let server = Arc::new(self);
        server.clone().spawn_stats_task();

        loop {
            if server.shutdown_signal.load(Ordering::Acquire) {
                info!("TCP server shutting down");
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    if !server.can_accept_connection() {
                        warn!(
                            "Connection limit reached, rejecting connection from {:?}",
                            addr
                        );
                        continue;
                    }
                    server.clone().handle_connection(SocketStream::Tcp(stream));
                }
                Err(e) => {
                    error!("Failed to accept TCP connection: {}", e);
                    sleep(server.timeout_config.connection_retry_delay()).await;
                }
            }
        }

        Ok(())
    }

    fn can_accept_connection(&self) -> bool {
        let current = self.active_connections.load(Ordering::Acquire);
        current < self.config.max_connections as u32
    }

    fn handle_connection(self: Arc<Self>, stream: SocketStream) {
        let command_handler = Arc::new(EnclaveCommandHandler::new(self.operator.clone()));
        let handler = create_server_handler::<Command, Outcome>(
            command_handler,
            self.active_connections.clone(),
        );
        let timeout_config = self.timeout_config.clone();
        let request_rate_tracker = Arc::new(RequestRateTracker::new());

        tokio::spawn(async move {
            if let Err(e) = handler
                .handle(stream, request_rate_tracker, timeout_config)
                .await
            {
                error!("Connection handler error: {}", e);
            }
        });
    }

    fn spawn_stats_task(self: Arc<Self>) {
        let server = self.clone();
        tokio::spawn(async move {
            let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                stats_interval.tick().await;
                if server.shutdown_signal.load(Ordering::Acquire) {
                    break;
                }
                server.log_server_stats().await;
            }
        });
    }

    async fn log_server_stats(&self) {
        let stats = self.get_stats().await;
        info!(
            "Server Stats: active_connections={}/{}, utilization={:.1}%",
            stats.active_connections,
            stats.max_connections,
            (stats.active_connections as f64 / stats.max_connections as f64) * 100.0
        );

        if stats.active_connections as f64 / stats.max_connections as f64 > 0.9 {
            warn!(
                "Server approaching connection limit: {}/{}",
                stats.active_connections, stats.max_connections
            );
        }
    }

    pub async fn shutdown(&self) {
        info!("Shutting down server...");
        self.shutdown_signal.store(true, Ordering::Release);
    }

    pub async fn get_stats(&self) -> ServerStats {
        ServerStats {
            active_connections: self.active_connections.load(Ordering::Acquire),
            max_connections: self.config.max_connections as u32,
        }
    }

    pub async fn is_healthy(&self) -> bool {
        let stats = self.get_stats().await;
        let utilization = stats.active_connections as f64 / stats.max_connections as f64;
        utilization < 0.95
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub active_connections: u32,
    pub max_connections: u32,
}
