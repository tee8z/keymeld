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
use tokio::time::sleep;
use tokio_vsock::{VsockAddr, VsockListener};
use tracing::{error, info, warn};

const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u32,
    pub max_connections: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 5000,
            max_connections: 500,
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

    let config = ServerConfig {
        port,
        ..Default::default()
    };

    let server = VsockServer::new(config, state, timeout_config).await?;
    info!("KeyMeld Enclave server starting...");

    server.start().await
}

pub struct VsockServer {
    config: ServerConfig,
    operator: Arc<EnclaveOperator>,
    active_connections: Arc<AtomicU32>,
    shutdown_signal: Arc<AtomicBool>,
    timeout_config: TimeoutConfig,
}

impl VsockServer {
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

        let stats_server = Arc::new(self);
        let stats_task_server = stats_server.clone();
        tokio::spawn(async move {
            let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                stats_interval.tick().await;
                if stats_task_server.shutdown_signal.load(Ordering::Acquire) {
                    break;
                }
                stats_task_server.log_server_stats().await;
            }
        });

        loop {
            if stats_server.shutdown_signal.load(Ordering::Acquire) {
                info!("VSock server shutting down");
                break;
            }

            match listener.accept().await {
                Ok((stream, addr)) => {
                    let current_connections =
                        stats_server.active_connections.load(Ordering::Acquire);
                    if current_connections >= stats_server.config.max_connections as u32 {
                        warn!(
                            "Connection limit reached, rejecting connection from {:?}",
                            addr
                        );
                        continue;
                    }

                    let command_handler =
                        Arc::new(EnclaveCommandHandler::new(stats_server.operator.clone()));

                    let handler = create_server_handler::<Command, Outcome>(
                        command_handler,
                        stats_server.active_connections.clone(),
                    );

                    let timeout_config = stats_server.timeout_config.clone();
                    let request_rate_tracker = Arc::new(RequestRateTracker::new());

                    tokio::spawn(async move {
                        if let Err(e) = handler
                            .handle(
                                SocketStream::Vsock(stream),
                                request_rate_tracker,
                                timeout_config,
                            )
                            .await
                        {
                            error!("Connection handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept VSock connection: {}", e);
                    sleep(stats_server.timeout_config.connection_retry_delay()).await;
                }
            }
        }

        Ok(())
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
        utilization < 0.95 // Server is healthy if under 95% utilization
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub active_connections: u32,
    pub max_connections: u32,
}
