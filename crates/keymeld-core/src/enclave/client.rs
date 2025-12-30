use crate::{identifiers::EnclaveId, resilience::TimeoutConfig, KeyMeldError};

use super::pool::VsockPool;
use super::protocol::{ConfigureCommand, EnclaveCommand, EnclaveResponse};
use std::sync::Arc;

pub struct VsockClient {
    pool: Arc<VsockPool>,
}

impl VsockClient {
    pub fn new(cid: u32, port: u32) -> Self {
        Self::with_config_and_pool_size(cid, port, &TimeoutConfig::default(), 10)
    }

    pub fn with_config(cid: u32, port: u32, timeout_config: &TimeoutConfig) -> Self {
        Self::with_config_and_pool_size(cid, port, timeout_config, 10)
    }

    pub fn with_config_and_pool_size(
        cid: u32,
        port: u32,
        timeout_config: &TimeoutConfig,
        pool_size: usize,
    ) -> Self {
        let pool = VsockPool::new(cid, port, pool_size, timeout_config)
            .expect("Failed to create VsockPool");

        Self {
            pool: Arc::new(pool),
        }
    }

    pub async fn send_command(
        &self,
        command: EnclaveCommand,
    ) -> Result<EnclaveResponse, KeyMeldError> {
        self.pool.send_command(command).await
    }

    pub async fn ping(&self) -> Result<(), KeyMeldError> {
        match self.send_command(EnclaveCommand::Ping).await? {
            EnclaveResponse::Pong => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(err.to_string())),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response to ping: {response:?}"
            ))),
        }
    }

    pub async fn configure(
        &self,
        enclave_id: EnclaveId,
        key_epoch: Option<u64>,
    ) -> Result<(), KeyMeldError> {
        let command = ConfigureCommand {
            enclave_id,
            key_epoch,
        };
        match self
            .send_command(EnclaveCommand::Configure(command))
            .await?
        {
            EnclaveResponse::Success => Ok(()),
            EnclaveResponse::Error(err) => Err(KeyMeldError::EnclaveError(err.to_string())),
            response => Err(KeyMeldError::EnclaveError(format!(
                "Unexpected response to configure: {response:?}"
            ))),
        }
    }

    pub async fn health_check(&self) -> Result<bool, KeyMeldError> {
        self.ping().await.map(|_| true).or(Ok(false))
    }
}
