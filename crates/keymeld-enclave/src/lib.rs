use anyhow::Result;
use keymeld_core::{
    logging::{init_logging, LoggingConfig},
    EnclaveId,
};
use tracing::info;

pub mod attestation;
pub mod operator;
pub mod server;
pub mod state;

pub use operator::EnclaveOperator;
pub use server::run_vsock_server;
pub use state::OperationState;

pub fn init_enclave_logging() {
    let config = LoggingConfig::enclave_default();
    init_logging(&config);
}

pub fn create_enclave_operator(enclave_id: EnclaveId) -> Result<EnclaveOperator> {
    info!("Creating enclave operator for enclave {}", enclave_id);
    EnclaveOperator::new(enclave_id)
        .map_err(|e| anyhow::anyhow!("Failed to create enclave operator: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enclave_operator_creation() {
        let enclave_id = EnclaveId::new(1);
        let state = create_enclave_operator(enclave_id).unwrap();
        assert_eq!(state.enclave_id, enclave_id);
        assert!(!state.get_public_key().is_empty());
    }

    #[tokio::test]
    async fn test_enclave_status() {
        let enclave_id = EnclaveId::new(1);
        let state = create_enclave_operator(enclave_id).unwrap();
        let (id, ready, pubkey, sessions) = state.get_status().await;

        assert_eq!(id, enclave_id);
        assert!(ready); // Always ready in dev mode
        assert!(!pubkey.is_empty());
        assert_eq!(sessions, 0);
    }

    #[test]
    fn test_logging_initialization() {
        init_enclave_logging();
        init_enclave_logging();
    }
}
