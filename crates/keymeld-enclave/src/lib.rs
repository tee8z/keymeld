use anyhow::Result;
use keymeld_core::{
    logging::{init_logging, LoggingConfig},
    EnclaveId,
};
use tracing::info;

pub mod attestation;
pub mod channel;
pub mod musig;
pub mod operations;
pub mod operator;
pub mod queue;
pub mod server;
pub mod state_dispatch;

pub use operator::EnclaveOperator;
pub use server::run_until_stopped;

pub fn init_enclave_logging() {
    let config = LoggingConfig::enclave_default();
    init_logging(&config);
}

pub fn create_enclave_operator(enclave_id: EnclaveId) -> Result<EnclaveOperator> {
    info!("Creating enclave operator for enclave {}", enclave_id);
    let mut operator = EnclaveOperator::new(enclave_id)
        .map_err(|e| anyhow::anyhow!("Failed to create enclave operator: {e}"))?;
    let development =
        std::env::var("KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES").as_deref() == Ok("true");
    let config = attestation::AttestationConfig {
        enabled: !development,
        generate_attestations: !development,
        ..Default::default()
    };
    operator.attestation_manager = Some(attestation::AttestationManager::new(config)?);
    Ok(operator)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test() {
        let _ = tracing::subscriber::set_default(tracing::subscriber::NoSubscriber::default());
    }

    #[test]
    fn test_enclave_operator_creation() {
        init_test();
        let enclave_id = EnclaveId::new(1);
        let state = EnclaveOperator::new(enclave_id).unwrap();
        assert_eq!(state.enclave_id, enclave_id);
        // Public key is empty until Configure command is called with KMS
        assert!(state.get_public_key().is_empty());
    }

    #[tokio::test]
    async fn test_enclave_status() {
        init_test();
        let enclave_id = EnclaveId::new(1);
        let state = EnclaveOperator::new(enclave_id).unwrap();

        assert_eq!(state.enclave_id, enclave_id);
        // Public key is empty until Configure command is called with KMS
        assert!(state.get_public_key().is_empty());
        assert_eq!(state.sessions.len(), 0);
    }

    #[test]
    fn test_logging_initialization() {
        init_enclave_logging();
        init_enclave_logging();
    }
}
