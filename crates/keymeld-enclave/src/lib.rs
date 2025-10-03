use anyhow::Result;
use keymeld_core::EnclaveId;
use std::sync::Once;
use tracing::{info, subscriber};

pub mod attestation;

pub mod operator;
pub mod server;
pub mod state;

pub use operator::EnclaveOperator;
pub use server::run_vsock_server;
pub use state::OperationState;

pub fn init_logging() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_target(true)
            .with_thread_ids(true)
            .with_level(true)
            .with_ansi(false) // VSock doesn't support ANSI colors
            .finish();

        if let Err(e) = subscriber::set_global_default(subscriber) {
            eprintln!("Failed to set global tracing subscriber: {}", e);
        }
    });
}

pub fn create_enclave_operator(enclave_id: EnclaveId) -> Result<EnclaveOperator> {
    info!("Creating enclave operator for enclave {}", enclave_id);
    EnclaveOperator::new(enclave_id)
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
        init_logging();
        init_logging();
    }
}
