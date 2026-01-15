pub mod auth;
pub mod config;
pub mod coordinator;
pub mod database;
pub mod enclave;
pub mod encrypted_data;
pub mod errors;
pub mod handlers;
pub mod headers;
pub mod kms;
pub mod metrics;
pub mod middleware;
pub mod routes;
pub mod session;
pub mod startup;
pub mod templates;

// Re-exports
pub use keymeld_core::{identifiers, AggregatePublicKey, EncryptedData, KeyMeldError};

// Gateway-specific trait for session state machines
#[async_trait::async_trait]
pub trait Advanceable<T> {
    async fn process(self, enclave_manager: &enclave::EnclaveManager) -> Result<T, KeyMeldError>;
}

// Re-export session types
pub use session::{KeygenSessionStatus, Session, SigningSessionStatus};
