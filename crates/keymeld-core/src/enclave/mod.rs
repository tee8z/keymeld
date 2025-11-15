pub mod client;
pub mod distribution;
pub mod manager;
pub mod protocol;

// Re-export main types that external code needs
pub use client::VsockClient;
pub use distribution::{EnclaveAssignmentManager, SessionAssignment};
pub use manager::{EnclaveConfig, EnclaveInfo, EnclaveManager};
pub use protocol::{
    AddNonceCommand, AddPartialSignatureCommand, AddParticipantCommand,
    AggregateKeyCompleteResponse, AggregateNonceResponse, AggregatePublicKeyResponse,
    AttestationResponse, ClearSessionCommand, ConfigureCommand, EnclaveCommand, EnclaveError,
    EnclaveResponse, ErrorResponse, FinalSignatureResponse, FinalizeCommand, GenerateNonceCommand,
    GetAggregateNonceCommand, GetAggregatePublicKeyCommand, InitKeygenSessionCommand,
    InitSigningSessionCommand, NonceResponse, ParitialSignatureCommand, PublicInfoResponse,
    SessionHmacValidationResponse, ShareAggregateNonceCommand, SignatureResponse, SuccessResponse,
    ValidateKeygenParticipantHmacCommand, ValidateSessionHmacCommand,
};

#[cfg(test)]
mod tests {
    use std::ptr::addr_of;

    use super::*;

    #[test]
    fn test_vsock_client_creation() {
        let client = VsockClient::new(10, 5000);
        assert!(addr_of!(client) as usize != 0);
    }

    #[test]
    fn test_enclave_manager() {
        let configs = vec![
            EnclaveConfig {
                id: 0,
                cid: 10,
                port: 5000,
            },
            EnclaveConfig {
                id: 1,
                cid: 11,
                port: 5000,
            },
        ];

        let manager = EnclaveManager::new(configs).unwrap();
        assert_eq!(manager.list_enclaves().len(), 2);
        assert!(!manager.is_configured());
    }

    #[tokio::test]
    async fn test_command_serialization() {
        let command = EnclaveCommand::Ping;
        let serialized = serde_json::to_string(&command).unwrap();
        assert!(serialized.contains("ping"));
    }
}
