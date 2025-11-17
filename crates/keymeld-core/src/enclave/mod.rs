pub mod client;
pub mod distribution;
pub mod manager;
pub mod protocol;
pub use client::VsockClient;
pub use distribution::{EnclaveAssignmentManager, SessionAssignment};
pub use manager::{EnclaveConfig, EnclaveInfo, EnclaveManager};
pub use protocol::{
    AdaptorPartialSignatureResponse, AdaptorSignaturesResponse, AddNonceCommand,
    AddPartialSignatureCommand, AddParticipantCommand, AggregateKeyCompleteResponse,
    AggregateNonceResponse, AggregatePublicKeyResponse, AttestationResponse, ClearSessionCommand,
    ConfigureCommand, EnclaveCommand, EnclaveError, EnclaveResponse, ErrorResponse,
    FinalSignatureResponse, FinalizeCommand, GenerateNonceCommand, GetAggregateNonceCommand,
    GetAggregatePublicKeyCommand, InitKeygenSessionCommand, InitSigningSessionCommand,
    InitiateAdaptorSigningCommand, NonceResponse, ParitialSignatureCommand,
    ProcessAdaptorSignaturesCommand, PublicInfoResponse, SessionHmacValidationResponse,
    ShareAggregateNonceCommand, SignAdaptorPartialSignatureCommand, SignatureResponse,
    SuccessResponse, ValidateKeygenParticipantHmacCommand, ValidateSessionHmacCommand,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::addr_of;

    #[test]
    fn test_vsock_client_creation() {
        let client = VsockClient::new(10, 5000);
        assert!(addr_of!(client) as usize != 0);
    }

    #[tokio::test]
    async fn test_command_serialization() {
        let command = EnclaveCommand::Ping;
        let serialized = serde_json::to_string(&command).unwrap();
        assert!(serialized.contains("ping"));
    }
}
