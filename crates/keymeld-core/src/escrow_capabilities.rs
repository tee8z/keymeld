//! Service-owned generic engine support. Application verifier selection and
//! capabilities travel only inside the confidential, authenticated protocol.
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EscrowCapabilities {
    pub escrow: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EscrowCapabilityError {
    #[error("Unsupported capability: escrow was not compiled into this service")]
    EscrowNotCompiled,
}
impl EscrowCapabilities {
    pub const fn for_service(escrow_compiled: bool) -> Self {
        Self {
            escrow: escrow_compiled,
        }
    }
    pub fn require_escrow(self) -> Result<(), EscrowCapabilityError> {
        self.escrow
            .then_some(())
            .ok_or(EscrowCapabilityError::EscrowNotCompiled)
    }
    pub fn intersection(self, other: Self) -> Self {
        Self {
            escrow: self.escrow && other.escrow,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_metadata_cannot_enable_a_disabled_local_engine() {
        let enabled = EscrowCapabilities::for_service(true);
        let disabled = EscrowCapabilities::for_service(false);
        assert!(enabled.require_escrow().is_ok());
        assert!(disabled.require_escrow().is_err());
        assert!(enabled.intersection(disabled).require_escrow().is_err());
    }
}
