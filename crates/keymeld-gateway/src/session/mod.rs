pub mod keygen;
pub mod signing;
pub mod types;
pub mod validation;

use std::fmt;

pub use keygen::{
    KeygenCollectingParticipants, KeygenCompleted, KeygenFailed, KeygenSessionStatus,
};
pub use keymeld_core::protocol::{KeygenStatusKind, SigningStatusKind};
use serde::{Deserialize, Serialize};
pub use signing::{
    SigningCollectingParticipants, SigningCompleted, SigningDistributingNonces, SigningFailed,
    SigningFinalizingSignature, SigningInitializingSession, SigningSessionStatus,
};
pub use types::ParticipantData;
use utoipa::ToSchema;
pub use validation::*;

use crate::{enclave::EnclaveManager, Advanceable, KeyMeldError};

#[derive(Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "detail", rename_all = "snake_case")]
pub enum Session {
    Keygen(KeygenSessionStatus),
    Signing(SigningSessionStatus),
}

impl AsRef<str> for Session {
    fn as_ref(&self) -> &str {
        match self {
            Session::Keygen(keygen) => keygen.as_ref(),
            Session::Signing(signing) => signing.as_ref(),
        }
    }
}

impl Session {
    pub fn kind(&self) -> SessionKind {
        self.into()
    }

    pub fn active_keygen_states() -> Vec<KeygenStatusKind> {
        KeygenSessionStatus::active_states()
    }

    pub fn active_signing_states() -> Vec<SigningStatusKind> {
        SigningSessionStatus::active_states()
    }
}

impl From<&Session> for SessionKind {
    fn from(value: &Session) -> Self {
        match value {
            Session::Keygen(_) => SessionKind::Keygen,
            Session::Signing(_) => SessionKind::Signing,
        }
    }
}

#[async_trait::async_trait]
impl Advanceable<Session> for Session {
    async fn process(self, enclave_manager: &EnclaveManager) -> Result<Session, KeyMeldError> {
        match self {
            Session::Keygen(keygen) => keygen.process(enclave_manager).await.map(Session::Keygen),
            Session::Signing(signing) => {
                signing.process(enclave_manager).await.map(Session::Signing)
            }
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Keygen,
    Signing,
}

impl fmt::Display for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionKind::Keygen => write!(f, "keygen"),
            SessionKind::Signing => write!(f, "signing"),
        }
    }
}
