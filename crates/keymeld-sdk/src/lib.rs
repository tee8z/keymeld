pub mod batch;
pub use batch::{BatchSigningItem, BatchSigningMode, SignatureResult};
pub mod config;
pub mod credentials;
pub mod error;
pub mod types;

#[cfg(feature = "dlctix")]
pub mod dlctix;

#[cfg(feature = "client")]
pub mod http;

#[cfg(feature = "client")]
pub(crate) mod polling;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "client")]
pub mod managers;

pub use config::{HttpConfig, PollingConfig};
pub use credentials::{AuthorizationCredentials, SessionCredentials, UserCredentials};
pub use error::{
    ApiError, CryptoError, KeyError, KeygenError, NetworkError, SdkError, SigningError,
};
pub use types::*;

pub use keymeld_core::attestation::AttestationPolicy;
pub use keymeld_core::crypto::{EncryptedData, SecureCrypto, SessionSecret};
pub use keymeld_core::hash_message;
pub use keymeld_core::request_auth;
pub use keymeld_core::validation;
pub use keymeld_core::{escrow, escrow_capabilities, escrow_protocol};

#[cfg(feature = "client")]
pub use http::HttpClient;

#[cfg(feature = "client")]
pub use client::{KeyMeldClient, KeyMeldClientBuilder};

#[cfg(feature = "client")]
pub use managers::{
    AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, HealthManager, JoinOptions,
    KeySlotReservation, KeygenManager, KeygenOptions, KeygenSession, ParticipantInvitation,
    RegisterOptions, SigningManager, SigningOptions, SigningSession, SingleSignerOps,
};

pub mod prelude {
    pub use crate::batch::{BatchSigningItem, BatchSigningMode, SignatureResult};
    pub use crate::config::{HttpConfig, PollingConfig};
    pub use crate::credentials::{AuthorizationCredentials, SessionCredentials, UserCredentials};
    pub use crate::error::SdkError;
    pub use crate::types::{
        BatchItemResult, EnclaveId, KeyId, KeygenStatusKind, SessionId, SignatureType,
        SigningBatchItem, SigningMode, SigningStatusKind, SubsetDefinition, TaprootTweak, UserId,
        UserKeyInfo,
    };
    pub use keymeld_core::attestation::AttestationPolicy;
    pub use keymeld_core::crypto::{SecureCrypto, SessionSecret};

    #[cfg(feature = "client")]
    pub use crate::client::{KeyMeldClient, KeyMeldClientBuilder};

    #[cfg(feature = "client")]
    pub use crate::http::HttpClient;

    #[cfg(feature = "client")]
    pub use crate::managers::{
        AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, HealthManager,
        JoinOptions, KeySlotReservation, KeygenManager, KeygenOptions, KeygenSession,
        ParticipantInvitation, RegisterOptions, SigningManager, SigningOptions, SigningSession,
        SingleSignerOps,
    };
}

pub mod confidential;

#[cfg(feature = "client")]
pub mod confidential_session;

pub mod confidential_scope;
