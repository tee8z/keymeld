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
pub use credentials::{SessionCredentials, UserCredentials};
pub use error::{
    ApiError, CryptoError, KeyError, KeygenError, NetworkError, SdkError, SigningError,
};
pub use types::*;

pub use keymeld_core::crypto::{EncryptedData, SecureCrypto, SessionSecret};
pub use keymeld_core::hash_message;
pub use keymeld_core::validation;

#[cfg(feature = "client")]
pub use http::HttpClient;

#[cfg(feature = "client")]
pub use client::{KeyMeldClient, KeyMeldClientBuilder};

#[cfg(feature = "client")]
pub use managers::{
    AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, BatchSigningItem,
    BatchSigningMode, HealthManager, JoinOptions, KeySlotReservation, KeygenManager, KeygenOptions,
    KeygenSession, RegisterOptions, SignatureResult, SigningManager, SigningOptions,
    SigningSession, SingleSignerOps,
};

pub mod prelude {
    pub use crate::config::{HttpConfig, PollingConfig};
    pub use crate::credentials::{SessionCredentials, UserCredentials};
    pub use crate::error::SdkError;
    pub use crate::types::{
        BatchItemResult, EnclaveId, KeyId, KeygenStatusKind, SessionId, SignatureType,
        SigningBatchItem, SigningMode, SigningStatusKind, SubsetDefinition, TaprootTweak, UserId,
        UserKeyInfo,
    };
    pub use keymeld_core::crypto::{SecureCrypto, SessionSecret};

    #[cfg(feature = "client")]
    pub use crate::client::{KeyMeldClient, KeyMeldClientBuilder};

    #[cfg(feature = "client")]
    pub use crate::http::HttpClient;

    #[cfg(feature = "client")]
    pub use crate::managers::{
        AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType, BatchSigningItem,
        BatchSigningMode, HealthManager, JoinOptions, KeySlotReservation, KeygenManager,
        KeygenOptions, KeygenSession, RegisterOptions, SignatureResult, SigningManager,
        SigningOptions, SigningSession, SingleSignerOps,
    };
}
