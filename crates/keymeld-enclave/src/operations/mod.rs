pub mod context;
pub mod context_aware_session;
pub mod enclave_context;
pub mod keygen_data;
pub mod session_context;
pub mod states;
pub mod user_key_handler;
pub mod user_key_store;

use std::collections::BTreeMap;

// New exports for the refactored architecture
pub use context::EnclaveSharedContext;
pub use context_aware_session::ContextAwareSession;
pub use keygen_data::{create_signing_musig_from_keygen, KeygenSessionData};
use keymeld_core::UserId;
pub use session_context::{
    decrypt_coordinator_data_from_enclave, decrypt_session_secret_from_enclave,
    KeygenSessionContext, SessionContext, SigningSessionContext,
};

// Re-export states
pub use states::{
    keygen::DistributingSecrets,
    signing::{
        CollectingNonces, CollectingPartialSignatures, FinalizingSignature, GeneratingNonces,
        GeneratingPartialSignatures,
    },
    KeygenCompleted, KeygenFailed, KeygenInitialized, OperatorStatus, SessionKind,
    SigningCompleted, SigningFailed, SigningInitialized,
};

#[derive(Debug, Clone)]
pub struct InitConfig {
    pub session_id: keymeld_core::SessionId,
    pub session_secret: Option<keymeld_core::SessionSecret>,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_keys: BTreeMap<UserId, Vec<u8>>,
    pub participants: Vec<UserId>,
    pub expected_participants: Vec<UserId>,
    pub expected_participant_count: usize,
}
