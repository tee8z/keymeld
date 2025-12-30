use keymeld_core::enclave::{EnclaveCommand, EnclaveError};

pub mod context;
pub mod states;

pub use context::EnclaveContext;
pub use states::{
    keygen::DistributingSecrets,
    signing::{
        CollectingNonces, CollectingPartialSignatures, FinalizingSignature, GeneratingNonces,
        GeneratingPartialSignatures,
    },
    KeygenCompleted, KeygenFailed, KeygenInitialized, OperatorStatus, SessionKind,
    SigningCompleted, SigningFailed, SigningInitialized,
};

pub trait EnclaveAdvanceable<T> {
    fn process(self, ctx: &mut EnclaveContext, cmd: &EnclaveCommand) -> Result<T, EnclaveError>;
}

#[derive(Debug, Clone)]
pub struct InitConfig {
    pub session_id: keymeld_core::SessionId,
    pub session_secret: Option<keymeld_core::SessionSecret>,
    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub participant_keys: std::collections::BTreeMap<keymeld_core::identifiers::UserId, Vec<u8>>,
    pub participants: Vec<keymeld_core::identifiers::UserId>,
    pub expected_participants: Vec<keymeld_core::identifiers::UserId>,
    pub expected_participant_count: usize,
    pub aggregate_public_key: Vec<u8>,
    pub is_coordinator: bool,
    pub coordinator_private_key: Option<Vec<u8>>,
    pub created_at: std::time::SystemTime,
}

impl InitConfig {
    pub fn new_keygen(
        session_id: keymeld_core::SessionId,
        session_secret: Option<keymeld_core::SessionSecret>,
        expected_participants: Vec<keymeld_core::identifiers::UserId>,
        is_coordinator: bool,
        coordinator_private_key: Option<Vec<u8>>,
        aggregate_public_key: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            session_secret,
            message: Vec::new(), // Keygen sessions don't have messages
            message_hash: Vec::new(),
            participant_keys: std::collections::BTreeMap::new(),
            participants: Vec::new(),
            expected_participants: expected_participants.clone(),
            expected_participant_count: expected_participants.len(),
            aggregate_public_key,
            is_coordinator,
            coordinator_private_key,
            created_at: std::time::SystemTime::now(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_signing(
        session_id: keymeld_core::SessionId,
        session_secret: Option<keymeld_core::SessionSecret>,
        message: Vec<u8>,
        message_hash: Vec<u8>,
        expected_participants: Vec<keymeld_core::identifiers::UserId>,
        is_coordinator: bool,
        coordinator_private_key: Option<Vec<u8>>,
        aggregate_public_key: Vec<u8>,
    ) -> Self {
        Self {
            session_id,
            session_secret,
            message,
            message_hash,
            participant_keys: std::collections::BTreeMap::new(),
            participants: Vec::new(),
            expected_participants: expected_participants.clone(),
            expected_participant_count: expected_participants.len(),
            aggregate_public_key,
            is_coordinator,
            coordinator_private_key,
            created_at: std::time::SystemTime::now(),
        }
    }
}
