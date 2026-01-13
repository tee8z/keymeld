use crate::{
    identifiers::{EnclaveId, KeyId, SessionId, UserId},
    AttestationDocument, KeyMeldError,
};
use musig2::{PartialSignature, PubNonce};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, time::SystemTime};
use thiserror::Error;
use uuid::Uuid;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

// ============================================================================
// Subset Aggregates Types
// ============================================================================

/// Definition of a participant subset for aggregate key computation.
/// Each subset produces its own aggregate public key from the specified participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub struct SubsetDefinition {
    /// Client-generated unique identifier for this subset
    pub subset_id: Uuid,
    /// List of user IDs that form this subset
    pub participants: Vec<UserId>,
}

/// Taproot tweak configuration for MuSig2 key aggregation
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TaprootTweak {
    /// No tweaking - use plain MuSig2 aggregate key
    #[default]
    None,
    /// Unspendable taproot tweak (key-path only spending)
    UnspendableTaproot,
    /// Taproot tweak with specific merkle root (commits to tapscript tree)
    TaprootWithMerkleRoot { merkle_root: [u8; 32] },
    /// Plain scalar tweak
    PlainTweak { tweak: [u8; 32] },
    /// X-only scalar tweak
    XOnlyTweak { tweak: [u8; 32] },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeygenStatusKind {
    Reserved,
    CollectingParticipants,
    Completed,
    Failed,
}

impl AsRef<str> for KeygenStatusKind {
    fn as_ref(&self) -> &str {
        match self {
            KeygenStatusKind::Reserved => "reserved",
            KeygenStatusKind::CollectingParticipants => "collecting_participants",
            KeygenStatusKind::Completed => "completed",
            KeygenStatusKind::Failed => "failed",
        }
    }
}

impl fmt::Display for KeygenStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SigningStatusKind {
    CollectingParticipants,
    InitializingSession,
    DistributingNonces,
    FinalizingSignature,
    Completed,
    Failed,
}

impl AsRef<str> for SigningStatusKind {
    fn as_ref(&self) -> &str {
        match self {
            SigningStatusKind::CollectingParticipants => "collecting_participants",
            SigningStatusKind::InitializingSession => "initializing_session",
            SigningStatusKind::DistributingNonces => "distributing_nonces",
            SigningStatusKind::FinalizingSignature => "finalizing_signature",
            SigningStatusKind::Completed => "completed",
            SigningStatusKind::Failed => "failed",
        }
    }
}

impl fmt::Display for SigningStatusKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdaptorHint {
    Scalar(Vec<u8>),
    Point(Vec<u8>),
    Hash(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorConfig {
    pub adaptor_id: Uuid,
    pub adaptor_type: AdaptorType,
    pub adaptor_points: Vec<String>,
    pub hints: Option<Vec<AdaptorHint>>,
}

impl AdaptorConfig {
    /// Create an adaptor config with a single adaptor point.
    /// The adaptor_id is automatically generated.
    pub fn single(adaptor_point: impl Into<String>) -> Self {
        Self {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Single,
            adaptor_points: vec![adaptor_point.into()],
            hints: None,
        }
    }

    /// Create an adaptor config requiring ALL adaptor points to be revealed.
    /// The adaptor_id is automatically generated.
    pub fn and(adaptor_points: Vec<String>) -> Self {
        Self {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::And,
            adaptor_points,
            hints: None,
        }
    }

    /// Create an adaptor config requiring ANY ONE adaptor point to be revealed.
    /// The adaptor_id is automatically generated.
    pub fn or(adaptor_points: Vec<String>) -> Self {
        Self {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Or,
            adaptor_points,
            hints: None,
        }
    }

    /// Add hints for the adaptor points (typically used with Or adaptors).
    pub fn with_hints(mut self, hints: Vec<AdaptorHint>) -> Self {
        self.hints = Some(hints);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AdaptorType {
    Single,
    And,
    Or,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorSignatureResult {
    pub adaptor_id: Uuid,
    pub adaptor_type: AdaptorType,
    pub signature_scalar: Vec<u8>,
    pub nonce_point: Vec<u8>,
    pub adaptor_points: Vec<Vec<u8>>,
    pub hints: Option<Vec<AdaptorHint>>,
    pub aggregate_adaptor_point: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnclaveCommandKind {
    System(SystemCommandKind),
    Musig(MusigCommandKind),
    UserKey(UserKeyCommandKind),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemCommandKind {
    Ping,
    Configure,
    GetPublicInfo,
    GetAttestation,
    ClearSession,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MusigCommandKind {
    Keygen(KeygenCommandKind),
    Signing(SigningCommandKind),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeygenCommandKind {
    InitSession,
    DistributeSessionSecret,
    AddParticipantsBatch,
    DistributeParticipantPublicKeysBatch,
    GetAggregatePublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningCommandKind {
    InitSession,
    DistributeNonces,
    FinalizeSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserKeyCommandKind {
    ImportKey,
    ListKeys,
    DeleteKey,
    SignSingle,
    StoreKeyFromKeygen,
    RestoreKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnclaveOutcomeKind {
    System(SystemOutcomeKind),
    Musig(MusigOutcomeKind),
    UserKey(UserKeyOutcomeKind),
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SystemOutcomeKind {
    Success,
    Pong,
    PublicInfo,
    Attestation,
    Configured,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MusigOutcomeKind {
    Keygen(KeygenOutcomeKind),
    Signing(SigningOutcomeKind),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeygenOutcomeKind {
    Success,
    ParticipantsAddedBatch,
    KeygenInitialized,
    KeysInitialized,
    AggregatePublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SigningOutcomeKind {
    Success,
    Nonces,
    PartialSignature,
    FinalSignature,
    AdaptorSignatures,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserKeyOutcomeKind {
    Success,
    KeyImported,
    KeyList,
    KeyDeleted,
    SingleSignature,
    KeyStoredFromKeygen,
    KeyRestored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Command {
    pub command_id: Uuid,
    pub created_at: SystemTime,
    pub command: EnclaveCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outcome {
    pub command_id: Uuid,
    pub created_at: SystemTime,
    pub completed_at: SystemTime,
    pub response: EnclaveOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveCommand {
    System(SystemCommand),
    Musig(MusigCommand),
    UserKey(UserKeyCommand),
}

impl Command {
    pub fn new(command: EnclaveCommand) -> Self {
        Self {
            command_id: uuid::Uuid::now_v7(),
            created_at: std::time::SystemTime::now(),
            command,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemCommand {
    Ping,
    Configure(ConfigureCommand),
    GetPublicInfo,
    GetAttestation,
    ClearSession(ClearSessionCommand),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MusigCommand {
    Keygen(KeygenCommand),
    Signing(SigningCommand),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeygenCommand {
    InitSession(InitKeygenSessionCommand),
    AddParticipantsBatch(AddParticipantsBatchCommand),
    DistributeParticipantPublicKeysBatch(DistributeParticipantPublicKeysBatchCommand),
    GetAggregatePublicKey(GetAggregatePublicKeyCommand),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningCommand {
    InitSession(InitSigningSessionCommand),
    DistributeNonces(DistributeNoncesCommand),
    FinalizeSignature(FinalizeSignatureCommand),
}

/// Commands for user key management and single-signer operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserKeyCommand {
    ImportKey(ImportUserKeyCommand),
    ListKeys(ListUserKeysCommand),
    DeleteKey(DeleteUserKeyCommand),
    SignSingle(SignSingleCommand),
    StoreKeyFromKeygen(StoreKeyFromKeygenCommand),
    RestoreKey(RestoreUserKeyCommand),
}

impl From<EnclaveCommand> for Command {
    fn from(command: EnclaveCommand) -> Self {
        Self {
            command_id: uuid::Uuid::now_v7(),
            created_at: std::time::SystemTime::now(),
            command,
        }
    }
}

impl From<Command> for EnclaveCommand {
    fn from(command: Command) -> Self {
        command.command
    }
}

impl From<&EnclaveCommand> for EnclaveCommandKind {
    fn from(command: &EnclaveCommand) -> Self {
        match command {
            EnclaveCommand::System(system_cmd) => EnclaveCommandKind::System(system_cmd.into()),
            EnclaveCommand::Musig(musig_cmd) => EnclaveCommandKind::Musig(musig_cmd.into()),
            EnclaveCommand::UserKey(user_key_cmd) => {
                EnclaveCommandKind::UserKey(user_key_cmd.into())
            }
        }
    }
}

impl From<&UserKeyCommand> for UserKeyCommandKind {
    fn from(command: &UserKeyCommand) -> Self {
        match command {
            UserKeyCommand::ImportKey(_) => UserKeyCommandKind::ImportKey,
            UserKeyCommand::ListKeys(_) => UserKeyCommandKind::ListKeys,
            UserKeyCommand::DeleteKey(_) => UserKeyCommandKind::DeleteKey,
            UserKeyCommand::SignSingle(_) => UserKeyCommandKind::SignSingle,
            UserKeyCommand::StoreKeyFromKeygen(_) => UserKeyCommandKind::StoreKeyFromKeygen,
            UserKeyCommand::RestoreKey(_) => UserKeyCommandKind::RestoreKey,
        }
    }
}

impl From<&SystemCommand> for SystemCommandKind {
    fn from(command: &SystemCommand) -> Self {
        match command {
            SystemCommand::Ping => SystemCommandKind::Ping,
            SystemCommand::Configure(_) => SystemCommandKind::Configure,
            SystemCommand::GetPublicInfo => SystemCommandKind::GetPublicInfo,
            SystemCommand::GetAttestation => SystemCommandKind::GetAttestation,
            SystemCommand::ClearSession(_) => SystemCommandKind::ClearSession,
        }
    }
}

impl From<&MusigCommand> for MusigCommandKind {
    fn from(command: &MusigCommand) -> Self {
        match command {
            MusigCommand::Keygen(keygen_cmd) => MusigCommandKind::Keygen(keygen_cmd.into()),
            MusigCommand::Signing(signing_cmd) => MusigCommandKind::Signing(signing_cmd.into()),
        }
    }
}

impl From<&KeygenCommand> for KeygenCommandKind {
    fn from(command: &KeygenCommand) -> Self {
        match command {
            KeygenCommand::InitSession(_) => KeygenCommandKind::InitSession,
            KeygenCommand::AddParticipantsBatch(_) => KeygenCommandKind::AddParticipantsBatch,
            KeygenCommand::DistributeParticipantPublicKeysBatch(_) => {
                KeygenCommandKind::DistributeParticipantPublicKeysBatch
            }
            KeygenCommand::GetAggregatePublicKey(_) => KeygenCommandKind::GetAggregatePublicKey,
        }
    }
}

impl From<&SigningCommand> for SigningCommandKind {
    fn from(command: &SigningCommand) -> Self {
        match command {
            SigningCommand::InitSession(_) => SigningCommandKind::InitSession,
            SigningCommand::DistributeNonces(_) => SigningCommandKind::DistributeNonces,
            SigningCommand::FinalizeSignature(_) => SigningCommandKind::FinalizeSignature,
        }
    }
}

impl KeygenCommand {
    pub fn user_id(&self) -> Option<UserId> {
        // Batch commands don't have a single user_id
        None
    }
}

impl SigningCommand {
    pub fn user_ids(&self) -> Option<Vec<UserId>> {
        match self {
            SigningCommand::InitSession(cmd) => Some(cmd.user_ids.clone()),
            SigningCommand::DistributeNonces(_) => None, // Per-enclave command, no single user
            SigningCommand::FinalizeSignature(_) => None,
        }
    }
}

impl fmt::Display for EnclaveCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EnclaveCommand::System(system_cmd) => match system_cmd {
                SystemCommand::Ping => write!(f, "ping"),
                SystemCommand::Configure(_) => write!(f, "configure"),
                SystemCommand::GetPublicInfo => write!(f, "get_public_info"),
                SystemCommand::GetAttestation => write!(f, "get_attestation"),
                SystemCommand::ClearSession(_) => write!(f, "clear_session"),
            },
            EnclaveCommand::Musig(musig_cmd) => match musig_cmd {
                MusigCommand::Keygen(keygen_cmd) => match keygen_cmd {
                    KeygenCommand::InitSession(_) => write!(f, "init_keygen"),
                    KeygenCommand::AddParticipantsBatch(_) => write!(f, "add_participants_batch"),
                    KeygenCommand::DistributeParticipantPublicKeysBatch(_) => {
                        write!(f, "distribute_participant_public_keys_batch")
                    }
                    KeygenCommand::GetAggregatePublicKey(_) => {
                        write!(f, "get_aggregate_public_key")
                    }
                },
                MusigCommand::Signing(signing_cmd) => match signing_cmd {
                    SigningCommand::InitSession(_) => write!(f, "init_signing"),
                    SigningCommand::DistributeNonces(_) => {
                        write!(f, "distribute_nonces")
                    }
                    SigningCommand::FinalizeSignature(_) => {
                        write!(f, "finalize_signature")
                    }
                },
            },
            EnclaveCommand::UserKey(user_key_cmd) => match user_key_cmd {
                UserKeyCommand::ImportKey(_) => write!(f, "import_user_key"),
                UserKeyCommand::ListKeys(_) => write!(f, "list_user_keys"),
                UserKeyCommand::DeleteKey(_) => write!(f, "delete_user_key"),
                UserKeyCommand::SignSingle(_) => write!(f, "sign_single"),
                UserKeyCommand::StoreKeyFromKeygen(_) => write!(f, "store_key_from_keygen"),
                UserKeyCommand::RestoreKey(_) => write!(f, "restore_user_key"),
            },
        }
    }
}

impl EnclaveCommand {
    pub fn session_id(&self) -> Result<SessionId, EnclaveError> {
        match self {
            EnclaveCommand::System(system_cmd) => match system_cmd {
                SystemCommand::ClearSession(cmd) => cmd
                    .keygen_session_id
                    .clone()
                    .or(cmd.signing_session_id.clone())
                    .ok_or(EnclaveError::Session(SessionError::InvalidId(
                        "Either keygen_session_id or signing_session_id must be provided"
                            .to_string(),
                    ))),
                _ => Err(EnclaveError::Session(SessionError::InvalidId(
                    "Command does not contain a session ID".to_string(),
                ))),
            },
            EnclaveCommand::Musig(musig_cmd) => match musig_cmd {
                MusigCommand::Keygen(keygen_cmd) => match keygen_cmd {
                    KeygenCommand::InitSession(cmd) => Ok(cmd.keygen_session_id.clone()),
                    KeygenCommand::AddParticipantsBatch(cmd) => Ok(cmd.keygen_session_id.clone()),
                    KeygenCommand::DistributeParticipantPublicKeysBatch(cmd) => {
                        Ok(cmd.keygen_session_id.clone())
                    }
                    KeygenCommand::GetAggregatePublicKey(cmd) => Ok(cmd.keygen_session_id.clone()),
                },
                MusigCommand::Signing(signing_cmd) => match signing_cmd {
                    SigningCommand::InitSession(cmd) => Ok(cmd.signing_session_id.clone()),
                    SigningCommand::DistributeNonces(cmd) => Ok(cmd.signing_session_id.clone()),
                    SigningCommand::FinalizeSignature(cmd) => Ok(cmd.signing_session_id.clone()),
                },
            },
            EnclaveCommand::UserKey(_) => Err(EnclaveError::Session(SessionError::InvalidId(
                "UserKey commands do not have a session ID".to_string(),
            ))),
        }
    }

    pub fn kind(&self) -> EnclaveCommandKind {
        self.into()
    }

    pub fn user_ids(&self) -> Option<Vec<UserId>> {
        match self {
            EnclaveCommand::Musig(musig_cmd) => match musig_cmd {
                MusigCommand::Keygen(_keygen_cmd) => {
                    // Keygen commands don't have user_ids at command level
                    None
                }
                MusigCommand::Signing(signing_cmd) => match signing_cmd {
                    SigningCommand::InitSession(cmd) => Some(cmd.user_ids.clone()),
                    SigningCommand::DistributeNonces(_) => None, // Per-enclave command, no single user
                    SigningCommand::FinalizeSignature(_) => None,
                },
            },
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnclaveOutcome {
    System(SystemOutcome),
    Musig(MusigOutcome),
    UserKey(UserKeyOutcome),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemOutcome {
    Success,
    Pong,
    PublicInfo(PublicInfoResponse),
    Attestation(AttestationDocument),
    /// Response from Configure command with KMS-encrypted keys
    Configured(ConfiguredResponse),
}

/// Response from Configure command containing KMS-encrypted enclave keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfiguredResponse {
    /// KMS-encrypted data encryption key (DEK)
    pub encrypted_dek: Vec<u8>,
    /// DEK-encrypted private key
    pub encrypted_private_key: Vec<u8>,
    /// Public key corresponding to the private key
    pub public_key: Vec<u8>,
    /// Whether these are newly generated keys (true) or restored from provided values (false)
    pub newly_generated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MusigOutcome {
    Keygen(KeygenOutcome),
    Signing(SigningOutcome),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeygenOutcome {
    Success,
    ParticipantsAddedBatch(ParticipantsAddedBatchResponse),
    KeygenInitialized(KeygenInitializedResponse),
    KeysInitialized(KeysInitializedResponse),
    AggregatePublicKey(AggregatePublicKeyResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningOutcome {
    Success,
    Nonces(NoncesResponse),
    PartialSignature(PartialSignatureResponse),
    FinalSignature(FinalSignatureResponse),
    AdaptorSignatures(AdaptorSignaturesResponse),
}

/// Outcomes for user key management and single-signer operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserKeyOutcome {
    Success,
    KeyImported(KeyImportedResponse),
    KeyList(KeyListResponse),
    KeyDeleted(KeyDeletedResponse),
    SingleSignature(SingleSignatureResponse),
    KeyStoredFromKeygen(KeyStoredFromKeygenResponse),
    KeyRestored(KeyRestoredResponse),
}

impl From<Outcome> for EnclaveOutcome {
    fn from(value: Outcome) -> Self {
        value.response
    }
}

impl Outcome {
    pub fn new(command: Command, response: EnclaveOutcome) -> Self {
        Self {
            command_id: command.command_id,
            created_at: command.created_at,
            completed_at: std::time::SystemTime::now(),
            response,
        }
    }

    pub fn kind(&self) -> EnclaveOutcomeKind {
        (&self.response).into()
    }
}

impl From<&EnclaveOutcome> for EnclaveOutcomeKind {
    fn from(outcome: &EnclaveOutcome) -> Self {
        match outcome {
            EnclaveOutcome::System(system_outcome) => {
                EnclaveOutcomeKind::System(system_outcome.into())
            }
            EnclaveOutcome::Musig(musig_outcome) => EnclaveOutcomeKind::Musig(musig_outcome.into()),
            EnclaveOutcome::UserKey(user_key_outcome) => {
                EnclaveOutcomeKind::UserKey(user_key_outcome.into())
            }
            EnclaveOutcome::Error(_) => EnclaveOutcomeKind::Error,
        }
    }
}

impl From<&UserKeyOutcome> for UserKeyOutcomeKind {
    fn from(outcome: &UserKeyOutcome) -> Self {
        match outcome {
            UserKeyOutcome::Success => UserKeyOutcomeKind::Success,
            UserKeyOutcome::KeyImported(_) => UserKeyOutcomeKind::KeyImported,
            UserKeyOutcome::KeyList(_) => UserKeyOutcomeKind::KeyList,
            UserKeyOutcome::KeyDeleted(_) => UserKeyOutcomeKind::KeyDeleted,
            UserKeyOutcome::SingleSignature(_) => UserKeyOutcomeKind::SingleSignature,
            UserKeyOutcome::KeyStoredFromKeygen(_) => UserKeyOutcomeKind::KeyStoredFromKeygen,
            UserKeyOutcome::KeyRestored(_) => UserKeyOutcomeKind::KeyRestored,
        }
    }
}

impl From<&SystemOutcome> for SystemOutcomeKind {
    fn from(outcome: &SystemOutcome) -> Self {
        match outcome {
            SystemOutcome::Success => SystemOutcomeKind::Success,
            SystemOutcome::Pong => SystemOutcomeKind::Pong,
            SystemOutcome::PublicInfo(_) => SystemOutcomeKind::PublicInfo,
            SystemOutcome::Attestation(_) => SystemOutcomeKind::Attestation,
            SystemOutcome::Configured(_) => SystemOutcomeKind::Configured,
        }
    }
}

impl From<&MusigOutcome> for MusigOutcomeKind {
    fn from(outcome: &MusigOutcome) -> Self {
        match outcome {
            MusigOutcome::Keygen(keygen_outcome) => MusigOutcomeKind::Keygen(keygen_outcome.into()),
            MusigOutcome::Signing(signing_outcome) => {
                MusigOutcomeKind::Signing(signing_outcome.into())
            }
        }
    }
}

impl From<&KeygenOutcome> for KeygenOutcomeKind {
    fn from(outcome: &KeygenOutcome) -> Self {
        match outcome {
            KeygenOutcome::Success => KeygenOutcomeKind::Success,
            KeygenOutcome::ParticipantsAddedBatch(_) => KeygenOutcomeKind::ParticipantsAddedBatch,
            KeygenOutcome::KeygenInitialized(_) => KeygenOutcomeKind::KeygenInitialized,
            KeygenOutcome::KeysInitialized(_) => KeygenOutcomeKind::KeysInitialized,
            KeygenOutcome::AggregatePublicKey(_) => KeygenOutcomeKind::AggregatePublicKey,
        }
    }
}

impl From<&SigningOutcome> for SigningOutcomeKind {
    fn from(outcome: &SigningOutcome) -> Self {
        match outcome {
            SigningOutcome::Success => SigningOutcomeKind::Success,
            SigningOutcome::Nonces(_) => SigningOutcomeKind::Nonces,
            SigningOutcome::PartialSignature(_) => SigningOutcomeKind::PartialSignature,
            SigningOutcome::FinalSignature(_) => SigningOutcomeKind::FinalSignature,
            SigningOutcome::AdaptorSignatures(_) => SigningOutcomeKind::AdaptorSignatures,
        }
    }
}

impl fmt::Display for EnclaveOutcome {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EnclaveOutcome::System(system_outcome) => match system_outcome {
                SystemOutcome::Success => write!(f, "success"),
                SystemOutcome::Pong => write!(f, "pong"),
                SystemOutcome::PublicInfo(_) => write!(f, "public_info"),
                SystemOutcome::Attestation(_) => write!(f, "attestation"),
                SystemOutcome::Configured(_) => write!(f, "configured"),
            },
            EnclaveOutcome::Musig(musig_outcome) => match musig_outcome {
                MusigOutcome::Keygen(keygen_outcome) => match keygen_outcome {
                    KeygenOutcome::Success => write!(f, "keygen_success"),
                    KeygenOutcome::ParticipantsAddedBatch(_) => {
                        write!(f, "participants_added_batch")
                    }
                    KeygenOutcome::KeygenInitialized(_) => write!(f, "keygen_initialized"),
                    KeygenOutcome::KeysInitialized(_) => {
                        write!(f, "keys_initialized")
                    }
                    KeygenOutcome::AggregatePublicKey(_) => {
                        write!(f, "aggregate_public_key")
                    }
                },
                MusigOutcome::Signing(signing_outcome) => match signing_outcome {
                    SigningOutcome::Success => write!(f, "signing_success"),
                    SigningOutcome::Nonces(_) => write!(f, "nonces"),
                    SigningOutcome::PartialSignature(_) => {
                        write!(f, "partial_signature")
                    }
                    SigningOutcome::FinalSignature(_) => {
                        write!(f, "final_signature")
                    }
                    SigningOutcome::AdaptorSignatures(_) => {
                        write!(f, "adaptor_signatures")
                    }
                },
            },
            EnclaveOutcome::UserKey(user_key_outcome) => match user_key_outcome {
                UserKeyOutcome::Success => write!(f, "user_key_success"),
                UserKeyOutcome::KeyImported(_) => write!(f, "key_imported"),
                UserKeyOutcome::KeyList(_) => write!(f, "key_list"),
                UserKeyOutcome::KeyDeleted(_) => write!(f, "key_deleted"),
                UserKeyOutcome::SingleSignature(_) => write!(f, "single_signature"),
                UserKeyOutcome::KeyStoredFromKeygen(_) => write!(f, "key_stored_from_keygen"),
                UserKeyOutcome::KeyRestored(_) => write!(f, "key_restored"),
            },
            EnclaveOutcome::Error(_) => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigureCommand {
    pub enclave_id: EnclaveId,
    pub key_epoch: Option<u64>,
    // KMS configuration for enclave key persistence
    pub kms_endpoint: Option<String>,
    pub kms_key_id: Option<String>,
    pub encrypted_dek: Option<Vec<u8>>,
    pub encrypted_private_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitKeygenSessionCommand {
    pub keygen_session_id: SessionId,
    pub coordinator_encrypted_private_key: Option<String>,
    pub coordinator_user_id: Option<UserId>,
    pub encrypted_session_secret: Option<String>,
    pub timeout_secs: u64,
    pub expected_participant_count: usize,
    pub expected_participants: Vec<UserId>,
    pub enclave_public_keys: Vec<EnclavePublicKeyInfo>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    /// Subset definitions for computing additional aggregate keys.
    /// Each subset produces its own aggregate from the specified participants.
    #[serde(default)]
    pub subset_definitions: Vec<SubsetDefinition>,
}

/// Approval signature for a user who requires signing approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningApproval {
    pub user_id: UserId,
    /// The auth public key to verify the signature against
    /// Included so the enclave can verify independently without trusting stored state
    pub auth_pubkey: Vec<u8>,
    /// Session-level signature (optional if per_item_approvals provided)
    /// Signature of (signing_session_id || timestamp) with auth_privkey
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    /// Timestamp used in the signature
    pub timestamp: u64,
    /// Per-item approvals (optional, takes precedence if provided)
    #[serde(default)]
    pub per_item_approvals: Vec<BatchItemApproval>,
}

/// Per-item approval for batch signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchItemApproval {
    pub batch_item_id: Uuid,
    /// Sign(auth_privkey, batch_item_id || message_hash || timestamp)
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

// ============================================================================
// Batch Signing Types
// ============================================================================

/// A single item in a batch signing session (enclave-level)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveBatchItem {
    pub batch_item_id: Uuid,
    /// Encrypted message for this batch item
    pub encrypted_message: String,
    /// Optional adaptor configuration for this specific message
    pub encrypted_adaptor_configs: Option<String>,
    /// Per-item taproot tweak (encrypted with session secret as JSON-serialized TaprootTweak)
    pub encrypted_taproot_tweak: String,
    /// Which subset of participants signs this item.
    /// None = all participants (full aggregate key).
    /// Some(subset_id) = only participants in that subset sign.
    #[serde(default)]
    pub subset_id: Option<Uuid>,
}

/// Result for a single batch item from the enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveBatchResult {
    pub batch_item_id: Uuid,
    /// Encrypted final signature (if successful)
    pub encrypted_final_signature: Option<String>,
    /// Encrypted adaptor signatures (if adaptor configs provided)
    pub encrypted_adaptor_signatures: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitSigningSessionCommand {
    pub keygen_session_id: SessionId,
    pub signing_session_id: SessionId,
    /// List of user IDs to initialize on this enclave
    pub user_ids: Vec<UserId>,
    /// Encrypted TaprootTweak as hex-encoded JSON
    pub encrypted_taproot_tweak: String,
    pub expected_participant_count: usize,
    /// Approval signatures from users who require signing approval
    /// Enclave verifies these against stored auth_pubkey before proceeding
    #[serde(default)]
    pub approval_signatures: Vec<SigningApproval>,
    /// Batch items to sign (single message = batch of 1)
    pub batch_items: Vec<EnclaveBatchItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributeNoncesCommand {
    pub signing_session_id: SessionId,
    /// Vec of (user_id, encrypted_nonce_data_hex)
    /// Each nonce is encrypted with session secret using binary hex format (EncryptedData::to_hex)
    /// Single message = batch of 1
    pub nonces: Vec<(UserId, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeSignatureCommand {
    pub signing_session_id: SessionId,
    /// Vec of (user_id, encrypted_signature_data_hex)
    /// Each signature is encrypted with session secret using binary hex format (EncryptedData::to_hex)
    /// Single message = batch of 1
    pub partial_signatures: Vec<(UserId, String)>,
}

/// Participant data for keygen registration including auth info for signing approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRegistrationData {
    pub user_id: UserId,
    /// ECIES-encrypted private key for this enclave
    pub enclave_encrypted_data: String,
    /// Auth public key for verifying signing approval signatures
    pub auth_pubkey: Vec<u8>,
    /// Whether this user requires explicit approval before signing
    pub require_signing_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddParticipantsBatchCommand {
    pub keygen_session_id: SessionId,
    /// Participant registration data including auth info
    pub participants: Vec<ParticipantRegistrationData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributeParticipantPublicKeysBatchCommand {
    pub keygen_session_id: SessionId,
    pub participants_public_keys: Vec<(UserId, String)>, // (user_id, encrypted_participant_public_key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAggregatePublicKeyCommand {
    pub keygen_session_id: SessionId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearSessionCommand {
    pub keygen_session_id: Option<SessionId>,
    pub signing_session_id: Option<SessionId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributeSessionSecretCommand {
    pub keygen_session_id: SessionId,
    pub encrypted_session_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEnclavePublicKeysCommand {
    pub enclave_ids: Vec<EnclaveId>,
}

// ============================================================================
// User Key Commands
// ============================================================================

/// Signature type for single-signer operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SignatureType {
    /// BIP-340 Schnorr signature (for taproot)
    SchnorrBip340,
    /// ECDSA signature
    Ecdsa,
}

impl AsRef<str> for SignatureType {
    fn as_ref(&self) -> &str {
        match self {
            SignatureType::SchnorrBip340 => "schnorr_bip340",
            SignatureType::Ecdsa => "ecdsa",
        }
    }
}

impl fmt::Display for SignatureType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl std::str::FromStr for SignatureType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "schnorr_bip340" => Ok(SignatureType::SchnorrBip340),
            "ecdsa" => Ok(SignatureType::Ecdsa),
            _ => Err(format!("Unknown signature type: {}", s)),
        }
    }
}

/// Import a user's private key into the enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportUserKeyCommand {
    pub user_id: UserId,
    pub key_id: KeyId,
    /// Private key ECIES-encrypted to enclave's public key
    pub encrypted_private_key: String,
    /// Auth public key for authenticating future requests
    pub auth_pubkey: Vec<u8>,
}

/// List keys for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListUserKeysCommand {
    pub user_id: UserId,
}

/// Delete a user's key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserKeyCommand {
    pub user_id: UserId,
    pub key_id: KeyId,
}

/// Sign a message with a stored key (single-signer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignSingleCommand {
    pub user_id: UserId,
    pub key_id: KeyId,
    /// Message encrypted with session secret
    pub encrypted_message: String,
    pub signature_type: SignatureType,
    /// Session secret ECIES-encrypted to enclave's public key
    pub encrypted_session_secret: String,
    /// Proof user approved this specific message: Sign(auth_privkey, message_hash || key_id || timestamp)
    pub approval_signature: Vec<u8>,
    /// Timestamp used in approval signature (enclave checks this is recent)
    pub approval_timestamp: u64,
}

/// Store a key from a completed keygen session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreKeyFromKeygenCommand {
    pub user_id: UserId,
    pub key_id: KeyId,
    pub keygen_session_id: SessionId,
}

/// Restore a user key from encrypted blob (for enclave restart)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreUserKeyCommand {
    pub user_id: UserId,
    pub key_id: KeyId,
    /// Private key ECIES-encrypted to enclave's public key
    pub encrypted_private_key: String,
    /// Auth public key for authenticating requests
    pub auth_pubkey: Vec<u8>,
    /// Original keygen session ID if key came from keygen
    pub origin_keygen_session_id: Option<SessionId>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedParticipantPublicKey {
    pub target_enclave_id: EnclaveId,
    pub encrypted_public_key: String, // Encrypted with target enclave's public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantsAddedBatchResponse {
    pub participants: Vec<UserId>,
    // For each participant, the encrypted public keys for other enclaves
    pub encrypted_public_keys: Vec<(UserId, Vec<EncryptedParticipantPublicKey>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeygenInitializedResponse {
    pub keygen_session_id: SessionId,
    pub encrypted_session_secrets: Vec<EncryptedSessionSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysInitializedResponse {
    pub enclave_id: EnclaveId,
    pub encrypted_dek: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    /// Encrypted public key as hex-encoded binary format (EncryptedData::to_hex)
    pub encrypted_public_key: String,
}

/// Response containing nonces for users initialized on this enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoncesResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    /// Vec of (user_id, encrypted_nonce_data_hex) for all users initialized on this enclave
    /// Single message = batch of 1
    pub nonces: Vec<(UserId, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureData {
    Regular(PartialSignature),
    Adaptor(Vec<(Uuid, PartialSignature)>),
    /// Batch signatures: map of batch_item_id -> SignatureData (Regular or Adaptor per item)
    Batch(BTreeMap<Uuid, Box<SignatureData>>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NonceData {
    Regular(PubNonce),
    Adaptor(Vec<(Uuid, PubNonce)>),
    /// Batch nonces: map of batch_item_id -> NonceData (Regular or Adaptor per item)
    Batch(BTreeMap<Uuid, Box<NonceData>>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignatureResponse {
    /// Vec of (user_id, encrypted_signature_data_hex)
    /// Each signature is encrypted with session secret using binary hex format (EncryptedData::to_hex)
    /// Single message = batch of 1
    pub partial_signatures: Vec<(UserId, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalSignatureResponse {
    pub signing_session_id: SessionId,
    pub keygen_session_id: SessionId,
    pub participant_count: usize,
    /// Batch results (single message = batch of 1)
    pub batch_results: Vec<EnclaveBatchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinalizedData {
    FinalSignature(Vec<u8>),
    AdaptorSignatures(Vec<(uuid::Uuid, Vec<u8>)>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatePublicKeyResponse {
    pub keygen_session_id: SessionId,
    /// Encrypted aggregate public key as hex-encoded binary format (EncryptedData::to_hex)
    pub encrypted_aggregate_public_key: String,
    pub participant_count: usize,
    /// Encrypted aggregate keys for each defined subset.
    /// Keys are subset_id -> encrypted_aggregate_public_key (hex-encoded).
    #[serde(default)]
    pub encrypted_subset_aggregates: BTreeMap<Uuid, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateKeyCompleteResponse {
    pub keygen_session_id: SessionId,
    /// Encrypted aggregate public key as hex-encoded binary format (EncryptedData::to_hex)
    pub encrypted_aggregate_public_key: String,
    pub participant_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInfoResponse {
    pub public_key: String,
    pub attestation_document: Option<AttestationDocument>,
    pub active_sessions: u32,
    pub uptime_seconds: u64,
    pub key_epoch: u64,
    pub key_generation_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionSecret {
    pub target_enclave_id: EnclaveId,
    pub encrypted_session_secret: String, // Session secret encrypted with target enclave's public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSecretResponse {
    pub session_secret: String,
    pub enclave_id: EnclaveId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorSignaturesResponse {
    pub signing_session_id: SessionId,
    pub adaptor_signatures: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclavePublicKeyInfo {
    pub enclave_id: EnclaveId,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclavePublicKeysResponse {
    pub enclave_keys: Vec<EnclavePublicKeyInfo>,
}

// ============================================================================
// User Key Responses
// ============================================================================

/// Response after successfully importing a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyImportedResponse {
    pub user_id: UserId,
    pub key_id: KeyId,
}

/// Key info returned to user (NO public key - treated as secret)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct UserKeyInfo {
    pub user_id: UserId,
    pub key_id: KeyId,
    pub created_at: u64,
    /// None = imported, Some = from keygen
    pub origin_keygen_session_id: Option<SessionId>,
}

/// Response listing user's keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyListResponse {
    pub user_id: UserId,
    pub keys: Vec<UserKeyInfo>,
}

/// Response after deleting a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDeletedResponse {
    pub user_id: UserId,
    pub key_id: KeyId,
}

/// Response with single-signer signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSignatureResponse {
    pub user_id: UserId,
    pub key_id: KeyId,
    /// Signature encrypted with session secret
    pub encrypted_signature: String,
    pub signature_type: SignatureType,
}

/// Response after storing key from keygen
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStoredFromKeygenResponse {
    pub user_id: UserId,
    pub key_id: KeyId,
    pub keygen_session_id: SessionId,
    /// Re-encrypted private key for gateway persistence (ECIES to enclave pubkey)
    pub encrypted_private_key: String,
}

/// Response after restoring a key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRestoredResponse {
    pub user_id: UserId,
    pub key_id: KeyId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: EnclaveError,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum ValidationError {
    #[error("Encrypted message cannot be empty")]
    EmptyEncryptedMessage,
    #[error("Decrypted message is empty")]
    EmptyDecryptedMessage,
    #[error("User {user_id} not found in expected participants")]
    UserNotFound { user_id: UserId },
    #[error("Signer index {index} exceeds expected participant count {expected}")]
    IndexOutOfBounds { index: usize, expected: usize },
    #[error("Invalid private key length: expected 32 bytes, got {actual}")]
    InvalidPrivateKeyLength { actual: usize },
    #[error("Message too large: {size} bytes (max 16MB)")]
    MessageTooLarge { size: usize },
    #[error("Cannot process commands in {state} state")]
    InvalidStateForCommand { state: String },
    #[error("Expected participant count must be greater than 0")]
    ZeroParticipantCount,
    #[error("Timeout must be greater than 0")]
    ZeroTimeout,
    #[error("Invalid nonce length: expected 66 bytes, got {actual}")]
    InvalidNonceLength { actual: usize },
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum CryptoError {
    #[error("Failed to generate keypair: {0}")]
    KeypairGeneration(String),
    #[error("Failed to encrypt {context}: {error}")]
    EncryptionFailed { context: String, error: String },
    #[error("Failed to decrypt {context}: {error}")]
    DecryptionFailed { context: String, error: String },
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    #[error("Private key too short: expected 32 bytes, got {actual}")]
    PrivateKeyTooShort { actual: usize },
    #[error("Failed to finalize signature: {0}")]
    SignatureFinalization(String),
    #[error("Failed to aggregate signatures: {0}")]
    SignatureAggregation(String),
    #[error("Failed to add participant to musig processor: {0}")]
    ParticipantAddition(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum NonceError {
    #[error("Failed to generate nonce for user {user_id}: {error}")]
    GenerationFailed { user_id: UserId, error: String },
    #[error("Failed to add nonce for user {user_id}: {error}")]
    AddFailed { user_id: UserId, error: String },
    #[error("Invalid nonce length: expected 66 bytes, got {actual}")]
    InvalidLength { actual: usize },
    #[error("Aggregate nonce not available in state {state}")]
    NotAvailable { state: String },
    #[error("Cannot get aggregate nonce from non-signing session")]
    WrongSessionType,
    #[error("Failed to convert AggNonce to PubNonce: {0}")]
    ConversionFailed(String),
    #[error("Failed to get aggregate nonce: {0}")]
    AggregateNonceFailed(String),
    #[error("No nonce found for user {user_id}")]
    NonceNotFound { user_id: UserId },
    #[error("Session {session_id} not ready for signature generation: {message}")]
    NotReady {
        session_id: SessionId,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum SigningError {
    #[error("Failed to generate partial signature for user {user_id}: {error}")]
    PartialSignatureGeneration { user_id: UserId, error: String },
    #[error("Adaptor partial signature generation failed: {0}")]
    AdaptorPartialSignatureGeneration(String),
    #[error("Failed to deserialize partial signature: {0}")]
    PartialSignatureDeserialization(String),
    #[error("Failed to deserialize adaptor partial signature: {0}")]
    AdaptorPartialSignatureDeserialization(String),
    #[error("Failed to aggregate signatures: {0}")]
    SignatureAggregation(String),
    #[error("Adaptor signature aggregation failed: {0}")]
    AdaptorSignatureAggregation(String),
    #[error("Failed to get adaptor signature results: {0}")]
    AdaptorResultsRetrieval(String),
    #[error("No partial signature found for user {user_id}")]
    PartialSignatureNotFound { user_id: UserId },
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum SessionError {
    #[error("Session not found: {0}")]
    NotFound(SessionId),
    #[error("Invalid session ID: {0}")]
    InvalidId(String),
    #[error("Session secret not initialized")]
    SecretNotInitialized,
    #[error("Invalid session secret length: expected 32 bytes, got {actual}")]
    InvalidSecretLength { actual: usize },
    #[error("Failed to initialize MuSig2 for keygen: {0}")]
    MusigInitialization(String),
    #[error("Failed to copy metadata from keygen {keygen_id} to signing {signing_id}: {error}")]
    MetadataCopy {
        keygen_id: SessionId,
        signing_id: SessionId,
        error: String,
    },
    #[error("Failed to update session message: {0}")]
    MessageUpdate(String),
    #[error("Failed to get aggregate public key: {0}")]
    AggregateKeyRetrieval(String),
    #[error("Session processing failed: {0}")]
    ProcessingFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum PhaseError {
    #[error("Keygen session not completed")]
    KeygenNotCompleted,
    #[error("Keygen session required to be in completed state: {state}")]
    KeygenInWrongState { state: String },
    #[error("Wrong phase: {0}")]
    WrongPhase(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum AttestationError {
    #[error("Failed to generate attestation: {0}")]
    GenerationFailed(String),
    #[error("Debug mode attestations not allowed")]
    DebugModeNotAllowed,
    #[error("Failed to parse measurements JSON: {0}")]
    MeasurementParsing(String),
    #[error("PCR {pcr_name} has invalid length: expected 48 bytes, got {actual}")]
    InvalidPcrLength { pcr_name: String, actual: usize },
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum InternalError {
    #[error("System time error")]
    SystemTime,
    #[error("NSM client not initialized")]
    NsmNotInitialized,
    #[error("MuSig processor not found for session")]
    MissingMusigProcessor,
    #[error("State inconsistency: {0}")]
    StateInconsistency(String),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Command processing failed: {0}")]
    CommandProcessing(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum PrivateKeyError {
    #[error("Missing private key for user {user_id}")]
    Missing { user_id: UserId },
    #[error("Invalid private key length: expected 32 bytes, got {actual}")]
    InvalidLength { actual: usize },
    #[error("Invalid private key: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum DataDecodingError {
    #[error("Hex decode failed: {0}")]
    HexDecode(String),
    #[error("Failed to decode {data_type}: {error}")]
    DecodeFailed { data_type: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum ParticipantError {
    #[error("Participant error: {0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum UserKeyError {
    #[error("Key not found: user={user_id}, key={key_id}")]
    KeyNotFound { user_id: UserId, key_id: KeyId },
    #[error("Key already exists: user={user_id}, key={key_id}")]
    KeyAlreadyExists { user_id: UserId, key_id: KeyId },
    #[error("Keygen session not found or not completed: {session_id}")]
    KeygenSessionNotFound { session_id: SessionId },
    #[error("User not found in keygen session: user={user_id}, session={session_id}")]
    UserNotInKeygenSession {
        user_id: UserId,
        session_id: SessionId,
    },
    #[error("Failed to sign message: {0}")]
    SigningFailed(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum EnclaveError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Nonce(#[from] NonceError),
    #[error(transparent)]
    Signing(#[from] SigningError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Phase(#[from] PhaseError),
    #[error(transparent)]
    Attestation(#[from] AttestationError),
    #[error(transparent)]
    Internal(#[from] InternalError),
    #[error(transparent)]
    PrivateKey(#[from] PrivateKeyError),
    #[error(transparent)]
    DataDecoding(#[from] DataDecodingError),
    #[error(transparent)]
    Participant(#[from] ParticipantError),
    #[error(transparent)]
    UserKey(#[from] UserKeyError),
    #[error("MuSig error: {0}")]
    Musig(String),
    #[error("KeyMeld error: {0}")]
    KeyMeld(String),
}

impl From<hex::FromHexError> for EnclaveError {
    fn from(err: hex::FromHexError) -> Self {
        EnclaveError::DataDecoding(DataDecodingError::HexDecode(err.to_string()))
    }
}

impl From<musig2::secp256k1::Error> for EnclaveError {
    fn from(err: musig2::secp256k1::Error) -> Self {
        EnclaveError::Crypto(CryptoError::InvalidPublicKey(err.to_string()))
    }
}

impl From<KeyMeldError> for EnclaveError {
    fn from(err: KeyMeldError) -> Self {
        EnclaveError::KeyMeld(err.to_string())
    }
}

#[cfg(feature = "networking")]
pub struct EnclaveHealthCheck;

#[cfg(feature = "networking")]
impl crate::managed_socket::pool::HealthCheckable for EnclaveHealthCheck {
    type Command = Command;
    type Response = Outcome;

    fn ping_command() -> Command {
        Command::new(EnclaveCommand::System(SystemCommand::Ping))
    }

    fn is_pong_response(response: &Outcome) -> bool {
        matches!(
            response.response,
            EnclaveOutcome::System(SystemOutcome::Pong)
        )
    }
}

#[cfg(feature = "networking")]
pub type SocketClient = crate::managed_socket::SocketClient<Command, Outcome>;
