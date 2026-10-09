use super::keygen_data::KeygenSessionData;
use crate::musig::MusigProcessor;
use crate::operations::{context::EnclaveSharedContext, states::signing::CoordinatorData};
use keymeld_core::protocol::{KeygenCommand, MusigCommand, SigningCommandKind};
use keymeld_core::{
    crypto::{EncryptedData, SessionSecret},
    identifiers::{SessionId, UserId},
    protocol::{
        EnclaveCommand, EnclaveError, EncryptedParticipantPublicKey, InitKeygenSessionCommand,
        InitSigningSessionCommand, SessionError,
    },
    KeyMaterial,
};
use keymeld_core::{hash_message, EnclaveId};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::SystemTime,
};

#[derive(Debug)]
pub enum SessionContext {
    Keygen(Box<KeygenSessionContext>),
    Signing(Box<SigningSessionContext>),
}

#[derive(Debug)]
pub struct KeygenSessionContext {
    pub recipient_authorization:
        Option<Box<keymeld_core::authorization::EnclaveRecipientAuthorization>>,
    pub session_id: SessionId,
    pub created_at: SystemTime,
    pub musig_processor: Option<MusigProcessor>,
    pub session_secret: Option<SessionSecret>,
    pub coordinator_data: Option<CoordinatorData>,
    pub coordinator_user_id: Option<UserId>,
    pub encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    pub session_enclave_public_keys: BTreeMap<EnclaveId, String>, // Other enclaves in this session
    pub command_history: Vec<ProcessedCommand>,
}

#[derive(Debug)]
pub struct SigningSessionContext {
    pub session_id: SessionId,
    pub created_at: SystemTime,
    pub keygen_session_id: SessionId,

    pub message: Vec<u8>,
    pub message_hash: Vec<u8>,
    pub session_secret: Option<SessionSecret>,
    pub coordinator_data: Option<CoordinatorData>,
    pub nonces: BTreeMap<UserId, Vec<u8>>,
    pub partial_signatures: BTreeMap<UserId, Vec<u8>>,
    pub session_enclave_public_keys: BTreeMap<EnclaveId, String>, // Other enclaves in this session
    pub command_history: Vec<ProcessedCommand>,
}

/// Retry metadata must not retain multi-megabyte escrow transcripts for a keygen's lifetime.
#[derive(Debug)]
pub struct ProcessedCommand {
    /// The queue skips a command delivered again under the same id.
    pub command_id: uuid::Uuid,
    /// Set only for a once-per-session stage, the only commands compared with their retries.
    exact_retry: Option<ExactRetry>,
}

/// A completed protocol stage may be replayed only with its original inputs.
/// Comparing command kind alone can hide a changed nonce or signing transcript.
#[derive(Debug, PartialEq, Eq)]
enum Stage {
    KeygenInit,
    Signing(SigningCommandKind),
}

#[derive(Debug)]
struct ExactRetry {
    stage: Stage,
    /// Covers the same canonical command bytes previously compared on every retry.
    digest: [u8; 32],
}

impl ProcessedCommand {
    /// Hashes the command only when it starts a once-per-session stage. Build it before
    /// taking the session: the session map's shard lock must not wait on hashing.
    pub fn new(command_id: uuid::Uuid, command: &EnclaveCommand) -> Result<Self, EnclaveError> {
        let stage = match command {
            EnclaveCommand::Musig(MusigCommand::Signing(signing)) => {
                Some(Stage::Signing(signing.into()))
            }
            EnclaveCommand::Musig(MusigCommand::Keygen(keygen)) => match keygen {
                KeygenCommand::InitSession(_) => Some(Stage::KeygenInit),
                // A session takes many of these: batches, reads and escrow operations.
                KeygenCommand::AddParticipantsBatch(_)
                | KeygenCommand::DistributeParticipantPublicKeysBatch(_)
                | KeygenCommand::GetAggregatePublicKey(_)
                | KeygenCommand::Escrow(_) => None,
            },
            // Never queued on a session.
            EnclaveCommand::System(_)
            | EnclaveCommand::UserKey(_)
            | EnclaveCommand::Confidential(_) => None,
        };
        let exact_retry = stage
            .map(|stage| command_digest(command).map(|digest| ExactRetry { stage, digest }))
            .transpose()?;
        Ok(Self {
            command_id,
            exact_retry,
        })
    }
}

fn command_digest(command: &EnclaveCommand) -> Result<[u8; 32], EnclaveError> {
    struct HashWriter(Sha256);
    impl std::io::Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let invalid = || {
        EnclaveError::Validation(keymeld_core::protocol::ValidationError::Other(
            "Cannot authenticate command retry".into(),
        ))
    };
    // Bincode writes ordinary Vec<u8> elements individually. Buffer those writes
    // so hashing a large command does not update SHA-256 once per byte.
    let mut writer = std::io::BufWriter::new(HashWriter(Sha256::new()));
    bincode::serialize_into(&mut writer, command).map_err(|_| invalid())?;
    Ok(writer
        .into_inner()
        .map_err(|_| invalid())?
        .0
        .finalize()
        .into())
}

impl SessionContext {
    pub fn new_keygen(session_id: SessionId) -> Self {
        Self::Keygen(Box::new(KeygenSessionContext {
            recipient_authorization: None,
            session_id,
            created_at: SystemTime::now(),
            musig_processor: None,
            session_secret: None,
            coordinator_data: None,
            coordinator_user_id: None,
            encrypted_public_keys_for_response: Vec::new(),
            session_enclave_public_keys: BTreeMap::new(),
            command_history: Vec::new(),
        }))
    }

    pub fn new_signing(
        session_id: SessionId,
        keygen_session_id: SessionId,
        message: Vec<u8>,
    ) -> Self {
        Self::Signing(Box::new(SigningSessionContext {
            session_id,
            created_at: SystemTime::now(),
            keygen_session_id,

            message_hash: hash_message(&message),
            message,
            session_secret: None,
            coordinator_data: None,
            nonces: BTreeMap::new(),
            partial_signatures: BTreeMap::new(),
            session_enclave_public_keys: BTreeMap::new(),
            command_history: Vec::new(),
        }))
    }

    pub fn session_id(&self) -> &SessionId {
        match self {
            SessionContext::Keygen(ctx) => &ctx.session_id,
            SessionContext::Signing(ctx) => &ctx.session_id,
        }
    }

    pub fn get_participants(&self) -> Vec<UserId> {
        match self {
            SessionContext::Keygen(ctx) => ctx.get_participants(),
            SessionContext::Signing(_) => {
                // Signing sessions get participants from their state-owned musig processors
                vec![]
            }
        }
    }

    /// Whether `command` repeats a completed once-per-session stage. A repeat with
    /// different inputs is refused.
    pub fn check_command_idempotency(
        &self,
        command: &ProcessedCommand,
    ) -> Result<bool, EnclaveError> {
        let Some(current) = &command.exact_retry else {
            return Ok(false);
        };
        let command_history = match self {
            SessionContext::Keygen(ctx) => &ctx.command_history,
            SessionContext::Signing(ctx) => &ctx.command_history,
        };
        let previous = command_history
            .iter()
            .filter_map(|processed| processed.exact_retry.as_ref())
            .find(|previous| previous.stage == current.stage);
        match previous {
            None => Ok(false),
            Some(previous) if previous.digest == current.digest => Ok(true),
            Some(_) => Err(EnclaveError::Validation(
                keymeld_core::protocol::ValidationError::Other(
                    "Processed command retry contains different inputs".into(),
                ),
            )),
        }
    }

    /// Add a processed command to the history for idempotency tracking
    pub fn add_processed_command(&mut self, cmd: ProcessedCommand) {
        match self {
            SessionContext::Keygen(ctx) => ctx.command_history.push(cmd),
            SessionContext::Signing(ctx) => ctx.command_history.push(cmd),
        }
    }
}

impl KeygenSessionContext {
    pub fn get_participants(&self) -> Vec<UserId> {
        self.musig_processor
            .as_ref()
            .map(|processor| processor.get_session_metadata_public())
            .map(|metadata| metadata.participant_public_keys.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl SigningSessionContext {
    pub fn add_nonce(&mut self, user_id: UserId, nonce: Vec<u8>) -> Result<(), EnclaveError> {
        self.nonces.insert(user_id, nonce);
        Ok(())
    }

    pub fn add_partial_signature(
        &mut self,
        user_id: UserId,
        signature: Vec<u8>,
    ) -> Result<(), EnclaveError> {
        self.partial_signatures.insert(user_id, signature);
        Ok(())
    }
}

impl
    From<(
        &InitKeygenSessionCommand,
        &Arc<RwLock<EnclaveSharedContext>>,
    )> for KeygenSessionContext
{
    fn from(
        (cmd, enclave_ctx): (
            &InitKeygenSessionCommand,
            &Arc<RwLock<EnclaveSharedContext>>,
        ),
    ) -> Self {
        let mut ctx = KeygenSessionContext {
            recipient_authorization: None,
            session_id: cmd.keygen_session_id.clone(),
            created_at: SystemTime::now(),
            musig_processor: None,
            session_secret: None,
            coordinator_data: None,
            coordinator_user_id: None,
            encrypted_public_keys_for_response: Vec::new(),
            session_enclave_public_keys: BTreeMap::new(),
            command_history: Vec::new(),
        };

        // Decrypt session secret using enclave context
        if let Some(encrypted_secret) = &cmd.encrypted_session_secret {
            if let Ok(session_secret) =
                decrypt_session_secret_from_enclave(enclave_ctx, encrypted_secret)
            {
                ctx.session_secret = Some(session_secret);
            }
        }

        // Participant registration is the only authorized key import path.

        // Recipient keys are installed only by init_session after creator authorization.

        // Decrypt taproot tweak if we have a session secret
        let taproot_tweak = if let Some(ref session_secret) = ctx.session_secret {
            match EncryptedData::from_hex(&cmd.encrypted_taproot_tweak) {
                Ok(encrypted) => match session_secret.decrypt(&encrypted, "taproot_tweak") {
                    Ok(decrypted_bytes) => match serde_json::from_slice(&decrypted_bytes) {
                        Ok(tweak) => tweak,
                        Err(_) => keymeld_core::protocol::TaprootTweak::None,
                    },
                    Err(_) => keymeld_core::protocol::TaprootTweak::None,
                },
                Err(_) => keymeld_core::protocol::TaprootTweak::None,
            }
        } else {
            keymeld_core::protocol::TaprootTweak::None
        };

        // Initialize musig processor
        ctx.musig_processor = Some(MusigProcessor::new(
            &ctx.session_id,
            taproot_tweak,
            Some(cmd.expected_participant_count),
            cmd.expected_participants.clone(),
        ));

        ctx
    }
}

pub fn create_signing_session_context(
    cmd: &InitSigningSessionCommand,
    keygen_data: &KeygenSessionData<'_>,
) -> Result<SigningSessionContext, EnclaveError> {
    // Get the first batch item's encrypted message (single message = batch of 1)
    let first_batch_item = cmd.batch_items.first().ok_or_else(|| {
        EnclaveError::Session(keymeld_core::protocol::SessionError::MusigInitialization(
            "No batch items provided for signing".to_string(),
        ))
    })?;

    // Decrypt the message once using session_data context
    let decrypted_message_hex = keymeld_core::validation::decrypt_session_data(
        &first_batch_item.encrypted_message,
        &hex::encode(keygen_data.session_secret.as_bytes()),
    )
    .map_err(|e| {
        EnclaveError::Crypto(keymeld_core::protocol::CryptoError::DecryptionFailed {
            context: "session_data".to_string(),
            error: format!("Failed to decrypt message: {e}"),
        })
    })?;

    let decrypted_message = hex::decode(&decrypted_message_hex).map_err(|e| {
        EnclaveError::Crypto(keymeld_core::protocol::CryptoError::DecryptionFailed {
            context: "session_data".to_string(),
            error: format!("Hex decode failed: {e}"),
        })
    })?;

    Ok(SigningSessionContext {
        session_id: cmd.signing_session_id.clone(),
        created_at: SystemTime::now(),
        keygen_session_id: cmd.keygen_session_id.clone(),
        message: decrypted_message.clone(),
        message_hash: hash_message(&decrypted_message),
        session_secret: Some(keygen_data.session_secret.clone()),
        coordinator_data: keygen_data.coordinator_data.clone(),

        nonces: BTreeMap::new(),
        partial_signatures: BTreeMap::new(),
        session_enclave_public_keys: BTreeMap::new(),
        command_history: Vec::new(),
    })
}

pub fn decrypt_session_secret_from_enclave(
    enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    encrypted_secret: &str,
) -> Result<SessionSecret, EnclaveError> {
    let enclave = enclave_ctx.read().unwrap();

    let decrypted_bytes = enclave
        .decrypt_with_ecies(encrypted_secret, "session secret")
        .map_err(|e| {
            tracing::error!(
                "Session secret decryption failed for enclave {}: {}",
                enclave.enclave_id,
                e
            );
            e
        })?;

    if decrypted_bytes.len() != 32 {
        return Err(EnclaveError::Session(SessionError::InvalidSecretLength {
            actual: decrypted_bytes.len(),
        }));
    }

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&decrypted_bytes);
    Ok(SessionSecret::from_bytes(secret_array))
}

pub fn decrypt_coordinator_data_from_enclave(
    enclave_ctx: &Arc<RwLock<EnclaveSharedContext>>,
    encrypted_private_key: &str,
    coordinator_user_id: &UserId,
) -> Result<CoordinatorData, EnclaveError> {
    let enclave = enclave_ctx.read().unwrap();
    let decrypted_key = enclave.decrypt_private_key_from_coordinator(encrypted_private_key)?;

    Ok(CoordinatorData {
        user_id: coordinator_user_id.clone(),
        private_key: KeyMaterial::new(decrypted_key),
    })
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    use crate::operations::registration::tests::fixture;
    use keymeld_core::{
        authorization::EnclaveRecipientAuthorization,
        escrow::{
            protocol::{EscrowCommand, Operation, Payload, RequestContext},
            ApplicationContext, EscrowContext,
        },
        protocol::{DistributeNoncesCommand, FinalizeSignatureCommand, SigningCommand},
    };

    fn nonce_command(session: &SessionId, value: &str) -> EnclaveCommand {
        EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::DistributeNonces(
            DistributeNoncesCommand {
                signing_session_id: session.clone(),
                nonces: vec![(UserId::new_v7(), value.into())],
            },
        )))
    }

    fn processed(command: &EnclaveCommand) -> ProcessedCommand {
        ProcessedCommand::new(uuid::Uuid::now_v7(), command).unwrap()
    }

    #[test]
    fn large_escrow_requests_keep_only_their_command_id() {
        let session = SessionId::new_v7();
        let command =
            EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(EscrowCommand {
                context: RequestContext {
                    schema_version: keymeld_core::escrow::SCHEMA_VERSION,
                    operation: Operation::Bind,
                    escrow: EscrowContext {
                        keygen_session_id: session.clone(),
                        user_id: UserId::new_v7(),
                        escrow_id: uuid::Uuid::now_v7(),
                        manifest_digest: [1; 32],
                        application: ApplicationContext::commit("test".into(), 1, b"policy")
                            .unwrap(),
                    },
                    policy_digest: [2; 32],
                    request_id: uuid::Uuid::now_v7(),
                    action_id: None,
                    attempt: None,
                    keygen_session_id: None,
                },
                encrypted_request: Payload::new(vec![42; 6 * 1024 * 1024]).unwrap(),
                authorization: vec![3; 64],
            })));
        let mut context = SessionContext::new_keygen(session);
        let ids: Vec<_> = (0..16).map(|_| uuid::Uuid::now_v7()).collect();
        for id in &ids {
            let processed = ProcessedCommand::new(*id, &command).unwrap();
            // No stage means no digest: the payload was never serialized or hashed.
            assert!(processed.exact_retry.is_none());
            assert!(!context.check_command_idempotency(&processed).unwrap());
            context.add_processed_command(processed);
        }
        let SessionContext::Keygen(context) = context else {
            unreachable!()
        };
        let kept: Vec<_> = context
            .command_history
            .iter()
            .map(|processed| processed.command_id)
            .collect();
        assert_eq!(kept, ids);
        assert!(std::mem::size_of::<ProcessedCommand>() <= 64);
        assert!(
            context.command_history.capacity() * std::mem::size_of::<ProcessedCommand>() <= 2048
        );
    }

    #[test]
    fn a_stage_digest_covers_the_canonical_command_encoding() {
        let command = nonce_command(&SessionId::new_v7(), &"n".repeat(1024 * 1024));
        let digest = processed(&command).exact_retry.unwrap().digest;
        assert_eq!(
            digest.as_slice(),
            Sha256::digest(bincode::serialize(&command).unwrap()).as_slice()
        );
    }

    #[test]
    fn an_exact_retry_of_a_completed_stage_is_accepted() {
        let session = SessionId::new_v7();
        let command = nonce_command(&session, "encrypted-nonce");
        let mut context = SessionContext::new_signing(session, SessionId::new_v7(), vec![1; 32]);
        assert!(!context
            .check_command_idempotency(&processed(&command))
            .unwrap());
        context.add_processed_command(processed(&command));
        assert!(context
            .check_command_idempotency(&processed(&command))
            .unwrap());
    }

    #[test]
    fn changed_nonce_or_session_is_rejected_before_reusing_stage_output() {
        let session = SessionId::new_v7();
        let command = nonce_command(&session, "original-encrypted-nonce");
        let mut context = SessionContext::new_signing(session, SessionId::new_v7(), vec![1; 32]);
        context.add_processed_command(processed(&command));
        for change_session in [false, true] {
            let mut changed = command.clone();
            let EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::DistributeNonces(
                ref mut inner,
            ))) = changed
            else {
                unreachable!()
            };
            if change_session {
                inner.signing_session_id = SessionId::new_v7();
            } else {
                inner.nonces[0].1 = "substituted-encrypted-nonce".into();
            }
            assert!(context
                .check_command_idempotency(&processed(&changed))
                .is_err());
        }
    }

    #[test]
    fn changed_partial_signatures_are_rejected_and_next_stage_is_not_a_retry() {
        let session = SessionId::new_v7();
        let nonce = nonce_command(&session, "encrypted-nonce");
        let original = EnclaveCommand::Musig(MusigCommand::Signing(
            SigningCommand::FinalizeSignature(FinalizeSignatureCommand {
                signing_session_id: session.clone(),
                partial_signatures: vec![(UserId::new_v7(), "encrypted-partial".into())],
            }),
        ));
        let mut context = SessionContext::new_signing(session, SessionId::new_v7(), vec![1; 32]);
        context.add_processed_command(processed(&nonce));
        assert!(!context
            .check_command_idempotency(&processed(&original))
            .unwrap());
        context.add_processed_command(processed(&original));
        let mut changed = original;
        let EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::FinalizeSignature(
            ref mut inner,
        ))) = changed
        else {
            unreachable!()
        };
        inner.partial_signatures.clear();
        assert!(context
            .check_command_idempotency(&processed(&changed))
            .is_err());
    }

    #[test]
    fn a_keygen_start_is_replayed_only_with_its_original_inputs() {
        let session = SessionId::new_v7();
        let start = EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::InitSession(
            InitKeygenSessionCommand {
                recipient_authorization: Box::new(EnclaveRecipientAuthorization {
                    keygen_session_id: session.clone(),
                    manifest_hash: vec![1; 32],
                    user_enclave_assignments: BTreeMap::new(),
                    recipient_public_keys: BTreeMap::new(),
                    signature: vec![2; 64],
                }),
                keygen_session_id: session.clone(),
                authorization_manifest: Box::new(fixture().manifest),
                coordinator_encrypted_private_key: None,
                coordinator_user_id: None,
                encrypted_session_secret: Some("encrypted-session-secret".into()),
                timeout_secs: 300,
                expected_participant_count: 1,
                expected_participants: vec![UserId::new_v7()],
                enclave_public_keys: Vec::new(),
                encrypted_taproot_tweak: "encrypted-tweak".into(),
                subset_definitions: Vec::new(),
            },
        )));
        let mut context = SessionContext::new_keygen(session);
        assert!(!context
            .check_command_idempotency(&processed(&start))
            .unwrap());
        context.add_processed_command(processed(&start));
        // A redelivery under another command id is still the same start.
        assert!(context
            .check_command_idempotency(&processed(&start))
            .unwrap());
        let mut changed = start;
        let EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::InitSession(ref mut inner))) =
            changed
        else {
            unreachable!()
        };
        inner.expected_participant_count = 2;
        assert!(context
            .check_command_idempotency(&processed(&changed))
            .is_err());
    }
}
