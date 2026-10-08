use super::keygen_data::KeygenSessionData;
use crate::musig::MusigProcessor;
use crate::operations::{context::EnclaveSharedContext, states::signing::CoordinatorData};
use keymeld_core::protocol::{
    EnclaveCommandKind, KeygenCommand, KeygenCommandKind, MusigCommand, MusigCommandKind,
    SigningCommandKind,
};
use keymeld_core::{
    crypto::{EncryptedData, SessionSecret},
    identifiers::{SessionId, UserId},
    protocol::{
        Command, EnclaveCommand, EnclaveError, EncryptedParticipantPublicKey,
        InitKeygenSessionCommand, InitSigningSessionCommand, SessionError,
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
/// The digest covers the same canonical command bytes previously compared on every retry.
#[derive(Debug)]
pub struct ProcessedCommand {
    pub command_id: uuid::Uuid,
    kind: EnclaveCommandKind,
    user: Option<UserId>,
    digest: [u8; 32],
}

impl ProcessedCommand {
    pub fn new(command_id: uuid::Uuid, command: &EnclaveCommand) -> Result<Self, EnclaveError> {
        Ok(Self {
            command_id,
            kind: command.kind(),
            user: match command {
                EnclaveCommand::Musig(MusigCommand::Keygen(command)) => command.user_id(),
                _ => None,
            },
            digest: command_digest(command)?,
        })
    }
}

impl TryFrom<Command> for ProcessedCommand {
    type Error = EnclaveError;

    fn try_from(command: Command) -> Result<Self, Self::Error> {
        Self::new(command.command_id, &command.command)
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
    // so hashing a large escrow payload does not update SHA-256 once per byte.
    let mut writer = std::io::BufWriter::new(HashWriter(Sha256::new()));
    bincode::serialize_into(&mut writer, command).map_err(|_| invalid())?;
    Ok(writer
        .into_inner()
        .map_err(|_| invalid())?
        .0
        .finalize()
        .into())
}

/// A completed protocol stage may be replayed only with its original inputs.
/// Comparing command kind alone can hide a changed nonce or signing transcript.
fn verify_exact_retry(
    current: &EnclaveCommand,
    previous: &ProcessedCommand,
) -> Result<bool, EnclaveError> {
    if command_digest(current)? != previous.digest {
        return Err(EnclaveError::Validation(
            keymeld_core::protocol::ValidationError::Other(
                "Processed command retry contains different inputs".into(),
            ),
        ));
    }
    Ok(true)
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

    /// Check if a command is idempotent based on MuSig command idempotency rules
    pub fn check_command_idempotency(&self, cmd: &EnclaveCommand) -> Result<bool, EnclaveError> {
        let command_history = match self {
            SessionContext::Keygen(ctx) => &ctx.command_history,
            SessionContext::Signing(ctx) => &ctx.command_history,
        };

        match cmd {
            EnclaveCommand::Musig(musig_cmd) => {
                match musig_cmd {
                    // Musig Signing: Once per session (check: command type + session ID)
                    MusigCommand::Signing(signing_cmd) => {
                        let signing_kind: SigningCommandKind = signing_cmd.into();
                        for processed_cmd in command_history {
                            if let EnclaveCommandKind::Musig(MusigCommandKind::Signing(prev_kind)) =
                                &processed_cmd.kind
                            {
                                if signing_kind == *prev_kind {
                                    return verify_exact_retry(cmd, processed_cmd);
                                }
                            }
                        }
                        Ok(false)
                    }

                    // Keygen Init: Once per session (check: command type + session ID)
                    MusigCommand::Keygen(KeygenCommand::InitSession(_)) => {
                        for processed_cmd in command_history {
                            if let EnclaveCommandKind::Musig(MusigCommandKind::Keygen(
                                KeygenCommandKind::InitSession,
                            )) = &processed_cmd.kind
                            {
                                return verify_exact_retry(cmd, processed_cmd);
                            }
                        }
                        Ok(false)
                    }

                    // Keygen Others: Once per user per session (check: command type + user ID + session ID)
                    MusigCommand::Keygen(keygen_cmd) => {
                        let current_user = keygen_cmd.user_id();
                        let keygen_kind: KeygenCommandKind = keygen_cmd.into();

                        for processed_cmd in command_history {
                            if let EnclaveCommandKind::Musig(MusigCommandKind::Keygen(prev_kind)) =
                                &processed_cmd.kind
                            {
                                if keygen_kind == *prev_kind {
                                    if let Some(prev_user) = &processed_cmd.user {
                                        if current_user.as_ref() == Some(prev_user) {
                                            return verify_exact_retry(cmd, processed_cmd);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(false)
                    }
                }
            }

            // System commands are handled at operator level, not here
            EnclaveCommand::Confidential(_) => Ok(false),
            EnclaveCommand::System(_) => Ok(false),
            // UserKey commands will be handled separately (not session-based)
            EnclaveCommand::UserKey(_) => Ok(false),
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

    pub fn check_command_idempotency(&self, cmd: &EnclaveCommand) -> Result<bool, EnclaveError> {
        match cmd {
            EnclaveCommand::Musig(musig_cmd) => {
                match musig_cmd {
                    // Musig Signing: Once per session (check: command type + session ID)
                    MusigCommand::Signing(signing_cmd) => {
                        let signing_kind: SigningCommandKind = signing_cmd.into();
                        for processed_cmd in &self.command_history {
                            if let EnclaveCommandKind::Musig(MusigCommandKind::Signing(prev_kind)) =
                                &processed_cmd.kind
                            {
                                if signing_kind == *prev_kind {
                                    return verify_exact_retry(cmd, processed_cmd);
                                }
                            }
                        }
                        Ok(false)
                    }
                    _ => Ok(false), // Other MuSig commands not relevant for signing sessions
                }
            }
            EnclaveCommand::Confidential(_) => Ok(false),
            EnclaveCommand::System(_) => Ok(false), // System commands handled at operator level
            EnclaveCommand::UserKey(_) => Ok(false), // UserKey commands handled separately
        }
    }

    /// Add a processed command to the history for idempotency tracking
    pub fn add_processed_command(&mut self, cmd: ProcessedCommand) {
        self.command_history.push(cmd);
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
    use keymeld_core::protocol::{
        DistributeNoncesCommand, FinalizeSignatureCommand, SigningCommand,
    };

    fn nonce_command(session: &SessionId, value: &str) -> EnclaveCommand {
        EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::DistributeNonces(
            DistributeNoncesCommand {
                signing_session_id: session.clone(),
                nonces: vec![(UserId::new_v7(), value.into())],
            },
        )))
    }

    #[test]
    fn large_escrow_requests_retain_only_bounded_retry_metadata() {
        use keymeld_core::escrow::{
            protocol::{EscrowCommand, Operation, Payload, RequestContext},
            ApplicationContext, EscrowContext,
        };
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
        // The streaming digest covers exactly the old comparison's encoding.
        let encoded = bincode::serialize(&command).unwrap();
        assert_eq!(
            command_digest(&command).unwrap().as_slice(),
            Sha256::digest(&encoded).as_slice()
        );
        drop(encoded);
        let mut context = SessionContext::new_keygen(session);
        let ids: Vec<_> = (0..16).map(|_| uuid::Uuid::now_v7()).collect();
        for id in &ids {
            context.add_processed_command(ProcessedCommand::new(*id, &command).unwrap());
        }
        let SessionContext::Keygen(context) = context else {
            unreachable!()
        };
        assert_eq!(context.command_history.len(), ids.len());
        assert!(std::mem::size_of::<ProcessedCommand>() <= 128);
        assert!(
            context.command_history.capacity() * std::mem::size_of::<ProcessedCommand>() <= 4096
        );
        for (processed, id) in context.command_history.iter().zip(ids) {
            assert_eq!(processed.command_id, id);
            assert!(verify_exact_retry(&command, processed).unwrap());
        }
        let mut changed = command;
        let EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(ref mut escrow))) =
            changed
        else {
            unreachable!()
        };
        escrow.authorization[0] ^= 1;
        assert!(verify_exact_retry(&changed, &context.command_history[0]).is_err());
    }

    #[test]
    fn exact_retry_is_accepted_by_both_context_entrypoints() {
        let session = SessionId::new_v7();
        let command = nonce_command(&session, "encrypted-nonce");
        let mut context = SessionContext::new_signing(session, SessionId::new_v7(), vec![1; 32]);
        assert!(!context.check_command_idempotency(&command).unwrap());
        context.add_processed_command(Command::new(command.clone()).try_into().unwrap());
        assert!(context.check_command_idempotency(&command).unwrap());
        let SessionContext::Signing(signing) = context else {
            unreachable!()
        };
        assert!(signing.check_command_idempotency(&command).unwrap());
    }

    #[test]
    fn changed_nonce_or_session_is_rejected_before_reusing_stage_output() {
        let session = SessionId::new_v7();
        let command = nonce_command(&session, "original-encrypted-nonce");
        let mut context = SessionContext::new_signing(session, SessionId::new_v7(), vec![1; 32]);
        context.add_processed_command(Command::new(command.clone()).try_into().unwrap());
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
            assert!(context.check_command_idempotency(&changed).is_err());
            let SessionContext::Signing(ref signing) = context else {
                unreachable!()
            };
            assert!(signing.check_command_idempotency(&changed).is_err());
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
        context.add_processed_command(Command::new(nonce).try_into().unwrap());
        assert!(!context.check_command_idempotency(&original).unwrap());
        context.add_processed_command(Command::new(original.clone()).try_into().unwrap());
        let mut changed = original;
        let EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::FinalizeSignature(
            ref mut inner,
        ))) = changed
        else {
            unreachable!()
        };
        inner.partial_signatures.clear();
        assert!(context.check_command_idempotency(&changed).is_err());
    }
}
