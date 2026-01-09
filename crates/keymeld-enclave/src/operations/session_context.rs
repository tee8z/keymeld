use super::keygen_data::KeygenSessionData;
use crate::musig::MusigProcessor;
use crate::operations::{context::EnclaveSharedContext, states::signing::CoordinatorData};
use keymeld_core::protocol::{KeygenCommand, KeygenCommandKind, MusigCommand, SigningCommandKind};
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
    pub session_id: SessionId,
    pub created_at: SystemTime,
    pub musig_processor: Option<MusigProcessor>,
    pub session_secret: Option<SessionSecret>,
    pub coordinator_data: Option<CoordinatorData>,
    pub encrypted_public_keys_for_response: Vec<EncryptedParticipantPublicKey>,
    pub session_enclave_public_keys: BTreeMap<EnclaveId, String>, // Other enclaves in this session
    pub command_history: Vec<Command>, // Track processed commands for idempotency
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
    pub command_history: Vec<Command>, // Track processed commands for idempotency
}

impl SessionContext {
    pub fn new_keygen(session_id: SessionId) -> Self {
        Self::Keygen(Box::new(KeygenSessionContext {
            session_id,
            created_at: SystemTime::now(),
            musig_processor: None,
            session_secret: None,
            coordinator_data: None,
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
                            if let EnclaveCommand::Musig(MusigCommand::Signing(prev_signing)) =
                                &processed_cmd.command
                            {
                                if signing_kind == prev_signing.into() {
                                    return Ok(true); // Already processed this type of signing command
                                }
                            }
                        }
                        Ok(false)
                    }

                    // Keygen Init: Once per session (check: command type + session ID)
                    MusigCommand::Keygen(KeygenCommand::InitSession(_)) => {
                        for processed_cmd in command_history {
                            if let EnclaveCommand::Musig(MusigCommand::Keygen(
                                KeygenCommand::InitSession(_),
                            )) = &processed_cmd.command
                            {
                                return Ok(true); // Already processed init keygen command
                            }
                        }
                        Ok(false)
                    }

                    // Keygen Others: Once per user per session (check: command type + user ID + session ID)
                    MusigCommand::Keygen(keygen_cmd) => {
                        let current_user = keygen_cmd.user_id();
                        let keygen_kind: KeygenCommandKind = keygen_cmd.into();

                        for processed_cmd in command_history {
                            if let EnclaveCommand::Musig(MusigCommand::Keygen(prev_keygen)) =
                                &processed_cmd.command
                            {
                                let prev_kind: KeygenCommandKind = prev_keygen.into();
                                if keygen_kind == prev_kind {
                                    if let Some(prev_user) = prev_keygen.user_id() {
                                        if current_user == Some(prev_user) {
                                            return Ok(true); // Already processed this command type for this user
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
            EnclaveCommand::System(_) => Ok(false),
            // UserKey commands will be handled separately (not session-based)
            EnclaveCommand::UserKey(_) => Ok(false),
        }
    }

    /// Add a processed command to the history for idempotency tracking
    pub fn add_processed_command(&mut self, cmd: Command) {
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
                            if let EnclaveCommand::Musig(MusigCommand::Signing(prev_signing)) =
                                &processed_cmd.command
                            {
                                if signing_kind == prev_signing.into() {
                                    return Ok(true); // Already processed this type of signing command
                                }
                            }
                        }
                        Ok(false)
                    }
                    _ => Ok(false), // Other MuSig commands not relevant for signing sessions
                }
            }
            EnclaveCommand::System(_) => Ok(false), // System commands handled at operator level
            EnclaveCommand::UserKey(_) => Ok(false), // UserKey commands handled separately
        }
    }

    /// Add a processed command to the history for idempotency tracking
    pub fn add_processed_command(&mut self, cmd: Command) {
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
            session_id: cmd.keygen_session_id.clone(),
            created_at: SystemTime::now(),
            musig_processor: None,
            session_secret: None,
            coordinator_data: None,
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

        // Decrypt coordinator private key
        if let Some(encrypted_key) = &cmd.coordinator_encrypted_private_key {
            if let Some(coordinator_user_id) = &cmd.coordinator_user_id {
                if let Ok(coordinator_data) = decrypt_coordinator_data_from_enclave(
                    enclave_ctx,
                    encrypted_key,
                    coordinator_user_id,
                ) {
                    ctx.coordinator_data = Some(coordinator_data);
                }
            }
        }

        // Store session participant enclave public keys in session context
        for enclave_key_info in &cmd.enclave_public_keys {
            ctx.session_enclave_public_keys.insert(
                enclave_key_info.enclave_id,
                enclave_key_info.public_key.clone(),
            );
        }

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
            vec![], // Empty message for keygen
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
