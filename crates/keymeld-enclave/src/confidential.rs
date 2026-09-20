//! Confidential client transport and downgrade protection. Plaintext commands
//! enter the native state machine only after enclave-side authentication.
use crate::operator::EnclaveOperator;
use keymeld_core::{
    confidential::{ConfidentialRequest, ConfidentialResponse, EnclaveEnvelope},
    protocol::{
        Command, EnclaveCommand, EnclaveError, EnclaveOutcome, ErrorResponse, KeygenCommand,
        MusigCommand, Outcome, SigningCommand, SystemCommand, UserKeyCommand, ValidationError,
    },
    SessionId,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, Weak},
};
use tracing::instrument::WithSubscriber;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_SESSIONS: usize = 4096;
const MAX_REPLAYS: usize = 16384;
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn rejected() -> EnclaveError {
    EnclaveError::Validation(ValidationError::Other(
        "Confidential transport request rejected".into(),
    ))
}

#[derive(Clone)]
struct SessionOwner {
    creator_key: Vec<u8>,
    signing_key: Vec<u8>,
    route_id: Uuid,
}
impl SessionOwner {
    fn allows(&self, request: &ConfidentialRequest) -> bool {
        self.route_id == request.header.opaque_route_id
            && (request.authority_public_key == self.creator_key
                || request.authority_public_key == self.signing_key)
    }
}

struct CachedResponse {
    request_digest: [u8; 32],
    response: EnclaveEnvelope,
    last_access: u64,
}

#[derive(Default)]
struct State {
    owners: BTreeMap<SessionId, SessionOwner>,
    replies: BTreeMap<(Vec<u8>, String), CachedResponse>,
    reply_bytes: usize,
    access_counter: u64,
}

impl State {
    fn cache_response(
        &mut self,
        request_key: (Vec<u8>, String),
        digest: [u8; 32],
        response: EnclaveEnvelope,
        max_entries: usize,
        max_bytes: usize,
    ) {
        if max_entries == 0 || response.ciphertext.len() > max_bytes {
            return;
        }
        if let Some(previous) = self.replies.remove(&request_key) {
            self.reply_bytes = self
                .reply_bytes
                .saturating_sub(previous.response.ciphertext.len());
        }
        // Correlation IDs commit to the blinded full request. Eviction cannot
        // permit changed inputs under an old ID, while native command history
        // and escrow receipts prevent repeating effects on an exact retry.
        // Cached ciphertext is only a response optimization, never admission.
        while self.replies.len() >= max_entries
            || self.reply_bytes.saturating_add(response.ciphertext.len()) > max_bytes
        {
            let Some(oldest) = self
                .replies
                .iter()
                .min_by_key(|(_, value)| value.last_access)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            let removed = self.replies.remove(&oldest).expect("selected cached reply");
            self.reply_bytes = self
                .reply_bytes
                .saturating_sub(removed.response.ciphertext.len());
        }
        self.access_counter = self.access_counter.saturating_add(1);
        let access = self.access_counter;
        self.reply_bytes += response.ciphertext.len();
        self.replies.insert(
            request_key,
            CachedResponse {
                request_digest: digest,
                response,
                last_access: access,
            },
        );
    }
}

#[derive(Default)]
pub(crate) struct ConfidentialDispatcher {
    state: Mutex<State>,
    locks: Mutex<BTreeMap<SessionId, Weak<tokio::sync::Mutex<()>>>>,
}

impl ConfidentialDispatcher {
    /// Serialize transitions for one native session, including legacy traffic.
    /// The global registry lock is never held during verification or network work.
    pub(crate) async fn lock(
        &self,
        session: &SessionId,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, EnclaveError> {
        let gate = {
            let mut gates = self.locks.lock().map_err(|_| rejected())?;
            gates.retain(|_, value| value.strong_count() > 0);
            if let Some(gate) = gates.get(session).and_then(Weak::upgrade) {
                gate
            } else {
                if gates.len() >= MAX_SESSIONS {
                    return Err(rejected());
                }
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                gates.insert(session.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        Ok(gate.lock_owned().await)
    }

    pub(crate) fn reject_legacy(&self, command: &EnclaveCommand) -> Result<(), EnclaveError> {
        let state = self.state.lock().map_err(|_| rejected())?;
        let ids = referenced_sessions(command);
        if ids.iter().any(|id| state.owners.contains_key(id)) {
            return Err(rejected());
        }
        // Generic escrow always uses the private dispatch. This also prevents a
        // host from submitting an unprotected escrow command after a restart.
        if matches!(
            command,
            EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(_)))
        ) {
            return Err(rejected());
        }
        Ok(())
    }
}

/// All session references must be considered, not just the primary command ID.
pub(crate) fn referenced_sessions(command: &EnclaveCommand) -> Vec<SessionId> {
    match command {
        EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::InitSession(cmd))) => vec![
            cmd.keygen_session_id.clone(),
            cmd.signing_session_id.clone(),
        ],
        EnclaveCommand::System(SystemCommand::CheckKeygenSession {
            keygen_session_id, ..
        }) => vec![keygen_session_id.clone()],
        EnclaveCommand::System(SystemCommand::ValidateRegistration(cmd)) => vec![cmd
            .authorization_manifest
            .manifest
            .keygen_session_id
            .clone()],
        EnclaveCommand::System(SystemCommand::ClearSession(cmd)) => cmd
            .keygen_session_id
            .iter()
            .chain(cmd.signing_session_id.iter())
            .cloned()
            .collect(),
        EnclaveCommand::UserKey(UserKeyCommand::StoreKeyFromKeygen(cmd)) => {
            vec![cmd.keygen_session_id.clone()]
        }
        EnclaveCommand::UserKey(UserKeyCommand::RestoreKey(cmd)) => {
            cmd.origin_keygen_session_id.iter().cloned().collect()
        }
        _ => command.session_id().ok().into_iter().collect(),
    }
}

impl EnclaveOperator {
    pub(crate) async fn handle_confidential(
        &self,
        outer: Command,
        envelope: &EnclaveEnvelope,
    ) -> Result<Outcome, EnclaveError> {
        if envelope.destination_enclave != self.enclave_id {
            return Err(rejected());
        }
        let secret_bytes = Zeroizing::new(
            <[u8; 32]>::try_from(self.private_key.read().map_err(|_| rejected())?.as_slice())
                .map_err(|_| rejected())?,
        );
        let secret =
            secp256k1::SecretKey::from_byte_array(*secret_bytes).map_err(|_| rejected())?;
        let request =
            ConfidentialRequest::decrypt(envelope, &secret, self.confidential_key_epoch())
                .map_err(|_| rejected())?;
        // From this point every command/authorization failure is encrypted to the
        // authenticated response key. Outer failures contain no private detail.
        let response = match self.dispatch_confidential(&request, &secret_bytes).await {
            Ok(response) => response,
            Err(error) => ConfidentialResponse::encrypt(
                &request,
                Outcome::new(
                    request.command.clone(),
                    EnclaveOutcome::Error(ErrorResponse { error }),
                ),
                &secret_bytes,
            )
            .map_err(|_| rejected())?,
        };
        Ok(Outcome::new(
            outer,
            EnclaveOutcome::Confidential(Box::new(response)),
        ))
    }

    async fn dispatch_confidential(
        &self,
        request: &ConfidentialRequest,
        enclave_secret: &[u8; 32],
    ) -> Result<EnclaveEnvelope, EnclaveError> {
        if matches!(
            request.command.command,
            EnclaveCommand::System(SystemCommand::DescribeEscrowVerifiers)
        ) {
            let outcome = self
                .handle_native_command(request.command.clone(), true)
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .unwrap_or_else(|error| {
                    Outcome::new(
                        request.command.clone(),
                        EnclaveOutcome::Error(ErrorResponse { error }),
                    )
                });
            return ConfidentialResponse::encrypt(request, outcome, enclave_secret)
                .map_err(|_| rejected());
        }
        let mut ids = referenced_sessions(&request.command.command);
        if ids.is_empty() {
            return Err(rejected());
        }
        // Use one stable order even for rejected cross-session commands.
        ids.sort();
        ids.dedup();
        let mut _session_gates = Vec::with_capacity(ids.len());
        for id in &ids {
            _session_gates.push(self.confidential.lock(id).await?);
        }
        if matches!(
            request.command.command,
            EnclaveCommand::System(SystemCommand::CheckKeygenSession { .. })
        ) {
            {
                let state = self.confidential.state.lock().map_err(|_| rejected())?;
                self.authorize_confidential(&state, request)?;
            }
            let outcome = self
                .handle_native_command(request.command.clone(), true)
                .with_subscriber(tracing::subscriber::NoSubscriber::default())
                .await
                .unwrap_or_else(|error| {
                    Outcome::new(
                        request.command.clone(),
                        EnclaveOutcome::Error(ErrorResponse { error }),
                    )
                });
            // Presence probes have no effects and use fresh client challenges;
            // they must not consume the durable command replay budget.
            return ConfidentialResponse::encrypt(request, outcome, enclave_secret)
                .map_err(|_| rejected());
        }
        let digest = request.digest().map_err(|_| rejected())?;
        let request_key = (
            request.authority_public_key.clone(),
            request.header.correlation_id.clone(),
        );
        let new_owner = {
            let mut state = self.confidential.state.lock().map_err(|_| rejected())?;
            state.access_counter = state.access_counter.saturating_add(1);
            let access = state.access_counter;
            if let Some(cached) = state.replies.get_mut(&request_key) {
                cached.last_access = access;
                return if cached.request_digest == digest {
                    Ok(cached.response.clone())
                } else {
                    Err(rejected())
                };
            }
            self.authorize_confidential(&state, request)?
        };
        let outcome = self
            .handle_native_command(request.command.clone(), true)
            .with_subscriber(tracing::subscriber::NoSubscriber::default())
            .await;
        let success = outcome
            .as_ref()
            .is_ok_and(|outcome| !matches!(outcome.response, EnclaveOutcome::Error(_)));
        if let Some((id, owner)) = new_owner {
            if success {
                // Install before response serialization/encryption: an output
                // failure must never leave admitted confidential state public.
                self.confidential
                    .state
                    .lock()
                    .map_err(|_| rejected())?
                    .owners
                    .insert(id, owner);
            } else {
                // Failed initial admission cannot reserve an existing session
                // or leave a half-created native state to block a valid retry.
                self.sessions.remove(&id);
            }
        }
        let outcome = outcome.unwrap_or_else(|error| {
            Outcome::new(
                request.command.clone(),
                EnclaveOutcome::Error(ErrorResponse { error }),
            )
        });
        let response = ConfidentialResponse::encrypt(request, outcome, enclave_secret)
            .map_err(|_| rejected())?;
        let mut state = self.confidential.state.lock().map_err(|_| rejected())?;
        state.cache_response(
            request_key,
            digest,
            response.clone(),
            MAX_REPLAYS,
            MAX_REPLAY_BYTES,
        );
        drop(state);
        Ok(response)
    }

    fn authorize_confidential(
        &self,
        state: &State,
        request: &ConfidentialRequest,
    ) -> Result<Option<(SessionId, SessionOwner)>, EnclaveError> {
        let require_owner = |id: &SessionId| -> Result<SessionOwner, EnclaveError> {
            let owner = state.owners.get(id).ok_or_else(rejected)?;
            if !owner.allows(request) {
                return Err(rejected());
            }
            Ok(owner.clone())
        };
        match &request.command.command {
            EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::InitSession(cmd))) => {
                cmd.authorization_manifest
                    .verify()
                    .map_err(|_| rejected())?;
                cmd.recipient_authorization
                    .verify(&cmd.authorization_manifest)
                    .map_err(|_| rejected())?;
                if cmd.keygen_session_id != cmd.authorization_manifest.manifest.keygen_session_id
                    || request.authority_public_key
                        != cmd.authorization_manifest.manifest.creator_pubkey
                    || cmd
                        .recipient_authorization
                        .recipient_public_keys
                        .get(&self.enclave_id)
                        != Some(&request.enclave_public_key)
                {
                    return Err(rejected());
                }
                if state.owners.contains_key(&cmd.keygen_session_id) {
                    require_owner(&cmd.keygen_session_id)?;
                    return Ok(None);
                }
                if self.sessions.contains_key(&cmd.keygen_session_id)
                    || state.owners.len() >= MAX_SESSIONS
                {
                    return Err(rejected());
                }
                Ok(Some((
                    cmd.keygen_session_id.clone(),
                    SessionOwner {
                        creator_key: cmd.authorization_manifest.manifest.creator_pubkey.clone(),
                        signing_key: cmd.authorization_manifest.manifest.signing_pubkey.clone(),
                        route_id: request.header.opaque_route_id,
                    },
                )))
            }
            EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::InitSession(cmd))) => {
                if cmd.keygen_session_id == cmd.signing_session_id {
                    return Err(rejected());
                }
                let owner = require_owner(&cmd.keygen_session_id)?;
                if let Some(existing) = state.owners.get(&cmd.signing_session_id) {
                    if existing.creator_key != owner.creator_key
                        || existing.signing_key != owner.signing_key
                        || !existing.allows(request)
                    {
                        return Err(rejected());
                    }
                    return Ok(None);
                }
                if self.sessions.contains_key(&cmd.signing_session_id)
                    || state.owners.len() >= MAX_SESSIONS
                {
                    return Err(rejected());
                }
                Ok(Some((cmd.signing_session_id.clone(), owner)))
            }
            EnclaveCommand::Musig(_) => {
                require_owner(&request.command.command.session_id()?)?;
                Ok(None)
            }
            EnclaveCommand::System(SystemCommand::CheckKeygenSession {
                keygen_session_id,
                recipient_authorization,
            }) => {
                if state.owners.contains_key(keygen_session_id) {
                    require_owner(keygen_session_id)?;
                } else {
                    // A restart probe authenticates the creator even before
                    // the native session has been restored.
                    if self.sessions.contains_key(keygen_session_id)
                        || recipient_authorization.keygen_session_id != *keygen_session_id
                        || recipient_authorization
                            .recipient_public_keys
                            .get(&self.enclave_id)
                            != Some(&request.enclave_public_key)
                    {
                        return Err(rejected());
                    }
                    keymeld_core::authorization::verify_authorization(
                        &request.authority_public_key,
                        "enclave-recipients",
                        &(
                            &recipient_authorization.keygen_session_id,
                            &recipient_authorization.manifest_hash,
                            &recipient_authorization.user_enclave_assignments,
                            &recipient_authorization.recipient_public_keys,
                        ),
                        &recipient_authorization.signature,
                    )
                    .map_err(|_| rejected())?;
                }
                Ok(None)
            }
            EnclaveCommand::System(SystemCommand::ValidateRegistration(cmd)) => {
                cmd.authorization_manifest
                    .verify()
                    .map_err(|_| rejected())?;
                let manifest = &cmd.authorization_manifest.manifest;
                let invited = manifest.participant_verifiers.get(&cmd.participant.user_id);
                if request.authority_public_key != manifest.creator_pubkey
                    && request.authority_public_key != manifest.signing_pubkey
                    && invited != Some(&request.authority_public_key)
                {
                    return Err(rejected());
                }
                Ok(None)
            }
            // System configuration, clear-session, key export and nested envelopes
            // cannot be smuggled through this unprivileged client API.
            _ => Err(rejected()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymeld_core::{
        confidential::{RoutingHeader, TRANSPORT_VERSION},
        identifiers::EnclaveId,
        protocol::{ClearSessionCommand, SystemOutcome},
    };
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn public(secret: u8) -> Vec<u8> {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array([secret; 32]).unwrap(),
        )
        .serialize()
        .to_vec()
    }
    fn operator() -> EnclaveOperator {
        let operator = EnclaveOperator::new(EnclaveId::new(1)).unwrap();
        *operator.private_key.write().unwrap() = vec![2; 32];
        *operator.public_key.write().unwrap() = public(2);
        operator
    }
    fn prepare(command: Command, route_id: Uuid, authority: u8) -> (ConfidentialRequest, Command) {
        let request = ConfidentialRequest::sign(
            RoutingHeader {
                transport_version: TRANSPORT_VERSION,
                destination_enclave: EnclaveId::new(1),
                opaque_route_id: route_id,
                correlation_id: String::new(),
            },
            public(2),
            1,
            &[authority; 32],
            public(4),
            command,
        )
        .unwrap();
        let outer = Command::new(EnclaveCommand::Confidential(Box::new(
            request.encrypt().unwrap(),
        )));
        (request, outer)
    }
    fn read_response(outcome: Outcome, request: &ConfidentialRequest) -> EnclaveOutcome {
        let EnclaveOutcome::Confidential(envelope) = outcome.response else {
            panic!("unencrypted outcome")
        };
        ConfidentialResponse::decrypt(
            &envelope,
            request,
            &SecretKey::from_byte_array([4; 32]).unwrap(),
        )
        .unwrap()
        .outcome
        .response
    }
    fn owned_session(operator: &EnclaveOperator, route_id: Uuid) -> SessionId {
        let id = SessionId::new_v7();
        operator.confidential.state.lock().unwrap().owners.insert(
            id.clone(),
            SessionOwner {
                creator_key: public(3),
                signing_key: public(5),
                route_id,
            },
        );
        id
    }
    fn read_command(session: SessionId) -> Command {
        Command::new(EnclaveCommand::Musig(MusigCommand::Keygen(
            KeygenCommand::GetAggregatePublicKey(
                keymeld_core::protocol::GetAggregatePublicKeyCommand {
                    keygen_session_id: session,
                },
            ),
        )))
    }
    #[tokio::test]
    async fn native_errors_are_encrypted_and_exact_retry_returns_identical_ciphertext() {
        let operator = operator();
        let route = Uuid::now_v7();
        let session = owned_session(&operator, route);
        let (request, command) = prepare(read_command(session), route, 3);
        let first = operator.handle_command(command.clone()).await.unwrap();
        let second = operator.handle_command(command).await.unwrap();
        let (EnclaveOutcome::Confidential(a), EnclaveOutcome::Confidential(b)) =
            (&first.response, &second.response)
        else {
            panic!("unencrypted outcome")
        };
        assert_eq!(a, b);
        assert!(matches!(
            read_response(first, &request),
            EnclaveOutcome::Error(_)
        ));
        let mut changed = request.clone();
        changed.command.created_at = std::time::UNIX_EPOCH;
        let changed_outer = Command::new(EnclaveCommand::Confidential(Box::new(
            changed.encrypt().unwrap(),
        )));
        assert!(operator.handle_command(changed_outer).await.is_err());
        assert_eq!(operator.confidential.state.lock().unwrap().replies.len(), 1);
    }
    #[tokio::test]
    async fn protected_sessions_reject_plaintext_and_unrelated_authorities() {
        let operator = operator();
        let route = Uuid::now_v7();
        let session = owned_session(&operator, route);
        assert!(operator
            .handle_command(read_command(session.clone()))
            .await
            .is_err());
        let clear = Command::new(EnclaveCommand::System(SystemCommand::ClearSession(
            ClearSessionCommand {
                keygen_session_id: Some(session.clone()),
                signing_session_id: None,
            },
        )));
        assert!(operator.handle_command(clear.clone()).await.is_err());
        let (request, outer) = prepare(read_command(session.clone()), route, 6);
        assert!(matches!(
            read_response(operator.handle_command(outer).await.unwrap(), &request),
            EnclaveOutcome::Error(_)
        ));
        let (request, outer) = prepare(read_command(session.clone()), Uuid::now_v7(), 3);
        assert!(matches!(
            read_response(operator.handle_command(outer).await.unwrap(), &request),
            EnclaveOutcome::Error(_)
        ));
        // Encrypting a privileged operation never grants permission to execute it.
        let (request, outer) = prepare(clear, route, 3);
        assert!(matches!(
            read_response(operator.handle_command(outer).await.unwrap(), &request),
            EnclaveOutcome::Error(_)
        ));
        assert!(operator
            .confidential
            .state
            .lock()
            .unwrap()
            .owners
            .contains_key(&session));
        assert!(matches!(
            operator
                .handle_command(Command::new(EnclaveCommand::System(SystemCommand::Ping)))
                .await
                .unwrap()
                .response,
            EnclaveOutcome::System(SystemOutcome::Pong)
        ));
    }

    #[tokio::test]
    async fn ciphertext_cache_eviction_preserves_ownership_and_existing_request_progress() {
        let operator = operator();
        let route = Uuid::now_v7();
        let session = owned_session(&operator, route);
        let (request, outer) = prepare(read_command(session.clone()), route, 3);
        let first = operator.handle_command(outer.clone()).await.unwrap();
        let EnclaveOutcome::Confidential(response) = first.response else {
            unreachable!()
        };
        let key = (
            request.authority_public_key.clone(),
            request.header.correlation_id.clone(),
        );
        {
            let mut state = operator.confidential.state.lock().unwrap();
            let mut other = *response.clone();
            other.correlation_id = "ab".repeat(32);
            state.cache_response(
                (public(3), other.correlation_id.clone()),
                [9; 32],
                other,
                1,
                MAX_REPLAY_BYTES,
            );
            assert!(!state.replies.contains_key(&key));
            assert_eq!(state.replies.len(), 1);
            assert!(state.owners.contains_key(&session));
        }
        let replay = operator.handle_command(outer).await.unwrap();
        assert!(matches!(
            read_response(replay, &request),
            EnclaveOutcome::Error(_)
        ));
        assert!(operator
            .confidential
            .state
            .lock()
            .unwrap()
            .replies
            .contains_key(&key));
        assert!(operator
            .handle_command(read_command(session))
            .await
            .is_err());
    }
    #[tokio::test]
    async fn invalid_ciphertext_has_one_generic_outer_error_and_no_session_effect() {
        let operator = operator();
        let (_, mut outer) = prepare(read_command(SessionId::new_v7()), Uuid::now_v7(), 3);
        let EnclaveCommand::Confidential(envelope) = &mut outer.command else {
            unreachable!()
        };
        envelope.destination_enclave = EnclaveId::new(2);
        assert_eq!(
            operator.handle_command(outer).await.unwrap_err(),
            rejected()
        );
        assert!(operator
            .confidential
            .state
            .lock()
            .unwrap()
            .owners
            .is_empty());
        assert!(operator.sessions.is_empty());
    }
}

#[cfg(test)]
#[path = "confidential_integration_tests.rs"]
mod integration_tests;
