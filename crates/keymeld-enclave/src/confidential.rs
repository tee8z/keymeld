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
    time::{Duration, Instant},
};
use tracing::instrument::WithSubscriber;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_SESSIONS: usize = 4096;
const MAX_REPLAYS: usize = 16384;
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
/// Shorter periods could release a session between two commands of one round.
const MIN_EXPIRY_SECS: u64 = 60;

pub(crate) fn rejected() -> EnclaveError {
    EnclaveError::Validation(ValidationError::Other(
        "Confidential transport request rejected".into(),
    ))
}

/// When the enclave releases the sessions of confidential clients. Nothing else does: the
/// relay is not trusted to close a session, and a client is not allowed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionExpiry {
    /// A keygen session and the signing sessions started from it are released once none
    /// of them has been used for this long. Its client restores it as after a restart.
    pub(crate) idle_keygen: Duration,
    /// A signing session is released this long after this enclave's part in its round
    /// ended.
    pub(crate) finished_signing: Duration,
}
impl Default for SessionExpiry {
    fn default() -> Self {
        Self {
            idle_keygen: Duration::from_secs(48 * 60 * 60),
            finished_signing: Duration::from_secs(10 * 60),
        }
    }
}
impl SessionExpiry {
    /// `ENCLAVE_SESSION_IDLE_SECS` and `ENCLAVE_FINISHED_SIGNING_SECS` replace the defaults.
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let default = Self::default();
        let read = |name: &str| expiry_period(name, std::env::var(name).ok().as_deref());
        Ok(Self {
            idle_keygen: read("ENCLAVE_SESSION_IDLE_SECS")?.unwrap_or(default.idle_keygen),
            finished_signing: read("ENCLAVE_FINISHED_SIGNING_SECS")?
                .unwrap_or(default.finished_signing),
        })
    }
}

fn expiry_period(name: &str, value: Option<&str>) -> anyhow::Result<Option<Duration>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let seconds: u64 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("{name} must be a whole number of seconds"))?;
    anyhow::ensure!(
        seconds >= MIN_EXPIRY_SECS,
        "{name} must be at least {MIN_EXPIRY_SECS} seconds"
    );
    Ok(Some(Duration::from_secs(seconds)))
}

/// What one pass of [`EnclaveOperator::expire_sessions`] released.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExpiredSessions {
    pub(crate) keygen: usize,
    pub(crate) signing: usize,
}

#[derive(Clone)]
struct SessionOwner {
    creator_key: Vec<u8>,
    signing_key: Vec<u8>,
    route_id: Uuid,
    /// The keygen session a signing session was started from.
    keygen: Option<SessionId>,
    last_used: Instant,
}
impl SessionOwner {
    fn allows(&self, request: &ConfidentialRequest) -> bool {
        self.route_id == request.header.opaque_route_id
            && (request.authority_public_key == self.creator_key
                || request.authority_public_key == self.signing_key)
    }
    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_used)
    }
}

struct CachedResponse {
    request_digest: [u8; 32],
    response: EnclaveEnvelope,
    last_access: u64,
    /// The sessions the request named and the keygen sessions those belong to.
    sessions: Vec<SessionId>,
}

#[derive(Default)]
struct State {
    owners: BTreeMap<SessionId, SessionOwner>,
    replies: BTreeMap<(Vec<u8>, String), CachedResponse>,
    reply_bytes: usize,
    access_counter: u64,
}

impl State {
    /// Record a use of each session, and of the keygen session a signing session was
    /// started from.
    fn touch(&mut self, sessions: &[SessionId], now: Instant) {
        for id in sessions {
            let keygen = match self.owners.get_mut(id) {
                Some(owner) => {
                    owner.last_used = now;
                    owner.keygen.clone()
                }
                None => continue,
            };
            if let Some(keygen) = keygen {
                if let Some(owner) = self.owners.get_mut(&keygen) {
                    owner.last_used = now;
                }
            }
        }
    }

    /// The sessions a cached reply is dropped with.
    fn reply_sessions(&self, sessions: &[SessionId]) -> Vec<SessionId> {
        let mut all = sessions.to_vec();
        for id in sessions {
            if let Some(keygen) = self.owners.get(id).and_then(|owner| owner.keygen.clone()) {
                if !all.contains(&keygen) {
                    all.push(keygen);
                }
            }
        }
        all
    }

    /// Drop every cached reply of a keygen session and of its signing sessions. An exact
    /// retry then runs again, as it does after a restart.
    fn forget_replies(&mut self, keygen: &SessionId) {
        let reply_bytes = &mut self.reply_bytes;
        self.replies.retain(|_, cached| {
            let keep = !cached.sessions.contains(keygen);
            if !keep {
                *reply_bytes = reply_bytes.saturating_sub(cached.response.ciphertext.len());
            }
            keep
        });
    }

    fn cache_response(
        &mut self,
        request_key: (Vec<u8>, String),
        digest: [u8; 32],
        response: EnclaveEnvelope,
        sessions: Vec<SessionId>,
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
                sessions,
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
    pub(crate) fn reply_cache_bytes(&self) -> Option<usize> {
        self.state.try_lock().ok().map(|state| state.reply_bytes)
    }

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

    /// As [`Self::lock`], for a caller that must not wait behind a running command.
    fn try_lock(&self, session: &SessionId) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let gate = {
            let mut gates = self.locks.lock().ok()?;
            gates.retain(|_, value| value.strong_count() > 0);
            if let Some(gate) = gates.get(session).and_then(Weak::upgrade) {
                gate
            } else {
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                gates.insert(session.clone(), Arc::downgrade(&gate));
                gate
            }
        };
        gate.try_lock_owned().ok()
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
        let now = Instant::now();
        if matches!(
            request.command.command,
            EnclaveCommand::System(SystemCommand::CheckKeygenSession { .. })
        ) {
            {
                let mut state = self.confidential.state.lock().map_err(|_| rejected())?;
                self.authorize_confidential(&state, request)?;
                state.touch(&ids, now);
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
            let cached = state.replies.get_mut(&request_key).map(|cached| {
                cached.last_access = access;
                (cached.request_digest == digest).then(|| cached.response.clone())
            });
            if let Some(cached) = cached {
                let response = cached.ok_or_else(rejected)?;
                state.touch(&ids, now);
                return Ok(response);
            }
            let new_owner = self.authorize_confidential(&state, request)?;
            // Only an authorized command, or an exact retry of one, counts as a use.
            state.touch(&ids, now);
            new_owner
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
                self.drop_session(&id);
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
        let sessions = state.reply_sessions(&ids);
        state.cache_response(
            request_key,
            digest,
            response.clone(),
            sessions,
            MAX_REPLAYS,
            MAX_REPLAY_BYTES,
        );
        drop(state);
        Ok(response)
    }

    pub(crate) fn memory_aware_expiry(&self, configured: &SessionExpiry) -> SessionExpiry {
        #[cfg(feature = "escrow")]
        if self
            .response_budget()
            .is_some_and(|budget| budget.pressured())
        {
            return SessionExpiry {
                idle_keygen: configured.idle_keygen.min(Duration::from_secs(5 * 60)),
                finished_signing: configured.finished_signing,
            };
        }
        SessionExpiry {
            idle_keygen: configured.idle_keygen,
            finished_signing: configured.finished_signing,
        }
    }

    /// Release the confidential sessions that are due under `expiry`, as of `now`.
    ///
    /// Releasing a keygen session leaves this enclave as a restart would, for that session
    /// alone: the session, the signing sessions started from it, their owners and their
    /// cached replies all go, and its client restores it from its journal when it next needs
    /// it. A signing session whose round has ended here goes on its own and keeps its cached
    /// replies, which still answer a late exact retry. One whose round is unfinished stays
    /// until its keygen session goes, because only then can its client tell that the round
    /// was lost. A session that is serving a command is left for the next pass.
    pub(crate) fn expire_sessions(&self, expiry: &SessionExpiry, now: Instant) -> ExpiredSessions {
        let mut expired = ExpiredSessions::default();
        let (keygens, signings): (Vec<SessionId>, Vec<SessionId>) = {
            let Ok(state) = self.confidential.state.lock() else {
                return expired;
            };
            let due = |keygen: bool, limit: Duration| -> Vec<SessionId> {
                state
                    .owners
                    .iter()
                    .filter(|(_, owner)| {
                        owner.keygen.is_none() == keygen && owner.idle_for(now) >= limit
                    })
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            (
                due(true, expiry.idle_keygen),
                due(false, expiry.finished_signing),
            )
        };
        for keygen in keygens {
            let Some(_gate) = self.confidential.try_lock(&keygen) else {
                continue;
            };
            // No signing session can start while the gate is held. A command may have used
            // the session since it was listed, so read it again.
            let family: Vec<SessionId> = {
                let Ok(state) = self.confidential.state.lock() else {
                    return expired;
                };
                let idle = state
                    .owners
                    .get(&keygen)
                    .is_some_and(|owner| owner.idle_for(now) >= expiry.idle_keygen);
                if !idle {
                    continue;
                }
                state
                    .owners
                    .iter()
                    .filter(|(_, owner)| owner.keygen.as_ref() == Some(&keygen))
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            let gates: Vec<_> = family
                .iter()
                .filter_map(|id| self.confidential.try_lock(id))
                .collect();
            if gates.len() != family.len() {
                continue;
            }
            // A child command can finish and refresh its parent while we acquire
            // the family gates. Check again with every command excluded.
            {
                let Ok(state) = self.confidential.state.lock() else {
                    return expired;
                };
                if !state
                    .owners
                    .get(&keygen)
                    .is_some_and(|owner| owner.idle_for(now) >= expiry.idle_keygen)
                {
                    continue;
                }
            }
            for id in family.iter().chain(std::iter::once(&keygen)) {
                self.drop_session(id);
            }
            let Ok(mut state) = self.confidential.state.lock() else {
                return expired;
            };
            for id in family.iter().chain(std::iter::once(&keygen)) {
                state.owners.remove(id);
            }
            state.forget_replies(&keygen);
            expired.keygen += 1;
            expired.signing += family.len();
        }
        for signing in signings {
            let Some(_gate) = self.confidential.try_lock(&signing) else {
                continue;
            };
            {
                let Ok(state) = self.confidential.state.lock() else {
                    return expired;
                };
                // Its keygen session may have taken it along above.
                let idle = state
                    .owners
                    .get(&signing)
                    .is_some_and(|owner| owner.idle_for(now) >= expiry.finished_signing);
                if !idle {
                    continue;
                }
            }
            let finished = self
                .sessions
                .get(&signing)
                .is_none_or(|session| session.signing_round_finished());
            if !finished {
                continue;
            }
            self.drop_session(&signing);
            let Ok(mut state) = self.confidential.state.lock() else {
                return expired;
            };
            state.owners.remove(&signing);
            expired.signing += 1;
        }
        expired
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
                        keygen: None,
                        last_used: Instant::now(),
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
                Ok(Some((
                    cmd.signing_session_id.clone(),
                    SessionOwner {
                        keygen: Some(cmd.keygen_session_id.clone()),
                        last_used: Instant::now(),
                        ..owner
                    },
                )))
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
    use crate::operations::{
        context_aware_session::ContextAwareSession,
        session_context::SessionContext,
        states::{KeygenStatus, OperatorStatus, SigningStatus},
        EnclaveSharedContext, KeygenInitialized, SigningFailed,
    };
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
                keygen: None,
                last_used: Instant::now(),
            },
        );
        id
    }
    fn native_context() -> Arc<std::sync::RwLock<EnclaveSharedContext>> {
        Arc::new(std::sync::RwLock::new(EnclaveSharedContext::new(
            EnclaveId::new(1),
            vec![1, 2, 3],
            vec![4, 5, 6],
            None,
            keymeld_core::managed_socket::config::TimeoutConfig::default(),
        )))
    }
    /// An owned keygen session that the native state machine holds too.
    fn held_keygen(operator: &EnclaveOperator, route_id: Uuid) -> SessionId {
        let id = owned_session(operator, route_id);
        operator.sessions.insert(
            id.clone(),
            ContextAwareSession::new(
                OperatorStatus::Keygen(KeygenStatus::Initialized(KeygenInitialized::new(
                    id.clone(),
                ))),
                SessionContext::new_keygen(id.clone()),
                native_context(),
            ),
        );
        id
    }
    /// The owner of a signing session started from `keygen`.
    fn owned_signing(operator: &EnclaveOperator, keygen: &SessionId) -> SessionId {
        let id = SessionId::new_v7();
        let mut state = operator.confidential.state.lock().unwrap();
        let owner = SessionOwner {
            keygen: Some(keygen.clone()),
            ..state.owners[keygen].clone()
        };
        state.owners.insert(id.clone(), owner);
        id
    }
    /// A signing session of `keygen` whose round has ended on this enclave.
    fn finished_signing(operator: &EnclaveOperator, keygen: &SessionId) -> SessionId {
        let id = owned_signing(operator, keygen);
        operator.sessions.insert(
            id.clone(),
            ContextAwareSession::new(
                OperatorStatus::Signing(SigningStatus::Failed(SigningFailed::new(
                    id.clone(),
                    std::time::SystemTime::now(),
                    "refused".into(),
                ))),
                SessionContext::new_signing(id.clone(), keygen.clone(), Vec::new()),
                native_context(),
            ),
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
                Vec::new(),
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

    #[cfg(feature = "escrow")]
    #[tokio::test]
    async fn memory_pressure_releases_idle_sessions_but_preserves_serving_sessions() {
        let operator = operator();
        let keygen = held_keygen(&operator, Uuid::now_v7());
        let configured = SessionExpiry::default();
        assert_eq!(
            operator.memory_aware_expiry(&configured).idle_keygen,
            configured.idle_keygen
        );
        let budget = operator.response_budget().unwrap();
        let pressure = budget.reserve(budget.snapshot().1).unwrap();
        let expiry = operator.memory_aware_expiry(&configured);
        assert_eq!(expiry.idle_keygen, Duration::from_secs(300));
        assert_eq!(expiry.finished_signing, configured.finished_signing);
        assert_eq!(
            operator.expire_sessions(&expiry, Instant::now()),
            ExpiredSessions::default()
        );
        let serving = operator.confidential.lock(&keygen).await.unwrap();
        let later = Instant::now() + expiry.idle_keygen;
        assert_eq!(
            operator.expire_sessions(&expiry, later),
            ExpiredSessions::default()
        );
        drop(serving);
        assert_eq!(operator.expire_sessions(&expiry, later).keygen, 1);
        drop(pressure);
        assert_eq!(
            operator.memory_aware_expiry(&configured).idle_keygen,
            configured.idle_keygen
        );
    }

    #[test]
    fn finished_signing_sessions_are_released_before_their_keygen_session() {
        let operator = operator();
        let keygen = held_keygen(&operator, Uuid::now_v7());
        let signing = finished_signing(&operator, &keygen);
        let expiry = SessionExpiry::default();
        let now = Instant::now();
        assert_eq!(
            operator.expire_sessions(&expiry, now),
            ExpiredSessions::default()
        );
        assert_eq!(operator.sessions.len(), 2);

        let expired = operator.expire_sessions(&expiry, now + expiry.finished_signing);
        assert_eq!(
            expired,
            ExpiredSessions {
                keygen: 0,
                signing: 1
            }
        );
        assert!(operator.sessions.contains_key(&keygen));
        assert!(!operator.sessions.contains_key(&signing));
        let state = operator.confidential.state.lock().unwrap();
        assert!(state.owners.contains_key(&keygen));
        assert!(!state.owners.contains_key(&signing));
    }

    #[tokio::test]
    async fn idle_keygen_sessions_are_released_with_their_signing_sessions_and_replies() {
        let operator = operator();
        let route = Uuid::now_v7();
        let keygen = held_keygen(&operator, route);
        let signing = finished_signing(&operator, &keygen);
        let in_use = held_keygen(&operator, route);
        let (request, command) = prepare(read_command(keygen.clone()), route, 3);
        operator.handle_command(command.clone()).await.unwrap();
        let (_, other) = prepare(read_command(in_use.clone()), route, 3);
        operator.handle_command(other).await.unwrap();
        assert_eq!(operator.confidential.state.lock().unwrap().replies.len(), 2);

        let expiry = SessionExpiry::default();
        let later = Instant::now() + expiry.idle_keygen;
        operator
            .confidential
            .state
            .lock()
            .unwrap()
            .touch(std::slice::from_ref(&in_use), later);
        let expired = operator.expire_sessions(&expiry, later);
        assert_eq!(
            expired,
            ExpiredSessions {
                keygen: 1,
                signing: 1
            }
        );
        assert!(!operator.sessions.contains_key(&keygen));
        assert!(!operator.sessions.contains_key(&signing));
        assert!(operator.sessions.contains_key(&in_use));
        {
            let state = operator.confidential.state.lock().unwrap();
            assert_eq!(state.owners.keys().collect::<Vec<_>>(), [&in_use]);
            assert_eq!(state.replies.len(), 1);
            let cached: usize = state
                .replies
                .values()
                .map(|cached| cached.response.ciphertext.len())
                .sum();
            assert_eq!(state.reply_bytes, cached);
        }
        // As after a restart, the cache no longer answers for the released session, and a
        // command that is not its start is refused.
        assert!(matches!(
            read_response(operator.handle_command(command).await.unwrap(), &request),
            EnclaveOutcome::Error(_)
        ));
        assert_eq!(operator.confidential.state.lock().unwrap().replies.len(), 1);
    }

    #[tokio::test]
    async fn a_session_serving_a_command_is_left_for_the_next_pass() {
        let operator = operator();
        let keygen = held_keygen(&operator, Uuid::now_v7());
        let expiry = SessionExpiry::default();
        let later = Instant::now() + expiry.idle_keygen;
        let serving = operator.confidential.lock(&keygen).await.unwrap();
        assert_eq!(
            operator.expire_sessions(&expiry, later),
            ExpiredSessions::default()
        );
        assert!(operator.sessions.contains_key(&keygen));
        drop(serving);
        assert_eq!(
            operator.expire_sessions(&expiry, later),
            ExpiredSessions {
                keygen: 1,
                signing: 0
            }
        );
        assert!(operator.sessions.is_empty());
    }

    #[tokio::test]
    async fn an_active_child_keeps_its_entire_family_until_the_next_pass() {
        let operator = operator();
        let keygen = held_keygen(&operator, Uuid::now_v7());
        let signing = finished_signing(&operator, &keygen);
        let expiry = SessionExpiry::default();
        let later = Instant::now() + expiry.idle_keygen;
        let serving = operator.confidential.lock(&signing).await.unwrap();
        assert_eq!(
            operator.expire_sessions(&expiry, later),
            ExpiredSessions::default()
        );
        assert_eq!(operator.sessions.len(), 2);
        operator
            .confidential
            .state
            .lock()
            .unwrap()
            .touch(std::slice::from_ref(&signing), later);
        drop(serving);
        assert_eq!(
            operator.expire_sessions(&expiry, later),
            ExpiredSessions::default()
        );
        assert_eq!(operator.sessions.len(), 2);
    }

    #[tokio::test]
    async fn an_authorized_command_counts_as_a_use_of_the_session_and_its_keygen_session() {
        let operator = operator();
        let route = Uuid::now_v7();
        let keygen = owned_session(&operator, route);
        let signing = owned_signing(&operator, &keygen);
        let last_used =
            |id: &SessionId| operator.confidential.state.lock().unwrap().owners[id].last_used;
        let (keygen_created, signing_created) = (last_used(&keygen), last_used(&signing));

        // Another authority is refused, and leaves both sessions as idle as they were.
        let (_, refused) = prepare(read_command(signing.clone()), route, 6);
        operator.handle_command(refused).await.unwrap();
        assert_eq!(last_used(&keygen), keygen_created);
        assert_eq!(last_used(&signing), signing_created);

        let before = Instant::now();
        let (_, command) = prepare(read_command(signing.clone()), route, 3);
        operator.handle_command(command).await.unwrap();
        assert!(last_used(&signing) >= before);
        assert!(last_used(&keygen) >= before);

        // So a keygen session lives for as long as one of its signing sessions is used.
        let expiry = SessionExpiry::default();
        let later = Instant::now() + expiry.idle_keygen;
        operator
            .confidential
            .state
            .lock()
            .unwrap()
            .touch(std::slice::from_ref(&signing), later);
        assert_eq!(
            operator.expire_sessions(&expiry, later),
            ExpiredSessions::default()
        );
    }

    #[test]
    fn expiry_periods_are_whole_seconds_with_a_floor() {
        assert_eq!(expiry_period("PERIOD", None).unwrap(), None);
        assert_eq!(
            expiry_period("PERIOD", Some("3600")).unwrap(),
            Some(Duration::from_secs(3600))
        );
        assert!(expiry_period("PERIOD", Some("59")).is_err());
        assert!(expiry_period("PERIOD", Some("an hour")).is_err());
    }
}

#[cfg(test)]
#[path = "confidential_integration_tests.rs"]
mod integration_tests;

#[cfg(all(test, feature = "escrow"))]
#[path = "partial_roster_tests.rs"]
mod partial_roster_tests;

#[cfg(all(test, feature = "escrow"))]
#[path = "deposit_registration_tests.rs"]
mod deposit_registration_tests;
