//! Key deposits: registrations sealed before their session exists.
//!
//! Players enter a competition before its pools are formed. Each seals their entry key and a
//! signed escrow policy to an attested enclave under a deposit scope, a session id and terms
//! digest that stand in for a session not yet created. At kickoff, the coordinator forms pools
//! and creates one session per pool, whose manifest names that scope, and registers each
//! member's sealed deposit into it. These tests drive real in-process enclaves through the SDK
//! and an opaque relay, as a gateway would carry them.
use super::integration_tests::{public_key, relay, Checkpoint, RelayState};
use super::*;
use crate::escrow_verifier::{
    BindView, EscrowVerifier, ExecutionView, PreparationView, PreparedAction, RegistrationView,
    VerificationFuture, VerifierDescriptor, VerifierRegistry,
};
use axum::{
    routing::{get, post},
    Router,
};
use keymeld_core::{
    authorization::{
        DepositScope, EnclaveRecipientAuthorization, RegistrationAuthorization,
        RegistrationContext, RegistrationEnvelope, SessionAuthorizationManifest,
        SignedSessionManifest,
    },
    escrow::{
        self,
        protocol::{
            BindEscrowRequest, EscrowCommand, EscrowResponse, ExecuteEscrowRequest,
            ExecutionOutput, Operation, Payload, PrepareEscrowRequest, ReceiptContext,
            RequestContext,
        },
        Action, ActionAttempt, ActionGrant, AdaptorContext, ApplicationContext, Bip340Item,
        Bip340Scope, Condition, ConditionProof, EscrowContext, EscrowPolicy, EscrowRegistration,
        KeyTweak, Permission, PublicKeyBytes, ScopeSigner, SignedEscrowPolicy, SigningItem,
        SigningScope, VerifierPolicy,
    },
    protocol::{
        AddParticipantsBatchCommand, EnclavePublicKeyInfo, InitKeygenSessionCommand, KeygenOutcome,
        MusigOutcome, ParticipantRegistrationData, TaprootTweak, ValidateRegistrationCommand,
    },
    EnclaveId, UserId,
};
use keymeld_sdk::{
    confidential_session::{ConfidentialJournal, ConfidentialSession},
    AuthorizationCredentials, BatchSigningItem, KeyMeldClient, SdkError, SessionCredentials,
    UserCredentials,
};

/// The entry rules every deposit's policy commits to.
const RULES: &[u8] = b"entry rules";
/// A bound permission: a share of the pool's payout, signed once the pool is bound.
const PAYOUT: &str = "payout";
/// An unbound permission: a refund, for a pool that never forms.
const REFUND: &str = "refund";
/// The message the pool's payout signs, as the verifier derives it from the binding.
const RESULT: [u8; 32] = [42; 32];

/// The application's evidence of a pool: who its members are.
fn evidence(members: &[&UserId]) -> Vec<u8> {
    serde_json::to_vec(members).unwrap()
}

fn members(evidence: &[u8]) -> Result<Vec<UserId>, EnclaveError> {
    serde_json::from_slice(evidence).map_err(|_| rejected())
}

/// Enrolls a deposit only in a pool whose evidence names it, and binds only its members.
struct PoolVerifier;
impl EscrowVerifier for PoolVerifier {
    fn descriptor(&self) -> VerifierDescriptor {
        VerifierDescriptor {
            id: "pool-rule".into(),
            version: 1,
        }
    }
    fn validate_registration(&self, view: RegistrationView<'_>) -> Result<(), EnclaveError> {
        if view
            .policy
            .policy
            .verifier
            .as_ref()
            .is_none_or(|verifier| verifier.policy_data.as_bytes() != RULES)
        {
            return Err(rejected());
        }
        // The session's evidence is part of its signed manifest.
        match &view.manifest.manifest.deposit_scope {
            Some(scope)
                if !members(&scope.evidence)?.contains(&view.policy.policy.context.user_id) =>
            {
                Err(rejected())
            }
            _ => Ok(()),
        }
    }
    fn bind(&self, view: BindView<'_>, data: &Payload) -> Result<Payload, EnclaveError> {
        let scope = view
            .manifest
            .manifest
            .deposit_scope
            .as_ref()
            .ok_or_else(rejected)?;
        let members = members(&scope.evidence)?;
        if data.as_bytes() != RESULT
            || view
                .participant_policies
                .keys()
                .any(|user| !members.contains(user))
        {
            return Err(rejected());
        }
        Ok(data.clone())
    }
    fn prepare<'a>(
        &'a self,
        view: PreparationView<'a>,
        parameters: &'a Payload,
    ) -> VerificationFuture<'a, PreparedAction> {
        Box::pin(async move {
            match view.rule {
                "pool_result" => {
                    let item_id: Uuid = parameters.decode().map_err(|_| rejected())?;
                    let mut signers: Vec<_> = view
                        .participant_public_keys
                        .iter()
                        .map(|(user, key)| ScopeSigner {
                            user_id: user.clone(),
                            public_key: key.clone(),
                        })
                        .collect();
                    signers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
                    Ok(PreparedAction {
                        action: Action::Sign {
                            scope: SigningScope {
                                session_tweak: KeyTweak::None,
                                batch: vec![SigningItem {
                                    item_id,
                                    message_digest: escrow::sha256(view.bound_state.as_bytes()),
                                    subset_id: None,
                                    signers,
                                    tweak: KeyTweak::None,
                                    adaptor: AdaptorContext::None,
                                }],
                            },
                        },
                        application_state: view.bound_state.clone(),
                        output: Payload::new(b"payout".to_vec()).unwrap(),
                    })
                }
                "refund_after_expiry" => {
                    let digest: [u8; 32] = parameters.decode().map_err(|_| rejected())?;
                    Ok(PreparedAction {
                        action: Action::SignBip340 {
                            scope: Bip340Scope {
                                public_key: view.policy.policy.participant_public_key.clone(),
                                items: vec![Bip340Item {
                                    item_id: Uuid::now_v7(),
                                    digest,
                                }],
                            },
                        },
                        application_state: Payload::default(),
                        output: Payload::new(b"refund".to_vec()).unwrap(),
                    })
                }
                _ => Err(rejected()),
            }
        })
    }
    fn verify_execution<'a>(
        &'a self,
        view: ExecutionView<'a>,
        _prepared: &'a PreparedAction,
        evidence: &'a Payload,
    ) -> VerificationFuture<'a, ()> {
        Box::pin(async move {
            if view.rule == "pool_result" && evidence.as_bytes() != b"approved" {
                return Err(rejected());
            }
            Ok(())
        })
    }
}

fn operator(id: EnclaveId) -> Arc<EnclaveOperator> {
    let registry = VerifierRegistry::new(vec![Arc::new(PoolVerifier)]).unwrap();
    let operator = Arc::new(EnclaveOperator::with_verifiers(id, registry).unwrap());
    operator.set_test_keys([200 + id.as_u32() as u8; 32]);
    operator
}

/// Two enclaves behind a relay that sees only ciphertext, as a gateway does.
struct Enclaves {
    state: RelayState,
    address: std::net::SocketAddr,
    server: tokio::task::JoinHandle<()>,
    keys: BTreeMap<EnclaveId, Vec<u8>>,
}

async fn enclaves() -> Enclaves {
    let operators = [EnclaveId::new(1), EnclaveId::new(2)]
        .into_iter()
        .map(|id| (id, operator(id)))
        .collect();
    let state = RelayState {
        operators: Arc::new(Mutex::new(operators)),
        requests: Default::default(),
        responses: Default::default(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/v1/confidential", post(relay))
        .route("/api/v1/enclaves/{id}/public-key", get(public_key))
        .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let keys = state
        .operators
        .lock()
        .unwrap()
        .iter()
        .map(|(id, operator)| (*id, operator.get_public_key()))
        .collect();
    Enclaves {
        state,
        address,
        server,
        keys,
    }
}

impl Enclaves {
    fn requests(&self) -> usize {
        self.state.requests.lock().unwrap().len()
    }
}

impl Drop for Enclaves {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// One player's entry, sealed to one enclave before any pool or session exists.
struct Deposit {
    user: UserId,
    enclave: EnclaveId,
    /// The player's entry key.
    key: [u8; 32],
    /// The ticket's slot credential, which the application holds and authorizes it with.
    slot: AuthorizationCredentials,
    registration: ParticipantRegistrationData,
    policy: SignedEscrowPolicy,
}

/// Every player's entry, sealed under one deposit session id and terms digest.
struct Deposits {
    deposit_session_id: SessionId,
    terms: Vec<u8>,
    /// Alice on enclave 2, Bob on enclave 1 and Carol on enclave 2.
    players: Vec<Deposit>,
}

impl Deposits {
    /// The deposit scope of a pool of `members`, which names them as its evidence.
    fn scope(&self, members: &[usize]) -> DepositScope {
        DepositScope {
            deposit_session_id: self.deposit_session_id.clone(),
            deposit_digest: self.terms.clone(),
            evidence: evidence(
                &members
                    .iter()
                    .map(|index| &self.players[*index].user)
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

/// The entry's escrow policy, bound to `session` and `digest`: a deposit scope, or a session.
fn entry_policy(
    session: &SessionId,
    digest: &[u8],
    user: &UserId,
    signing: &UserCredentials,
) -> SignedEscrowPolicy {
    let grant = |rule: &str, operation, repetition, unbound| ActionGrant {
        preparation: escrow::PreparationPolicy::Single,
        repetition,
        unbound,
        condition: Condition::VerifierRule { rule: rule.into() },
        operation,
    };
    SignedEscrowPolicy::sign(
        EscrowPolicy {
            schema_version: escrow::SCHEMA_VERSION,
            // The policy is a template of the competition's rules. A deposit's names its
            // deposit scope, since no session exists yet.
            context: EscrowContext {
                keygen_session_id: session.clone(),
                user_id: user.clone(),
                escrow_id: Uuid::now_v7(),
                manifest_digest: digest.try_into().unwrap(),
                application: ApplicationContext::commit("entry".into(), 1, RULES).unwrap(),
            },
            participant_public_key: PublicKeyBytes::new(&signing.public_key_bytes()).unwrap(),
            verifier: Some(VerifierPolicy {
                id: "pool-rule".into(),
                version: 1,
                policy_data: Payload::new(RULES.to_vec()).unwrap(),
            }),
            secrets: BTreeMap::new(),
            grants: BTreeMap::from([
                (
                    PAYOUT.into(),
                    grant(
                        "pool_result",
                        Permission::Sign,
                        escrow::Repetition::Once,
                        false,
                    ),
                ),
                (
                    REFUND.into(),
                    grant(
                        "refund_after_expiry",
                        Permission::SignBip340,
                        escrow::Repetition::VerifierAuthorizedAttempts,
                        true,
                    ),
                ),
            ]),
        },
        &signing.private_key_bytes(),
    )
    .unwrap()
}

/// Seal `key`'s registration in `user`'s slot on `enclave`, bound to `session` and `digest`,
/// and authorize it with the slot credential. A deposit is sealed as one.
#[allow(clippy::too_many_arguments)]
fn seal(
    enclaves: &Enclaves,
    user: &UserId,
    enclave: EnclaveId,
    key: &[u8; 32],
    slot: &AuthorizationCredentials,
    (session, digest): (&SessionId, &[u8]),
    policy: Option<&SignedEscrowPolicy>,
    deposit: bool,
) -> ParticipantRegistrationData {
    let signing = UserCredentials::from_private_key(key).unwrap();
    // A deposit derives its session auth key from its deposit session id.
    let auth_pubkey = signing
        .derive_session_auth_pubkey(&session.to_string())
        .unwrap();
    let context = RegistrationContext {
        keygen_session_id: session.clone(),
        manifest_hash: digest.to_vec(),
        user_id: user.clone(),
        enclave_id: enclave,
        enclave_key_epoch: 1,
        public_key: signing.public_key_bytes(),
        auth_pubkey: auth_pubkey.clone(),
        require_signing_approval: false,
    };
    let escrow = policy.map(|policy| EscrowRegistration {
        policy: policy.clone(),
        secrets: BTreeMap::new(),
    });
    let envelope = match (escrow, deposit) {
        (None, false) => RegistrationEnvelope::new(context.clone(), key),
        (Some(escrow), false) => RegistrationEnvelope::with_escrow(context.clone(), key, escrow),
        (None, true) => RegistrationEnvelope::deposit(context.clone(), key),
        (Some(escrow), true) => {
            RegistrationEnvelope::deposit_with_escrow(context.clone(), key, escrow)
        }
    }
    .unwrap();
    let ciphertext = hex::encode(
        keymeld_core::crypto::SecureCrypto::ecies_encrypt_from_hex(
            &hex::encode(&enclaves.keys[&enclave]),
            &serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap(),
    );
    ParticipantRegistrationData {
        user_id: user.clone(),
        registration_authorization: RegistrationAuthorization::sign(
            &slot.export_secret(),
            context,
            &ciphertext,
        )
        .unwrap(),
        enclave_encrypted_data: ciphertext,
        auth_pubkey,
        require_signing_approval: false,
    }
}

/// Seal every player's entry, as each browser does at entry. Nothing reaches an enclave: the
/// sealed registrations wait with the application until their pool's session exists.
fn seal_deposits(enclaves: &Enclaves, seed: u8) -> Deposits {
    let deposit_session_id = SessionId::new_v7();
    let terms = escrow::sha256(b"published competition terms").to_vec();
    let players = (0..3u8)
        .map(|index| {
            let user = UserId::new_v7();
            let enclave = EnclaveId::new(if index % 2 == 0 { 2 } else { 1 });
            let key = [seed + index; 32];
            let slot = AuthorizationCredentials::from_secret(&[seed + 10 + index; 32]).unwrap();
            let signing = UserCredentials::from_private_key(&key).unwrap();
            let policy = entry_policy(&deposit_session_id, &terms, &user, &signing);
            let registration = seal(
                enclaves,
                &user,
                enclave,
                &key,
                &slot,
                (&deposit_session_id, &terms),
                Some(&policy),
                true,
            );
            Deposit {
                user,
                enclave,
                key,
                slot,
                registration,
                policy,
            }
        })
        .collect();
    Deposits {
        deposit_session_id,
        terms,
        players,
    }
}

/// One pool's keygen session: the coordinator on enclave 1, and the deposits of its members.
struct Pool {
    manifest: SignedSessionManifest,
    recipients: EnclaveRecipientAuthorization,
    epochs: BTreeMap<EnclaveId, u64>,
    credentials: SessionCredentials,
    authority: AuthorizationCredentials,
    reply: AuthorizationCredentials,
    client: KeyMeldClient,
    coordinator: UserId,
    registrations: BTreeMap<UserId, ParticipantRegistrationData>,
    policies: BTreeMap<UserId, SignedEscrowPolicy>,
}

/// Create the session of a pool of `members` under `scope`, at kickoff. Under a deposit scope,
/// its members are registered by their deposits. Without one, the session is an ordinary one,
/// and each member's key is sealed for it after it exists.
fn pool(
    enclaves: &Enclaves,
    seed: u8,
    deposits: &Deposits,
    members: &[usize],
    scope: Option<DepositScope>,
) -> Pool {
    let coordinator = UserId::new_v7();
    let authority = AuthorizationCredentials::from_secret(&[seed; 32]).unwrap();
    let reply = AuthorizationCredentials::from_secret(&[seed + 1; 32]).unwrap();
    let credentials = SessionCredentials::from_session_secret(&[seed + 2; 32]).unwrap();
    let coordinator_slot = AuthorizationCredentials::from_secret(&[seed + 3; 32]).unwrap();
    let chosen: Vec<&Deposit> = members
        .iter()
        .map(|index| &deposits.players[*index])
        .collect();
    let manifest = SignedSessionManifest::sign(
        SessionAuthorizationManifest {
            keygen_session_id: SessionId::new_v7(),
            coordinator_user_id: coordinator.clone(),
            creator_pubkey: authority.public_key_bytes(),
            signing_pubkey: authority.public_key_bytes(),
            session_public_key: credentials.public_key_bytes(),
            participant_verifiers: std::iter::once((
                coordinator.clone(),
                coordinator_slot.public_key_bytes(),
            ))
            .chain(
                chosen
                    .iter()
                    .map(|deposit| (deposit.user.clone(), deposit.slot.public_key_bytes())),
            )
            .collect(),
            timeout_secs: 300,
            max_signing_sessions: Some(10),
            encrypted_taproot_tweak: credentials
                .encrypt(
                    &serde_json::to_vec(&TaprootTweak::None).unwrap(),
                    "taproot_tweak",
                )
                .unwrap(),
            subset_definitions: Vec::new(),
            deposit_scope: scope,
        },
        &[seed; 32],
    )
    .unwrap();
    // Each member stays on the enclave their deposit was sealed to.
    let recipients = EnclaveRecipientAuthorization::sign(
        &manifest,
        std::iter::once((coordinator.clone(), EnclaveId::new(1)))
            .chain(
                chosen
                    .iter()
                    .map(|deposit| (deposit.user.clone(), deposit.enclave)),
            )
            .collect(),
        enclaves.keys.clone(),
        &[seed; 32],
    )
    .unwrap();
    // The coordinator registers its own key after the session exists, in its scope.
    let (scope_session_id, scope_digest) = manifest.registration_scope().unwrap();
    let scoped = manifest.manifest.deposit_scope.is_some();
    let mut registrations = BTreeMap::from([(
        coordinator.clone(),
        seal(
            enclaves,
            &coordinator,
            EnclaveId::new(1),
            &[seed + 4; 32],
            &coordinator_slot,
            (&scope_session_id, &scope_digest),
            None,
            scoped,
        ),
    )]);
    let mut policies = BTreeMap::new();
    for deposit in &chosen {
        let (registration, policy) = if scoped {
            (deposit.registration.clone(), deposit.policy.clone())
        } else {
            let signing = UserCredentials::from_private_key(&deposit.key).unwrap();
            let policy = entry_policy(&scope_session_id, &scope_digest, &deposit.user, &signing);
            let registration = seal(
                enclaves,
                &deposit.user,
                deposit.enclave,
                &deposit.key,
                &deposit.slot,
                (&scope_session_id, &scope_digest),
                Some(&policy),
                false,
            );
            (registration, policy)
        };
        registrations.insert(deposit.user.clone(), registration);
        policies.insert(deposit.user.clone(), policy);
    }
    let client =
        KeyMeldClient::builder(&format!("http://{}", enclaves.address), coordinator.clone())
            .dangerous_trust_unattested_enclaves()
            .build()
            .unwrap();
    Pool {
        manifest,
        recipients,
        epochs: enclaves.keys.keys().map(|id| (*id, 1)).collect(),
        credentials,
        authority,
        reply,
        client,
        coordinator,
        registrations,
        policies,
    }
}

/// Another creator's session that names `victim`'s session id and manifest digest as its
/// deposit scope, with the same participants, slots and enclaves, to adopt its registrations.
fn adopt(enclaves: &Enclaves, seed: u8, victim: &Pool) -> Pool {
    let authority = AuthorizationCredentials::from_secret(&[seed; 32]).unwrap();
    let reply = AuthorizationCredentials::from_secret(&[seed + 1; 32]).unwrap();
    let credentials = SessionCredentials::from_session_secret(&[seed + 2; 32]).unwrap();
    let mut manifest = victim.manifest.manifest.clone();
    manifest.keygen_session_id = SessionId::new_v7();
    manifest.creator_pubkey = authority.public_key_bytes();
    manifest.signing_pubkey = authority.public_key_bytes();
    manifest.session_public_key = credentials.public_key_bytes();
    manifest.encrypted_taproot_tweak = credentials
        .encrypt(
            &serde_json::to_vec(&TaprootTweak::None).unwrap(),
            "taproot_tweak",
        )
        .unwrap();
    manifest.deposit_scope = Some(DepositScope {
        deposit_session_id: victim.session_id(),
        deposit_digest: victim.manifest.digest().unwrap(),
        evidence: evidence(&victim.registrations.keys().collect::<Vec<_>>()),
    });
    let manifest = SignedSessionManifest::sign(manifest, &[seed; 32]).unwrap();
    let recipients = EnclaveRecipientAuthorization::sign(
        &manifest,
        victim.recipients.user_enclave_assignments.clone(),
        enclaves.keys.clone(),
        &[seed; 32],
    )
    .unwrap();
    Pool {
        manifest,
        recipients,
        epochs: victim.epochs.clone(),
        credentials,
        authority,
        reply,
        client: KeyMeldClient::builder(
            &format!("http://{}", enclaves.address),
            victim.coordinator.clone(),
        )
        .dangerous_trust_unattested_enclaves()
        .build()
        .unwrap(),
        coordinator: victim.coordinator.clone(),
        registrations: victim.registrations.clone(),
        policies: victim.policies.clone(),
    }
}

impl Pool {
    async fn connect<'a>(
        &'a self,
        journal: &'a mut ConfidentialJournal,
        checkpoint: &'a Checkpoint,
    ) -> ConfidentialSession<'a> {
        ConfidentialSession::connect(
            &self.client,
            &self.manifest,
            &self.recipients,
            &self.epochs,
            &self.credentials,
            &self.authority,
            &self.reply,
            journal,
            checkpoint,
        )
        .await
        .unwrap()
    }

    fn session_id(&self) -> SessionId {
        self.manifest.manifest.keygen_session_id.clone()
    }

    /// The coordinator's registration and those of the members at `members`.
    fn present(
        &self,
        deposits: &Deposits,
        members: &[usize],
    ) -> BTreeMap<UserId, ParticipantRegistrationData> {
        std::iter::once(&self.coordinator)
            .chain(members.iter().map(|index| &deposits.players[*index].user))
            .map(|user| (user.clone(), self.registrations[user].clone()))
            .collect()
    }

    /// The command that starts this keygen session on `enclave_id`, as the SDK builds it.
    fn init_command(&self, enclave_id: EnclaveId) -> EnclaveCommand {
        let manifest = &self.manifest.manifest;
        let key = hex::encode(&self.recipients.recipient_public_keys[&enclave_id]);
        EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::InitSession(
            InitKeygenSessionCommand {
                keygen_session_id: self.session_id(),
                coordinator_encrypted_private_key: None,
                coordinator_user_id: (enclave_id == EnclaveId::new(1))
                    .then(|| self.coordinator.clone()),
                encrypted_session_secret: Some(
                    self.credentials.encrypt_secret_for_enclave(&key).unwrap(),
                ),
                timeout_secs: manifest.timeout_secs,
                expected_participant_count: manifest.participant_verifiers.len(),
                expected_participants: manifest.participant_verifiers.keys().cloned().collect(),
                enclave_public_keys: self
                    .recipients
                    .recipient_public_keys
                    .iter()
                    .map(|(id, key)| EnclavePublicKeyInfo {
                        enclave_id: *id,
                        public_key: hex::encode(key),
                    })
                    .collect(),
                encrypted_taproot_tweak: manifest.encrypted_taproot_tweak.clone(),
                subset_definitions: manifest.subset_definitions.clone(),
                recipient_authorization: Box::new(self.recipients.clone()),
                authorization_manifest: Box::new(self.manifest.clone()),
            },
        )))
    }
}

/// Send one escrow request for `user` to its enclave, naming `target` as the session it acts
/// in, and verify the enclave's receipt.
#[allow(clippy::too_many_arguments)]
async fn escrow_request_in<T: serde::Serialize>(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    enclaves: &Enclaves,
    user: &UserId,
    operation: Operation,
    action: Option<(&str, &ActionAttempt)>,
    request: &T,
    target: Option<SessionId>,
) -> Result<EscrowResponse, SdkError> {
    let policy = &pool.policies[user];
    let enclave_id = pool.recipients.user_enclave_assignments[user];
    let context = RequestContext {
        schema_version: escrow::SCHEMA_VERSION,
        operation,
        escrow: policy.policy.context.clone(),
        policy_digest: policy.policy.digest()?,
        request_id: Uuid::now_v7(),
        action_id: action.map(|(id, _)| id.to_string()),
        attempt: action.map(|(_, attempt)| attempt.clone()),
        keygen_session_id: target,
    };
    let stage = format!("escrow/{}", context.request_id);
    let outcome = session
        .command_once(&stage, enclave_id, request, || {
            let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(request)?);
            let encrypted = pool
                .credentials
                .session_secret()
                .encrypt(&plaintext, "escrow-request-v1")?;
            let command = EscrowCommand::sign(
                context,
                Payload::new(encrypted.to_bytes()?)?,
                &pool.authority.export_secret(),
            )?;
            Ok(EnclaveCommand::Musig(MusigCommand::Keygen(
                KeygenCommand::Escrow(command),
            )))
        })
        .await?;
    let EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::Escrow(response))) = outcome
    else {
        panic!("wrong private escrow response")
    };
    let EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(command))) = &session
        .recorded_command(&stage, enclave_id)
        .unwrap()
        .command
    else {
        unreachable!()
    };
    response.verify(
        &ReceiptContext {
            schema_version: escrow::SCHEMA_VERSION,
            enclave_id,
            enclave_key_epoch: 1,
            request: command.context.clone(),
            request_digest: command.digest()?,
        },
        &enclaves.keys[&enclave_id],
    )?;
    Ok(*response)
}

/// Send one escrow request for `user` in `pool`'s session. A deposit's policy names its
/// deposit scope, so the command names the session.
async fn escrow_request<T: serde::Serialize>(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    enclaves: &Enclaves,
    user: &UserId,
    operation: Operation,
    action: Option<(&str, &ActionAttempt)>,
    request: &T,
) -> Result<EscrowResponse, SdkError> {
    let target = (pool.policies[user].policy.context.keygen_session_id != pool.session_id())
        .then(|| pool.session_id());
    escrow_request_in(
        session, pool, enclaves, user, operation, action, request, target,
    )
    .await
}

fn bind_request(pool: &Pool, user: &UserId) -> BindEscrowRequest {
    BindEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        policy: pool.policies[user].clone(),
        application_context: Payload::new(RULES.to_vec()).unwrap(),
        participant_policies: pool.policies.clone(),
        binding_data: Payload::new(RESULT.to_vec()).unwrap(),
    }
}

fn payout_request(
    binding: &EscrowResponse,
    attempt: &ActionAttempt,
    item: Uuid,
) -> PrepareEscrowRequest {
    PrepareEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: binding.sealed_state.clone(),
        action_id: PAYOUT.into(),
        attempt: attempt.clone(),
        action: None,
        action_parameters: Payload::encode(&item).unwrap(),
        prior_preparation_receipts: vec![],
    }
}

/// Bind `user`'s policy to the pool's result.
async fn bind(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    enclaves: &Enclaves,
    user: &UserId,
) -> EscrowResponse {
    escrow_request(
        session,
        pool,
        enclaves,
        user,
        Operation::Bind,
        None,
        &bind_request(pool, user),
    )
    .await
    .unwrap()
}

/// Bind every member's policy to the pool's result, and authorize each member's share of the
/// payout signature in `signing_session`.
async fn authorize_payout(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    enclaves: &Enclaves,
    signing_session: &SessionId,
    item: Uuid,
) -> Result<(), SdkError> {
    for user in pool.policies.keys() {
        let binding = escrow_request(
            session,
            pool,
            enclaves,
            user,
            Operation::Bind,
            None,
            &bind_request(pool, user),
        )
        .await?;
        let attempt = ActionAttempt {
            attempt_id: Uuid::now_v7(),
            signing_session_id: Some(signing_session.clone()),
        };
        let prepared = escrow_request(
            session,
            pool,
            enclaves,
            user,
            Operation::Prepare,
            Some((PAYOUT, &attempt)),
            &payout_request(&binding, &attempt, item),
        )
        .await?;
        let execute = ExecuteEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            prepared_receipt: prepared.sealed_state,
            proof: ConditionProof::VerifierEvidence {
                evidence: Payload::new(b"approved".to_vec())?,
            },
        };
        let executed = escrow_request(
            session,
            pool,
            enclaves,
            user,
            Operation::Execute,
            Some((PAYOUT, &attempt)),
            &execute,
        )
        .await?;
        assert!(matches!(
            executed.output.decode()?,
            ExecutionOutput::SigningPermit { signing_session_id, .. }
                if &signing_session_id == signing_session
        ));
    }
    Ok(())
}

/// Refund `user`'s deposit by signing `digest` with their own key, under the unbound refund
/// permission.
async fn refund(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    enclaves: &Enclaves,
    user: &UserId,
    digest: [u8; 32],
) -> Result<(), SdkError> {
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: None,
    };
    let prepare = PrepareEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: Payload::default(),
        action_id: REFUND.into(),
        attempt: attempt.clone(),
        action: None,
        action_parameters: Payload::encode(&digest)?,
        prior_preparation_receipts: vec![],
    };
    let action = Some((REFUND, &attempt));
    let prepared = escrow_request(
        session,
        pool,
        enclaves,
        user,
        Operation::Prepare,
        action,
        &prepare,
    )
    .await?;
    let execute = ExecuteEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        prepared_receipt: prepared.sealed_state,
        proof: ConditionProof::VerifierEvidence {
            evidence: Payload::default(),
        },
    };
    let executed = escrow_request(
        session,
        pool,
        enclaves,
        user,
        Operation::Execute,
        action,
        &execute,
    )
    .await?;
    let ExecutionOutput::Bip340Signatures {
        public_key,
        signatures,
    } = executed.output.decode()?
    else {
        panic!("expected the refund's signature");
    };
    assert_eq!(
        public_key,
        pool.policies[user].policy.participant_public_key
    );
    let [signature] = signatures.as_slice() else {
        panic!("a refund signs one digest");
    };
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_byte_array(
                signature.signature.clone().try_into().unwrap(),
            ),
            &digest,
            &secp256k1::PublicKey::from_slice(public_key.as_bytes())
                .unwrap()
                .x_only_public_key()
                .0,
        )
        .expect("the player's own key signed the refund");
    Ok(())
}

fn verify_signature(
    results: &[keymeld_core::protocol::EnclaveBatchResult],
    credentials: &SessionCredentials,
    aggregate: &[u8],
    message: [u8; 32],
) {
    let [result] = results else {
        panic!("one signature per item");
    };
    assert!(result.error.is_none());
    let plaintext = credentials
        .decrypt(
            result.encrypted_final_signature.as_ref().unwrap(),
            "signature",
        )
        .unwrap();
    let bytes = if plaintext.len() == 64 {
        plaintext
    } else {
        hex::decode(plaintext).unwrap()
    };
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_byte_array(bytes.try_into().unwrap()),
            &message,
            &secp256k1::PublicKey::from_slice(aggregate)
                .unwrap()
                .x_only_public_key()
                .0,
        )
        .expect("the pool's aggregate key signed its result");
}

#[tokio::test]
async fn deposits_sealed_before_their_session_complete_keygen_and_sign_under_their_policies() {
    let enclaves = enclaves().await;
    // Alice and Bob enter before any pool exists.
    let deposits = seal_deposits(&enclaves, 100);
    assert_eq!(
        enclaves.requests(),
        0,
        "a deposit waits with the application"
    );

    // At kickoff they are drawn into one pool, whose session names their deposit scope.
    let pool = pool(
        &enclaves,
        20,
        &deposits,
        &[0, 1],
        Some(deposits.scope(&[0, 1])),
    );
    let [alice, bob] = [&deposits.players[0].user, &deposits.players[1].user];
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    for user in [alice, bob] {
        session
            .validate_registration(&pool.registrations[user])
            .await
            .unwrap();
    }
    let roster = session.complete_keygen(&pool.registrations).await.unwrap();
    // The roster names the session and its manifest; its registrations, the deposit scope.
    assert_eq!(roster.roster.keygen_session_id, pool.session_id());
    assert_eq!(roster.roster.manifest_hash, pool.manifest.digest().unwrap());
    for registration in roster.roster.registrations.values() {
        assert_eq!(
            registration.context.keygen_session_id,
            deposits.deposit_session_id
        );
        assert_eq!(registration.context.manifest_hash, deposits.terms);
    }

    // An escrow command must name the session its deposit-scoped policy does not.
    assert!(escrow_request_in(
        &mut session,
        &pool,
        &enclaves,
        alice,
        Operation::Bind,
        None,
        &bind_request(&pool, alice),
        None,
    )
    .await
    .is_err());

    // Each member's policy authorizes their share of the payout, and the pool signs it.
    let signing = SessionId::new_v7();
    let item = BatchSigningItem::new(RESULT);
    session
        .prepare_signing_batch(&signing, std::slice::from_ref(&item))
        .await
        .unwrap();
    authorize_payout(&mut session, &pool, &enclaves, &signing, item.id())
        .await
        .unwrap();
    let results = session
        .sign_prepared_batch(&signing, 300, &[])
        .await
        .unwrap();
    verify_signature(
        &results,
        &pool.credentials,
        &roster.roster.aggregate_public_key,
        RESULT,
    );
}

#[tokio::test]
async fn a_verifier_refuses_a_deposit_its_session_evidence_does_not_name() {
    let enclaves = enclaves().await;
    let deposits = seal_deposits(&enclaves, 100);
    let [alice, bob] = [&deposits.players[0].user, &deposits.players[1].user];
    // The manifest has a slot for Bob, but the pool's evidence names only Alice.
    let pool = pool(
        &enclaves,
        20,
        &deposits,
        &[0, 1],
        Some(deposits.scope(&[0])),
    );
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    session
        .validate_registration(&pool.registrations[alice])
        .await
        .unwrap();
    assert!(session
        .validate_registration(&pool.registrations[bob])
        .await
        .is_err());
    assert!(session.complete_keygen(&pool.registrations).await.is_err());
}

/// Past the SDK's checks, with the coordinator's key, send `registration` to enclave 2 for
/// admission, and for import into the session after starting it there. Both must be refused.
async fn refused_past_the_sdk(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    stage: &str,
    registration: &ParticipantRegistrationData,
) {
    let enclave = EnclaveId::new(2);
    let manifest = pool.manifest.clone();
    let admission = registration.clone();
    assert!(session
        .command_once(
            &format!("{stage}/admit"),
            enclave,
            registration,
            move || {
                Ok(EnclaveCommand::System(SystemCommand::ValidateRegistration(
                    ValidateRegistrationCommand {
                        authorization_manifest: Box::new(manifest),
                        participant: admission,
                    },
                )))
            }
        )
        .await
        .is_err());
    let init = pool.init_command(enclave);
    session
        .command_once("init-past-the-sdk", enclave, &(), move || Ok(init))
        .await
        .unwrap();
    let import = EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::AddParticipantsBatch(
        AddParticipantsBatchCommand {
            keygen_session_id: pool.session_id(),
            participants: vec![registration.clone()],
        },
    )));
    assert!(session
        .command_once(
            &format!("{stage}/import"),
            enclave,
            registration,
            move || { Ok(import) }
        )
        .await
        .is_err());
}

#[tokio::test]
async fn a_deposit_is_refused_by_a_session_under_other_terms_or_none() {
    let enclaves = enclaves().await;
    let deposits = seal_deposits(&enclaves, 100);
    let alice = &deposits.players[0];
    let mut other_terms = deposits.scope(&[0, 1]);
    other_terms.deposit_digest = escrow::sha256(b"other terms").to_vec();
    let mut other_id = deposits.scope(&[0, 1]);
    other_id.deposit_session_id = SessionId::new_v7();

    for (seed, scope) in [(20, Some(other_terms)), (40, Some(other_id)), (60, None)] {
        let pool = pool(&enclaves, seed, &deposits, &[0, 1], scope);
        let mut registrations = pool.registrations.clone();
        registrations.insert(alice.user.clone(), alice.registration.clone());
        let checkpoint = Checkpoint::default();
        let mut journal = ConfidentialJournal::default();
        let mut session = pool.connect(&mut journal, &checkpoint).await;
        let sent = enclaves.requests();
        // The SDK refuses the deposit before sending anything.
        assert!(session
            .validate_registration(&alice.registration)
            .await
            .is_err());
        assert!(session.complete_keygen(&registrations).await.is_err());
        assert_eq!(enclaves.requests(), sent, "a refused deposit sent nothing");
        // Past the SDK, the enclave refuses it.
        refused_past_the_sdk(&mut session, &pool, "deposit", &alice.registration).await;
    }

    // A deposit-scoped session refuses a registration sealed for the session itself, and one
    // that names the deposit scope but was not sealed as a deposit.
    let pool = pool(
        &enclaves,
        80,
        &deposits,
        &[0, 1],
        Some(deposits.scope(&[0, 1])),
    );
    let signing = UserCredentials::from_private_key(&alice.key).unwrap();
    let session_id = pool.session_id();
    let manifest_digest = pool.manifest.digest().unwrap();
    let session_policy = entry_policy(&session_id, &manifest_digest, &alice.user, &signing);
    let session_sealed = seal(
        &enclaves,
        &alice.user,
        alice.enclave,
        &alice.key,
        &alice.slot,
        (&session_id, &manifest_digest),
        Some(&session_policy),
        false,
    );
    let unmarked = seal(
        &enclaves,
        &alice.user,
        alice.enclave,
        &alice.key,
        &alice.slot,
        (&deposits.deposit_session_id, &deposits.terms),
        Some(&alice.policy),
        false,
    );
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    assert!(session
        .validate_registration(&session_sealed)
        .await
        .is_err());
    refused_past_the_sdk(&mut session, &pool, "session-sealed", &session_sealed).await;
    // The slot's authorization of the unmarked envelope verifies, so only the enclave, which
    // reads the participant's own proof, can refuse it.
    unmarked
        .registration_authorization
        .verify(&pool.manifest, &unmarked.enclave_encrypted_data)
        .unwrap();
    refused_past_the_sdk(&mut session, &pool, "unmarked", &unmarked).await;
    // Its own deposit still registers.
    session
        .validate_registration(&alice.registration)
        .await
        .unwrap();
}

/// A deposit scope cannot name an existing session to adopt its registrations: they were not
/// sealed as deposits. Otherwise any creator holding them could re-register an ordinary
/// session's keys, under the same aggregate key, with a signing authority of its own.
#[tokio::test]
async fn a_session_cannot_adopt_another_sessions_registrations_as_deposits() {
    let enclaves = enclaves().await;
    let deposits = seal_deposits(&enclaves, 100);
    let victim = pool(&enclaves, 20, &deposits, &[0, 1], None);
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = victim.connect(&mut journal, &checkpoint).await;
    session
        .complete_keygen(&victim.registrations)
        .await
        .unwrap();

    let adopter = adopt(&enclaves, 50, &victim);
    // Every slot authorization verifies against the adopting manifest, and every escrow
    // policy names its scope.
    for registration in adopter.registrations.values() {
        registration
            .registration_authorization
            .verify(&adopter.manifest, &registration.enclave_encrypted_data)
            .unwrap();
    }
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = adopter.connect(&mut journal, &checkpoint).await;
    for registration in adopter.registrations.values() {
        assert!(session.validate_registration(registration).await.is_err());
    }
    assert!(session
        .complete_keygen(&adopter.registrations)
        .await
        .is_err());
}

/// Keymeld keeps no ledger of deposits, so one can be registered into two sessions that name
/// its scope. Each session's escrow receipts stay its own.
#[tokio::test]
async fn a_deposit_in_two_sessions_keeps_each_sessions_receipts_apart() {
    let enclaves = enclaves().await;
    let deposits = seal_deposits(&enclaves, 100);
    let alice = &deposits.players[0].user;
    let scope = deposits.scope(&[0, 1]);
    let first = pool(&enclaves, 20, &deposits, &[0, 1], Some(scope.clone()));
    let second = pool(&enclaves, 40, &deposits, &[0, 1], Some(scope));
    let (first_checkpoint, second_checkpoint) = (Checkpoint::default(), Checkpoint::default());
    let (mut first_journal, mut second_journal) = (
        ConfidentialJournal::default(),
        ConfidentialJournal::default(),
    );
    let mut first_session = first.connect(&mut first_journal, &first_checkpoint).await;
    let mut second_session = second
        .connect(&mut second_journal, &second_checkpoint)
        .await;
    first_session
        .complete_keygen(&first.registrations)
        .await
        .unwrap();
    second_session
        .complete_keygen(&second.registrations)
        .await
        .unwrap();

    let first_binding = bind(&mut first_session, &first, &enclaves, alice).await;
    let second_binding = bind(&mut second_session, &second, &enclaves, alice).await;
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: Some(SessionId::new_v7()),
    };
    let item = Uuid::now_v7();
    // The same enclave sealed both receipts, for the same policy, but neither session takes the
    // other's.
    assert!(escrow_request(
        &mut first_session,
        &first,
        &enclaves,
        alice,
        Operation::Prepare,
        Some((PAYOUT, &attempt)),
        &payout_request(&second_binding, &attempt, item),
    )
    .await
    .is_err());
    assert!(escrow_request(
        &mut second_session,
        &second,
        &enclaves,
        alice,
        Operation::Prepare,
        Some((PAYOUT, &attempt)),
        &payout_request(&first_binding, &attempt, item),
    )
    .await
    .is_err());
    escrow_request(
        &mut first_session,
        &first,
        &enclaves,
        alice,
        Operation::Prepare,
        Some((PAYOUT, &attempt)),
        &payout_request(&first_binding, &attempt, item),
    )
    .await
    .unwrap();
}

/// A pool that never fills registers only the deposits present, and refunds them.
#[tokio::test]
async fn a_deposit_scoped_pool_that_never_fills_refunds_its_deposits() {
    let enclaves = enclaves().await;
    let deposits = seal_deposits(&enclaves, 100);
    let [alice, bob, carol] = [
        &deposits.players[0].user,
        &deposits.players[1].user,
        &deposits.players[2].user,
    ];
    let pool = pool(
        &enclaves,
        20,
        &deposits,
        &[0, 1, 2],
        Some(deposits.scope(&[0, 1, 2])),
    );
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    // Alice and Carol's deposits arrived; Bob's never did.
    session
        .register_partial_roster(&pool.present(&deposits, &[0, 2]))
        .await
        .unwrap();
    refund(&mut session, &pool, &enclaves, alice, [1; 32])
        .await
        .unwrap();
    refund(&mut session, &pool, &enclaves, carol, [2; 32])
        .await
        .unwrap();
    assert!(refund(&mut session, &pool, &enclaves, bob, [3; 32])
        .await
        .is_err());
    // Until keygen completes, a bound permission is refused.
    assert!(escrow_request(
        &mut session,
        &pool,
        &enclaves,
        alice,
        Operation::Bind,
        None,
        &bind_request(&pool, alice),
    )
    .await
    .is_err());
    refund(&mut session, &pool, &enclaves, alice, [4; 32])
        .await
        .unwrap();
}
