//! Keygen for only the participants who are present.
//!
//! A pool that closes before every participant registers never completes keygen, yet each
//! participant who did register must still be able to get their escrow refunded. The SDK
//! registers them without completing keygen, and the enclave serves only their unbound,
//! verifier-authorized refunds. These tests drive real in-process enclaves through the SDK
//! and an opaque relay, as a gateway would carry them.
use super::integration_tests::{public_key, relay, Checkpoint, RelayState};
use super::*;
use crate::escrow_verifier::{
    BindView, EscrowVerifier, ExecutionView, PreparationView, PreparedAction, RegistrationView,
    VerificationFuture, VerifierDescriptor, VerifierRegistry,
};
use crate::operations::states::{KeygenStatus, OperatorStatus};
use axum::{
    routing::{get, post},
    Router,
};
use keymeld_core::{
    authorization::{
        EnclaveRecipientAuthorization, RegistrationAuthorization, RegistrationContext,
        SessionAuthorizationManifest, SignedSessionManifest,
    },
    escrow::{
        self,
        protocol::{
            BindEscrowRequest, EscrowCommand, EscrowResponse, ExecuteEscrowRequest,
            ExecutionOutput, Operation, Payload, PrepareEscrowRequest, ReceiptContext,
            RequestContext,
        },
        Action, ActionAttempt, ActionGrant, ApplicationContext, Bip340Item, Bip340Scope, Condition,
        ConditionProof, EscrowContext, EscrowPolicy, EscrowRegistration, Permission,
        PublicKeyBytes, SignedEscrowPolicy, VerifierPolicy,
    },
    protocol::{
        AddParticipantsBatchCommand, EnclavePublicKeyInfo, InitKeygenSessionCommand, KeygenOutcome,
        MusigOutcome, ParticipantRegistrationData, TaprootTweak,
    },
    EnclaveId, UserId,
};
use keymeld_sdk::{
    confidential::ConfidentialTransport,
    confidential_session::{ConfidentialJournal, ConfidentialSession},
    AuthorizationCredentials, BatchSigningItem, KeyMeldClient, SdkError, SessionCredentials,
    UserCredentials,
};

/// The unbound permission: a refund, which needs no pool.
const REFUND: &str = "refund";
/// A bound permission, which needs the pool: refused until keygen completes.
const PAYOUT: &str = "payout";
const POLICY: &[u8] = b"refund policy";

/// Authorizes a participant's refund. A real verifier derives the digest from the refund
/// transaction it checks; this one signs the digest it is given.
struct RefundVerifier;
impl EscrowVerifier for RefundVerifier {
    fn descriptor(&self) -> VerifierDescriptor {
        VerifierDescriptor {
            id: "refund-rule".into(),
            version: 1,
        }
    }
    fn validate_registration(&self, view: RegistrationView<'_>) -> Result<(), EnclaveError> {
        match &view.policy.policy.verifier {
            Some(verifier) if verifier.policy_data.as_bytes() == POLICY => Ok(()),
            _ => Err(rejected()),
        }
    }
    fn bind(&self, _view: BindView<'_>, data: &Payload) -> Result<Payload, EnclaveError> {
        Ok(data.clone())
    }
    fn prepare<'a>(
        &'a self,
        view: PreparationView<'a>,
        parameters: &'a Payload,
    ) -> VerificationFuture<'a, PreparedAction> {
        Box::pin(async move {
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
        })
    }
    fn verify_execution<'a>(
        &'a self,
        _view: ExecutionView<'a>,
        _prepared: &'a PreparedAction,
        _evidence: &'a Payload,
    ) -> VerificationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn operator(id: EnclaveId) -> Arc<EnclaveOperator> {
    let registry = VerifierRegistry::new(vec![Arc::new(RefundVerifier)]).unwrap();
    let operator = Arc::new(EnclaveOperator::with_verifiers(id, registry).unwrap());
    operator.set_test_keys([40 + id.as_u32() as u8; 32]);
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
    /// Replace an enclave with a fresh one holding the same key, as after a restart.
    fn restart(&self, id: EnclaveId) {
        self.state
            .operators
            .lock()
            .unwrap()
            .insert(id, operator(id));
    }
    /// The requests the relay has carried, as it saw them.
    fn requests(&self) -> Vec<String> {
        self.state.requests.lock().unwrap().clone()
    }
    /// Whether enclave `id` holds `session` at all.
    fn holds(&self, id: EnclaveId, session: &SessionId) -> bool {
        let operator = self.state.operators.lock().unwrap()[&id].clone();
        operator.sessions.contains_key(session)
    }
    /// Whether enclave `id` holds `session` with its participants still registering.
    fn registering(&self, id: EnclaveId, session: &SessionId) -> bool {
        let operator = self.state.operators.lock().unwrap()[&id].clone();
        let registering = operator.sessions.get(session).is_some_and(|held| {
            matches!(
                held.status,
                OperatorStatus::Keygen(KeygenStatus::Distributing(_))
            )
        });
        registering
    }
}

impl Drop for Enclaves {
    fn drop(&mut self) {
        self.server.abort();
    }
}

/// A pool of a coordinator and three players over two enclaves. The coordinator and Bob are
/// on enclave 1, Alice and Carol on enclave 2. Each player's registration carries a refund
/// permission.
struct Pool {
    /// Every key below derives from it.
    seed: u8,
    manifest: SignedSessionManifest,
    recipients: EnclaveRecipientAuthorization,
    epochs: BTreeMap<EnclaveId, u64>,
    credentials: SessionCredentials,
    authority: AuthorizationCredentials,
    reply: AuthorizationCredentials,
    client: KeyMeldClient,
    /// The coordinator, then Alice, Bob and Carol.
    users: Vec<UserId>,
    /// Each slot's key, which authorizes the registration in it.
    invitations: Vec<AuthorizationCredentials>,
    registrations: BTreeMap<UserId, ParticipantRegistrationData>,
    policies: BTreeMap<UserId, SignedEscrowPolicy>,
}

fn pool(enclaves: &Enclaves, seed: u8) -> Pool {
    pool_in(
        enclaves,
        seed,
        (0..4).map(|_| UserId::new_v7()).collect(),
        SessionId::new_v7(),
    )
}

fn pool_in(enclaves: &Enclaves, seed: u8, users: Vec<UserId>, session_id: SessionId) -> Pool {
    let authority = AuthorizationCredentials::from_secret(&[seed; 32]).unwrap();
    let reply = AuthorizationCredentials::from_secret(&[seed + 1; 32]).unwrap();
    let credentials = SessionCredentials::from_session_secret(&[seed + 2; 32]).unwrap();
    let invitations: Vec<_> = (0..users.len() as u8)
        .map(|index| AuthorizationCredentials::from_secret(&[seed + 3 + index; 32]).unwrap())
        .collect();
    let manifest = SignedSessionManifest::sign(
        SessionAuthorizationManifest {
            keygen_session_id: session_id,
            coordinator_user_id: users[0].clone(),
            creator_pubkey: authority.public_key_bytes(),
            signing_pubkey: authority.public_key_bytes(),
            session_public_key: credentials.public_key_bytes(),
            participant_verifiers: users
                .iter()
                .cloned()
                .zip(invitations.iter().map(|key| key.public_key_bytes()))
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
        },
        &[seed; 32],
    )
    .unwrap();
    let recipients = EnclaveRecipientAuthorization::sign(
        &manifest,
        users
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, user)| (user, EnclaveId::new(1 + index as u32 % 2)))
            .collect(),
        enclaves.keys.clone(),
        &[seed; 32],
    )
    .unwrap();
    let client = KeyMeldClient::builder(&format!("http://{}", enclaves.address), users[0].clone())
        .dangerous_trust_unattested_enclaves()
        .build()
        .unwrap();
    let mut pool = Pool {
        seed,
        manifest,
        recipients,
        epochs: enclaves.keys.keys().map(|id| (*id, 1)).collect(),
        credentials,
        authority,
        reply,
        client,
        users,
        invitations,
        registrations: BTreeMap::new(),
        policies: BTreeMap::new(),
    };
    for index in 0..pool.users.len() {
        let signing = UserCredentials::from_private_key(&[seed + 10 + index as u8; 32]).unwrap();
        let (registration, policy) = pool.registration(enclaves, index, &signing);
        let user = pool.users[index].clone();
        if let Some(policy) = policy {
            pool.policies.insert(user.clone(), policy);
        }
        pool.registrations.insert(user, registration);
    }
    pool
}

fn refund_policy(
    manifest: &SignedSessionManifest,
    user: &UserId,
    signing: &UserCredentials,
) -> SignedEscrowPolicy {
    let grant = |repetition, unbound| ActionGrant {
        preparation: escrow::PreparationPolicy::Single,
        repetition,
        unbound,
        condition: Condition::VerifierRule {
            rule: "refund_after_expiry".into(),
        },
        operation: Permission::SignBip340,
    };
    SignedEscrowPolicy::sign(
        EscrowPolicy {
            schema_version: escrow::SCHEMA_VERSION,
            context: EscrowContext {
                keygen_session_id: manifest.manifest.keygen_session_id.clone(),
                user_id: user.clone(),
                escrow_id: Uuid::now_v7(),
                manifest_digest: manifest.digest().unwrap().try_into().unwrap(),
                application: ApplicationContext::commit("refund".into(), 1, POLICY).unwrap(),
            },
            participant_public_key: PublicKeyBytes::new(&signing.public_key_bytes()).unwrap(),
            verifier: Some(VerifierPolicy {
                id: "refund-rule".into(),
                version: 1,
                policy_data: Payload::new(POLICY.to_vec()).unwrap(),
            }),
            secrets: BTreeMap::new(),
            grants: BTreeMap::from([
                (
                    REFUND.into(),
                    grant(escrow::Repetition::VerifierAuthorizedAttempts, true),
                ),
                (PAYOUT.into(), grant(escrow::Repetition::Once, false)),
            ]),
        },
        &signing.private_key_bytes(),
    )
    .unwrap()
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

    /// The coordinator's registration and those of the players at `players` (1 Alice,
    /// 2 Bob, 3 Carol).
    fn present(&self, players: &[usize]) -> BTreeMap<UserId, ParticipantRegistrationData> {
        std::iter::once(0)
            .chain(players.iter().copied())
            .map(|index| {
                let user = &self.users[index];
                (user.clone(), self.registrations[user].clone())
            })
            .collect()
    }

    fn session_id(&self) -> SessionId {
        self.manifest.manifest.keygen_session_id.clone()
    }

    /// The same pool in another keygen session: the same coordinator key, participants, slot
    /// keys and entry keys. Only the session differs.
    fn in_another_session(&self, enclaves: &Enclaves) -> Pool {
        pool_in(enclaves, self.seed, self.users.clone(), SessionId::new_v7())
    }

    /// The registration of `signing`'s key in the slot of `users[index]`, authorized by that
    /// slot's key. A player's carries a refund permission, and the coordinator's none.
    fn registration(
        &self,
        enclaves: &Enclaves,
        index: usize,
        signing: &UserCredentials,
    ) -> (ParticipantRegistrationData, Option<SignedEscrowPolicy>) {
        let user = &self.users[index];
        let session_id = self.session_id();
        let assigned = self.recipients.user_enclave_assignments[user];
        let enclave_key = hex::encode(&enclaves.keys[&assigned]);
        let auth_pubkey = signing
            .derive_session_auth_pubkey(&session_id.to_string())
            .unwrap();
        let context = RegistrationContext {
            keygen_session_id: session_id,
            manifest_hash: self.manifest.digest().unwrap(),
            user_id: user.clone(),
            enclave_id: assigned,
            enclave_key_epoch: 1,
            public_key: signing.public_key_bytes(),
            auth_pubkey: auth_pubkey.clone(),
            require_signing_approval: false,
        };
        let policy = (index > 0).then(|| refund_policy(&self.manifest, user, signing));
        let ciphertext = match &policy {
            None => signing
                .prepare_registration(context.clone(), &enclave_key)
                .unwrap(),
            Some(policy) => {
                let envelope = keymeld_core::authorization::RegistrationEnvelope::with_escrow(
                    context.clone(),
                    &signing.private_key_bytes(),
                    EscrowRegistration {
                        policy: policy.clone(),
                        secrets: BTreeMap::new(),
                    },
                )
                .unwrap();
                hex::encode(
                    keymeld_core::crypto::SecureCrypto::ecies_encrypt_from_hex(
                        &enclave_key,
                        &serde_json::to_vec(&envelope).unwrap(),
                    )
                    .unwrap(),
                )
            }
        };
        let registration = ParticipantRegistrationData {
            user_id: user.clone(),
            registration_authorization: RegistrationAuthorization::sign(
                &self.invitations[index].export_secret(),
                context,
                &ciphertext,
            )
            .unwrap(),
            enclave_encrypted_data: ciphertext,
            auth_pubkey,
            require_signing_approval: false,
        };
        (registration, policy)
    }

    /// The command that starts this keygen session on `enclave_id`, as the SDK builds it.
    fn init_command(&self, enclave_id: EnclaveId) -> EnclaveCommand {
        let manifest = &self.manifest.manifest;
        let coordinator = &manifest.coordinator_user_id;
        let key = hex::encode(&self.recipients.recipient_public_keys[&enclave_id]);
        EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::InitSession(
            InitKeygenSessionCommand {
                keygen_session_id: self.session_id(),
                coordinator_encrypted_private_key: None,
                coordinator_user_id: (self.recipients.user_enclave_assignments[coordinator]
                    == enclave_id)
                    .then(|| coordinator.clone()),
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

/// A batch registering `participants` in `session`.
fn batch(session: SessionId, participants: Vec<ParticipantRegistrationData>) -> EnclaveCommand {
    EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::AddParticipantsBatch(
        AddParticipantsBatchCommand {
            keygen_session_id: session,
            participants,
        },
    )))
}

/// Send a registration batch to `enclave` with the coordinator's key, past the SDK's checks.
async fn register_past_the_sdk(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    stage: &str,
    enclave: EnclaveId,
    participants: Vec<ParticipantRegistrationData>,
) -> Result<EnclaveOutcome, SdkError> {
    let command = batch(pool.session_id(), participants.clone());
    session
        .command_once(stage, enclave, &participants, move || Ok(command))
        .await
}

/// Send one escrow request for `user` to its enclave, and verify the enclave's receipt.
async fn escrow_request<T: serde::Serialize>(
    session: &mut ConfidentialSession<'_>,
    pool: &Pool,
    enclaves: &Enclaves,
    user: &UserId,
    operation: Operation,
    action: Option<(&str, &ActionAttempt)>,
    request: &T,
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

/// Sign `user`'s refund of `digest` in a fresh attempt, and check the signature is by the
/// player's own key.
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
        // Unbound: the pool it would have funded never formed.
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
    let key = secp256k1::PublicKey::from_slice(public_key.as_bytes())
        .unwrap()
        .x_only_public_key()
        .0;
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_byte_array(
                signature.signature.clone().try_into().unwrap(),
            ),
            &digest,
            &key,
        )
        .expect("the player's own key signed the refund");
    Ok(())
}

#[tokio::test]
async fn a_partial_roster_refunds_each_player_who_registered() {
    let enclaves = enclaves().await;
    let pool = pool(&enclaves, 20);
    let [_, alice, bob, carol] = &pool.users[..] else {
        unreachable!()
    };
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;

    // Alice and Bob entered. Carol never did, so the pool never filled.
    let present = pool.present(&[1, 2]);
    session.register_partial_roster(&present).await.unwrap();
    for enclave in [EnclaveId::new(1), EnclaveId::new(2)] {
        assert!(session
            .recorded_command("keygen/distribute", enclave)
            .is_none());
        assert!(session
            .recorded_command("keygen/aggregate", enclave)
            .is_none());
    }

    refund(&mut session, &pool, &enclaves, alice, [1; 32])
        .await
        .unwrap();
    refund(&mut session, &pool, &enclaves, bob, [2; 32])
        .await
        .unwrap();
    // A retried refund signs its own digest in a fresh attempt.
    refund(&mut session, &pool, &enclaves, alice, [3; 32])
        .await
        .unwrap();
    // No enclave holds the key of a player who never registered.
    assert!(refund(&mut session, &pool, &enclaves, carol, [4; 32])
        .await
        .is_err());

    // Until keygen completes, the enclave refuses every escrow action but an unbound one.
    let bind = BindEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        policy: pool.policies[alice].clone(),
        application_context: Payload::new(POLICY.to_vec()).unwrap(),
        participant_policies: pool.policies.clone(),
        binding_data: Payload::new(vec![1]).unwrap(),
    };
    assert!(escrow_request(
        &mut session,
        &pool,
        &enclaves,
        alice,
        Operation::Bind,
        None,
        &bind
    )
    .await
    .is_err());
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: None,
    };
    let payout = PrepareEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: Payload::new(vec![1]).unwrap(),
        action_id: PAYOUT.into(),
        attempt: attempt.clone(),
        action: None,
        action_parameters: Payload::encode(&[5u8; 32]).unwrap(),
        prior_preparation_receipts: vec![],
    };
    assert!(escrow_request(
        &mut session,
        &pool,
        &enclaves,
        alice,
        Operation::Prepare,
        Some((PAYOUT, &attempt)),
        &payout
    )
    .await
    .is_err());
    // There is no aggregate key to restore or to sign under.
    assert!(session.restore_keygen(&present).await.is_err());
    let signing = SessionId::new_v7();
    session
        .prepare_signing_batch(&signing, &[BatchSigningItem::new([6; 32])])
        .await
        .unwrap();
    assert!(session
        .sign_prepared_batch(&signing, 300, &[])
        .await
        .is_err());

    // None of those refusals cost the registrations the refunds need.
    refund(&mut session, &pool, &enclaves, alice, [7; 32])
        .await
        .unwrap();
    refund(&mut session, &pool, &enclaves, bob, [8; 32])
        .await
        .unwrap();
}

#[tokio::test]
async fn a_partial_roster_repeats_as_exact_retries_and_restores_after_a_restart() {
    let enclaves = enclaves().await;
    let pool = pool(&enclaves, 60);
    let alice = &pool.users[1];
    let present = pool.present(&[1]);
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    {
        let mut session = pool.connect(&mut journal, &checkpoint).await;
        session.register_partial_roster(&present).await.unwrap();

        // A repeat sends each enclave its journaled requests again, exactly, and nothing new.
        // Live enclaves answer them without effect.
        let before = enclaves.requests();
        session.register_partial_roster(&present).await.unwrap();
        let after = enclaves.requests();
        assert_eq!(
            after.len() - before.len(),
            4,
            "the start and the registration, on each enclave"
        );
        for request in &after[before.len()..] {
            assert!(before.contains(request), "a repeat sent a new request");
        }
        for enclave in [EnclaveId::new(1), EnclaveId::new(2)] {
            assert!(enclaves.registering(enclave, &pool.session_id()));
        }

        // Once the enclaves have evicted their cached replies, they skip the same requests as
        // commands they already ran, rather than refusing them.
        for operator in enclaves.state.operators.lock().unwrap().values() {
            let mut state = operator.confidential.state.lock().unwrap();
            state.replies.clear();
            state.reply_bytes = 0;
        }
        session.register_partial_roster(&present).await.unwrap();
        for enclave in [EnclaveId::new(1), EnclaveId::new(2)] {
            assert!(enclaves.registering(enclave, &pool.session_id()));
        }
        refund(&mut session, &pool, &enclaves, alice, [1; 32])
            .await
            .unwrap();
    }

    // Alice's enclave restarts, and so does the coordinator, from its durable journal.
    enclaves.restart(EnclaveId::new(2));
    let mut journal: ConfidentialJournal =
        serde_json::from_str(checkpoint.saved.lock().unwrap().as_ref().unwrap()).unwrap();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    assert!(
        refund(&mut session, &pool, &enclaves, alice, [2; 32])
            .await
            .is_err(),
        "the restarted enclave lost the session"
    );
    session.register_partial_roster(&present).await.unwrap();
    refund(&mut session, &pool, &enclaves, alice, [3; 32])
        .await
        .unwrap();
}

#[tokio::test]
async fn a_registered_partial_roster_cannot_change() {
    let enclaves = enclaves().await;
    let pool = pool(&enclaves, 100);
    let alice = &pool.users[1];
    let (coordinator_enclave, alice_enclave) = (EnclaveId::new(1), EnclaveId::new(2));
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    session
        .register_partial_roster(&pool.present(&[1]))
        .await
        .unwrap();
    let sent = enclaves.requests().len();

    // Alice's slot again, for a new entry key: authorized by her slot's key, for this session.
    let (changed, _) = pool.registration(
        &enclaves,
        1,
        &UserCredentials::from_private_key(&[252; 32]).unwrap(),
    );
    let mut with_changed = pool.present(&[1]);
    with_changed.insert(alice.clone(), changed.clone());
    // Carol on Alice's enclave, Bob on the coordinator's, leaving Alice's enclave out, or
    // Alice under another key.
    for roster in [
        pool.present(&[1, 3]),
        pool.present(&[1, 2]),
        pool.present(&[]),
        with_changed,
    ] {
        assert!(session.register_partial_roster(&roster).await.is_err());
    }
    // Completing keygen would register the others on enclaves that already hold registrations.
    assert!(session.complete_keygen(&pool.registrations).await.is_err());
    assert_eq!(
        enclaves.requests().len(),
        sent,
        "a refused roster sent nothing"
    );

    // Past the SDK, with the coordinator's key, Alice's slot takes no second registration.
    assert!(
        register_past_the_sdk(&mut session, &pool, "changed", alice_enclave, vec![changed])
            .await
            .is_err()
    );
    // The refusal cost nothing: both enclaves are still registering, and Alice is refunded
    // under her original key.
    assert!(enclaves.registering(coordinator_enclave, &pool.session_id()));
    assert!(enclaves.registering(alice_enclave, &pool.session_id()));
    refund(&mut session, &pool, &enclaves, alice, [1; 32])
        .await
        .unwrap();
}

#[tokio::test]
async fn a_partial_roster_needs_the_coordinator_and_only_its_own_participants() {
    let enclaves = enclaves().await;
    let pool = pool(&enclaves, 140);
    let other = pool.in_another_session(&enclaves);
    let alice = &pool.users[1];
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;

    // A participant the manifest never authorized.
    let stranger = UserId::new_v7();
    let mut with_stranger = pool.present(&[1]);
    let mut registration = pool.registrations[&pool.users[2]].clone();
    registration.user_id = stranger.clone();
    with_stranger.insert(stranger, registration);
    // Another participant's registration in Alice's slot.
    let mut substituted = pool.present(&[1]);
    substituted.insert(alice.clone(), pool.registrations[&pool.users[2]].clone());
    // Alice's registration for another session of the same coordinator, participants and
    // keys, so only its session binding tells them apart.
    let mut replayed = pool.present(&[1]);
    replayed.insert(alice.clone(), other.registrations[alice].clone());
    // Alice's slot authorized by a key other than her slot's verifier.
    let mut forged = pool.present(&[1]);
    let registration = forged.get_mut(alice).unwrap();
    registration.registration_authorization = RegistrationAuthorization::sign(
        &[250; 32],
        registration.registration_authorization.context.clone(),
        &registration.enclave_encrypted_data,
    )
    .unwrap();
    // No coordinator.
    let mut without_coordinator = pool.present(&[1, 2]);
    without_coordinator.remove(&pool.users[0]);
    for roster in [
        with_stranger,
        substituted,
        replayed,
        forged,
        without_coordinator,
        // The complete roster completes keygen instead.
        pool.registrations.clone(),
    ] {
        assert!(session.register_partial_roster(&roster).await.is_err());
    }
    assert!(
        enclaves.requests().is_empty(),
        "a refused roster sent nothing"
    );

    // The complete roster still completes keygen, and refunds work on it too.
    let roster = session.complete_keygen(&pool.registrations).await.unwrap();
    assert_eq!(roster.roster.registrations.len(), pool.users.len());
    refund(&mut session, &pool, &enclaves, alice, [1; 32])
        .await
        .unwrap();
}

/// What the SDK checks, the enclave enforces for a caller that skips the SDK, and a gateway
/// without the coordinator's key cannot act at all.
#[tokio::test]
async fn enclaves_refuse_a_partial_roster_the_sdk_would_not_send() {
    let enclaves = enclaves().await;
    let pool = pool(&enclaves, 20);
    // Another session of the same coordinator, participants and keys, on the same enclaves.
    let other = pool.in_another_session(&enclaves);
    let [_, alice, bob, carol] = &pool.users[..] else {
        unreachable!()
    };
    let (enclave_1, enclave_2) = (EnclaveId::new(1), EnclaveId::new(2));

    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    session
        .register_partial_roster(&pool.present(&[1]))
        .await
        .unwrap();
    let route = serde_json::from_str::<EnclaveEnvelope>(&enclaves.requests()[0])
        .unwrap()
        .opaque_route_id;

    let other_checkpoint = Checkpoint::default();
    let mut other_journal = ConfidentialJournal::default();
    let mut other_session = other.connect(&mut other_journal, &other_checkpoint).await;
    other_session
        .register_partial_roster(&other.present(&[1]))
        .await
        .unwrap();

    // A gateway knows a session's route, but not the coordinator's key. Its request to add
    // Carol is refused, and the session is untouched.
    let transport = ConfidentialTransport::new(&pool.client);
    let recipient = transport.attest(enclave_2).await.unwrap();
    let intruder = AuthorizationCredentials::from_secret(&[251; 32]).unwrap();
    let command = Command::new(batch(
        pool.session_id(),
        vec![pool.registrations[carol].clone()],
    ));
    let prepared = transport
        .prepare(&recipient, route, command, &intruder, &intruder)
        .unwrap();
    if let Ok(outcome) = transport.execute(&recipient, &prepared, &intruder).await {
        assert!(matches!(outcome.response, EnclaveOutcome::Error(_)));
    }
    refund(&mut session, &pool, &enclaves, alice, [1; 32])
        .await
        .unwrap();
    assert!(refund(&mut session, &pool, &enclaves, carol, [2; 32])
        .await
        .is_err());

    // With the coordinator's key but past the SDK's checks, the other session's registration
    // of Carol is refused: it belongs to that session's manifest.
    let replayed = vec![other.registrations[carol].clone()];
    assert!(
        register_past_the_sdk(&mut session, &pool, "replayed", enclave_2, replayed)
            .await
            .is_err()
    );

    // So is a registration for a participant outside the manifest.
    let mut stranger = pool.registrations[bob].clone();
    stranger.user_id = UserId::new_v7();
    assert!(
        register_past_the_sdk(&mut session, &pool, "stranger", enclave_1, vec![stranger])
            .await
            .is_err()
    );

    // The refusals cost this session nothing: both enclaves are still registering, Alice is
    // still refunded, and Carol still is not.
    assert!(enclaves.registering(enclave_1, &pool.session_id()));
    assert!(enclaves.registering(enclave_2, &pool.session_id()));
    refund(&mut session, &pool, &enclaves, alice, [3; 32])
        .await
        .unwrap();
    assert!(refund(&mut session, &pool, &enclaves, carol, [4; 32])
        .await
        .is_err());

    // Nor did any reach the other session, whose Alice is refunded under its own policy.
    refund(&mut other_session, &other, &enclaves, alice, [5; 32])
        .await
        .unwrap();
}

/// Only the manifest's signer chooses whom to register. Someone holding everything else (the
/// manifest, the session secret, the players' registrations and a route of its own) can
/// neither start the session nor add anyone to it, and a refused attempt reserves nothing.
#[tokio::test]
async fn only_the_manifest_signer_chooses_a_partial_roster() {
    let enclaves = enclaves().await;
    let pool = pool(&enclaves, 220);
    let [_, alice, _, carol] = &pool.users[..] else {
        unreachable!()
    };
    let enclave_2 = EnclaveId::new(2);
    let intruder = AuthorizationCredentials::from_secret(&[251; 32]).unwrap();
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();

    // The SDK acts only with the manifest's signing key.
    assert!(ConfidentialSession::connect(
        &pool.client,
        &pool.manifest,
        &pool.recipients,
        &pool.epochs,
        &pool.credentials,
        &intruder,
        &pool.reply,
        &mut journal,
        &checkpoint,
    )
    .await
    .is_err());

    // Past the SDK, the enclave neither starts the session for another key nor registers
    // Carol for it.
    let transport = ConfidentialTransport::new(&pool.client);
    let recipient = transport.attest(enclave_2).await.unwrap();
    let route = Uuid::now_v7();
    for command in [
        pool.init_command(enclave_2),
        batch(pool.session_id(), vec![pool.registrations[carol].clone()]),
    ] {
        let prepared = transport
            .prepare(
                &recipient,
                route,
                Command::new(command),
                &intruder,
                &intruder,
            )
            .unwrap();
        if let Ok(outcome) = transport.execute(&recipient, &prepared, &intruder).await {
            assert!(matches!(outcome.response, EnclaveOutcome::Error(_)));
        }
    }
    assert!(!enclaves.holds(enclave_2, &pool.session_id()));

    // The refusals reserved nothing: the coordinator's own selection goes through, and only
    // the player it selected is refunded.
    let mut session = pool.connect(&mut journal, &checkpoint).await;
    session
        .register_partial_roster(&pool.present(&[1]))
        .await
        .unwrap();
    refund(&mut session, &pool, &enclaves, alice, [1; 32])
        .await
        .unwrap();
    assert!(refund(&mut session, &pool, &enclaves, carol, [2; 32])
        .await
        .is_err());
}
