//! Exercise the SDK's real native MuSig2 orchestration through an opaque HTTP
//! relay. This is an in-process cryptographic test, not a Nitro attestation test.
use super::*;
use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use keymeld_core::{
    authorization::{
        EnclaveRecipientAuthorization, RegistrationAuthorization, RegistrationContext,
        SessionAuthorizationManifest, SignedSessionManifest,
    },
    protocol::{EnclaveBatchResult, MusigOutcome, ParticipantRegistrationData, TaprootTweak},
    EnclaveId, UserId,
};
use keymeld_sdk::{
    confidential_session::{
        CheckpointFuture, ConfidentialCheckpoint, ConfidentialJournal, ConfidentialSession,
    },
    AuthorizationCredentials, BatchSigningItem, KeyMeldClient, SessionCredentials, UserCredentials,
};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
struct RelayState {
    operators: Arc<Mutex<BTreeMap<EnclaveId, Arc<EnclaveOperator>>>>,
    requests: Arc<Mutex<Vec<String>>>,
    responses: Arc<Mutex<Vec<String>>>,
}

async fn public_key(
    State(state): State<RelayState>,
    Path(id): Path<u32>,
) -> Json<serde_json::Value> {
    let public = state.operators.lock().unwrap()[&EnclaveId::new(id)].get_public_key();
    Json(serde_json::json!({
        "enclave_id":id,"public_key":hex::encode(public),"attestation_document":"",
        "pcr_measurements":{},"timestamp":0,"healthy":true,"key_epoch":1
    }))
}

async fn relay(
    State(state): State<RelayState>,
    Json(envelope): Json<EnclaveEnvelope>,
) -> Json<EnclaveEnvelope> {
    state
        .requests
        .lock()
        .unwrap()
        .push(serde_json::to_string(&envelope).unwrap());
    let operator = state.operators.lock().unwrap()[&envelope.destination_enclave].clone();
    let outcome = operator
        .handle_command(Command::new(EnclaveCommand::Confidential(Box::new(
            envelope,
        ))))
        .await
        .unwrap();
    let EnclaveOutcome::Confidential(response) = outcome.response else {
        panic!("private response escaped encryption")
    };
    state
        .responses
        .lock()
        .unwrap()
        .push(serde_json::to_string(&response).unwrap());
    Json(*response)
}

#[derive(Default)]
struct Checkpoint {
    fail_next: AtomicBool,
    saved: Mutex<Option<String>>,
}
impl ConfidentialCheckpoint for Checkpoint {
    fn save<'a>(&'a self, journal: &'a ConfidentialJournal) -> CheckpointFuture<'a> {
        Box::pin(async move {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(keymeld_sdk::SdkError::Internal(
                    "simulated durable storage failure".into(),
                ));
            }
            *self.saved.lock().unwrap() = Some(serde_json::to_string(journal)?);
            Ok(())
        })
    }
}

fn new_operator(id: EnclaveId) -> Arc<EnclaveOperator> {
    let operator = Arc::new(EnclaveOperator::new(id).unwrap());
    operator.set_test_keys([14 + id.as_u32() as u8; 32]);
    operator
}

fn verify_signature(
    result: &[EnclaveBatchResult],
    credentials: &SessionCredentials,
    aggregate: &[u8],
    message: [u8; 32],
) {
    assert_eq!(result.len(), 1);
    assert!(result[0].error.is_none());
    let encrypted = result[0].encrypted_final_signature.as_ref().unwrap();
    let plaintext = credentials.decrypt(encrypted, "signature").unwrap();
    // Native result encoding matches the SDK's published final-signature format.
    let signature_bytes = if plaintext.len() == 64 {
        plaintext
    } else {
        hex::decode(plaintext).unwrap()
    };
    let signature =
        secp256k1::schnorr::Signature::from_byte_array(signature_bytes.try_into().unwrap());
    let public = secp256k1::PublicKey::from_slice(aggregate)
        .unwrap()
        .x_only_public_key()
        .0;
    secp256k1::Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public)
        .unwrap();
}

#[tokio::test]
async fn native_musig_rounds_are_confidential_durable_and_restore_without_reusing_nonces() {
    run_native_flow(false, 1).await;
}

#[cfg(feature = "escrow")]
#[tokio::test]
async fn trusted_verifier_authorizes_exact_native_signing_only_inside_confidential_transport() {
    run_native_flow(true, 1).await;
}

#[cfg(feature = "escrow")]
#[tokio::test]
async fn trusted_verifier_protects_distributed_native_rounds_across_two_enclaves() {
    run_native_flow(true, 2).await;
}

async fn run_native_flow(with_policy: bool, enclave_count: u32) {
    let operators = (1..=enclave_count)
        .map(|id| {
            let enclave_id = EnclaveId::new(id);
            let operator = if with_policy {
                let registry =
                    crate::escrow_verifier::VerifierRegistry::new(vec![Arc::new(TestVerifier {
                        reject_next: AtomicBool::new(true),
                    })])
                    .unwrap();
                let operator =
                    Arc::new(EnclaveOperator::with_verifiers(enclave_id, registry).unwrap());
                operator.set_test_keys([14 + id as u8; 32]);
                operator
            } else {
                new_operator(enclave_id)
            };
            (enclave_id, operator)
        })
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
    let authority = AuthorizationCredentials::from_secret(&[11; 32]).unwrap();
    let reply = AuthorizationCredentials::from_secret(&[12; 32]).unwrap();
    let credentials = SessionCredentials::from_session_secret(&[16; 32]).unwrap();
    let users = [UserId::new_v7(), UserId::new_v7()];
    let session_id = SessionId::new_v7();
    let invitations = [
        AuthorizationCredentials::from_secret(&[13; 32]).unwrap(),
        AuthorizationCredentials::from_secret(&[14; 32]).unwrap(),
    ];
    let manifest = SignedSessionManifest::sign(
        SessionAuthorizationManifest {
            keygen_session_id: session_id.clone(),
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
        &[11; 32],
    )
    .unwrap();
    let enclave_keys: BTreeMap<_, _> = state
        .operators
        .lock()
        .unwrap()
        .iter()
        .map(|(id, operator)| (*id, operator.get_public_key()))
        .collect();
    let protected_enclave = EnclaveId::new(enclave_count);
    let protected_key = enclave_keys[&protected_enclave].clone();
    let recipients = EnclaveRecipientAuthorization::sign(
        &manifest,
        users
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, user)| (user, EnclaveId::new(1 + index as u32 % enclave_count)))
            .collect(),
        enclave_keys.clone(),
        &[11; 32],
    )
    .unwrap();
    let mut policies = BTreeMap::new();
    let mut registrations = BTreeMap::new();
    for (index, user) in users.iter().enumerate() {
        let signing = UserCredentials::from_private_key(&[21 + index as u8; 32]).unwrap();
        let assigned = recipients.user_enclave_assignments[user];
        let enclave_key = &enclave_keys[&assigned];
        let context = RegistrationContext {
            keygen_session_id: session_id.clone(),
            manifest_hash: manifest.digest().unwrap(),
            user_id: user.clone(),
            enclave_id: assigned,
            enclave_key_epoch: 1,
            public_key: signing.public_key_bytes(),
            auth_pubkey: signing
                .derive_session_auth_pubkey(&session_id.to_string())
                .unwrap(),
            require_signing_approval: false,
        };
        let ciphertext = if with_policy && index == 1 {
            let policy = document_policy(&manifest, user, &signing);
            policies.insert(user.clone(), policy.clone());
            let envelope = keymeld_core::authorization::RegistrationEnvelope::with_escrow(
                context.clone(),
                &signing.private_key_bytes(),
                keymeld_core::escrow::EscrowRegistration {
                    policy,
                    secrets: BTreeMap::new(),
                },
            )
            .unwrap();
            hex::encode(
                keymeld_core::crypto::SecureCrypto::ecies_encrypt_from_hex(
                    &hex::encode(enclave_key),
                    &serde_json::to_vec(&envelope).unwrap(),
                )
                .unwrap(),
            )
        } else {
            signing
                .prepare_registration(context.clone(), &hex::encode(enclave_key))
                .unwrap()
        };
        registrations.insert(
            user.clone(),
            ParticipantRegistrationData {
                user_id: user.clone(),
                registration_authorization: RegistrationAuthorization::sign(
                    &invitations[index].export_secret(),
                    context,
                    &ciphertext,
                )
                .unwrap(),
                enclave_encrypted_data: ciphertext,
                auth_pubkey: signing
                    .derive_session_auth_pubkey(&session_id.to_string())
                    .unwrap(),
                require_signing_approval: false,
            },
        );
    }
    let client = KeyMeldClient::builder(&format!("http://{address}"), users[0].clone())
        .dangerous_trust_unattested_enclaves()
        .build()
        .unwrap();
    let epochs = enclave_keys.keys().map(|id| (*id, 1)).collect();
    let checkpoint = Checkpoint::default();
    let mut journal = ConfidentialJournal::default();
    let mut session = ConfidentialSession::connect(
        &client,
        &manifest,
        &recipients,
        &epochs,
        &credentials,
        &authority,
        &reply,
        &mut journal,
        &checkpoint,
    )
    .await
    .unwrap();
    checkpoint.fail_next.store(true, Ordering::SeqCst);
    assert!(session.complete_keygen(&registrations).await.is_err());
    assert!(
        state.requests.lock().unwrap().is_empty(),
        "an enclave side effect preceded durable request storage"
    );
    let pending_id = session
        .recorded_command("keygen/init", EnclaveId::new(1))
        .unwrap()
        .command_id;
    assert!(session
        .clear_rejected_command("keygen/init", EnclaveId::new(1))
        .await
        .is_err());
    let roster = session.complete_keygen(&registrations).await.unwrap();
    assert_eq!(
        session
            .recorded_command("keygen/init", EnclaveId::new(1))
            .unwrap()
            .command_id,
        pending_id
    );
    assert!(session
        .clear_rejected_command("keygen/init", EnclaveId::new(1))
        .await
        .is_err());
    let signing_id = SessionId::new_v7();
    let item = BatchSigningItem::new([42; 32]);
    session
        .prepare_signing_batch(&signing_id, std::slice::from_ref(&item))
        .await
        .unwrap();
    if with_policy {
        let stage = format!("sign/{signing_id}/nonces");
        assert!(session
            .sign_prepared_batch(&signing_id, 300, &[])
            .await
            .is_err());
        assert!(session.command_was_rejected(&stage, protected_enclave));
        let raw = session
            .recorded_command(&stage, protected_enclave)
            .unwrap()
            .clone();
        let enclave = state.operators.lock().unwrap()[&protected_enclave].clone();
        assert!(
            enclave.handle_command(raw.clone()).await.is_err(),
            "legacy raw signing bypassed private policy"
        );
        session
            .clear_rejected_command(&stage, protected_enclave)
            .await
            .unwrap();
        approve_document(
            &mut session,
            &credentials,
            &authority,
            &policies,
            &signing_id,
            item.id(),
            protected_enclave,
            &protected_key,
        )
        .await;
        // Bypass SDK batch immutability and present a valid creator signature
        // over a different message. The enclave's final nonce guard must reject
        // it even though the original session now has an installed permit.
        let EnclaveCommand::Musig(MusigCommand::Signing(SigningCommand::InitSession(mut changed))) =
            raw.command
        else {
            panic!("expected native signing initialization")
        };
        changed.batch_items[0].encrypted_message = credentials
            .encrypt(hex::encode([43; 32]).as_bytes(), "session_data")
            .unwrap();
        changed.signing_authorization = keymeld_core::authorization::SigningAuthorization::sign(
            &authority.export_secret(),
            &changed.keygen_session_id,
            &changed.signing_session_id,
            300,
            &changed.batch_items,
        )
        .unwrap();
        let input = changed.clone();
        assert!(
            session
                .command_once("sign/altered-scope", protected_enclave, &input, move || {
                    Ok(EnclaveCommand::Musig(MusigCommand::Signing(
                        SigningCommand::InitSession(changed),
                    )))
                })
                .await
                .is_err(),
            "authorized caller changed the verifier-approved message"
        );
        let altered = item
            .clone()
            .with_tweak(TaprootTweak::PlainTweak { tweak: [1; 32] });
        assert!(session
            .prepare_signing_batch(&signing_id, &[altered])
            .await
            .is_err());
    }
    let result = session
        .sign_prepared_batch(&signing_id, 300, &[])
        .await
        .unwrap();
    verify_signature(
        &result,
        &credentials,
        &roster.roster.aggregate_public_key,
        [42; 32],
    );
    let count = state.requests.lock().unwrap().len();
    let repeated = session
        .sign_prepared_batch(&signing_id, 300, &[])
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&result).unwrap(),
        serde_json::to_vec(&repeated).unwrap()
    );
    assert_eq!(
        state.requests.lock().unwrap().len(),
        count,
        "completed retries unexpectedly started another nonce round"
    );
    if with_policy {
        for wire in state
            .requests
            .lock()
            .unwrap()
            .iter()
            .chain(state.responses.lock().unwrap().iter())
        {
            for private in [
                "private approval policy",
                "document-rule",
                "prepared_receipt",
                "binding_receipt",
                "message_digest",
                "Sign",
                "Escrow",
            ] {
                assert!(
                    !wire.contains(private),
                    "private policy content leaked at relay"
                );
            }
        }
        server.abort();
        return;
    }
    let unfinished = SessionId::new_v7();
    session
        .prepare_signing_batch(&unfinished, &[BatchSigningItem::new([43; 32])])
        .await
        .unwrap();
    state
        .operators
        .lock()
        .unwrap()
        .insert(EnclaveId::new(1), new_operator(EnclaveId::new(1)));
    session.restore_keygen(&registrations).await.unwrap();
    assert!(session
        .sign_prepared_batch(&unfinished, 300, &[])
        .await
        .is_err());
    let fresh = SessionId::new_v7();
    session
        .prepare_signing_batch(&fresh, &[BatchSigningItem::new([44; 32])])
        .await
        .unwrap();
    let result = session.sign_prepared_batch(&fresh, 300, &[]).await.unwrap();
    verify_signature(
        &result,
        &credentials,
        &roster.roster.aggregate_public_key,
        [44; 32],
    );
    for wire in state
        .requests
        .lock()
        .unwrap()
        .iter()
        .chain(state.responses.lock().unwrap().iter())
    {
        let value: serde_json::Value = serde_json::from_str(wire).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        for private in [
            session_id.to_string(),
            signing_id.to_string(),
            users[0].to_string(),
            hex::encode(&roster.roster.aggregate_public_key),
            "InitSession".into(),
            "Nonces".into(),
            "FinalSignature".into(),
        ] {
            assert!(
                !wire.contains(&private),
                "private protocol field appeared at relay boundary"
            );
        }
    }
    server.abort();
}

use crate::escrow_verifier::{
    BindView, EscrowVerifier, ExecutionView, PreparationView, PreparedAction, RegistrationView,
    VerificationFuture, VerifierDescriptor,
};
use keymeld_core::escrow::protocol::{
    BindEscrowRequest, EscrowCommand, EscrowResponse, ExecuteEscrowRequest, Operation, Payload,
    PrepareEscrowRequest, ReceiptContext, RequestContext,
};
use keymeld_core::escrow::{
    self, Action, ActionAttempt, ActionGrant, AdaptorContext, ApplicationContext, Condition,
    ConditionProof, EscrowContext, EscrowPolicy, KeyTweak, Permission, PublicKeyBytes, ScopeSigner,
    SignedEscrowPolicy, SigningItem, SigningScope, VerifierPolicy,
};

struct TestVerifier {
    reject_next: AtomicBool,
}
impl EscrowVerifier for TestVerifier {
    fn descriptor(&self) -> VerifierDescriptor {
        VerifierDescriptor {
            id: "document-rule".into(),
            version: 1,
        }
    }
    fn validate_registration(&self, view: RegistrationView<'_>) -> Result<(), EnclaveError> {
        if view
            .policy
            .policy
            .verifier
            .as_ref()
            .unwrap()
            .policy_data
            .as_bytes()
            != b"private approval policy"
        {
            return Err(rejected());
        }
        Ok(())
    }
    fn bind(&self, view: BindView<'_>, data: &Payload) -> Result<Payload, EnclaveError> {
        if view.participant_policies.len() != 1
            || !view
                .participant_policies
                .contains_key(&view.policy.policy.context.user_id)
            || data.as_bytes() != [42; 32]
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
            if self.reject_next.swap(false, Ordering::SeqCst) {
                return Err(rejected());
            }
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
            // Derive the actual message commitment from the authenticated bound
            // document. Caller parameters contain only the stable batch item ID.
            let scope = SigningScope {
                session_tweak: KeyTweak::None,
                batch: vec![SigningItem {
                    item_id,
                    message_digest: escrow::sha256(view.bound_state.as_bytes()),
                    subset_id: None,
                    signers,
                    tweak: KeyTweak::None,
                    adaptor: AdaptorContext::None,
                }],
            };
            Ok(PreparedAction {
                action: Action::Sign { scope },
                application_state: view.bound_state.clone(),
                output: Payload::new(b"private approved document".to_vec()).unwrap(),
            })
        })
    }
    fn verify_execution<'a>(
        &'a self,
        _view: ExecutionView<'a>,
        prepared: &'a PreparedAction,
        evidence: &'a Payload,
    ) -> VerificationFuture<'a, ()> {
        Box::pin(async move {
            if prepared.application_state.as_bytes() != [42; 32]
                || evidence.as_bytes() != b"approved"
            {
                return Err(rejected());
            }
            Ok(())
        })
    }
}
fn document_policy(
    manifest: &SignedSessionManifest,
    user: &UserId,
    signing: &UserCredentials,
) -> SignedEscrowPolicy {
    SignedEscrowPolicy::sign(
        EscrowPolicy {
            schema_version: escrow::SCHEMA_VERSION,
            context: EscrowContext {
                keygen_session_id: manifest.manifest.keygen_session_id.clone(),
                user_id: user.clone(),
                escrow_id: Uuid::now_v7(),
                manifest_digest: manifest.digest().unwrap().try_into().unwrap(),
                application: ApplicationContext::commit(
                    "document".into(),
                    1,
                    b"private approval policy",
                )
                .unwrap(),
            },
            participant_public_key: PublicKeyBytes::new(&signing.public_key_bytes()).unwrap(),
            verifier: Some(VerifierPolicy {
                id: "document-rule".into(),
                version: 1,
                policy_data: Payload::new(b"private approval policy".to_vec()).unwrap(),
            }),
            secrets: BTreeMap::new(),
            grants: BTreeMap::from([(
                "sign".into(),
                ActionGrant {
                    preparation: escrow::PreparationPolicy::Single,
                    repetition: escrow::Repetition::Once,
                    condition: Condition::VerifierRule {
                        rule: "approved_document".into(),
                    },
                    operation: Permission::Sign,
                },
            )]),
        },
        &signing.private_key_bytes(),
    )
    .unwrap()
}
#[allow(clippy::too_many_arguments)]
async fn escrow_round<T: serde::Serialize>(
    session: &mut ConfidentialSession<'_>,
    credentials: &SessionCredentials,
    authority: &AuthorizationCredentials,
    policy: &SignedEscrowPolicy,
    stage: &str,
    operation: Operation,
    attempt: Option<&ActionAttempt>,
    request: &T,
    enclave_id: EnclaveId,
    enclave_key: &[u8],
) -> Result<EscrowResponse, keymeld_sdk::SdkError> {
    let context = RequestContext {
        schema_version: escrow::SCHEMA_VERSION,
        operation,
        escrow: policy.policy.context.clone(),
        policy_digest: policy.policy.digest().unwrap(),
        request_id: Uuid::now_v7(),
        action_id: attempt.map(|_| "sign".into()),
        attempt: attempt.cloned(),
    };
    let outcome = session
        .command_once(stage, enclave_id, request, || {
            let plaintext = zeroize::Zeroizing::new(serde_json::to_vec(request)?);
            let encrypted = credentials
                .session_secret()
                .encrypt(&plaintext, "escrow-request-v1")?;
            let command = EscrowCommand::sign(
                context,
                Payload::new(encrypted.to_bytes()?)?,
                &authority.export_secret(),
            )?;
            Ok(EnclaveCommand::Musig(MusigCommand::Keygen(
                KeygenCommand::Escrow(command),
            )))
        })
        .await?;
    let EnclaveOutcome::Musig(MusigOutcome::Keygen(keymeld_core::protocol::KeygenOutcome::Escrow(
        response,
    ))) = outcome
    else {
        panic!("wrong private escrow response")
    };
    let EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(command))) =
        &session.recorded_command(stage, enclave_id).unwrap().command
    else {
        unreachable!()
    };
    response.verify(
        &ReceiptContext {
            schema_version: escrow::SCHEMA_VERSION,
            enclave_id,
            enclave_key_epoch: 1,
            request: command.context.clone(),
            request_digest: command.digest().unwrap(),
        },
        enclave_key,
    )?;
    Ok(*response)
}
// A fixture that threads the full authorization context through one approval.
#[allow(clippy::too_many_arguments)]
async fn approve_document(
    session: &mut ConfidentialSession<'_>,
    credentials: &SessionCredentials,
    authority: &AuthorizationCredentials,
    policies: &BTreeMap<UserId, SignedEscrowPolicy>,
    signing_session: &SessionId,
    item: Uuid,
    enclave_id: EnclaveId,
    enclave_key: &[u8],
) {
    let policy = policies.values().next().unwrap();
    let bind = BindEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        policy: policy.clone(),
        application_context: Payload::new(b"private approval policy".to_vec()).unwrap(),
        participant_policies: policies.clone(),
        binding_data: Payload::new(vec![42; 32]).unwrap(),
    };
    let binding = escrow_round(
        session,
        credentials,
        authority,
        policy,
        "escrow/bind",
        Operation::Bind,
        None,
        &bind,
        enclave_id,
        enclave_key,
    )
    .await
    .unwrap();
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: Some(signing_session.clone()),
    };
    let prepare = PrepareEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: binding.sealed_state,
        action_id: "sign".into(),
        attempt: attempt.clone(),
        action: None,
        action_parameters: Payload::encode(&item).unwrap(),
        prior_preparation_receipts: vec![],
    };
    assert!(escrow_round(
        session,
        credentials,
        authority,
        policy,
        "escrow/prepare",
        Operation::Prepare,
        Some(&attempt),
        &prepare,
        enclave_id,
        enclave_key
    )
    .await
    .is_err());
    assert!(session.command_was_rejected("escrow/prepare", enclave_id));
    let failed_id = session
        .recorded_command("escrow/prepare", enclave_id)
        .unwrap()
        .command_id;
    session
        .clear_rejected_command("escrow/prepare", enclave_id)
        .await
        .unwrap();
    let prepared = escrow_round(
        session,
        credentials,
        authority,
        policy,
        "escrow/prepare",
        Operation::Prepare,
        Some(&attempt),
        &prepare,
        enclave_id,
        enclave_key,
    )
    .await
    .unwrap();
    assert_ne!(
        failed_id,
        session
            .recorded_command("escrow/prepare", enclave_id)
            .unwrap()
            .command_id
    );
    assert!(session
        .clear_rejected_command("escrow/prepare", enclave_id)
        .await
        .is_err());
    let execute = ExecuteEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        prepared_receipt: prepared.sealed_state,
        proof: ConditionProof::VerifierEvidence {
            evidence: Payload::new(b"approved".to_vec()).unwrap(),
        },
    };
    escrow_round(
        session,
        credentials,
        authority,
        policy,
        "escrow/execute",
        Operation::Execute,
        Some(&attempt),
        &execute,
        enclave_id,
        enclave_key,
    )
    .await
    .unwrap();
}
