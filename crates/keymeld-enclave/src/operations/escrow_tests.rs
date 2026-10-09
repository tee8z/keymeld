use super::*;
fn handle(
    completed: &Completed,
    context: &EnclaveSharedContext,
    command: &EscrowCommand,
    epoch: u64,
) -> Result<EscrowResponse, EnclaveError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(super::handle(completed, context, command, epoch))
}
use crate::musig::types::{BatchItemData, ParticipantSettings};
use crate::operations::registration::tests::{fixture as registration_fixture, public_key};
use keymeld_core::{
    authorization::SigningAuthorization,
    escrow::protocol::RequestContext,
    escrow::{
        ActionGrant, ApplicationContext, Condition, EscrowPolicy, Recipient, SecretCommitment,
    },
    protocol::{AdaptorConfig, EnclaveBatchItem, FinalizedData, SubsetDefinition},
    KeyMaterial,
};
use std::{sync::Arc, time::SystemTime};
use uuid::Uuid;

struct Fixture {
    completed: Completed,
    context: EnclaveSharedContext,
    user: UserId,
    maker: UserId,
    registration: Arc<EscrowRegistration>,
    signing: InitSigningSessionCommand,
}

fn fixture(exports: bool) -> Fixture {
    fixture_inner(exports, false)
}
fn fixture_inner(exports: bool, application: bool) -> Fixture {
    fixture_with_repetition(exports, application, false)
}
fn fixture_with_repetition(exports: bool, application: bool, repeat: bool) -> Fixture {
    fixture_with_preparation(exports, application, repeat, false)
}
fn fixture_with_preparation(
    exports: bool,
    application: bool,
    repeat: bool,
    renewable: bool,
) -> Fixture {
    fixture_with_grants(exports, application, repeat, renewable, vec![])
}
/// `extra` grants are added as given, after application mode converts the built-in ones.
fn fixture_with_grants(
    exports: bool,
    application: bool,
    repeat: bool,
    renewable: bool,
    extra: Vec<(&str, ActionGrant)>,
) -> Fixture {
    let original = registration_fixture();
    let user = original.participant.user_id;
    let maker = UserId::new_v7();
    let mut manifest = original.manifest.manifest;
    manifest.coordinator_user_id = maker.clone();
    manifest
        .participant_verifiers
        .insert(maker.clone(), public_key(&[17; 32]));
    manifest.subset_definitions = vec![SubsetDefinition {
        subset_id: Uuid::from_u128(3),
        participants: vec![user.clone(), maker.clone()],
    }];
    let manifest = SignedSessionManifest::sign(manifest, &[11; 32]).unwrap();
    let session = manifest.manifest.keygen_session_id.clone();
    let mut processor = MusigProcessor::new(
        &session,
        TaprootTweak::None,
        Some(2),
        vec![user.clone(), maker.clone()],
    );
    for (id, secret) in [(&user, [14; 32]), (&maker, [18; 32])] {
        processor
            .add_participant(
                id.clone(),
                secp256k1::PublicKey::from_slice(&public_key(&secret)).unwrap(),
            )
            .unwrap();
    }
    processor.session_metadata.subset_definitions = manifest.manifest.subset_definitions.clone();
    processor.session_metadata.authorization_manifest = Some(manifest.clone());
    processor.create_key_aggregation_context(&session).unwrap();
    processor.compute_subset_aggregates().unwrap();
    let item = EnclaveBatchItem {
        batch_item_id: Uuid::from_u128(1),
        encrypted_message: original
            .session_secret
            .encrypt(hex::encode([42; 32]).as_bytes(), "session_data")
            .unwrap()
            .to_hex()
            .unwrap(),
        encrypted_adaptor_configs: None,
        encrypted_taproot_tweak: original
            .session_secret
            .encrypt_value(&TaprootTweak::None, "session_data")
            .unwrap()
            .to_hex()
            .unwrap(),
        subset_id: None,
    };
    let signing_session_id = SessionId::new_v7();
    let signing = InitSigningSessionCommand {
        keygen_session_id: session.clone(),
        signing_session_id: signing_session_id.clone(),
        signing_authorization: SigningAuthorization::sign(
            &[12; 32],
            &session,
            &signing_session_id,
            60,
            std::slice::from_ref(&item),
        )
        .unwrap(),
        user_ids: vec![user.clone(), maker.clone()],
        encrypted_taproot_tweak: original
            .session_secret
            .encrypt_value(&TaprootTweak::None, "taproot_tweak")
            .unwrap()
            .to_hex()
            .unwrap(),
        expected_participant_count: 2,
        approval_signatures: vec![],
        batch_items: vec![item],
    };
    let scope = signing_scope(
        &processor.session_metadata,
        &original.session_secret,
        &signing,
        &user,
    )
    .unwrap();
    let context = EscrowContext {
        keygen_session_id: session.clone(),
        user_id: user.clone(),
        escrow_id: Uuid::now_v7(),
        manifest_digest: manifest.digest().unwrap().try_into().unwrap(),
        application: ApplicationContext::commit("document-signing".into(), 1, b"approved document")
            .unwrap(),
    };
    let condition = Condition::HashlockSha256 {
        commitment: escrow::sha256(&[6; 32]),
    };
    let mut grants = BTreeMap::from([(
        "sign".into(),
        ActionGrant {
            preparation: keymeld_core::escrow::PreparationPolicy::Single,
            repetition: escrow::Repetition::Once,
            unbound: false,
            condition: condition.clone(),
            operation: keymeld_core::escrow::Permission::Exact {
                action: Action::Sign { scope },
            },
        },
    )]);
    let recipient = Recipient {
        encryption_public_key: PublicKeyBytes::new(&public_key(&[19; 32])).unwrap(),
    };
    if exports {
        grants.insert(
            "secret".into(),
            ActionGrant {
                preparation: keymeld_core::escrow::PreparationPolicy::Single,
                repetition: escrow::Repetition::Once,
                unbound: false,
                condition: condition.clone(),
                operation: keymeld_core::escrow::Permission::Exact {
                    action: Action::ReleaseSecret {
                        name: "document-key".into(),
                        recipient: recipient.clone(),
                    },
                },
            },
        );
        grants.insert(
            "key".into(),
            ActionGrant {
                preparation: keymeld_core::escrow::PreparationPolicy::Single,
                repetition: escrow::Repetition::Once,
                unbound: false,
                condition,
                operation: keymeld_core::escrow::Permission::Exact {
                    action: Action::ReleaseSigningKey {
                        public_key: PublicKeyBytes::new(&public_key(&[14; 32])).unwrap(),
                        recipient,
                    },
                },
            },
        );
    }
    if application {
        for grant in grants.values_mut() {
            grant.condition = Condition::VerifierRule {
                rule: "document_approved".into(),
            };
            grant.operation = match grant.operation.exact().unwrap() {
                Action::Sign { .. } => escrow::Permission::Sign,
                Action::SignBip340 { .. } => escrow::Permission::SignBip340,
                Action::ReleaseSecret { name, recipient } => escrow::Permission::ReleaseSecret {
                    name: name.clone(),
                    recipient: recipient.clone(),
                },
                Action::ReleaseSigningKey {
                    public_key,
                    recipient,
                } => escrow::Permission::ReleaseSigningKey {
                    public_key: public_key.clone(),
                    recipient: recipient.clone(),
                },
            };
        }
    }
    if repeat {
        grants.get_mut("sign").unwrap().repetition =
            escrow::Repetition::RepeatIdenticalSigningScope;
    }
    if renewable {
        for id in ["secret", "key"] {
            grants.get_mut(id).unwrap().preparation =
                escrow::PreparationPolicy::RenewableIdenticalAction;
        }
    }
    for (id, grant) in extra {
        grants.insert(id.into(), grant);
    }
    let policy = SignedEscrowPolicy::sign(
        EscrowPolicy {
            verifier: application.then(|| escrow::VerifierPolicy {
                id: "document-approval".into(),
                version: 1,
                policy_data: Payload::new(b"document v1".to_vec()).unwrap(),
            }),
            schema_version: escrow::SCHEMA_VERSION,
            context,
            participant_public_key: PublicKeyBytes::new(&public_key(&[14; 32])).unwrap(),
            secrets: BTreeMap::from([(
                "document-key".into(),
                SecretCommitment::from_secret(&[7; 32]).unwrap(),
            )]),
            grants,
        },
        &[14; 32],
    )
    .unwrap();
    let registration = Arc::new(EscrowRegistration {
        policy,
        secrets: BTreeMap::from([("document-key".into(), vec![7; 32])]),
    });
    validate_registration(&manifest, &user, &public_key(&[14; 32]), &registration).unwrap();
    for (id, secret, escrow) in [
        (&user, vec![14; 32], Some(registration.clone())),
        (&maker, vec![18; 32], None),
    ] {
        let index = processor
            .session_metadata
            .get_all_participant_ids()
            .iter()
            .position(|candidate| candidate == id)
            .unwrap();
        processor
            .store_user_private_key(
                id,
                KeyMaterial::new(secret),
                index,
                id == &maker,
                ParticipantSettings {
                    escrow,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    for (id, key, invite) in [(&user, [14; 32], [13; 32]), (&maker, [18; 32], [17; 32])] {
        let ctx = keymeld_core::authorization::RegistrationContext {
            keygen_session_id: session.clone(),
            manifest_hash: manifest.digest().unwrap(),
            user_id: id.clone(),
            enclave_id: original.enclave.enclave_id,
            enclave_key_epoch: 1,
            public_key: public_key(&key),
            auth_pubkey: public_key(&invite),
            require_signing_approval: false,
        };
        processor.session_metadata.registrations.insert(
            id.clone(),
            keymeld_core::authorization::RegistrationAuthorization::sign(&invite, ctx, "001122")
                .unwrap(),
        );
    }
    Fixture {
        completed: Completed::new(
            session,
            original.session_secret,
            None,
            SystemTime::now(),
            vec![],
            vec![],
            processor,
        ),
        context: original.enclave,
        user,
        maker,
        registration,
        signing,
    }
}

fn command<T: Serialize>(
    f: &Fixture,
    operation: Operation,
    action: Option<(&str, &ActionAttempt)>,
    request: &T,
) -> EscrowCommand {
    let context = RequestContext {
        schema_version: escrow::SCHEMA_VERSION,
        operation,
        escrow: f.registration.policy.policy.context.clone(),
        policy_digest: f.registration.policy.policy.digest().unwrap(),
        request_id: Uuid::now_v7(),
        action_id: action.map(|(id, _)| id.into()),
        attempt: action.map(|(_, attempt)| attempt.clone()),
        keygen_session_id: None,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(request).unwrap());
    let encrypted = f
        .completed
        .session_secret()
        .encrypt(&plaintext, "escrow-request-v1")
        .unwrap();
    EscrowCommand::sign(
        context,
        Payload::new(encrypted.to_bytes().unwrap()).unwrap(),
        &[12; 32],
    )
    .unwrap()
}
fn bind(f: &Fixture) -> EscrowResponse {
    let command = command(
        f,
        Operation::Bind,
        None,
        &BindEscrowRequest {
            participant_policies: BTreeMap::new(),
            binding_data: Payload::default(),
            schema_version: escrow::SCHEMA_VERSION,
            policy: f.registration.policy.clone(),
            application_context: Payload::new(b"approved document".to_vec()).unwrap(),
        },
    );
    handle(&f.completed, &f.context, &command, 1).unwrap()
}
fn prepare(f: &Fixture, grant: &str) -> (EscrowResponse, ActionAttempt) {
    let action = f.registration.policy.policy.grants[grant]
        .operation
        .exact()
        .unwrap()
        .clone();
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: matches!(&action, Action::Sign { .. })
            .then(|| f.signing.signing_session_id.clone()),
    };
    let command = command(
        f,
        Operation::Prepare,
        Some((grant, &attempt)),
        &PrepareEscrowRequest {
            action_parameters: Payload::default(),
            prior_preparation_receipts: vec![],
            schema_version: escrow::SCHEMA_VERSION,
            binding_receipt: bind(f).sealed_state,
            action_id: grant.into(),
            attempt: attempt.clone(),
            action: Some(action),
        },
    );
    (
        handle(&f.completed, &f.context, &command, 1).unwrap(),
        attempt,
    )
}
fn execute_command(
    f: &Fixture,
    grant: &str,
    attempt: &ActionAttempt,
    receipt: Payload,
    proof: ConditionProof,
) -> EscrowCommand {
    command(
        f,
        Operation::Execute,
        Some((grant, attempt)),
        &ExecuteEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            prepared_receipt: receipt,
            proof,
        },
    )
}
fn proof() -> ConditionProof {
    ConditionProof::HashlockPreimage {
        preimage: vec![6; 32],
    }
}

#[test]
fn hashlock_unlocks_exact_musig_signing_without_exporting_any_secret() {
    let f = fixture(false);
    assert!(verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing
    )
    .is_err());
    let (prepared, attempt) = prepare(&f, "sign");
    let wrong = execute_command(
        &f,
        "sign",
        &attempt,
        prepared.sealed_state.clone(),
        ConditionProof::HashlockPreimage {
            preimage: vec![8; 32],
        },
    );
    assert!(handle(&f.completed, &f.context, &wrong, 1).is_err());
    assert!(verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing
    )
    .is_err());
    let cmd = execute_command(&f, "sign", &attempt, prepared.sealed_state, proof());
    let result = handle(&f.completed, &f.context, &cmd, 1).unwrap();
    result
        .verify(
            &ReceiptContext {
                schema_version: escrow::SCHEMA_VERSION,
                enclave_id: f.context.enclave_id,
                enclave_key_epoch: 1,
                request: cmd.context.clone(),
                request_digest: cmd.digest().unwrap(),
            },
            &f.context.public_key,
        )
        .unwrap();
    assert!(matches!(
        result.output.decode::<ExecutionOutput>().unwrap(),
        ExecutionOutput::SigningPermit { .. }
    ));
    verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing,
    )
    .unwrap();
    // Exercise the production MuSig nonce/partial/final-signature machinery.
    let mut signer = f
        .completed
        .musig_processor()
        .into_signing_processor(f.signing.signing_session_id.clone())
        .unwrap();
    let item = f.signing.batch_items[0].batch_item_id;
    signer
        .set_batch_items(BTreeMap::from([(
            item,
            BatchItemData {
                batch_item_id: item,
                message: vec![42; 32],
                adaptor_configs: vec![],
                adaptor_final_signatures: BTreeMap::new(),
                taproot_tweak: TaprootTweak::None,
                subset_id: None,
            },
        )]))
        .unwrap();
    let mut nonces = Vec::new();
    for user in [&f.user, &f.maker] {
        let participant = signer.get_user_session_data(user).unwrap();
        nonces.push((
            user.clone(),
            signer
                .generate_batch_nonces(
                    user,
                    participant.signer_index,
                    participant.private_key.as_ref().unwrap(),
                )
                .unwrap(),
        ));
    }
    for (user, nonces) in nonces {
        signer.store_batch_nonces(&user, nonces).unwrap();
    }
    signer.check_nonce_completion().unwrap();
    for user in [&f.user, &f.maker] {
        signer.finalize_batch_nonce_rounds(user).unwrap();
    }
    let partials = [&f.user, &f.maker]
        .into_iter()
        .map(|user| {
            (
                user.clone(),
                signer.get_user_batch_partial_signatures(user).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    for (user, partials) in partials {
        signer
            .add_batch_partial_signatures(&user, partials)
            .unwrap();
    }
    let aggregate = signer.get_aggregate_pubkey().unwrap();
    let results = signer.finalize_batch(&f.maker).unwrap();
    let FinalizedData::FinalSignature(signature) = &results[&item] else {
        panic!("expected ordinary generic signature")
    };
    let signature: [u8; 64] = signature.as_slice().try_into().unwrap();
    musig2::verify_single(aggregate, signature, [42; 32]).unwrap();
    let retry = handle(&f.completed, &f.context, &cmd, 1).unwrap();
    assert_eq!(
        serde_json::to_vec(&retry).unwrap(),
        serde_json::to_vec(&result).unwrap()
    );
    assert_eq!(
        f.completed
            .musig_processor()
            .get_user_session_data(&f.user)
            .unwrap()
            .private_key
            .unwrap()
            .as_bytes(),
        &[14; 32]
    );
}

#[test]
fn signing_permit_rejects_message_item_subset_tweak_adaptor_and_session_changes() {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    let cmd = execute_command(&f, "sign", &attempt, prepared.sealed_state, proof());
    handle(&f.completed, &f.context, &cmd, 1).unwrap();
    for variant in 0..7 {
        let mut changed = f.signing.clone();
        match variant {
            0 => {
                changed.batch_items[0].encrypted_message = f
                    .completed
                    .session_secret()
                    .encrypt(hex::encode([43; 32]).as_bytes(), "session_data")
                    .unwrap()
                    .to_hex()
                    .unwrap()
            }
            1 => changed.batch_items[0].batch_item_id = Uuid::now_v7(),
            2 => changed.batch_items[0].subset_id = Some(Uuid::from_u128(3)),
            3 => {
                changed.batch_items[0].encrypted_taproot_tweak = f
                    .completed
                    .session_secret()
                    .encrypt_value(&TaprootTweak::UnspendableTaproot, "session_data")
                    .unwrap()
                    .to_hex()
                    .unwrap()
            }
            4 => {
                changed.batch_items[0].encrypted_adaptor_configs = Some(
                    f.completed
                        .session_secret()
                        .encrypt_value(
                            &vec![AdaptorConfig::single(hex::encode(public_key(&[21; 32])))],
                            "adaptor_configs",
                        )
                        .unwrap()
                        .to_hex()
                        .unwrap(),
                )
            }
            5 => changed.signing_session_id = SessionId::new_v7(),
            _ => changed.batch_items.push(changed.batch_items[0].clone()),
        }
        assert!(
            verify_signing_batch(
                f.completed.musig_processor(),
                f.completed.session_secret(),
                &changed
            )
            .is_err(),
            "variant {variant}"
        );
    }
}

#[test]
fn generic_release_requires_separate_grant_and_encrypts_only_to_approved_recipient() {
    let f = fixture(true);
    for (grant, expected) in [("secret", [7; 32]), ("key", [14; 32])] {
        let (prepared, attempt) = prepare(&f, grant);
        let cmd = execute_command(&f, grant, &attempt, prepared.sealed_state, proof());
        let result = handle(&f.completed, &f.context, &cmd, 1).unwrap();
        let output: ExecutionOutput = result.output.decode().unwrap();
        let encrypted = match output {
            ExecutionOutput::ReleasedSecret {
                encrypted_secret, ..
            } => encrypted_secret,
            ExecutionOutput::ReleasedSigningKey { encrypted_key, .. } => encrypted_key,
            _ => panic!("expected explicitly approved release"),
        };
        let recipient = secp256k1::SecretKey::from_byte_array([19; 32]).unwrap();
        assert_eq!(
            SecureCrypto::ecies_decrypt(&recipient, encrypted.as_bytes()).unwrap(),
            expected
        );
        let operator = secp256k1::SecretKey::from_byte_array([12; 32]).unwrap();
        assert!(SecureCrypto::ecies_decrypt(&operator, encrypted.as_bytes()).is_err());
    }
    let sign_only = fixture(false);
    let binding = bind(&sign_only);
    let request = PrepareEscrowRequest {
        action_parameters: Payload::default(),
        prior_preparation_receipts: vec![],
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: binding.sealed_state,
        action_id: "sign".into(),
        attempt: ActionAttempt {
            attempt_id: Uuid::now_v7(),
            signing_session_id: None,
        },
        action: Some(Action::ReleaseSigningKey {
            public_key: sign_only
                .registration
                .policy
                .policy
                .participant_public_key
                .clone(),
            recipient: Recipient {
                encryption_public_key: PublicKeyBytes::new(&public_key(&[12; 32])).unwrap(),
            },
        }),
    };
    let cmd = command(
        &sign_only,
        Operation::Prepare,
        Some(("sign", &request.attempt)),
        &request,
    );
    assert!(handle(&sign_only.completed, &sign_only.context, &cmd, 1).is_err());
}

#[test]
fn sealed_receipt_restores_only_the_same_action_after_restart_and_cannot_be_forged_with_session_key(
) {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    let command = execute_command(&f, "sign", &attempt, prepared.sealed_state.clone(), proof());
    let executed = handle(&f.completed, &f.context, &command, 1).unwrap();
    *f.completed
        .musig_processor()
        .get_session_metadata_public()
        .escrow_state
        .inner
        .lock()
        .unwrap() = SessionState::default();
    assert!(verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing
    )
    .is_err());
    let recovery = execute_command(
        &f,
        "sign",
        &attempt,
        executed.sealed_state.clone(),
        ConditionProof::None,
    );
    let restored = handle(&f.completed, &f.context, &recovery, 2).unwrap();
    assert_eq!(restored.context.enclave_key_epoch, 2);
    verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing,
    )
    .unwrap();
    let mut other_attempt = attempt.clone();
    other_attempt.signing_session_id = Some(SessionId::new_v7());
    let substituted = execute_command(
        &f,
        "sign",
        &other_attempt,
        executed.sealed_state,
        ConditionProof::None,
    );
    assert!(handle(&f.completed, &f.context, &substituted, 2).is_err());
    let fake = f
        .completed
        .session_secret()
        .encrypt(b"{}", "escrow_state_v1")
        .unwrap()
        .to_bytes()
        .unwrap();
    let forged = execute_command(&f, "sign", &attempt, Payload::new(fake).unwrap(), proof());
    assert!(handle(&f.completed, &f.context, &forged, 2).is_err());
    let replay = execute_command(&f, "sign", &attempt, prepared.sealed_state, proof());
    handle(&f.completed, &f.context, &replay, 2).unwrap();
}

#[test]
fn authority_context_receipt_and_action_attempt_substitution_fail_closed() {
    let f = fixture(true);
    let (prepared, attempt) = prepare(&f, "secret");
    let original = execute_command(
        &f,
        "secret",
        &attempt,
        prepared.sealed_state.clone(),
        proof(),
    );
    let mut wrong_authority = original.clone();
    wrong_authority.authorization = vec![0; 64];
    assert!(handle(&f.completed, &f.context, &wrong_authority, 1).is_err());
    handle(&f.completed, &f.context, &original, 1).unwrap();
    let mut changed = command(
        &f,
        Operation::Execute,
        Some(("secret", &attempt)),
        &ExecuteEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            prepared_receipt: prepared.sealed_state.clone(),
            proof: proof(),
        },
    );
    changed.context.request_id = original.context.request_id;
    changed = EscrowCommand::sign(changed.context, changed.encrypted_request, &[12; 32]).unwrap();
    assert!(handle(&f.completed, &f.context, &changed, 1).is_err());
    let mut changed_attempt = attempt.clone();
    changed_attempt.attempt_id = Uuid::now_v7();
    let cmd = execute_command(
        &f,
        "secret",
        &changed_attempt,
        prepared.sealed_state.clone(),
        proof(),
    );
    assert!(handle(&f.completed, &f.context, &cmd, 1).is_err());
    let mut corrupted = prepared.sealed_state.as_bytes().to_vec();
    *corrupted.last_mut().unwrap() ^= 1;
    let cmd = execute_command(
        &f,
        "secret",
        &attempt,
        Payload::new(corrupted).unwrap(),
        proof(),
    );
    assert!(handle(&f.completed, &f.context, &cmd, 1).is_err());
    let mut foreign = original.clone();
    foreign.context.escrow.application.commitment = [99; 32];
    foreign = EscrowCommand::sign(foreign.context, foreign.encrypted_request, &[12; 32]).unwrap();
    assert!(handle(&f.completed, &f.context, &foreign, 1).is_err());
}

#[test]
fn signed_recipient_binding_and_application_commitment_cannot_be_replaced() {
    let f = fixture(true);
    let bound = bind(&f);
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: None,
    };
    let mut action = f.registration.policy.policy.grants["secret"]
        .operation
        .exact()
        .unwrap()
        .clone();
    let Action::ReleaseSecret { recipient, .. } = &mut action else {
        unreachable!()
    };
    recipient.encryption_public_key = PublicKeyBytes::new(&public_key(&[12; 32])).unwrap();
    let forged = PrepareEscrowRequest {
        action_parameters: Payload::default(),
        prior_preparation_receipts: vec![],
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: bound.sealed_state,
        action_id: "secret".into(),
        attempt: attempt.clone(),
        action: Some(action),
    };
    let cmd = command(&f, Operation::Prepare, Some(("secret", &attempt)), &forged);
    assert!(handle(&f.completed, &f.context, &cmd, 1).is_err());
    let substituted = command(
        &f,
        Operation::Bind,
        None,
        &BindEscrowRequest {
            participant_policies: BTreeMap::new(),
            binding_data: Payload::default(),
            schema_version: escrow::SCHEMA_VERSION,
            policy: f.registration.policy.clone(),
            application_context: Payload::new(b"a different document".to_vec()).unwrap(),
        },
    );
    assert!(handle(&f.completed, &f.context, &substituted, 1).is_err());
}

#[test]
fn exhausted_preparation_cache_cannot_block_authorized_execution_or_recovery() {
    let f = fixture(true);
    let mut candidates = Vec::new();
    for permission in ["sign", "secret", "key"] {
        let (prepared, attempt) = prepare(&f, permission);
        candidates.push((permission, prepared, attempt));
    }
    // Executing a preparation releases that preparation's cached reply.
    let released: usize = candidates
        .iter()
        .map(|(_, prepared, _)| cached_reply_bytes(prepared))
        .sum();
    let unrelated = bind(&f);
    let escrow_state = &f
        .completed
        .musig_processor()
        .get_session_metadata_public()
        .escrow_state;
    {
        let mut state = escrow_state.inner.lock().unwrap();
        state.cached_response_bytes = MAX_REQUEST_CACHE_BYTES;
        // Represents arbitrary other participants and prior preparation history
        // exhausting both shared response bytes and this participant's request quota.
        for _ in 0..escrow::MAX_ACTIONS * 4 {
            state.requests.insert(
                (f.user.clone(), Uuid::now_v7()),
                (
                    [0; 32],
                    CachedRequest::Reply {
                        reply: Box::new(unrelated.clone()),
                        charge: f.context.response_budget.reserve(0).unwrap(),
                    },
                ),
            );
        }
    }
    let rebind = command(
        &f,
        Operation::Bind,
        None,
        &BindEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            policy: f.registration.policy.clone(),
            application_context: Payload::new(b"approved document".to_vec()).unwrap(),
            participant_policies: BTreeMap::new(),
            binding_data: Payload::default(),
        },
    );
    assert!(matches!(
        handle(&f.completed, &f.context, &rebind, 1),
        Err(EnclaveError::EscrowPreparationExhausted { .. })
    ));
    let held = f.context.response_budget.snapshot();
    let _other_sessions = f
        .context
        .response_budget
        .reserve(held.limit - held.used)
        .unwrap();
    assert_eq!(f.context.response_budget.snapshot().used, held.limit);
    let cached_count = escrow_state.inner.lock().unwrap().requests.len();
    for (permission, prepared, attempt) in candidates {
        let execute = execute_command(&f, permission, &attempt, prepared.sealed_state, proof());
        let original = handle(&f.completed, &f.context, &execute, 1).unwrap();
        let refreshed = handle(&f.completed, &f.context, &execute, 2).unwrap();
        assert_eq!(refreshed.output, original.output);
        assert_eq!(refreshed.sealed_state, original.sealed_state);
        let mut expected = original.context;
        expected.enclave_key_epoch = 2;
        refreshed.verify(&expected, &f.context.public_key).unwrap();
        // Fresh recovery request identities cannot grow the full response cache.
        for _ in 0..4 {
            let recovered = handle(
                &f.completed,
                &f.context,
                &execute_command(
                    &f,
                    permission,
                    &attempt,
                    original.sealed_state.clone(),
                    ConditionProof::None,
                ),
                2,
            )
            .unwrap();
            assert_eq!(recovered.output, original.output);
            assert_eq!(recovered.sealed_state, original.sealed_state);
        }
    }
    let state = escrow_state.inner.lock().unwrap();
    assert_eq!(state.requests.len(), cached_count);
    assert_eq!(
        state.cached_response_bytes,
        MAX_REQUEST_CACHE_BYTES - released
    );
    assert_eq!(state.execution_receipts.len(), 3);
    assert_eq!(state.executions.len(), 3);
    assert_eq!(state.permits.len(), 1);
}

#[test]
fn subset_tweak_must_match_the_actual_keygen_context_before_permit_lookup() {
    let f = fixture(false);
    let mut command = f.signing.clone();
    command.batch_items[0].subset_id = Some(Uuid::from_u128(3));
    command.batch_items[0].encrypted_taproot_tweak = f
        .completed
        .session_secret()
        .encrypt_value(&TaprootTweak::UnspendableTaproot, "session_data")
        .unwrap()
        .to_hex()
        .unwrap();
    let error = verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &command,
    )
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Subset escrow item tweak must equal"),
        "{error}"
    );
    assert!(f
        .completed
        .musig_processor()
        .get_session_metadata_public()
        .escrow_state
        .inner
        .lock()
        .unwrap()
        .permits
        .is_empty());
}

#[path = "escrow_verifier_tests.rs"]
mod verifier_tests;

/// The sealed binding as it was before it could record a deposit-scoped policy's session.
#[derive(Serialize)]
struct LegacyBinding<'a> {
    context: &'a EscrowContext,
    policy_digest: [u8; 32],
    enclave_id: keymeld_core::EnclaveId,
    participant_policy_digests: &'a BTreeMap<UserId, [u8; 32]>,
    application_state: &'a Payload,
}

#[test]
fn a_binding_sealed_before_session_naming_still_decodes_unchanged() {
    let binding = Binding {
        context: EscrowContext {
            keygen_session_id: SessionId::new_v7(),
            user_id: UserId::new_v7(),
            escrow_id: Uuid::now_v7(),
            manifest_digest: [2; 32],
            application: ApplicationContext::commit("document".into(), 1, b"terms").unwrap(),
        },
        policy_digest: [3; 32],
        enclave_id: keymeld_core::EnclaveId::new(1),
        participant_policy_digests: BTreeMap::from([(UserId::new_v7(), [4; 32])]),
        application_state: Payload::new(vec![5]).unwrap(),
        keygen_session_id: None,
    };
    let written_before = serde_json::to_vec(&LegacyBinding {
        context: &binding.context,
        policy_digest: binding.policy_digest,
        enclave_id: binding.enclave_id,
        participant_policy_digests: &binding.participant_policy_digests,
        application_state: &binding.application_state,
    })
    .unwrap();
    let stored: Binding = serde_json::from_slice(&written_before).unwrap();
    assert_eq!(stored, binding);
    assert_eq!(serde_json::to_vec(&stored).unwrap(), written_before);
    // A deposit-scoped session's binding records its session.
    let mut scoped = binding;
    scoped.keygen_session_id = Some(SessionId::new_v7());
    assert_ne!(serde_json::to_vec(&scoped).unwrap(), written_before);
    assert_eq!(
        serde_json::from_slice::<Binding>(&serde_json::to_vec(&scoped).unwrap()).unwrap(),
        scoped
    );
}

/// A state as the previous release sealed it: uncompressed JSON under the v1 label.
fn seal_v1(context: &EnclaveSharedContext, state: SealedState) -> Payload {
    let envelope = SealedEnvelope {
        schema_version: escrow::SCHEMA_VERSION,
        enclave_id: context.enclave_id,
        state,
    };
    let sealed = sealing_key(context)
        .unwrap()
        .encrypt(&serde_json::to_vec(&envelope).unwrap(), SEALED_STATE_V1)
        .unwrap()
        .to_bytes()
        .unwrap();
    Payload::new(sealed).unwrap()
}
fn unseal_prepared(context: &EnclaveSharedContext, sealed: &Payload) -> PreparedAction {
    match unseal(context, sealed).unwrap() {
        SealedState::Prepared { prepared } => Arc::unwrap_or_clone(prepared),
        other => panic!("expected a prepared state, got {other:?}"),
    }
}
fn sealed_label(sealed: &Payload) -> String {
    EncryptedData::from_bytes(sealed.as_bytes())
        .unwrap()
        .context
}

#[test]
fn compressed_sealed_state_round_trips_and_v1_states_still_execute() {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    assert_eq!(sealed_label(&prepared.sealed_state), SEALED_STATE);
    let state = unseal_prepared(&f.context, &prepared.sealed_state);
    let resealed = seal_state(
        &f.context,
        SealedState::Prepared {
            prepared: Arc::new(state.clone()),
        },
    )
    .unwrap();
    assert_eq!(unseal_prepared(&f.context, &resealed), state);

    // A receipt the previous release handed out before a redeploy.
    let legacy = seal_v1(
        &f.context,
        SealedState::Prepared {
            prepared: Arc::new(state.clone()),
        },
    );
    assert_eq!(sealed_label(&legacy), SEALED_STATE_V1);
    assert_eq!(unseal_prepared(&f.context, &legacy), state);
    let command = execute_command(&f, "sign", &attempt, legacy, proof());
    let executed = handle(&f.completed, &f.context, &command, 1).unwrap();
    assert_eq!(sealed_label(&executed.sealed_state), SEALED_STATE);
    verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing,
    )
    .unwrap();
}

#[test]
fn tampered_or_session_key_compressed_state_is_refused() {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    let mut corrupted = prepared.sealed_state.as_bytes().to_vec();
    let middle = corrupted.len() / 2;
    corrupted[middle] ^= 1;
    let corrupted = Payload::new(corrupted).unwrap();
    assert!(unseal(&f.context, &corrupted).is_err());
    let cmd = execute_command(&f, "sign", &attempt, corrupted, proof());
    assert!(handle(&f.completed, &f.context, &cmd, 1).is_err());

    // Both labels are bound to the enclave sealing key, not the session key.
    for (label, plaintext) in [
        (
            SEALED_STATE,
            miniz_oxide::deflate::compress_to_vec(b"{}", SEALED_STATE_DEFLATE_LEVEL),
        ),
        (SEALED_STATE_V1, b"{}".to_vec()),
    ] {
        let forged = f
            .completed
            .session_secret()
            .encrypt(&plaintext, label)
            .unwrap()
            .to_bytes()
            .unwrap();
        assert!(unseal(&f.context, &Payload::new(forged).unwrap()).is_err());
    }
    let unknown = sealing_key(&f.context)
        .unwrap()
        .encrypt(b"{}", "escrow_state_v0")
        .unwrap()
        .to_bytes()
        .unwrap();
    assert!(unseal(&f.context, &Payload::new(unknown).unwrap()).is_err());
}

#[test]
fn compressed_state_over_the_payload_limit_is_refused_before_decoding() {
    let f = fixture(false);
    let sealed = |plaintext: &[u8]| {
        let compressed =
            miniz_oxide::deflate::compress_to_vec(plaintext, SEALED_STATE_DEFLATE_LEVEL);
        let sealed = sealing_key(&f.context)
            .unwrap()
            .encrypt(&compressed, SEALED_STATE)
            .unwrap()
            .to_bytes()
            .unwrap();
        (compressed.len(), Payload::new(sealed).unwrap())
    };
    let (compressed, bomb) = sealed(&vec![b' '; escrow::MAX_PAYLOAD_BYTES + 1]);
    assert!(compressed < 16 * 1024);
    let error = unseal(&f.context, &bomb).unwrap_err().to_string();
    assert!(error.contains("size limit"), "{error}");
    // At the limit the state decompresses and fails only as JSON.
    let (_, largest) = sealed(&vec![b' '; escrow::MAX_PAYLOAD_BYTES]);
    let error = unseal(&f.context, &largest).unwrap_err().to_string();
    assert!(!error.contains("size limit"), "{error}");
}

/// A pool contract's permit for one of `players`: N+2 outcome transactions with adaptor
/// points, N+1 splits and N expiry splits, each listing all N+1 signers.
fn contract_scope(players: usize) -> (SigningScope, BTreeMap<UserId, [u8; 32]>) {
    let mut signers: Vec<ScopeSigner> = (0..=players)
        .map(|index| ScopeSigner {
            user_id: UserId::new_v7(),
            public_key: PublicKeyBytes::new(&public_key(&[index as u8 + 1; 32])).unwrap(),
        })
        .collect();
    signers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
    let batch = (0..3 * players + 3)
        .map(|index| SigningItem {
            item_id: Uuid::now_v7(),
            message_digest: escrow::sha256(&index.to_le_bytes()),
            subset_id: None,
            signers: signers.clone(),
            tweak: KeyTweak::TaprootKeyPath,
            adaptor: if index < players + 2 {
                AdaptorContext::Single {
                    adaptor_id: Uuid::now_v7(),
                    point: PublicKeyBytes::new(&public_key(&[index as u8 + 100; 32])).unwrap(),
                }
            } else {
                AdaptorContext::None
            },
        })
        .collect();
    let digests = signers
        .iter()
        .map(|signer| {
            (
                signer.user_id.clone(),
                escrow::sha256(signer.public_key.as_bytes()),
            )
        })
        .collect();
    (
        SigningScope {
            session_tweak: KeyTweak::None,
            batch,
        },
        digests,
    )
}

#[test]
fn contract_scope_sealed_state_shrinks_for_large_pools() {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    let template = unseal_prepared(&f.context, &prepared.sealed_state);
    for players in [22, 25] {
        let (scope, digests) = contract_scope(players);
        let mut state = template.clone();
        state.action = Action::Sign { scope };
        Arc::make_mut(&mut state.binding).participant_policy_digests = digests;
        let state = SealedState::Prepared {
            prepared: Arc::new(state),
        };
        let v1 = seal_v1(&f.context, state.clone());
        let v2 = seal_state(&f.context, state).unwrap();
        assert_eq!(
            unseal_prepared(&f.context, &v2),
            unseal_prepared(&f.context, &v1)
        );
        // The Execute request the caller sends back, before the transport envelope.
        let request = |sealed: Payload| {
            serde_json::to_vec(&execute_command(&f, "sign", &attempt, sealed, proof()))
                .unwrap()
                .len()
        };
        let (v1_len, v2_len) = (v1.as_bytes().len(), v2.as_bytes().len());
        let (v1_request, v2_request) = (request(v1), request(v2));
        println!(
            "{players} players: sealed {v1_len} -> {v2_len} bytes, execute request {v1_request} -> {v2_request} bytes"
        );
        assert!(v2_len * 10 < v1_len, "{v1_len} -> {v2_len}");
        assert!(v2_request * 5 < v1_request, "{v1_request} -> {v2_request}");
    }
}

/// The coordinator's permit in a two-place pool of `players`: P(N,2) outcome transactions
/// with adaptor points and 2N+2 refund and expiry transactions list all N+1 signers, and
/// each outcome's two splits list the coordinator and that outcome's two winners.
fn two_place_scope(players: usize) -> SigningScope {
    let signers = contract_scope(players).0.batch[0].signers.clone();
    let outcomes = players * (players - 1);
    let item = |index: usize, signers: &[ScopeSigner], subset_id: Option<Uuid>| SigningItem {
        item_id: Uuid::now_v7(),
        message_digest: escrow::sha256(&index.to_le_bytes()),
        subset_id,
        signers: signers.to_vec(),
        tweak: KeyTweak::TaprootKeyPath,
        adaptor: if index < outcomes {
            AdaptorContext::Single {
                adaptor_id: Uuid::now_v7(),
                point: PublicKeyBytes::new(&public_key(&[(index % 250) as u8 + 1; 32])).unwrap(),
            }
        } else {
            AdaptorContext::None
        },
    };
    let full = (0..outcomes + 2 * players + 2).map(|index| item(index, &signers, None));
    let splits = (0..2 * outcomes).map(|index| {
        item(
            outcomes + 2 * players + 2 + index,
            &signers[..3],
            Some(Uuid::now_v7()),
        )
    });
    SigningScope {
        session_tweak: KeyTweak::None,
        batch: full.chain(splits).collect(),
    }
}

#[test]
fn a_two_place_pool_of_twenty_fits_one_permit_and_one_signing_request() {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    let mut state = unseal_prepared(&f.context, &prepared.sealed_state);
    let scope = two_place_scope(20);
    assert_eq!(scope.batch.len(), 1182);
    assert!(scope.batch.len() <= escrow::MAX_BATCH_ITEMS);
    state.action = Action::Sign {
        scope: scope.clone(),
    };
    let action = Payload::encode(&state.action).unwrap();
    let sealed = seal_state(
        &f.context,
        SealedState::Prepared {
            prepared: Arc::new(state),
        },
    )
    .unwrap();
    let restored = unseal_prepared(&f.context, &sealed);
    assert_eq!(restored.action, Action::Sign { scope });
    // A signing retry sends the scope as verifier parameters beside its prior receipt.
    let request = command(
        &f,
        Operation::Prepare,
        Some(("sign", &attempt)),
        &PrepareEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            binding_receipt: bind(&f).sealed_state,
            action_id: "sign".into(),
            attempt: attempt.clone(),
            action: None,
            action_parameters: action,
            prior_preparation_receipts: vec![sealed],
        },
    );
    let size = serde_json::to_vec(&request).unwrap().len();
    println!("two places, 20 players: signing request {size} bytes");
    assert!(size + 64 * 1024 <= keymeld_core::confidential::MAX_PLAINTEXT_BYTES);
}

#[test]
fn trial_transition_shares_large_receipts_and_keeps_live_state_isolated() {
    let user = UserId::new_v7();
    let mut state = SessionState::default();
    for index in 0..32 {
        state.execution_receipts.insert(
            (user.clone(), format!("receipt-{index}")),
            Arc::new(Payload::new(vec![index as u8; 512 * 1024]).unwrap()),
        );
    }
    let key = (user, "receipt-0".to_string());
    let original_bytes = state.execution_receipts[&key].as_bytes().as_ptr();
    let mut next = state.transition();
    for (key, receipt) in &state.execution_receipts {
        assert_eq!(
            receipt.as_bytes().as_ptr(),
            next.execution_receipts[key].as_bytes().as_ptr(),
            "trial updates must not copy accumulated receipts"
        );
    }
    next.execution_receipts
        .insert(key.clone(), Arc::new(Payload::new(vec![99]).unwrap()));
    assert_eq!(
        state.execution_receipts[&key].as_bytes().as_ptr(),
        original_bytes
    );
    assert_eq!(state.execution_receipts[&key].as_bytes().len(), 512 * 1024);
    let observed = EscrowSessionState {
        inner: Mutex::new(state),
    };
    assert_eq!(
        observed.memory_usage().unwrap().receipt_bytes,
        16 * 1024 * 1024
    );
    let _busy = observed.inner.lock().unwrap();
    assert!(
        observed.memory_usage().is_none(),
        "diagnostics must not wait for protocol state"
    );
}

#[test]
fn preparation_reply_budget_is_shared_across_sessions_and_exact_retries_do_not_recharge() {
    use super::super::response_budget::ResponseBudget;
    let mut first = fixture(true);
    let mut second = fixture(true);
    let budget = Arc::new(ResponseBudget::new(MAX_CACHED_RESPONSE_BYTES));
    first.context.response_budget = budget.clone();
    second.context.response_budget = budget.clone();
    let bind_command = |f: &Fixture| {
        command(
            f,
            Operation::Bind,
            None,
            &BindEscrowRequest {
                participant_policies: BTreeMap::new(),
                binding_data: Payload::default(),
                schema_version: escrow::SCHEMA_VERSION,
                policy: f.registration.policy.clone(),
                application_context: Payload::new(b"approved document".to_vec()).unwrap(),
            },
        )
    };
    let initial = bind_command(&first);
    let reply = handle(&first.completed, &first.context, &initial, 1).unwrap();
    let retained = budget.snapshot().used;
    assert!(retained > 0 && retained < MAX_CACHED_RESPONSE_BYTES);
    assert_eq!(budget.snapshot().retained, retained);
    let cached = handle(&first.completed, &first.context, &initial, 1).unwrap();
    assert_eq!(cached.output, reply.output);
    assert_eq!(budget.snapshot().used, retained);
    let next = bind_command(&second);
    // Retryable, unlike a spent per-permission or per-session bound.
    assert!(matches!(
        handle(&second.completed, &second.context, &next, 1),
        Err(EnclaveError::EscrowPreparationBusy { .. })
    ));
    assert_eq!(budget.snapshot().used, retained);
    drop(first);
    assert_eq!(budget.snapshot().used, 0);
    handle(&second.completed, &second.context, &next, 1).unwrap();
    drop(second);
    assert_eq!(budget.snapshot().used, 0);
}

#[test]
fn a_committed_trial_keeps_the_live_policy_bindings_and_reply_cache() {
    let user = UserId::new_v7();
    let mut state = SessionState::default();
    state.bindings.insert(user.clone(), [1; 32]);
    state.cached_response_bytes = 4096;
    state
        .inflight_request_ids
        .insert((user.clone(), Uuid::now_v7()), [2; 32]);
    let mut trial = state.transition();
    assert!(
        trial.bindings.is_empty(),
        "a trial copied bindings it never commits"
    );
    let key = (user.clone(), "refund".to_string());
    trial
        .execution_receipts
        .insert(key.clone(), Arc::new(Payload::new(vec![3]).unwrap()));
    state.commit(trial);
    assert_eq!(state.execution_receipts[&key].as_bytes(), [3].as_slice());
    assert_eq!(state.bindings[&user], [1; 32]);
    assert_eq!(state.cached_response_bytes, 4096);
    assert_eq!(state.inflight_request_ids.len(), 1);
}

#[test]
fn an_executed_signing_action_shares_one_preparation_scope_binding_and_receipt() {
    let f = fixture(false);
    let (prepared, attempt) = prepare(&f, "sign");
    let execute = execute_command(&f, "sign", &attempt, prepared.sealed_state, proof());
    let executed = handle(&f.completed, &f.context, &execute, 1).unwrap();
    let escrow_state = &f
        .completed
        .musig_processor()
        .get_session_metadata_public()
        .escrow_state;
    let key = (f.user.clone(), "sign".to_string());
    let receipt = {
        let state = escrow_state.inner.lock().unwrap();
        let shared = &state.executions[&key].prepared;
        assert!(Arc::ptr_eq(&state.preparations[&key], shared));
        let permit = &state.permits[&(f.signing.signing_session_id.clone(), f.user.clone())];
        assert!(Arc::ptr_eq(&permit.prepared, shared));
        assert!(Arc::ptr_eq(
            &state.required_bindings[&f.user],
            &shared.binding
        ));
        state.execution_receipts[&key].clone()
    };
    // An exact retry answers from the canonical receipt and keeps it, not a fresh copy.
    let retry = handle(&f.completed, &f.context, &execute, 1).unwrap();
    assert_eq!(retry.sealed_state, executed.sealed_state);
    let state = escrow_state.inner.lock().unwrap();
    assert!(Arc::ptr_eq(&state.execution_receipts[&key], &receipt));
    let scope = scope_bytes(&state.executions[&key].prepared.action);
    drop(state);
    let usage = escrow_state.memory_usage().unwrap();
    assert!(scope > 0);
    assert_eq!(usage.scope_bytes, scope, "a shared scope counts once");
    assert!(usage.prepared_bytes > 0);
    assert!(usage.binding_bytes > 0);
}

/// Escrow states as sealed while each held its values directly.
#[derive(Serialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
enum ByValueState<'a> {
    Bound { binding: &'a Binding },
    Prepared { prepared: ByValuePrepared<'a> },
    Executed { executed: ByValueExecuted<'a> },
}
#[derive(Serialize)]
struct ByValuePrepared<'a> {
    binding: &'a Binding,
    action_id: &'a str,
    attempt: &'a ActionAttempt,
    action: &'a Action,
    application_state: &'a Payload,
    output: &'a Payload,
    predecessor: Option<[u8; 32]>,
    generation: u16,
}
impl<'a> From<&'a PreparedAction> for ByValuePrepared<'a> {
    fn from(prepared: &'a PreparedAction) -> Self {
        Self {
            binding: &prepared.binding,
            action_id: &prepared.action_id,
            attempt: &prepared.attempt,
            action: &prepared.action,
            application_state: &prepared.application_state,
            output: &prepared.output,
            predecessor: prepared.predecessor,
            generation: prepared.generation,
        }
    }
}
#[derive(Serialize)]
struct ByValueExecuted<'a> {
    prepared: ByValuePrepared<'a>,
    execution_digest: [u8; 32],
    original_request_id: Uuid,
    original_request_digest: [u8; 32],
    output: &'a ExecutionOutput,
}

#[test]
fn shared_escrow_states_seal_and_digest_exactly_as_by_value_states() {
    let f = fixture(false);
    let bound = bind(&f);
    let (prepared, attempt) = prepare(&f, "sign");
    let execute = execute_command(&f, "sign", &attempt, prepared.sealed_state, proof());
    let receipt = handle(&f.completed, &f.context, &execute, 1)
        .unwrap()
        .sealed_state;
    let SealedState::Bound { binding } = unseal(&f.context, &bound.sealed_state).unwrap() else {
        panic!("expected a bound state")
    };
    let SealedState::Executed { executed } = unseal(&f.context, &receipt).unwrap() else {
        panic!("expected an executed state")
    };
    let cases = [
        (
            SealedState::Bound {
                binding: binding.clone(),
            },
            ByValueState::Bound { binding: &binding },
        ),
        (
            SealedState::Prepared {
                prepared: executed.prepared.clone(),
            },
            ByValueState::Prepared {
                prepared: executed.prepared.as_ref().into(),
            },
        ),
        (
            SealedState::Executed {
                executed: executed.clone(),
            },
            ByValueState::Executed {
                executed: ByValueExecuted {
                    prepared: executed.prepared.as_ref().into(),
                    execution_digest: executed.execution_digest,
                    original_request_id: executed.original_request_id,
                    original_request_digest: executed.original_request_digest,
                    output: &executed.output,
                },
            },
        ),
    ];
    for (shared, by_value) in cases {
        let written = serde_json::to_vec(&shared).unwrap();
        assert_eq!(written, serde_json::to_vec(&by_value).unwrap());
        // A state sealed before sharing decodes and is written again unchanged.
        let decoded: SealedState = serde_json::from_slice(&written).unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), written);
    }
    assert_eq!(
        preparation_digest(&executed.prepared).unwrap(),
        authorization_digest(
            "escrow-prepared-action-v2",
            &ByValuePrepared::from(executed.prepared.as_ref())
        )
        .unwrap()
    );
}
