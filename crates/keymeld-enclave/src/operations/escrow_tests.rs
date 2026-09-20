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
                ([0; 32], candidates[0].1.clone()),
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
    assert_eq!(state.cached_response_bytes, MAX_REQUEST_CACHE_BYTES);
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
