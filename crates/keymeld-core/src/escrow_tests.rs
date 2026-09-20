use super::*;
use protocol::*;
use secp256k1::{Secp256k1, SecretKey};

fn key(byte: u8) -> PublicKeyBytes {
    PublicKeyBytes::new(
        &PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array([byte; 32]).unwrap(),
        )
        .serialize(),
    )
    .unwrap()
}
fn fixture() -> EscrowPolicy {
    let user = UserId::new_v7();
    let context = EscrowContext {
        keygen_session_id: SessionId::new_v7(),
        user_id: user.clone(),
        escrow_id: Uuid::now_v7(),
        manifest_digest: [1; 32],
        application: ApplicationContext::commit("document-escrow".into(), 1, b"exact-document")
            .unwrap(),
    };
    let scope = SigningScope {
        session_tweak: KeyTweak::None,
        batch: vec![SigningItem {
            item_id: Uuid::now_v7(),
            message_digest: sha256(b"approved-message"),
            subset_id: None,
            signers: vec![ScopeSigner {
                user_id: user,
                public_key: key(2),
            }],
            tweak: KeyTweak::None,
            adaptor: AdaptorContext::None,
        }],
    };
    EscrowPolicy {
        verifier: None,
        schema_version: crate::escrow::SCHEMA_VERSION,
        context,
        participant_public_key: key(2),
        secrets: BTreeMap::from([(
            "document-key".into(),
            SecretCommitment::from_secret(&[3; 32]).unwrap(),
        )]),
        grants: BTreeMap::from([
            (
                "sign".into(),
                ActionGrant {
                    preparation: crate::escrow::PreparationPolicy::Single,
                    repetition: crate::escrow::Repetition::Once,
                    condition: Condition::HashlockSha256 {
                        commitment: sha256(&[4; 32]),
                    },
                    operation: Permission::Exact {
                        action: Action::Sign { scope },
                    },
                },
            ),
            (
                "release".into(),
                ActionGrant {
                    preparation: crate::escrow::PreparationPolicy::Single,
                    repetition: crate::escrow::Repetition::Once,
                    condition: Condition::HashlockSha256 {
                        commitment: sha256(&[4; 32]),
                    },
                    operation: Permission::Exact {
                        action: Action::ReleaseSecret {
                            name: "document-key".into(),
                            recipient: Recipient {
                                encryption_public_key: key(5),
                            },
                        },
                    },
                },
            ),
        ]),
    }
}
fn signed() -> SignedEscrowPolicy {
    SignedEscrowPolicy::sign(fixture(), &[2; 32]).unwrap()
}
fn attempt(sign: bool) -> ActionAttempt {
    ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: sign.then(SessionId::new_v7),
    }
}
fn proof() -> ConditionProof {
    ConditionProof::HashlockPreimage {
        preimage: vec![4; 32],
    }
}
fn request_context(policy: &SignedEscrowPolicy, operation: Operation) -> RequestContext {
    let action = operation != Operation::Bind;
    RequestContext {
        schema_version: crate::escrow::SCHEMA_VERSION,
        operation,
        escrow: policy.policy.context.clone(),
        policy_digest: policy.policy.digest().unwrap(),
        request_id: Uuid::now_v7(),
        action_id: action.then(|| "sign".into()),
        attempt: action.then(|| attempt(true)),
    }
}

#[test]
fn policy_signature_and_expected_enrollment_bind_every_context() {
    let original = signed();
    let context = original.policy.context.clone();
    original.verify(&context, key(2).as_bytes()).unwrap();
    assert!(original.verify(&context, key(6).as_bytes()).is_err());
    let mut changed = original.clone();
    changed.policy.grants.get_mut("sign").unwrap().condition = Condition::Unconditional;
    assert!(changed.verify(&context, key(2).as_bytes()).is_err());
    let mut contexts = vec![context.clone(); 5];
    contexts[0].keygen_session_id = SessionId::new_v7();
    contexts[1].user_id = UserId::new_v7();
    contexts[2].escrow_id = Uuid::now_v7();
    contexts[3].manifest_digest[0] ^= 1;
    contexts[4].application.commitment[0] ^= 1;
    for wrong in contexts {
        assert!(original.verify(&wrong, key(2).as_bytes()).is_err());
    }
    let mut wrong = fixture();
    wrong.schema_version = SCHEMA_VERSION + 1;
    assert!(SignedEscrowPolicy::sign(wrong, &[2; 32]).is_err());
    assert!(SignedEscrowPolicy::sign(fixture(), &[6; 32]).is_err());
}

#[test]
fn hashlock_is_required_before_signing_or_export() {
    let signed = signed();
    for (id, sign) in [("sign", true), ("release", false)] {
        let grant = &signed.policy.grants[id];
        let attempt = attempt(sign);
        signed
            .authorize(
                &signed.policy.context,
                key(2).as_bytes(),
                id,
                &attempt,
                grant.operation.exact().unwrap(),
                &proof(),
            )
            .unwrap();
        for wrong in [
            ConditionProof::None,
            ConditionProof::HashlockPreimage {
                preimage: vec![9; 32],
            },
            ConditionProof::HashlockPreimage {
                preimage: vec![4; MAX_SECRET_BYTES + 1],
            },
        ] {
            assert!(signed
                .authorize(
                    &signed.policy.context,
                    key(2).as_bytes(),
                    id,
                    &attempt,
                    grant.operation.exact().unwrap(),
                    &wrong
                )
                .is_err());
        }
    }
}

#[test]
fn signing_permission_never_implies_key_or_secret_export() {
    let signed = signed();
    let key_export = Action::ReleaseSigningKey {
        public_key: key(2),
        recipient: Recipient {
            encryption_public_key: key(5),
        },
    };
    assert!(signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "sign",
            &attempt(false),
            &key_export,
            &proof()
        )
        .is_err());
    assert!(signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "release",
            &attempt(false),
            &key_export,
            &proof()
        )
        .is_err());
    let mut explicit = signed.policy.clone();
    explicit.grants.insert(
        "export-key".into(),
        ActionGrant {
            preparation: crate::escrow::PreparationPolicy::Single,
            repetition: crate::escrow::Repetition::Once,
            condition: Condition::HashlockSha256 {
                commitment: sha256(&[4; 32]),
            },
            operation: Permission::Exact {
                action: key_export.clone(),
            },
        },
    );
    let explicit = SignedEscrowPolicy::sign(explicit, &[2; 32]).unwrap();
    explicit
        .authorize(
            &explicit.policy.context,
            key(2).as_bytes(),
            "export-key",
            &attempt(false),
            &key_export,
            &proof(),
        )
        .unwrap();
    let mut substituted = key_export.clone();
    if let Action::ReleaseSigningKey { recipient, .. } = &mut substituted {
        recipient.encryption_public_key = key(6);
    }
    assert!(explicit
        .authorize(
            &explicit.policy.context,
            key(2).as_bytes(),
            "export-key",
            &attempt(false),
            &substituted,
            &proof()
        )
        .is_err());
}

#[test]
fn exact_batch_scope_rejects_message_subset_tweak_adaptor_and_batch_substitution() {
    let signed = signed();
    let action = signed.policy.grants["sign"]
        .operation
        .exact()
        .unwrap()
        .clone();
    let Action::Sign { scope } = &action else {
        unreachable!()
    };
    let mut scopes = vec![scope.clone(); 7];
    scopes[0].batch[0].message_digest[0] ^= 1;
    scopes[1].batch[0].subset_id = Some(Uuid::now_v7());
    scopes[2].batch[0].tweak = KeyTweak::PlainScalar { scalar: [1; 32] };
    scopes[3].session_tweak = KeyTweak::TaprootKeyPath;
    scopes[4].batch[0].adaptor = AdaptorContext::Single {
        adaptor_id: Uuid::now_v7(),
        point: key(8),
    };
    scopes[5].batch[0].signers[0].public_key = key(7);
    scopes[6].batch.clear();
    for scope in scopes {
        assert!(signed
            .authorize(
                &signed.policy.context,
                key(2).as_bytes(),
                "sign",
                &attempt(true),
                &Action::Sign { scope },
                &proof()
            )
            .is_err());
    }
}

#[test]
fn scope_requires_real_canonical_distinct_signers_and_supported_tweaks() {
    let mut policy = fixture();
    let Action::Sign { scope } = policy
        .grants
        .get_mut("sign")
        .unwrap()
        .operation
        .exact_mut()
        .unwrap()
    else {
        unreachable!()
    };
    scope.batch[0].signers.push(ScopeSigner {
        user_id: UserId::new_v7(),
        public_key: key(7),
    });
    scope.batch[0]
        .signers
        .sort_by(|a, b| a.public_key.cmp(&b.public_key));
    policy.validate().unwrap();
    let mut reversed = policy.clone();
    let Action::Sign { scope } = reversed
        .grants
        .get_mut("sign")
        .unwrap()
        .operation
        .exact_mut()
        .unwrap()
    else {
        unreachable!()
    };
    scope.batch[0].signers.reverse();
    assert!(reversed.validate().is_err());
    let mut duplicate = policy.clone();
    let Action::Sign { scope } = duplicate
        .grants
        .get_mut("sign")
        .unwrap()
        .operation
        .exact_mut()
        .unwrap()
    else {
        unreachable!()
    };
    scope.batch.push(scope.batch[0].clone());
    assert!(duplicate.validate().is_err());
    let Action::Sign { scope } = policy
        .grants
        .get_mut("sign")
        .unwrap()
        .operation
        .exact_mut()
        .unwrap()
    else {
        unreachable!()
    };
    scope.batch[0].tweak = KeyTweak::XOnlyScalar { scalar: [255; 32] };
    assert!(policy.validate().is_err());
    assert!(PublicKeyBytes::new(&[0; 33]).is_err());
    assert!(PublicKeyBytes::new(
        &PublicKey::from_slice(key(2).as_bytes())
            .unwrap()
            .serialize_uncompressed()
    )
    .is_err());
}

#[test]
fn execution_replay_is_bound_to_action_policy_and_target_signing_session() {
    let signed = signed();
    let action = signed.policy.grants["sign"].operation.exact().unwrap();
    let id = attempt(true);
    let verified = signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "sign",
            &id,
            action,
            &proof(),
        )
        .unwrap();
    let mut ledger = ExecutionLedger::default();
    assert_eq!(
        ledger.record_success(&verified).unwrap(),
        ExecutionStatus::Fresh
    );
    assert_eq!(
        ledger.record_success(&verified).unwrap(),
        ExecutionStatus::Replay
    );
    let mut wrong = id.clone();
    wrong.signing_session_id = Some(SessionId::new_v7());
    let changed = signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "sign",
            &wrong,
            action,
            &proof(),
        )
        .unwrap();
    assert!(ledger.record_success(&changed).is_err());
    let changed = signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "sign",
            &attempt(true),
            action,
            &proof(),
        )
        .unwrap();
    assert!(ledger.record_success(&changed).is_err());
    assert!(signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "sign",
            &attempt(false),
            action,
            &proof()
        )
        .is_err());
    assert!(signed
        .authorize(
            &signed.policy.context,
            key(2).as_bytes(),
            "release",
            &attempt(true),
            signed.policy.grants["release"].operation.exact().unwrap(),
            &proof()
        )
        .is_err());
}

#[test]
fn registration_checks_exact_secret_inventory_without_debug_leaks() {
    let mut registration = EscrowRegistration {
        policy: signed(),
        secrets: BTreeMap::from([("document-key".into(), vec![3; 32])]),
    };
    registration
        .verify(&registration.policy.policy.context, key(2).as_bytes())
        .unwrap();
    let dump = format!("{registration:?}");
    assert!(dump.contains("[REDACTED]"));
    assert!(!dump.contains("3, 3, 3, 3"));
    registration.secrets.get_mut("document-key").unwrap()[0] = 1;
    assert!(registration.validate_secret_commitments().is_err());
    registration
        .secrets
        .insert("document-key".into(), vec![3; 32]);
    registration
        .secrets
        .insert("unexpected".into(), vec![7; 32]);
    assert!(registration.validate_secret_commitments().is_err());
}

#[test]
fn request_signature_covers_operation_attempt_context_and_ciphertext() {
    let policy = signed();
    let expected = request_context(&policy, Operation::Execute);
    let command = EscrowCommand::sign(
        expected.clone(),
        Payload::new(vec![1, 2, 3]).unwrap(),
        &[8; 32],
    )
    .unwrap();
    command.verify(&expected, key(8).as_bytes()).unwrap();
    let mut changed = command.clone();
    changed.encrypted_request = Payload::new(vec![1, 2, 4]).unwrap();
    assert!(changed.verify(&expected, key(8).as_bytes()).is_err());
    let mut changed = command.clone();
    changed.context.operation = Operation::Prepare;
    assert!(changed.verify(&changed.context, key(8).as_bytes()).is_err());
    let mut changed = command.clone();
    changed.context.attempt.as_mut().unwrap().signing_session_id = Some(SessionId::new_v7());
    assert!(changed.verify(&changed.context, key(8).as_bytes()).is_err());
    let mut wrong = expected.clone();
    wrong.escrow.user_id = UserId::new_v7();
    assert!(command.verify(&wrong, key(8).as_bytes()).is_err());
    let mut wrong = expected;
    wrong.schema_version = SCHEMA_VERSION + 1;
    assert!(EscrowCommand::sign(wrong, Payload::new(vec![1]).unwrap(), &[8; 32]).is_err());
}

#[test]
fn enclave_response_authenticates_issuer_epoch_phase_payload_and_receipt() {
    let policy = signed();
    let expected = ReceiptContext {
        schema_version: crate::escrow::SCHEMA_VERSION,
        enclave_id: crate::EnclaveId::new(1),
        enclave_key_epoch: 8,
        request: request_context(&policy, Operation::Prepare),
        request_digest: [9; 32],
    };
    let response = EscrowResponse::sign(
        expected.clone(),
        Payload::new(vec![1]).unwrap(),
        Payload::new(vec![2]).unwrap(),
        &[8; 32],
    )
    .unwrap();
    response.verify(&expected, key(8).as_bytes()).unwrap();
    let mut altered = response.clone();
    altered.output = Payload::new(vec![3]).unwrap();
    assert!(altered.verify(&expected, key(8).as_bytes()).is_err());
    let mut altered = response.clone();
    altered.sealed_state = Payload::new(vec![3]).unwrap();
    assert!(altered.verify(&expected, key(8).as_bytes()).is_err());
    let mut wrong_epoch = expected.clone();
    wrong_epoch.enclave_key_epoch += 1;
    assert!(response.verify(&wrong_epoch, key(8).as_bytes()).is_err());
    let mut wrong_issuer = expected.clone();
    wrong_issuer.enclave_id = crate::EnclaveId::new(2);
    assert!(response.verify(&wrong_issuer, key(8).as_bytes()).is_err());
    let mut wrong = expected.clone();
    wrong.request.operation = Operation::Execute;
    assert!(response.verify(&wrong, key(8).as_bytes()).is_err());
    assert!(response.verify(&expected, key(9).as_bytes()).is_err());
}

#[test]
fn bounded_versioned_wire_rejects_unknown_fields_and_context_substitution() {
    let policy = signed();
    let request = BindEscrowRequest {
        participant_policies: BTreeMap::new(),
        binding_data: Payload::default(),
        schema_version: crate::escrow::SCHEMA_VERSION,
        policy: policy.clone(),
        application_context: Payload::new(b"exact-document".to_vec()).unwrap(),
    };
    request
        .verify(&policy.policy.context, key(2).as_bytes())
        .unwrap();
    let mut changed = request.clone();
    changed.application_context = Payload::new(b"other-document".to_vec()).unwrap();
    assert!(changed
        .verify(&policy.policy.context, key(2).as_bytes())
        .is_err());
    assert!(Payload::new(vec![0; MAX_PAYLOAD_BYTES + 1]).is_err());
    assert!(decode::<EscrowPolicy>(&vec![b' '; MAX_WIRE_BYTES + 1]).is_err());
    let mut wire = serde_json::to_value(&policy.policy).unwrap();
    wire["host_verified"] = serde_json::json!(true);
    assert!(serde_json::from_value::<EscrowPolicy>(wire).is_err());
    let mut oversized = fixture();
    oversized.grants = (0..MAX_ACTIONS + 1)
        .map(|index| {
            (
                format!("action{index}"),
                oversized.grants["release"].clone(),
            )
        })
        .collect();
    assert!(oversized.validate().is_err());
}

#[test]
fn opaque_payloads_use_bounded_canonical_base64_and_preserve_binary_transport() {
    let value = Payload::new(vec![0, 1, 254, 255]).unwrap();
    let json = serde_json::to_string(&value).unwrap();
    assert_eq!(json, "\"AAH+/w==\"");
    assert_eq!(serde_json::from_str::<Payload>(&json).unwrap(), value);
    let binary = bincode::serialize(&value).unwrap();
    assert_eq!(
        binary,
        bincode::serialize(&vec![0_u8, 1, 254, 255]).unwrap()
    );
    assert_eq!(bincode::deserialize::<Payload>(&binary).unwrap(), value);
    for invalid in ["\"AAH+/x==\"", "\"AAH+/w\"", "\"%\"", "[0,1,254,255]"] {
        assert!(
            serde_json::from_str::<Payload>(invalid).is_err(),
            "{invalid}"
        );
    }
    let maximum = Payload::new(vec![255; MAX_PAYLOAD_BYTES]).unwrap();
    let encoded = serde_json::to_string(&maximum).unwrap();
    assert_eq!(encoded.len(), MAX_PAYLOAD_BYTES.div_ceil(3) * 4 + 2);
    assert_eq!(serde_json::from_str::<Payload>(&encoded).unwrap(), maximum);
    let too_large = format!("\"{}\"", "AAAA".repeat(MAX_PAYLOAD_BYTES.div_ceil(3) + 1));
    assert!(serde_json::from_str::<Payload>(&too_large).is_err());
    let too_large = bincode::serialize(&vec![0_u8; MAX_PAYLOAD_BYTES + 1]).unwrap();
    assert!(bincode::deserialize::<Payload>(&too_large).is_err());
}

#[test]
fn generic_commands_and_responses_roundtrip_over_actual_bincode_transport() {
    use crate::protocol::{
        EnclaveCommand, EnclaveOutcome, KeygenCommand, KeygenOutcome, MusigCommand, MusigOutcome,
    };
    let policy = signed();
    let context = request_context(&policy, Operation::Execute);
    let command = EscrowCommand::sign(
        context.clone(),
        Payload::new(vec![1, 2, 3]).unwrap(),
        &[8; 32],
    )
    .unwrap();
    let digest = command.digest().unwrap();
    let transport = EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(command)));
    let bytes = bincode::serialize(&transport).unwrap();
    let decoded: EnclaveCommand = bincode::deserialize(&bytes).unwrap();
    let EnclaveCommand::Musig(MusigCommand::Keygen(KeygenCommand::Escrow(command))) = decoded
    else {
        panic!("wrong decoded command")
    };
    command.verify(&context, key(8).as_bytes()).unwrap();
    assert_eq!(command.digest().unwrap(), digest);
    let receipt = ReceiptContext {
        schema_version: crate::escrow::SCHEMA_VERSION,
        enclave_id: crate::EnclaveId::new(1),
        enclave_key_epoch: 3,
        request: context,
        request_digest: digest,
    };
    let response = EscrowResponse::sign(
        receipt.clone(),
        Payload::new(vec![4]).unwrap(),
        Payload::new(vec![5]).unwrap(),
        &[9; 32],
    )
    .unwrap();
    let transport = EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::Escrow(Box::new(
        response,
    ))));
    let bytes = bincode::serialize(&transport).unwrap();
    let decoded: EnclaveOutcome = bincode::deserialize(&bytes).unwrap();
    let EnclaveOutcome::Musig(MusigOutcome::Keygen(KeygenOutcome::Escrow(response))) = decoded
    else {
        panic!("wrong decoded response")
    };
    response.verify(&receipt, key(9).as_bytes()).unwrap();
}

#[test]
fn subset_tweak_must_match_keygen_context_while_full_group_can_override() {
    let mut policy = fixture();
    let Action::Sign { scope } = policy
        .grants
        .get_mut("sign")
        .unwrap()
        .operation
        .exact_mut()
        .unwrap()
    else {
        panic!("expected signing grant")
    };
    scope.session_tweak = KeyTweak::TaprootKeyPath;
    // Full-group signing rebuilds the aggregate with the item's exact tweak.
    scope
        .validate(&policy.context, &policy.participant_public_key)
        .unwrap();
    scope.batch[0].subset_id = Some(Uuid::now_v7());
    assert!(scope
        .validate(&policy.context, &policy.participant_public_key)
        .is_err());
    scope.batch[0].tweak = KeyTweak::TaprootKeyPath;
    scope
        .validate(&policy.context, &policy.participant_public_key)
        .unwrap();
    scope.batch[0].tweak = KeyTweak::TaprootMerkleRoot {
        merkle_root: [7; 32],
    };
    assert!(scope
        .validate(&policy.context, &policy.participant_public_key)
        .is_err());
}

#[test]
fn late_bound_permissions_require_a_verifier_and_cannot_escalate() {
    let mut policy = fixture();
    let sign_action = policy.grants["sign"].operation.exact().unwrap().clone();
    policy.grants.get_mut("sign").unwrap().operation = Permission::Sign;
    assert!(policy.validate().is_err());
    policy.grants.get_mut("sign").unwrap().condition = Condition::VerifierRule {
        rule: "document_approved".into(),
    };
    assert!(policy.validate().is_err());
    policy.verifier = Some(VerifierPolicy {
        id: "document-approval".into(),
        version: 1,
        policy_data: Payload::default(),
    });
    policy.validate().unwrap();
    let grant = &policy.grants["sign"];
    grant
        .operation
        .validate_action(&sign_action, &policy)
        .unwrap();
    let release = policy.grants["release"].operation.exact().unwrap();
    assert!(grant.operation.validate_action(release, &policy).is_err());
    let signed = SignedEscrowPolicy::sign(policy.clone(), &[2; 32]).unwrap();
    assert!(signed
        .authorize(
            &policy.context,
            key(2).as_bytes(),
            "sign",
            &attempt(true),
            &sign_action,
            &ConditionProof::None
        )
        .is_err());
    assert!(signed
        .authorize(
            &policy.context,
            key(2).as_bytes(),
            "sign",
            &attempt(true),
            &sign_action,
            &ConditionProof::VerifierEvidence {
                evidence: Payload::encode(&true).unwrap()
            }
        )
        .is_err());
    let Action::ReleaseSecret { name, recipient } = release else {
        panic!()
    };
    let permission = Permission::ReleaseSecret {
        name: name.clone(),
        recipient: recipient.clone(),
    };
    permission.validate_action(release, &policy).unwrap();
    assert!(permission
        .validate_action(
            &Action::ReleaseSecret {
                name: name.clone(),
                recipient: Recipient {
                    encryption_public_key: key(9)
                }
            },
            &policy
        )
        .is_err());
    assert!(permission
        .validate_action(
            &Action::ReleaseSigningKey {
                public_key: key(2),
                recipient: recipient.clone()
            },
            &policy
        )
        .is_err());
    let mut changed = signed;
    changed.policy.verifier.as_mut().unwrap().policy_data =
        Payload::new(b"replacement rules".to_vec()).unwrap();
    assert!(changed.verify(&policy.context, key(2).as_bytes()).is_err());
}

#[test]
fn repetition_requires_an_explicit_signing_grant_and_is_participant_signed() {
    let mut policy = fixture();
    for id in ["sign", "release"] {
        policy.grants.get_mut(id).unwrap().repetition = Repetition::RepeatIdenticalSigningScope;
        assert!(policy.validate().is_err());
        policy.grants.get_mut(id).unwrap().repetition = Repetition::Once;
    }
    policy.verifier = Some(VerifierPolicy {
        id: "document-approval".into(),
        version: 1,
        policy_data: protocol::Payload::default(),
    });
    let grant = policy.grants.get_mut("sign").unwrap();
    grant.operation = Permission::Sign;
    grant.condition = Condition::VerifierRule {
        rule: "document_approved".into(),
    };
    grant.repetition = Repetition::RepeatIdenticalSigningScope;
    let signed = SignedEscrowPolicy::sign(policy, &[2; 32]).unwrap();
    signed
        .verify(&signed.policy.context, key(2).as_bytes())
        .unwrap();
    let mut changed = signed.clone();
    changed.policy.grants.get_mut("sign").unwrap().repetition = Repetition::Once;
    assert!(changed
        .verify(&signed.policy.context, key(2).as_bytes())
        .is_err());
    let mut invalid = signed.policy;
    let grant = invalid.grants.get_mut("release").unwrap();
    let Action::ReleaseSecret { name, recipient } = grant.operation.exact().unwrap().clone() else {
        panic!()
    };
    grant.operation = Permission::ReleaseSecret { name, recipient };
    grant.condition = Condition::VerifierRule {
        rule: "document_approved".into(),
    };
    grant.repetition = Repetition::RepeatIdenticalSigningScope;
    assert!(invalid.validate().is_err());
}

#[test]
fn renewable_preparation_is_signed_separate_from_execution_and_restricted_to_fixed_releases() {
    let mut policy = fixture();
    policy.grants.get_mut("sign").unwrap().preparation =
        PreparationPolicy::RenewableIdenticalAction;
    assert!(policy.validate().is_err());
    policy.grants.get_mut("sign").unwrap().preparation = PreparationPolicy::Single;
    policy.grants.get_mut("release").unwrap().preparation =
        PreparationPolicy::RenewableIdenticalAction;
    assert_eq!(policy.grants["release"].repetition, Repetition::Once);
    let signed = SignedEscrowPolicy::sign(policy, &[2; 32]).unwrap();
    signed
        .verify(&signed.policy.context, key(2).as_bytes())
        .unwrap();
    let mut changed = signed.clone();
    changed
        .policy
        .grants
        .get_mut("release")
        .unwrap()
        .preparation = PreparationPolicy::Single;
    assert!(changed
        .verify(&signed.policy.context, key(2).as_bytes())
        .is_err());
}
