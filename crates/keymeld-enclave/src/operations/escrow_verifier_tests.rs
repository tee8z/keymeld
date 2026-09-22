use super::*;
use crate::escrow_verifier::{
    EscrowVerifier, VerificationFuture, VerifierDescriptor, VerifierRegistry,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct ExecutionGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}
struct DocumentVerifier {
    calls: Arc<AtomicUsize>,
    execution_gate: Option<Arc<ExecutionGate>>,
    reject_recovery: bool,
}
impl EscrowVerifier for DocumentVerifier {
    fn descriptor(&self) -> VerifierDescriptor {
        VerifierDescriptor {
            id: "document-approval".into(),
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
            != b"document v1"
        {
            return Err(invalid("Wrong document rules"));
        }
        Ok(())
    }
    fn bind(&self, view: BindView<'_>, data: &Payload) -> Result<Payload, EnclaveError> {
        if view.participant_policies.len() != 1
            || !view
                .participant_policies
                .contains_key(&view.policy.policy.context.user_id)
            || data.as_bytes() != b"document signed later"
        {
            return Err(invalid("Wrong document binding"));
        }
        Ok(data.clone())
    }
    fn prepare<'a>(
        &'a self,
        view: PreparationView<'a>,
        parameters: &'a Payload,
    ) -> VerificationFuture<'a, VerifierPreparedAction> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            if view.bound_state.as_bytes() != b"document signed later" {
                return Err(invalid("Wrong bound document"));
            }
            let (action, candidate) = match parameters.decode::<Action>() {
                Ok(action) => (action, None),
                Err(_) => {
                    let (action, candidate): (Action, u8) = parameters.decode().map_err(invalid)?;
                    (action, Some(candidate))
                }
            };
            Ok(VerifierPreparedAction {
                action,
                application_state: candidate
                    .map(|id| Payload::encode(&id).unwrap())
                    .unwrap_or_else(|| Payload::new(b"exact prepared document".to_vec()).unwrap()),
                output: Payload::new(b"authorized client output".to_vec()).unwrap(),
            })
        })
    }
    fn verify_execution<'a>(
        &'a self,
        view: ExecutionView<'a>,
        prepared: &'a VerifierPreparedAction,
        evidence: &'a Payload,
    ) -> VerificationFuture<'a, ()> {
        Box::pin(async move {
            if let Some(gate) = &self.execution_gate {
                gate.entered.add_permits(1);
                gate.release.acquire().await.unwrap().forget();
            }
            let expected = if prepared.application_state.as_bytes() == b"exact prepared document" {
                b"approved".to_vec()
            } else {
                let candidate: u8 = prepared.application_state.decode().map_err(invalid)?;
                format!("approved-{candidate}").into_bytes()
            };
            if view.bound_state.as_bytes() != b"document signed later"
                || evidence.as_bytes() != expected
            {
                return Err(invalid("Document approval missing"));
            }
            Ok(())
        })
    }
    fn restore_execution<'a>(
        &'a self,
        view: ExecutionView<'a>,
        _prepared: &'a VerifierPreparedAction,
    ) -> VerificationFuture<'a, ()> {
        Box::pin(async move {
            if self.reject_recovery || view.bound_state.as_bytes() != b"document signed later" {
                return Err(invalid("Application execution recovery rejected"));
            }
            Ok(())
        })
    }
}
fn application_fixture() -> (Fixture, Arc<AtomicUsize>) {
    application_fixture_options(false, None)
}
fn application_fixture_options(
    repeat: bool,
    execution_gate: Option<Arc<ExecutionGate>>,
) -> (Fixture, Arc<AtomicUsize>) {
    application_fixture_policies(repeat, false, execution_gate)
}
fn application_fixture_policies(
    repeat: bool,
    renewable: bool,
    execution_gate: Option<Arc<ExecutionGate>>,
) -> (Fixture, Arc<AtomicUsize>) {
    let mut f = fixture_with_preparation(true, true, repeat, renewable);
    let calls = Arc::new(AtomicUsize::new(0));
    f.context.escrow_verifiers = Arc::new(
        VerifierRegistry::new(vec![Arc::new(DocumentVerifier {
            calls: calls.clone(),
            execution_gate,
            reject_recovery: false,
        })])
        .unwrap(),
    );
    (f, calls)
}
fn binding_command(f: &Fixture) -> EscrowCommand {
    command(
        f,
        Operation::Bind,
        None,
        &BindEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            policy: f.registration.policy.clone(),
            application_context: Payload::new(b"approved document".to_vec()).unwrap(),
            participant_policies: BTreeMap::from([(f.user.clone(), f.registration.policy.clone())]),
            binding_data: Payload::new(b"document signed later".to_vec()).unwrap(),
        },
    )
}
fn prepare_command(
    f: &Fixture,
    binding: Payload,
    permission: &str,
    attempt: &ActionAttempt,
    action: &Action,
) -> EscrowCommand {
    command(
        f,
        Operation::Prepare,
        Some((permission, attempt)),
        &PrepareEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            binding_receipt: binding,
            action_id: permission.into(),
            attempt: attempt.clone(),
            action: None,
            action_parameters: Payload::encode(action).unwrap(),
            prior_preparation_receipts: vec![],
        },
    )
}
fn signing_action(f: &Fixture) -> Action {
    Action::Sign {
        scope: signing_scope(
            f.completed.musig_processor().get_session_metadata_public(),
            f.completed.session_secret(),
            &f.signing,
            &f.user,
        )
        .unwrap(),
    }
}
fn approved() -> ConditionProof {
    ConditionProof::VerifierEvidence {
        evidence: Payload::new(b"approved".to_vec()).unwrap(),
    }
}

#[test]
fn unknown_verifier_and_duplicate_registration_fail_closed() {
    let (mut f, _) = application_fixture();
    f.context.escrow_verifiers = Arc::new(VerifierRegistry::default());
    assert!(handle(&f.completed, &f.context, &binding_command(&f), 1).is_err());
    let verifier: Arc<dyn EscrowVerifier> = Arc::new(DocumentVerifier {
        calls: Arc::new(AtomicUsize::new(0)),
        execution_gate: None,
        reject_recovery: false,
    });
    assert!(VerifierRegistry::new(vec![verifier.clone(), verifier]).is_err());
    assert!(VerifierRegistry::default()
        .get("document-approval", 1)
        .is_err());
}

#[tokio::test]
async fn concurrent_identical_prepare_resolves_once_and_verified_execution_restores_without_prepare(
) {
    let (f, calls) = application_fixture();
    let binding = super::super::handle(&f.completed, &f.context, &binding_command(&f), 1)
        .await
        .unwrap();
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: Some(f.signing.signing_session_id.clone()),
    };
    let prepare = prepare_command(
        &f,
        binding.sealed_state,
        "sign",
        &attempt,
        &signing_action(&f),
    );
    let (first, second) = tokio::join!(
        super::super::handle(&f.completed, &f.context, &prepare, 1),
        super::super::handle(&f.completed, &f.context, &prepare, 1)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.sealed_state, second.sealed_state);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let wrong = execute_command(
        &f,
        "sign",
        &attempt,
        first.sealed_state.clone(),
        ConditionProof::None,
    );
    assert!(super::super::handle(&f.completed, &f.context, &wrong, 1)
        .await
        .is_err());
    assert!(verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing
    )
    .is_err());
    let execute = execute_command(&f, "sign", &attempt, first.sealed_state.clone(), approved());
    let result = super::super::handle(&f.completed, &f.context, &execute, 1)
        .await
        .unwrap();
    verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing,
    )
    .unwrap();
    *f.completed
        .musig_processor()
        .get_session_metadata_public()
        .escrow_state
        .inner
        .lock()
        .unwrap() = SessionState::default();
    let restore = execute_command(
        &f,
        "sign",
        &attempt,
        result.sealed_state,
        ConditionProof::None,
    );
    super::super::handle(&f.completed, &f.context, &restore, 2)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    verify_signing_batch(
        f.completed.musig_processor(),
        f.completed.session_secret(),
        &f.signing,
    )
    .unwrap();
}

#[test]
fn trusted_verifier_cannot_change_operation_or_release_recipient() {
    let (f, calls) = application_fixture();
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1).unwrap();
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: Some(f.signing.signing_session_id.clone()),
    };
    let recipient = Recipient {
        encryption_public_key: PublicKeyBytes::new(&public_key(&[19; 32])).unwrap(),
    };
    let wrong = prepare_command(
        &f,
        binding.sealed_state.clone(),
        "sign",
        &attempt,
        &Action::ReleaseSigningKey {
            public_key: f.registration.policy.policy.participant_public_key.clone(),
            recipient: recipient.clone(),
        },
    );
    assert!(handle(&f.completed, &f.context, &wrong, 1).is_err());
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: None,
    };
    let wrong = prepare_command(
        &f,
        binding.sealed_state.clone(),
        "secret",
        &attempt,
        &Action::ReleaseSecret {
            name: "document-key".into(),
            recipient: Recipient {
                encryption_public_key: PublicKeyBytes::new(&public_key(&[12; 32])).unwrap(),
            },
        },
    );
    assert!(handle(&f.completed, &f.context, &wrong, 1).is_err());
    let correct = prepare_command(
        &f,
        binding.sealed_state,
        "secret",
        &attempt,
        &Action::ReleaseSecret {
            name: "document-key".into(),
            recipient,
        },
    );
    let prepared = handle(&f.completed, &f.context, &correct, 1).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    let execute = execute_command(&f, "secret", &attempt, prepared.sealed_state, approved());
    let result = handle(&f.completed, &f.context, &execute, 1).unwrap();
    let ExecutionOutput::ReleasedSecret {
        encrypted_secret, ..
    } = result.output.decode().unwrap()
    else {
        panic!()
    };
    assert_eq!(
        SecureCrypto::ecies_decrypt(
            &secp256k1::SecretKey::from_byte_array([19; 32]).unwrap(),
            encrypted_secret.as_bytes()
        )
        .unwrap(),
        vec![7; 32]
    );
}

#[test]
fn authenticated_binding_rejects_policy_omission_and_pre_nonce_guard_detects_stripped_registration()
{
    let (f, _) = application_fixture();
    let mut request: BindEscrowRequest = decrypt_request(
        f.completed.session_secret(),
        &binding_command(&f).encrypted_request,
    )
    .unwrap();
    request.participant_policies.clear();
    let omitted = command(&f, Operation::Bind, None, &request);
    assert!(handle(&f.completed, &f.context, &omitted, 1).is_err());
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1).unwrap();
    let SealedState::Bound { binding } = unseal(&f.context, &binding.sealed_state).unwrap() else {
        panic!()
    };
    let processor = f.completed.musig_processor();
    let mut stripped = MusigProcessor::new(
        &f.completed.session_id,
        TaprootTweak::None,
        Some(2),
        vec![f.user.clone(), f.maker.clone()],
    );
    stripped.session_metadata = processor.session_metadata.clone();
    for user in processor.get_users_in_session() {
        stripped.user_sessions.insert(
            user.clone(),
            processor.get_user_session_data(&user).unwrap(),
        );
    }
    stripped.user_sessions.get_mut(&f.user).unwrap().escrow = None;
    assert!(validate_roster(&stripped, &binding).is_err());
    assert!(verify_signing_batch(&stripped, f.completed.session_secret(), &f.signing).is_err());
    stripped.session_metadata.registrations.remove(&f.user);
    assert!(validate_roster(&stripped, &binding).is_err());
}

fn repeated_prepare_command(
    f: &Fixture,
    binding: &Payload,
    prior: &Payload,
    attempt: &ActionAttempt,
    action: &Action,
) -> EscrowCommand {
    command(
        f,
        Operation::Prepare,
        Some(("sign", attempt)),
        &PrepareEscrowRequest {
            schema_version: escrow::SCHEMA_VERSION,
            binding_receipt: binding.clone(),
            action_id: "sign".into(),
            attempt: attempt.clone(),
            action: None,
            action_parameters: Payload::encode(action).unwrap(),
            prior_preparation_receipts: vec![prior.clone()],
        },
    )
}

#[test]
fn repeated_signing_requires_participant_consent_and_the_exact_scope() {
    for repeat in [false, true] {
        let (f, _) = application_fixture_options(repeat, None);
        let binding = handle(&f.completed, &f.context, &binding_command(&f), 1).unwrap();
        let action = signing_action(&f);
        let first_attempt = ActionAttempt {
            attempt_id: Uuid::now_v7(),
            signing_session_id: Some(f.signing.signing_session_id.clone()),
        };
        let first = handle(
            &f.completed,
            &f.context,
            &prepare_command(
                &f,
                binding.sealed_state.clone(),
                "sign",
                &first_attempt,
                &action,
            ),
            1,
        )
        .unwrap();
        let executed = handle(
            &f.completed,
            &f.context,
            &execute_command(
                &f,
                "sign",
                &first_attempt,
                first.sealed_state.clone(),
                approved(),
            ),
            1,
        )
        .unwrap();
        let next_attempt = ActionAttempt {
            attempt_id: Uuid::now_v7(),
            signing_session_id: Some(SessionId::new_v7()),
        };
        let request = repeated_prepare_command(
            &f,
            &binding.sealed_state,
            &executed.sealed_state,
            &next_attempt,
            &action,
        );
        if !repeat {
            assert!(handle(&f.completed, &f.context, &request, 1).is_err());
            continue;
        }
        // No successful preparation exists for the retry yet. Rejected proposed
        // variants cannot reserve the attempt or poison the valid later request.
        let Action::Sign { scope } = &action else {
            panic!()
        };
        let mut changed = vec![scope.clone(); 7];
        changed[0].batch[0].message_digest[0] ^= 1;
        changed[1].batch[0].item_id = Uuid::now_v7();
        changed[2].batch[0].subset_id = Some(Uuid::now_v7());
        changed[3].batch[0].tweak = KeyTweak::TaprootKeyPath;
        changed[4].session_tweak = KeyTweak::TaprootKeyPath;
        changed[5].batch[0].signers.reverse();
        changed[6].batch[0].adaptor = AdaptorContext::Single {
            adaptor_id: Uuid::now_v7(),
            point: PublicKeyBytes::new(&public_key(&[20; 32])).unwrap(),
        };
        for scope in changed {
            let changed_request = repeated_prepare_command(
                &f,
                &binding.sealed_state,
                &first.sealed_state,
                &next_attempt,
                &Action::Sign { scope },
            );
            assert!(handle(&f.completed, &f.context, &changed_request, 1).is_err());
        }
        for wrong_attempt in [
            ActionAttempt {
                attempt_id: first_attempt.attempt_id,
                ..next_attempt.clone()
            },
            ActionAttempt {
                signing_session_id: first_attempt.signing_session_id.clone(),
                ..next_attempt.clone()
            },
        ] {
            let wrong = repeated_prepare_command(
                &f,
                &binding.sealed_state,
                &first.sealed_state,
                &wrong_attempt,
                &action,
            );
            assert!(handle(&f.completed, &f.context, &wrong, 1).is_err());
        }
        let next = handle(&f.completed, &f.context, &request, 1).unwrap();
        let response = handle(
            &f.completed,
            &f.context,
            &execute_command(&f, "sign", &next_attempt, next.sealed_state, approved()),
            1,
        )
        .unwrap();
        let output: ExecutionOutput = response.output.decode().unwrap();
        assert!(
            matches!(output, ExecutionOutput::SigningPermit { signing_session_id, .. }
            if Some(&signing_session_id) == next_attempt.signing_session_id.as_ref())
        );
        let mut signing = f.signing.clone();
        signing.signing_session_id = next_attempt.signing_session_id.clone().unwrap();
        signing.signing_authorization = SigningAuthorization::sign(
            &[12; 32],
            &signing.keygen_session_id,
            &signing.signing_session_id,
            60,
            &signing.batch_items,
        )
        .unwrap();
        verify_signing_batch(
            f.completed.musig_processor(),
            f.completed.session_secret(),
            &signing,
        )
        .unwrap();
        // An older receipt cannot roll live state back to the superseded attempt.
        assert!(handle(
            &f.completed,
            &f.context,
            &execute_command(
                &f,
                "sign",
                &first_attempt,
                executed.sealed_state,
                ConditionProof::None
            ),
            1
        )
        .is_err());
        *f.completed
            .musig_processor()
            .get_session_metadata_public()
            .escrow_state
            .inner
            .lock()
            .unwrap() = SessionState::default();
        handle(
            &f.completed,
            &f.context,
            &execute_command(
                &f,
                "sign",
                &next_attempt,
                response.sealed_state,
                ConditionProof::None,
            ),
            2,
        )
        .unwrap();
        verify_signing_batch(
            f.completed.musig_processor(),
            f.completed.session_secret(),
            &signing,
        )
        .unwrap();
    }
}

#[tokio::test]
async fn pending_or_rejected_execution_has_no_effect_and_does_not_hold_the_ledger() {
    let gate = Arc::new(ExecutionGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    let (f, _) = application_fixture_options(false, Some(gate.clone()));
    let binding = super::super::handle(&f.completed, &f.context, &binding_command(&f), 1)
        .await
        .unwrap();
    let recipient = Recipient {
        encryption_public_key: PublicKeyBytes::new(&public_key(&[19; 32])).unwrap(),
    };
    let actions = [
        (
            "sign",
            signing_action(&f),
            Some(f.signing.signing_session_id.clone()),
        ),
        (
            "secret",
            Action::ReleaseSecret {
                name: "document-key".into(),
                recipient: recipient.clone(),
            },
            None,
        ),
        (
            "key",
            Action::ReleaseSigningKey {
                public_key: f.registration.policy.policy.participant_public_key.clone(),
                recipient,
            },
            None,
        ),
    ];
    let mut prepared = Vec::new();
    for (id, action, signing_session_id) in &actions {
        let attempt = ActionAttempt {
            attempt_id: Uuid::now_v7(),
            signing_session_id: signing_session_id.clone(),
        };
        prepared.push((
            attempt.clone(),
            prepare_command(&f, binding.sealed_state.clone(), id, &attempt, action),
        ));
    }
    let mut receipt = super::super::handle(&f.completed, &f.context, &prepared[0].1, 1)
        .await
        .unwrap();
    for index in 0..2 {
        let execute = execute_command(
            &f,
            actions[index].0,
            &prepared[index].0,
            receipt.sealed_state.clone(),
            ConditionProof::VerifierEvidence {
                evidence: Payload::new(b"rejected".to_vec()).unwrap(),
            },
        );
        let (result, next) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::join!(
                super::super::handle(&f.completed, &f.context, &execute, 1),
                async {
                    gate.entered.acquire().await.unwrap().forget();
                    {
                        let state = f
                            .completed
                            .musig_processor()
                            .get_session_metadata_public()
                            .escrow_state
                            .inner
                            .try_lock()
                            .unwrap();
                        assert!(state.executions.is_empty());
                        assert!(state.permits.is_empty());
                    }
                    assert!(verify_signing_batch(
                        f.completed.musig_processor(),
                        f.completed.session_secret(),
                        &f.signing
                    )
                    .is_err());
                    // A different permission makes progress while this external
                    // authorization is pending, even on a single-thread runtime.
                    let next =
                        super::super::handle(&f.completed, &f.context, &prepared[index + 1].1, 1)
                            .await
                            .unwrap();
                    gate.release.add_permits(1);
                    next
                },
            )
        })
        .await
        .expect("Execution verification must not hold a global state lock");
        assert!(result.is_err());
        let state = f
            .completed
            .musig_processor()
            .get_session_metadata_public()
            .escrow_state
            .inner
            .try_lock()
            .unwrap();
        assert!(state.executions.is_empty());
        assert!(state.permits.is_empty());
        assert!(state.inflight.is_empty());
        drop(state);
        receipt = next;
    }
}

fn release_candidate(
    f: &Fixture,
    binding: &Payload,
    permission: &str,
    action: &Action,
    candidate: u8,
    predecessor: Option<&Payload>,
) -> (EscrowCommand, ActionAttempt) {
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: None,
    };
    let request = PrepareEscrowRequest {
        schema_version: escrow::SCHEMA_VERSION,
        binding_receipt: binding.clone(),
        action_id: permission.into(),
        attempt: attempt.clone(),
        action: None,
        action_parameters: Payload::encode(&(action, candidate)).unwrap(),
        prior_preparation_receipts: predecessor.cloned().into_iter().collect(),
    };
    (
        command(
            f,
            Operation::Prepare,
            Some((permission, &attempt)),
            &request,
        ),
        attempt,
    )
}
fn candidate_proof(candidate: u8) -> ConditionProof {
    ConditionProof::VerifierEvidence {
        evidence: Payload::new(format!("approved-{candidate}").into_bytes()).unwrap(),
    }
}
fn release_action(f: &Fixture, permission: &str) -> Action {
    let recipient = Recipient {
        encryption_public_key: PublicKeyBytes::new(&public_key(&[19; 32])).unwrap(),
    };
    if permission == "secret" {
        Action::ReleaseSecret {
            name: "document-key".into(),
            recipient,
        }
    } else {
        Action::ReleaseSigningKey {
            public_key: f.registration.policy.policy.participant_public_key.clone(),
            recipient,
        }
    }
}

#[test]
fn renewable_release_preserves_late_candidates_and_first_execution_freezes_the_grant() {
    for permission in ["secret", "key"] {
        for winner in [0, 1] {
            let (f, calls) = application_fixture_policies(false, true, None);
            let binding = handle(&f.completed, &f.context, &binding_command(&f), 1).unwrap();
            let action = release_action(&f, permission);
            let (first, first_attempt) =
                release_candidate(&f, &binding.sealed_state, permission, &action, 1, None);
            let first = handle(&f.completed, &f.context, &first, 1).unwrap();
            let (second, second_attempt) = release_candidate(
                &f,
                &binding.sealed_state,
                permission,
                &action,
                2,
                Some(&first.sealed_state),
            );
            let second = handle(&f.completed, &f.context, &second, 1).unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            let candidates = [(first, first_attempt), (second, second_attempt)];
            // A caller cannot transplant the second candidate's application
            // proof onto the first authenticated preparation.
            let wrong = execute_command(
                &f,
                permission,
                &candidates[0].1,
                candidates[0].0.sealed_state.clone(),
                candidate_proof(2),
            );
            assert!(handle(&f.completed, &f.context, &wrong, 1).is_err());
            if permission == "key" {
                *f.completed
                    .musig_processor()
                    .get_session_metadata_public()
                    .escrow_state
                    .inner
                    .lock()
                    .unwrap() = SessionState::default();
            }
            let accepted = handle(
                &f.completed,
                &f.context,
                &execute_command(
                    &f,
                    permission,
                    &candidates[winner].1,
                    candidates[winner].0.sealed_state.clone(),
                    candidate_proof((winner + 1) as u8),
                ),
                1,
            )
            .unwrap();
            let output: ExecutionOutput = accepted.output.decode().unwrap();
            let (encrypted, expected) = match output {
                ExecutionOutput::ReleasedSecret {
                    encrypted_secret, ..
                } => (encrypted_secret, vec![7; 32]),
                ExecutionOutput::ReleasedSigningKey { encrypted_key, .. } => {
                    (encrypted_key, vec![14; 32])
                }
                _ => panic!("Expected an independently authorized custody release"),
            };
            assert_eq!(
                SecureCrypto::ecies_decrypt(
                    &secp256k1::SecretKey::from_byte_array([19; 32]).unwrap(),
                    encrypted.as_bytes()
                )
                .unwrap(),
                expected
            );
            let other = 1 - winner;
            assert!(handle(
                &f.completed,
                &f.context,
                &execute_command(
                    &f,
                    permission,
                    &candidates[other].1,
                    candidates[other].0.sealed_state.clone(),
                    candidate_proof((other + 1) as u8)
                ),
                1
            )
            .is_err());
            let (after, _) = release_candidate(
                &f,
                &binding.sealed_state,
                permission,
                &action,
                3,
                Some(&candidates[winner].0.sealed_state),
            );
            assert!(handle(&f.completed, &f.context, &after, 1).is_err());
            assert_eq!(
                calls.load(Ordering::SeqCst),
                2,
                "Frozen grants must reject before external preparation"
            );
            *f.completed
                .musig_processor()
                .get_session_metadata_public()
                .escrow_state
                .inner
                .lock()
                .unwrap() = SessionState::default();
            let recovered = handle(
                &f.completed,
                &f.context,
                &execute_command(
                    &f,
                    permission,
                    &candidates[winner].1,
                    accepted.sealed_state,
                    ConditionProof::None,
                ),
                2,
            )
            .unwrap();
            assert_eq!(recovered.output, accepted.output);
            assert!(handle(
                &f.completed,
                &f.context,
                &execute_command(
                    &f,
                    permission,
                    &candidates[other].1,
                    candidates[other].0.sealed_state.clone(),
                    candidate_proof((other + 1) as u8)
                ),
                2
            )
            .is_err());
        }
    }
}

#[test]
fn renewable_release_requires_consent_current_predecessor_identical_recipient_and_bounded_candidates(
) {
    for renewable in [false, true] {
        let (f, calls) = application_fixture_policies(false, renewable, None);
        let binding = handle(&f.completed, &f.context, &binding_command(&f), 1).unwrap();
        let action = release_action(&f, "secret");
        let (initial, _) = release_candidate(&f, &binding.sealed_state, "secret", &action, 1, None);
        let initial = handle(&f.completed, &f.context, &initial, 1).unwrap();
        let (missing, _) = release_candidate(&f, &binding.sealed_state, "secret", &action, 2, None);
        assert!(handle(&f.completed, &f.context, &missing, 1).is_err());
        let (next, _) = release_candidate(
            &f,
            &binding.sealed_state,
            "secret",
            &action,
            2,
            Some(&initial.sealed_state),
        );
        if !renewable {
            assert!(handle(&f.completed, &f.context, &next, 1).is_err());
            continue;
        }
        let mut wrong = action.clone();
        if let Action::ReleaseSecret { recipient, .. } = &mut wrong {
            recipient.encryption_public_key = PublicKeyBytes::new(&public_key(&[21; 32])).unwrap();
        }
        for wrong in [wrong, release_action(&f, "key")] {
            let (request, _) = release_candidate(
                &f,
                &binding.sealed_state,
                "secret",
                &wrong,
                2,
                Some(&initial.sealed_state),
            );
            assert!(handle(&f.completed, &f.context, &request, 1).is_err());
        }
        let second = handle(&f.completed, &f.context, &next, 1).unwrap();
        let (stale, _) = release_candidate(
            &f,
            &binding.sealed_state,
            "secret",
            &action,
            3,
            Some(&initial.sealed_state),
        );
        assert!(handle(&f.completed, &f.context, &stale, 1).is_err());
        let mut latest = second;
        for candidate in 3..=escrow::MAX_PREPARATIONS_PER_ACTION {
            let (request, _) = release_candidate(
                &f,
                &binding.sealed_state,
                "secret",
                &action,
                candidate as u8,
                Some(&latest.sealed_state),
            );
            latest = handle(&f.completed, &f.context, &request, 1).unwrap();
        }
        let before = calls.load(Ordering::SeqCst);
        for restart in [false, true] {
            if restart {
                *f.completed
                    .musig_processor()
                    .get_session_metadata_public()
                    .escrow_state
                    .inner
                    .lock()
                    .unwrap() = SessionState::default();
            }
            let (request, _) = release_candidate(
                &f,
                &binding.sealed_state,
                "secret",
                &action,
                17,
                Some(&latest.sealed_state),
            );
            assert!(matches!(
                handle(&f.completed, &f.context, &request, 1),
                Err(EnclaveError::EscrowPreparationExhausted { .. })
            ));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before,
            "Candidate limit must reject before external work"
        );
    }
}

#[test]
fn executed_receipt_recovery_must_pass_the_trusted_recovery_gate_before_restoring_effects() {
    let (mut f, calls) = application_fixture();
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1).unwrap();
    let attempt = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: Some(f.signing.signing_session_id.clone()),
    };
    let prepared = handle(
        &f.completed,
        &f.context,
        &prepare_command(
            &f,
            binding.sealed_state,
            "sign",
            &attempt,
            &signing_action(&f),
        ),
        1,
    )
    .unwrap();
    let executed = handle(
        &f.completed,
        &f.context,
        &execute_command(&f, "sign", &attempt, prepared.sealed_state, approved()),
        1,
    )
    .unwrap();
    *f.completed
        .musig_processor()
        .get_session_metadata_public()
        .escrow_state
        .inner
        .lock()
        .unwrap() = SessionState::default();
    let restore = execute_command(
        &f,
        "sign",
        &attempt,
        executed.sealed_state,
        ConditionProof::None,
    );
    for reject_recovery in [true, false] {
        f.context.escrow_verifiers = Arc::new(
            VerifierRegistry::new(vec![Arc::new(DocumentVerifier {
                calls: calls.clone(),
                execution_gate: None,
                reject_recovery,
            })])
            .unwrap(),
        );
        let result = handle(&f.completed, &f.context, &restore, 2);
        assert_eq!(result.is_err(), reject_recovery);
        assert_eq!(
            verify_signing_batch(
                f.completed.musig_processor(),
                f.completed.session_secret(),
                &f.signing
            )
            .is_err(),
            reject_recovery
        );
        if reject_recovery {
            let state = f
                .completed
                .musig_processor()
                .get_session_metadata_public()
                .escrow_state
                .inner
                .lock()
                .unwrap();
            assert!(state.permits.is_empty());
            assert!(state.executions.is_empty());
            assert!(state.inflight.is_empty());
        }
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "Recovery cannot create another preparation"
    );
}

/// An application fixture whose participant may sign BIP340 digests the verifier resolves.
fn bip340_fixture(repetition: escrow::Repetition) -> Fixture {
    let mut f = fixture_with_grants(
        true,
        true,
        false,
        false,
        vec![(
            "bip340",
            escrow::ActionGrant {
                preparation: escrow::PreparationPolicy::Single,
                repetition,
                unbound: false,
                condition: Condition::VerifierRule {
                    rule: "document_approved".into(),
                },
                operation: escrow::Permission::SignBip340,
            },
        )],
    );
    f.context.escrow_verifiers = Arc::new(
        VerifierRegistry::new(vec![Arc::new(DocumentVerifier {
            calls: Arc::new(AtomicUsize::new(0)),
            execution_gate: None,
            reject_recovery: false,
        })])
        .unwrap(),
    );
    f
}
fn bip340_action(f: &Fixture, digests: &[[u8; 32]]) -> Action {
    Action::SignBip340 {
        scope: escrow::Bip340Scope {
            public_key: f.registration.policy.policy.participant_public_key.clone(),
            items: digests
                .iter()
                .map(|digest| escrow::Bip340Item {
                    item_id: Uuid::now_v7(),
                    digest: *digest,
                })
                .collect(),
        },
    }
}
fn fresh_attempt() -> ActionAttempt {
    ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: None,
    }
}
/// Prepare and execute `action` under `attempt`, returning the checked signatures.
fn sign_bip340(f: &Fixture, binding: &Payload, attempt: &ActionAttempt, action: &Action) -> usize {
    let prepared = handle(
        &f.completed,
        &f.context,
        &prepare_command(f, binding.clone(), "bip340", attempt, action),
        1,
    )
    .unwrap();
    let executed = handle(
        &f.completed,
        &f.context,
        &execute_command(f, "bip340", attempt, prepared.sealed_state, approved()),
        1,
    )
    .unwrap();
    let ExecutionOutput::Bip340Signatures {
        public_key,
        signatures,
    } = executed.output.decode().unwrap()
    else {
        panic!("expected BIP340 signatures");
    };
    let Action::SignBip340 { scope } = action else {
        unreachable!()
    };
    assert_eq!(public_key, scope.public_key);
    assert_eq!(signatures.len(), scope.items.len());
    let key = secp256k1::PublicKey::from_slice(public_key.as_bytes())
        .unwrap()
        .x_only_public_key()
        .0;
    for (signature, item) in signatures.iter().zip(&scope.items) {
        assert_eq!(signature.item_id, item.item_id);
        let signature = secp256k1::schnorr::Signature::from_byte_array(
            signature.signature.clone().try_into().unwrap(),
        );
        secp256k1::Secp256k1::verification_only()
            .verify_schnorr(&signature, &item.digest, &key)
            .unwrap();
    }
    signatures.len()
}

#[test]
fn bip340_signatures_verify_and_every_fresh_attempt_signs_its_own_digests() {
    let f = bip340_fixture(escrow::Repetition::VerifierAuthorizedAttempts);
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1)
        .unwrap()
        .sealed_state;

    // A batch's intent proof, then a retried batch's with other digests.
    let first = fresh_attempt();
    assert_eq!(
        sign_bip340(
            &f,
            &binding,
            &first,
            &bip340_action(&f, &[[1; 32], [2; 32]])
        ),
        2
    );
    let second = fresh_attempt();
    let action = bip340_action(&f, &[[3; 32]]);
    assert_eq!(sign_bip340(&f, &binding, &second, &action), 1);

    // An attempt cannot be reused for other digests.
    let replaced = prepare_command(
        &f,
        binding.clone(),
        "bip340",
        &second,
        &bip340_action(&f, &[[4; 32]]),
    );
    assert!(handle(&f.completed, &f.context, &replaced, 1).is_err());
}

#[test]
fn a_one_time_bip340_permission_signs_once() {
    let f = bip340_fixture(escrow::Repetition::Once);
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1)
        .unwrap()
        .sealed_state;
    sign_bip340(
        &f,
        &binding,
        &fresh_attempt(),
        &bip340_action(&f, &[[1; 32]]),
    );
    let again = prepare_command(
        &f,
        binding,
        "bip340",
        &fresh_attempt(),
        &bip340_action(&f, &[[2; 32]]),
    );
    assert!(handle(&f.completed, &f.context, &again, 1).is_err());
}

#[test]
fn a_bip340_scope_signs_only_with_the_participant_key() {
    let f = bip340_fixture(escrow::Repetition::VerifierAuthorizedAttempts);
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1)
        .unwrap()
        .sealed_state;
    let Action::SignBip340 { mut scope } = bip340_action(&f, &[[1; 32]]) else {
        unreachable!()
    };
    scope.public_key = PublicKeyBytes::new(&public_key(&[18; 32])).unwrap();
    let other_key = prepare_command(
        &f,
        binding.clone(),
        "bip340",
        &fresh_attempt(),
        &Action::SignBip340 { scope },
    );
    assert!(handle(&f.completed, &f.context, &other_key, 1).is_err());

    // A BIP340 attempt never targets a MuSig2 signing session.
    let with_session = ActionAttempt {
        attempt_id: Uuid::now_v7(),
        signing_session_id: Some(f.signing.signing_session_id.clone()),
    };
    let wrong = prepare_command(
        &f,
        binding,
        "bip340",
        &with_session,
        &bip340_action(&f, &[[1; 32]]),
    );
    assert!(handle(&f.completed, &f.context, &wrong, 1).is_err());
}

#[test]
fn verifier_authorized_musig_signing_repeats_in_fresh_sessions() {
    let mut f = fixture_with_grants(
        true,
        true,
        false,
        false,
        vec![(
            "sign",
            escrow::ActionGrant {
                preparation: escrow::PreparationPolicy::Single,
                repetition: escrow::Repetition::VerifierAuthorizedAttempts,
                unbound: false,
                condition: Condition::VerifierRule {
                    rule: "document_approved".into(),
                },
                operation: escrow::Permission::Sign,
            },
        )],
    );
    f.context.escrow_verifiers = Arc::new(
        VerifierRegistry::new(vec![Arc::new(DocumentVerifier {
            calls: Arc::new(AtomicUsize::new(0)),
            execution_gate: None,
            reject_recovery: false,
        })])
        .unwrap(),
    );
    let binding = handle(&f.completed, &f.context, &binding_command(&f), 1)
        .unwrap()
        .sealed_state;
    // A failed batch is retried with new messages, each attempt in its own signing session.
    for _ in 0..2 {
        let session = SessionId::new_v7();
        let attempt = ActionAttempt {
            attempt_id: Uuid::now_v7(),
            signing_session_id: Some(session.clone()),
        };
        let prepared = handle(
            &f.completed,
            &f.context,
            &prepare_command(&f, binding.clone(), "sign", &attempt, &signing_action(&f)),
            1,
        )
        .unwrap();
        let executed = handle(
            &f.completed,
            &f.context,
            &execute_command(&f, "sign", &attempt, prepared.sealed_state, approved()),
            1,
        )
        .unwrap();
        let ExecutionOutput::SigningPermit {
            signing_session_id, ..
        } = executed.output.decode().unwrap()
        else {
            panic!("expected a signing permit");
        };
        assert_eq!(signing_session_id, session);
    }
}
