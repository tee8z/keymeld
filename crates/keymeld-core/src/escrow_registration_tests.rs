use super::*;
use crate::escrow::*;

fn public(byte: u8) -> Vec<u8> {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_byte_array([byte; 32]).unwrap(),
    )
    .serialize()
    .to_vec()
}
fn fixture() -> (SignedSessionManifest, RegistrationEnvelope) {
    let session = SessionId::new_v7();
    let user = UserId::new_v7();
    let secret = crate::SessionSecret::from_bytes([16; 32]);
    let manifest = SignedSessionManifest::sign(
        SessionAuthorizationManifest {
            keygen_session_id: session.clone(),
            coordinator_user_id: user.clone(),
            creator_pubkey: public(11),
            signing_pubkey: public(12),
            session_public_key: SecureCrypto::derive_public_key_from_seed(secret.as_bytes())
                .unwrap()
                .serialize()
                .to_vec(),
            participant_verifiers: BTreeMap::from([(user.clone(), public(13))]),
            timeout_secs: 300,
            max_signing_sessions: Some(4),
            encrypted_taproot_tweak: secret
                .encrypt(
                    &serde_json::to_vec(&TaprootTweak::None).unwrap(),
                    "taproot_tweak",
                )
                .unwrap()
                .to_hex()
                .unwrap(),
            subset_definitions: vec![],
        },
        &[11; 32],
    )
    .unwrap();
    let (_, auth) =
        SecureCrypto::derive_session_auth_keypair(&[14; 32], &session.to_string()).unwrap();
    let context = RegistrationContext {
        keygen_session_id: session.clone(),
        manifest_hash: manifest.digest().unwrap(),
        user_id: user.clone(),
        enclave_id: EnclaveId::new(1),
        enclave_key_epoch: 1,
        public_key: public(14),
        auth_pubkey: auth.serialize().to_vec(),
        require_signing_approval: false,
    };
    let escrow_context = EscrowContext {
        keygen_session_id: session,
        user_id: user.clone(),
        escrow_id: uuid::Uuid::now_v7(),
        manifest_digest: manifest.digest().unwrap().try_into().unwrap(),
        application: ApplicationContext::commit("document-escrow".into(), 1, b"document").unwrap(),
    };
    let policy = SignedEscrowPolicy::sign(
        EscrowPolicy {
            verifier: None,
            schema_version: crate::escrow::SCHEMA_VERSION,
            context: escrow_context,
            participant_public_key: PublicKeyBytes::new(&public(14)).unwrap(),
            secrets: BTreeMap::new(),
            grants: BTreeMap::from([(
                "sign".into(),
                ActionGrant {
                    preparation: crate::escrow::PreparationPolicy::Single,
                    repetition: crate::escrow::Repetition::Once,
                    unbound: false,
                    condition: Condition::HashlockSha256 {
                        commitment: sha256(&[18; 32]),
                    },
                    operation: Permission::Exact {
                        action: Action::Sign {
                            scope: SigningScope {
                                session_tweak: KeyTweak::None,
                                batch: vec![SigningItem {
                                    item_id: uuid::Uuid::now_v7(),
                                    message_digest: sha256(b"document"),
                                    subset_id: None,
                                    signers: vec![ScopeSigner {
                                        user_id: user,
                                        public_key: PublicKeyBytes::new(&public(14)).unwrap(),
                                    }],
                                    tweak: KeyTweak::None,
                                    adaptor: AdaptorContext::None,
                                }],
                            },
                        },
                    },
                },
            )]),
        },
        &[14; 32],
    )
    .unwrap();
    let envelope = RegistrationEnvelope::with_escrow(
        context,
        &[14; 32],
        EscrowRegistration {
            policy,
            secrets: BTreeMap::new(),
        },
    )
    .unwrap();
    (manifest, envelope)
}

#[test]
fn stripping_generic_escrow_cannot_downgrade_to_unrestricted_legacy_registration() {
    let (_, envelope) = fixture();
    envelope.verify().unwrap();
    let mut serialized = serde_json::to_value(&envelope).unwrap();
    serialized.as_object_mut().unwrap().remove("escrow");
    let downgraded: RegistrationEnvelope = serde_json::from_value(serialized).unwrap();
    assert!(downgraded.verify().is_err());
    // Plain old registrations still use the original domain and restore intact.
    let legacy = RegistrationEnvelope::new(envelope.context.clone(), &[14; 32]).unwrap();
    let mut serialized = serde_json::to_value(&legacy).unwrap();
    serialized.as_object_mut().unwrap().remove("escrow");
    let restored: RegistrationEnvelope = serde_json::from_value(serialized).unwrap();
    restored.verify().unwrap();
}

#[test]
fn new_invitation_signature_cannot_replace_participant_signed_enclave_context() {
    let (manifest, envelope) = fixture();
    let original: RegistrationEnvelope =
        serde_json::from_slice(&serde_json::to_vec(&envelope).unwrap()).unwrap();
    let mut substituted = envelope.context.clone();
    substituted.enclave_key_epoch += 1;
    let ciphertext = "aabbcc";
    let invitation =
        RegistrationAuthorization::sign(&[13; 32], substituted.clone(), ciphertext).unwrap();
    invitation.verify(&manifest, ciphertext).unwrap();
    // The gateway can sign its invitation again, but neither change nor relabel
    // the decrypted participant envelope. Actual import compares both contexts.
    assert_ne!(
        serde_json::to_vec(&original.context).unwrap(),
        serde_json::to_vec(&invitation.context).unwrap()
    );
    let mut relabeled: RegistrationEnvelope =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    relabeled.context = substituted;
    assert!(relabeled.verify().is_err());
}

#[test]
fn independently_valid_policy_signature_cannot_move_between_registration_contexts() {
    let (_, mut envelope) = fixture();
    let escrow = envelope.escrow.as_mut().unwrap();
    let mut changed = escrow.policy.policy.clone();
    changed.context.manifest_digest[0] ^= 1;
    escrow.policy = SignedEscrowPolicy::sign(changed, &[14; 32]).unwrap();
    // Both policy and registration possession signatures are recreated, but the
    // nested policy still disagrees with the outer manifest commitment.
    envelope.proof_signature = sign_authorization(
        &[14; 32],
        "registration-escrow-possession-v1",
        &(&envelope.context, envelope.escrow.as_ref().unwrap()),
    )
    .unwrap();
    assert!(envelope.verify().is_err());
}

#[test]
fn signing_only_registration_has_no_implicit_secret_or_signing_key_export() {
    let (_, envelope) = fixture();
    let escrow = envelope.escrow.as_ref().unwrap();
    let export = Action::ReleaseSigningKey {
        public_key: PublicKeyBytes::new(&public(14)).unwrap(),
        recipient: Recipient {
            encryption_public_key: PublicKeyBytes::new(&public(12)).unwrap(),
        },
    };
    let attempt = ActionAttempt {
        attempt_id: uuid::Uuid::now_v7(),
        signing_session_id: None,
    };
    assert!(escrow
        .policy
        .authorize(
            &escrow.policy.policy.context,
            &public(14),
            "sign",
            &attempt,
            &export,
            &ConditionProof::HashlockPreimage {
                preimage: vec![18; 32]
            }
        )
        .is_err());
    assert!(escrow
        .policy
        .authorize(
            &escrow.policy.policy.context,
            &public(14),
            "export",
            &attempt,
            &export,
            &ConditionProof::HashlockPreimage {
                preimage: vec![18; 32]
            }
        )
        .is_err());
}
