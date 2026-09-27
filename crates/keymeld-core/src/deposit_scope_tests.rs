//! Registrations sealed under a deposit scope before their session existed.
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

/// A pool of a coordinator and one player, and the scope the player's deposit was made under.
#[derive(Clone)]
struct Pool {
    session: SessionId,
    coordinator: UserId,
    player: UserId,
    deposit: DepositScope,
}

fn pool() -> Pool {
    Pool {
        session: SessionId::new_v7(),
        coordinator: UserId::new_v7(),
        player: UserId::new_v7(),
        deposit: DepositScope {
            deposit_session_id: SessionId::new_v7(),
            deposit_digest: sha256(b"published terms").to_vec(),
            evidence: b"pool 1 of 3".to_vec(),
        },
    }
}

impl Pool {
    fn unsigned(&self, deposit_scope: Option<DepositScope>) -> SessionAuthorizationManifest {
        SessionAuthorizationManifest {
            keygen_session_id: self.session.clone(),
            coordinator_user_id: self.coordinator.clone(),
            creator_pubkey: public(1),
            signing_pubkey: public(2),
            session_public_key: public(3),
            participant_verifiers: BTreeMap::from([
                (self.coordinator.clone(), public(4)),
                (self.player.clone(), public(5)),
            ]),
            timeout_secs: 300,
            max_signing_sessions: Some(2),
            encrypted_taproot_tweak: "tweak".into(),
            subset_definitions: vec![],
            deposit_scope,
        }
    }

    fn manifest(&self, deposit_scope: Option<DepositScope>) -> SignedSessionManifest {
        SignedSessionManifest::sign(self.unsigned(deposit_scope), &[1; 32]).unwrap()
    }

    /// The same pool in another session, as when a deposit is registered into a second pool.
    fn in_another_session(&self) -> Pool {
        Pool {
            session: SessionId::new_v7(),
            ..self.clone()
        }
    }
}

/// `key`'s registration in `user`'s slot, bound to `session` and `digest`.
fn context(session: &SessionId, digest: Vec<u8>, user: &UserId, key: u8) -> RegistrationContext {
    RegistrationContext {
        keygen_session_id: session.clone(),
        manifest_hash: digest,
        user_id: user.clone(),
        enclave_id: EnclaveId::new(1),
        enclave_key_epoch: 1,
        public_key: public(key),
        auth_pubkey: SecureCrypto::derive_session_auth_keypair(&[key; 32], &session.to_string())
            .unwrap()
            .1
            .serialize()
            .to_vec(),
        require_signing_approval: false,
    }
}

fn escrow_policy(session: &SessionId, digest: &[u8], user: &UserId, key: u8) -> SignedEscrowPolicy {
    SignedEscrowPolicy::sign(
        EscrowPolicy {
            schema_version: crate::escrow::SCHEMA_VERSION,
            context: EscrowContext {
                keygen_session_id: session.clone(),
                user_id: user.clone(),
                escrow_id: uuid::Uuid::now_v7(),
                manifest_digest: digest.try_into().unwrap(),
                application: ApplicationContext::commit("entry".into(), 1, b"rules").unwrap(),
            },
            participant_public_key: PublicKeyBytes::new(&public(key)).unwrap(),
            verifier: None,
            secrets: BTreeMap::new(),
            grants: BTreeMap::from([(
                "release".into(),
                ActionGrant {
                    preparation: crate::escrow::PreparationPolicy::Single,
                    repetition: crate::escrow::Repetition::Once,
                    unbound: false,
                    condition: Condition::HashlockSha256 {
                        commitment: sha256(&[18; 32]),
                    },
                    operation: Permission::Exact {
                        action: Action::ReleaseSigningKey {
                            public_key: PublicKeyBytes::new(&public(key)).unwrap(),
                            recipient: Recipient {
                                encryption_public_key: PublicKeyBytes::new(&public(19)).unwrap(),
                            },
                        },
                    },
                },
            )]),
        },
        &[key; 32],
    )
    .unwrap()
}

#[test]
fn registration_scope_is_the_session_without_a_deposit_scope_and_the_scope_with_one() {
    let pool = pool();
    let plain = pool.manifest(None);
    assert_eq!(
        plain.registration_scope().unwrap(),
        (pool.session.clone(), plain.digest().unwrap())
    );
    let scoped = pool.manifest(Some(pool.deposit.clone()));
    assert_eq!(
        scoped.registration_scope().unwrap(),
        (
            pool.deposit.deposit_session_id.clone(),
            pool.deposit.deposit_digest.clone()
        )
    );
    // The manifest digest still identifies the session, and commits to its whole scope.
    assert_ne!(scoped.digest().unwrap(), plain.digest().unwrap());
    let mut other = pool.deposit.clone();
    other.evidence = b"pool 2 of 3".to_vec();
    assert_ne!(
        pool.manifest(Some(other)).digest().unwrap(),
        scoped.digest().unwrap()
    );
}

#[test]
fn a_manifest_refuses_a_malformed_deposit_scope() {
    let pool = pool();
    let mut malformed = Vec::new();
    for length in [0, 31, 33] {
        let mut scope = pool.deposit.clone();
        scope.deposit_digest = vec![7; length];
        malformed.push(scope);
    }
    let mut scope = pool.deposit.clone();
    scope.evidence = vec![7; MAX_DEPOSIT_EVIDENCE_BYTES + 1];
    malformed.push(scope);
    let mut scope = pool.deposit.clone();
    scope.deposit_session_id = pool.session.clone();
    malformed.push(scope);
    let mut scope = pool.deposit.clone();
    scope.deposit_session_id = SessionId::from(uuid::Uuid::nil());
    malformed.push(scope);
    for scope in malformed {
        assert!(SignedSessionManifest::sign(pool.unsigned(Some(scope.clone())), &[1; 32]).is_err());
        // Nor does a manifest signed without it verify with it.
        let mut signed = pool.manifest(None);
        signed.manifest.deposit_scope = Some(scope);
        assert!(signed.verify().is_err());
    }
    let mut largest = pool.deposit.clone();
    largest.evidence = vec![7; MAX_DEPOSIT_EVIDENCE_BYTES];
    pool.manifest(Some(largest)).verify().unwrap();
    // The creator's signature covers the scope: neither its evidence nor its removal can
    // change afterwards.
    let signed = pool.manifest(Some(pool.deposit.clone()));
    let mut changed = signed.clone();
    changed.manifest.deposit_scope.as_mut().unwrap().evidence = b"pool 3 of 3".to_vec();
    assert!(changed.verify().is_err());
    let mut changed = signed;
    changed.manifest.deposit_scope = None;
    assert!(changed.verify().is_err());
}

#[test]
fn deposit_and_session_scoped_registrations_are_each_refused_by_the_other_manifest() {
    let pool = pool();
    let plain = pool.manifest(None);
    let scoped = pool.manifest(Some(pool.deposit.clone()));
    let (deposit_id, deposit_digest) = scoped.registration_scope().unwrap();
    let authorize = |context| RegistrationAuthorization::sign(&[5; 32], context, "aabb").unwrap();

    let deposit = authorize(context(
        &deposit_id,
        deposit_digest.clone(),
        &pool.player,
        9,
    ));
    deposit.verify(&scoped, "aabb").unwrap();
    assert!(deposit.verify(&plain, "aabb").is_err());

    let session_scoped = authorize(context(
        &pool.session,
        plain.digest().unwrap(),
        &pool.player,
        9,
    ));
    session_scoped.verify(&plain, "aabb").unwrap();
    assert!(session_scoped.verify(&scoped, "aabb").is_err());

    // Every mix of session and scope is refused by both.
    for (session, digest) in [
        (&pool.session, scoped.digest().unwrap()),
        (&pool.session, deposit_digest.clone()),
        (&deposit_id, plain.digest().unwrap()),
        (&deposit_id, scoped.digest().unwrap()),
    ] {
        let mixed = authorize(context(session, digest, &pool.player, 9));
        assert!(mixed.verify(&scoped, "aabb").is_err());
        assert!(mixed.verify(&plain, "aabb").is_err());
    }

    // A session under other terms refuses the deposit.
    let mut other_terms = pool.deposit.clone();
    other_terms.deposit_digest = sha256(b"other terms").to_vec();
    assert!(deposit
        .verify(&pool.manifest(Some(other_terms)), "aabb")
        .is_err());
    // So does one under another deposit session id.
    let mut other_id = pool.deposit.clone();
    other_id.deposit_session_id = SessionId::new_v7();
    assert!(deposit
        .verify(&pool.manifest(Some(other_id)), "aabb")
        .is_err());
    // Any session naming the scope accepts it: Keymeld keeps no ledger of used deposits.
    deposit
        .verify(
            &pool
                .in_another_session()
                .manifest(Some(pool.deposit.clone())),
            "aabb",
        )
        .unwrap();
    // The slot credential still authorizes each registration.
    let forged =
        RegistrationAuthorization::sign(&[4; 32], deposit.context.clone(), "aabb").unwrap();
    assert!(forged.verify(&scoped, "aabb").is_err());
}

#[test]
fn a_deposit_envelope_binds_its_escrow_policy_to_the_same_scope() {
    let pool = pool();
    let scoped = pool.manifest(Some(pool.deposit.clone()));
    let (deposit_id, deposit_digest) = scoped.registration_scope().unwrap();
    let deposit = context(&deposit_id, deposit_digest.clone(), &pool.player, 9);
    let escrow = |policy| EscrowRegistration {
        policy,
        secrets: BTreeMap::new(),
    };
    let sealed = RegistrationEnvelope::deposit_with_escrow(
        deposit.clone(),
        &[9; 32],
        escrow(escrow_policy(&deposit_id, &deposit_digest, &pool.player, 9)),
    )
    .unwrap();
    sealed.verify().unwrap();
    sealed.verify_for(&scoped).unwrap();
    // A policy naming the session or its manifest instead does not match the deposit.
    for (session, digest) in [
        (&pool.session, scoped.digest().unwrap()),
        (&pool.session, deposit_digest.clone()),
        (&deposit_id, scoped.digest().unwrap()),
    ] {
        assert!(RegistrationEnvelope::deposit_with_escrow(
            deposit.clone(),
            &[9; 32],
            escrow(escrow_policy(session, &digest, &pool.player, 9)),
        )
        .is_err());
    }
    // A session auth key derived from the session id instead does not match either.
    let mut session_auth = deposit;
    session_auth.auth_pubkey = context(&pool.session, deposit_digest, &pool.player, 9).auth_pubkey;
    assert!(RegistrationEnvelope::deposit(session_auth, &[9; 32]).is_err());
}

#[test]
fn only_an_envelope_sealed_as_a_deposit_registers_under_a_deposit_scope() {
    let pool = pool();
    let plain = pool.manifest(None);
    let plain_context = context(&pool.session, plain.digest().unwrap(), &pool.player, 9);
    let registered = RegistrationEnvelope::new(plain_context.clone(), &[9; 32]).unwrap();
    registered.verify_for(&plain).unwrap();
    // Anyone can sign a manifest whose deposit scope names another session and its digest,
    // and its slot authorization of that session's registration verifies. The participant's
    // own proof, sealed for that one session, does not.
    let mut lifted = pool.deposit.clone();
    lifted.deposit_session_id = pool.session.clone();
    lifted.deposit_digest = plain.digest().unwrap();
    let adopting = Pool {
        session: SessionId::new_v7(),
        ..pool.clone()
    }
    .manifest(Some(lifted));
    RegistrationAuthorization::sign(&[5; 32], plain_context.clone(), "aabb")
        .unwrap()
        .verify(&adopting, "aabb")
        .unwrap();
    assert!(registered.verify_for(&adopting).is_err());

    // Nor does a deposit register in a session without a deposit scope.
    let scoped = pool.manifest(Some(pool.deposit.clone()));
    let (deposit_id, deposit_digest) = scoped.registration_scope().unwrap();
    let deposit = RegistrationEnvelope::deposit(
        context(&deposit_id, deposit_digest, &pool.player, 9),
        &[9; 32],
    )
    .unwrap();
    deposit.verify_for(&scoped).unwrap();
    assert!(deposit.verify_for(&plain).is_err());
    // A session-sealed envelope naming the deposit scope is not a deposit either.
    let unmarked = RegistrationEnvelope::new(deposit.context.clone(), &[9; 32]).unwrap();
    assert!(unmarked.verify_for(&scoped).is_err());

    // The proof commits to the marking: flipping it breaks the proof.
    let flip = |envelope: &RegistrationEnvelope| {
        let mut wire = serde_json::to_value(envelope).unwrap();
        wire["deposit"] = serde_json::json!(!envelope.deposit);
        serde_json::from_value::<RegistrationEnvelope>(wire).unwrap()
    };
    assert!(flip(&deposit).verify().is_err());
    assert!(flip(&registered).verify().is_err());
    // An envelope sealed for a session encodes as before deposits existed.
    assert!(serde_json::to_value(&registered)
        .unwrap()
        .get("deposit")
        .is_none());
}

#[test]
fn a_roster_of_deposits_still_names_its_session_and_manifest() {
    let pool = pool();
    let scoped = pool.manifest(Some(pool.deposit.clone()));
    let (deposit_id, deposit_digest) = scoped.registration_scope().unwrap();
    let registrations: BTreeMap<_, _> = [(&pool.coordinator, 4, 8), (&pool.player, 5, 9)]
        .into_iter()
        .map(|(user, slot, key)| {
            (
                user.clone(),
                RegistrationAuthorization::sign(
                    &[slot; 32],
                    context(&deposit_id, deposit_digest.clone(), user, key),
                    "aabb",
                )
                .unwrap(),
            )
        })
        .collect();
    let roster = |keygen_session_id: SessionId, manifest_hash: Vec<u8>| {
        SignedRoster::sign(
            ParticipantRoster {
                keygen_session_id,
                manifest_hash,
                participants: registrations
                    .iter()
                    .map(|(user, registration)| {
                        (user.clone(), registration.context.public_key.clone())
                    })
                    .collect(),
                registrations: registrations.clone(),
                aggregate_public_key: public(10),
                subset_aggregate_keys: BTreeMap::new(),
                subset_definitions: vec![],
                taproot_tweak: TaprootTweak::None,
            },
            &[11; 32],
        )
        .unwrap()
    };
    roster(pool.session.clone(), scoped.digest().unwrap())
        .verify_registrations(&scoped)
        .unwrap();
    for (session, digest) in [
        (deposit_id.clone(), deposit_digest.clone()),
        (pool.session.clone(), deposit_digest),
        (deposit_id, scoped.digest().unwrap()),
    ] {
        assert!(roster(session, digest)
            .verify_registrations(&scoped)
            .is_err());
    }
}

/// The manifest as it was before deposit scopes, field for field.
#[derive(Serialize)]
struct LegacyManifest<'a> {
    keygen_session_id: &'a SessionId,
    coordinator_user_id: &'a UserId,
    creator_pubkey: &'a Vec<u8>,
    signing_pubkey: &'a Vec<u8>,
    session_public_key: &'a Vec<u8>,
    participant_verifiers: &'a BTreeMap<UserId, Vec<u8>>,
    timeout_secs: u64,
    max_signing_sessions: Option<u32>,
    encrypted_taproot_tweak: &'a String,
    subset_definitions: &'a Vec<SubsetDefinition>,
}

#[derive(Serialize)]
struct LegacySignedManifest<'a> {
    manifest: LegacyManifest<'a>,
    signature: &'a Vec<u8>,
}

fn legacy(manifest: &SessionAuthorizationManifest) -> LegacyManifest<'_> {
    LegacyManifest {
        keygen_session_id: &manifest.keygen_session_id,
        coordinator_user_id: &manifest.coordinator_user_id,
        creator_pubkey: &manifest.creator_pubkey,
        signing_pubkey: &manifest.signing_pubkey,
        session_public_key: &manifest.session_public_key,
        participant_verifiers: &manifest.participant_verifiers,
        timeout_secs: manifest.timeout_secs,
        max_signing_sessions: manifest.max_signing_sessions,
        encrypted_taproot_tweak: &manifest.encrypted_taproot_tweak,
        subset_definitions: &manifest.subset_definitions,
    }
}

#[test]
fn a_manifest_without_a_deposit_scope_encodes_signs_and_digests_as_before() {
    let pool = pool();
    let signed = pool.manifest(None);
    let old = LegacySignedManifest {
        manifest: legacy(&signed.manifest),
        signature: &signed.signature,
    };
    assert_eq!(
        serde_json::to_vec(&signed.manifest).unwrap(),
        serde_json::to_vec(&old.manifest).unwrap()
    );
    assert_eq!(
        serde_json::to_vec(&signed).unwrap(),
        serde_json::to_vec(&old).unwrap()
    );
    // ECDSA signing is deterministic, so the creator's signature is the one it always made.
    assert_eq!(
        sign_authorization(&[1; 32], "session-manifest", &old.manifest).unwrap(),
        signed.signature
    );
    assert_eq!(
        signed.digest().unwrap(),
        authorization_digest("signed-session-manifest", &old)
            .unwrap()
            .to_vec()
    );
    // A manifest stored before the field existed reads back without a scope, and verifies.
    let stored: SignedSessionManifest =
        serde_json::from_slice(&serde_json::to_vec(&old).unwrap()).unwrap();
    assert!(stored.manifest.deposit_scope.is_none());
    stored.verify().unwrap();
    assert_eq!(stored.digest().unwrap(), signed.digest().unwrap());

    // A fixed vector, independent of this crate's types.
    let user = UserId::parse("01890a5d-ac96-774b-bcce-b302099a8058").unwrap();
    let fixed = SignedSessionManifest {
        manifest: SessionAuthorizationManifest {
            keygen_session_id: SessionId::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            coordinator_user_id: user.clone(),
            creator_pubkey: vec![1, 2],
            signing_pubkey: vec![3],
            session_public_key: vec![4],
            participant_verifiers: BTreeMap::from([(user.clone(), vec![5, 6])]),
            timeout_secs: 300,
            max_signing_sessions: Some(3),
            encrypted_taproot_tweak: "tweak".into(),
            subset_definitions: vec![SubsetDefinition {
                subset_id: uuid::Uuid::parse_str("01890a5d-ac96-774b-bcce-b302099a8059").unwrap(),
                participants: vec![user],
            }],
            deposit_scope: None,
        },
        signature: vec![7, 8],
    };
    let written_before = concat!(
        r#"{"manifest":{"keygen_session_id":"01890a5d-ac96-774b-bcce-b302099a8057","#,
        r#""coordinator_user_id":"01890a5d-ac96-774b-bcce-b302099a8058","#,
        r#""creator_pubkey":[1,2],"signing_pubkey":[3],"session_public_key":[4],"#,
        r#""participant_verifiers":{"01890a5d-ac96-774b-bcce-b302099a8058":[5,6]},"#,
        r#""timeout_secs":300,"max_signing_sessions":3,"encrypted_taproot_tweak":"tweak","#,
        r#""subset_definitions":[{"subset_id":"01890a5d-ac96-774b-bcce-b302099a8059","#,
        r#""participants":["01890a5d-ac96-774b-bcce-b302099a8058"]}]},"signature":[7,8]}"#,
    );
    let digest = "823c64ff9cf8bc8b6ae07b04f5e85ae4a1068dbdb7e5120aad6314c735a5233e";
    assert_eq!(serde_json::to_string(&fixed).unwrap(), written_before);
    assert_eq!(hex::encode(fixed.digest().unwrap()), digest);
    // Stored JSON from before the field existed, such as a gateway session row or an
    // application's journal, decodes to the same manifest and digest.
    let stored: SignedSessionManifest = serde_json::from_str(written_before).unwrap();
    assert!(stored.manifest.deposit_scope.is_none());
    assert_eq!(serde_json::to_string(&stored).unwrap(), written_before);
    assert_eq!(hex::encode(stored.digest().unwrap()), digest);
}

/// Binary encodings cannot omit a field, so the bincode channel between gateway and enclave,
/// which upgrade together, carries the scope after the earlier layout. Stored state is JSON.
#[test]
fn the_binary_enclave_channel_appends_the_scope_to_the_earlier_layout() {
    let manifest = pool().manifest(None).manifest;
    let earlier = bincode::serialize(&legacy(&manifest)).unwrap();
    assert_eq!(
        bincode::serialize(&manifest).unwrap(),
        [earlier.as_slice(), &[0_u8]].concat()
    );
    assert!(bincode::deserialize::<SessionAuthorizationManifest>(&earlier).is_err());
}

#[test]
fn a_deposit_scope_round_trips_through_json_and_the_binary_enclave_channel() {
    let pool = pool();
    for manifest in [
        pool.manifest(None),
        pool.manifest(Some(pool.deposit.clone())),
    ] {
        let json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(
            json["manifest"].get("deposit_scope").is_some(),
            manifest.manifest.deposit_scope.is_some()
        );
        let decoded: SignedSessionManifest = serde_json::from_value(json).unwrap();
        decoded.verify().unwrap();
        assert_eq!(
            decoded.manifest.deposit_scope,
            manifest.manifest.deposit_scope
        );
        assert_eq!(decoded.digest().unwrap(), manifest.digest().unwrap());

        // The gateway sends manifests to enclaves in bincode, which cannot skip a field.
        let command = crate::protocol::SystemCommand::ValidateRegistration(
            crate::protocol::ValidateRegistrationCommand {
                authorization_manifest: Box::new(manifest.clone()),
                participant: crate::protocol::ParticipantRegistrationData {
                    user_id: pool.player.clone(),
                    enclave_encrypted_data: "aabb".into(),
                    auth_pubkey: vec![1],
                    require_signing_approval: false,
                    registration_authorization: RegistrationAuthorization::sign(
                        &[5; 32],
                        context(
                            &manifest.registration_scope().unwrap().0,
                            manifest.registration_scope().unwrap().1,
                            &pool.player,
                            9,
                        ),
                        "aabb",
                    )
                    .unwrap(),
                },
            },
        );
        let decoded: crate::protocol::SystemCommand =
            bincode::deserialize(&bincode::serialize(&command).unwrap()).unwrap();
        let crate::protocol::SystemCommand::ValidateRegistration(decoded) = decoded else {
            panic!("wrong decoded command");
        };
        decoded.authorization_manifest.verify().unwrap();
        assert_eq!(
            decoded.authorization_manifest.manifest.deposit_scope,
            manifest.manifest.deposit_scope
        );
        decoded
            .participant
            .registration_authorization
            .verify(&decoded.authorization_manifest, "aabb")
            .unwrap();
    }
}
