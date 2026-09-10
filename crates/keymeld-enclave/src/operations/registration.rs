use super::EnclaveSharedContext;
use keymeld_core::{
    authorization::{RegistrationEnvelope, SignedSessionManifest},
    protocol::{EnclaveError, ParticipantRegistrationData, ValidationError},
};

/// Shared by stateless admission and stateful key import, including restoration.
pub fn validate_registration(
    manifest: &SignedSessionManifest,
    participant: &ParticipantRegistrationData,
    enclave: &EnclaveSharedContext,
    current_epoch: Option<u64>,
) -> Result<RegistrationEnvelope, EnclaveError> {
    let invalid = |message: String| EnclaveError::Validation(ValidationError::Other(message));
    manifest.verify().map_err(|e| invalid(e.to_string()))?;
    let authorization = &participant.registration_authorization;
    authorization
        .verify(manifest, &participant.enclave_encrypted_data)
        .map_err(|e| invalid(e.to_string()))?;
    let context = &authorization.context;
    if context.keygen_session_id != manifest.manifest.keygen_session_id
        || context.user_id != participant.user_id
        || context.enclave_id != enclave.enclave_id
        || current_epoch.is_some_and(|epoch| context.enclave_key_epoch != epoch)
        || context.auth_pubkey != participant.auth_pubkey
        || context.require_signing_approval != participant.require_signing_approval
    {
        return Err(invalid(
            "Registration context does not match participant or enclave".into(),
        ));
    }
    let decrypted = zeroize::Zeroizing::new(enclave.decrypt_with_ecies(
        &participant.enclave_encrypted_data,
        "participant registration",
    )?);
    let envelope: RegistrationEnvelope =
        serde_json::from_slice(&decrypted).map_err(|e| invalid(e.to_string()))?;
    envelope.verify().map_err(|e| invalid(e.to_string()))?;
    if serde_json::to_vec(&envelope.context).map_err(|e| invalid(e.to_string()))?
        != serde_json::to_vec(context).map_err(|e| invalid(e.to_string()))?
    {
        return Err(invalid(
            "Encrypted registration differs from authorized context".into(),
        ));
    }
    Ok(envelope)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use keymeld_core::{
        authorization::{
            RegistrationAuthorization, RegistrationContext, SessionAuthorizationManifest,
        },
        crypto::SecureCrypto,
        protocol::TaprootTweak,
        EnclaveId, SessionId, SessionSecret, UserId,
    };
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::collections::BTreeMap;

    pub(crate) fn public_key(secret: &[u8; 32]) -> Vec<u8> {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array(*secret).unwrap(),
        )
        .serialize()
        .to_vec()
    }

    pub(crate) struct Fixture {
        pub manifest: SignedSessionManifest,
        pub participant: ParticipantRegistrationData,
        pub enclave: EnclaveSharedContext,
        pub session_secret: SessionSecret,
    }

    pub(crate) fn fixture() -> Fixture {
        let creator = [11; 32];
        let signer = [12; 32];
        let invite = [13; 32];
        let key = [14; 32];
        let enclave_key = [15; 32];
        let session_secret = SessionSecret::from_bytes([16; 32]);
        let session_id = SessionId::new_v7();
        let user_id = UserId::new_v7();
        let manifest = SignedSessionManifest::sign(
            SessionAuthorizationManifest {
                keygen_session_id: session_id.clone(),
                coordinator_user_id: user_id.clone(),
                creator_pubkey: public_key(&creator),
                signing_pubkey: public_key(&signer),
                session_public_key: SecureCrypto::derive_public_key_from_seed(
                    session_secret.as_bytes(),
                )
                .unwrap()
                .serialize()
                .to_vec(),
                participant_verifiers: BTreeMap::from([(user_id.clone(), public_key(&invite))]),
                timeout_secs: 300,
                max_signing_sessions: Some(5),
                encrypted_taproot_tweak: session_secret
                    .encrypt(
                        &serde_json::to_vec(&TaprootTweak::None).unwrap(),
                        "taproot_tweak",
                    )
                    .unwrap()
                    .to_hex()
                    .unwrap(),
                subset_definitions: Vec::new(),
            },
            &creator,
        )
        .unwrap();
        let (_, auth) =
            SecureCrypto::derive_session_auth_keypair(&key, &session_id.to_string()).unwrap();
        let context = RegistrationContext {
            keygen_session_id: session_id,
            manifest_hash: manifest.digest().unwrap(),
            user_id: user_id.clone(),
            enclave_id: EnclaveId::new(1),
            enclave_key_epoch: 1,
            public_key: public_key(&key),
            auth_pubkey: auth.serialize().to_vec(),
            require_signing_approval: true,
        };
        let envelope = RegistrationEnvelope::new(context.clone(), &key).unwrap();
        let ciphertext = hex::encode(
            SecureCrypto::ecies_encrypt(
                &PublicKey::from_slice(&public_key(&enclave_key)).unwrap(),
                &serde_json::to_vec(&envelope).unwrap(),
            )
            .unwrap(),
        );
        let registration_authorization =
            RegistrationAuthorization::sign(&invite, context, &ciphertext).unwrap();
        Fixture {
            manifest,
            participant: ParticipantRegistrationData {
                user_id,
                auth_pubkey: auth.serialize().to_vec(),
                enclave_encrypted_data: ciphertext,
                require_signing_approval: true,
                registration_authorization,
            },
            enclave: EnclaveSharedContext::new(
                EnclaveId::new(1),
                public_key(&enclave_key),
                enclave_key.to_vec(),
                None,
                Default::default(),
            ),
            session_secret,
        }
    }

    #[test]
    fn authorized_registration_checks_epoch_at_admission_and_restores_original_proof() {
        let f = fixture();
        assert!(validate_registration(&f.manifest, &f.participant, &f.enclave, Some(1)).is_ok());
        assert!(validate_registration(&f.manifest, &f.participant, &f.enclave, Some(2)).is_err());
        assert!(validate_registration(&f.manifest, &f.participant, &f.enclave, None).is_ok());
    }

    #[test]
    fn enclave_rejects_outer_identity_auth_and_policy_substitution() {
        let f = fixture();
        let mut participant = f.participant.clone();
        participant.user_id = UserId::new_v7();
        assert!(validate_registration(&f.manifest, &participant, &f.enclave, Some(1)).is_err());
        participant = f.participant.clone();
        participant.auth_pubkey = public_key(&[21; 32]);
        assert!(validate_registration(&f.manifest, &participant, &f.enclave, Some(1)).is_err());
        participant = f.participant.clone();
        participant.require_signing_approval = false;
        assert!(validate_registration(&f.manifest, &participant, &f.enclave, Some(1)).is_err());
    }

    #[test]
    fn invitation_holder_cannot_import_a_key_without_matching_possession_proof() {
        let f = fixture();
        let mut participant = f.participant.clone();
        let envelope = RegistrationEnvelope {
            context: participant.registration_authorization.context.clone(),
            private_key: [22; 32].to_vec(),
            proof_signature: vec![0; 64],
        };
        participant.enclave_encrypted_data = hex::encode(
            SecureCrypto::ecies_encrypt(
                &PublicKey::from_slice(&f.enclave.public_key).unwrap(),
                &serde_json::to_vec(&envelope).unwrap(),
            )
            .unwrap(),
        );
        participant.registration_authorization = RegistrationAuthorization::sign(
            &[13; 32],
            envelope.context.clone(),
            &participant.enclave_encrypted_data,
        )
        .unwrap();
        assert!(validate_registration(&f.manifest, &participant, &f.enclave, Some(1)).is_err());
    }

    #[test]
    fn shared_secret_holder_cannot_authorize_their_own_key_or_swap_manifest() {
        let f = fixture();
        let mut participant = f.participant.clone();
        participant.registration_authorization = RegistrationAuthorization::sign(
            f.session_secret.as_bytes(),
            participant.registration_authorization.context.clone(),
            &participant.enclave_encrypted_data,
        )
        .unwrap();
        assert!(validate_registration(&f.manifest, &participant, &f.enclave, Some(1)).is_err());
        let mut swapped = f.manifest.manifest.clone();
        swapped.signing_pubkey = public_key(&[25; 32]);
        let swapped = SignedSessionManifest::sign(swapped, &[11; 32]).unwrap();
        assert!(validate_registration(&swapped, &f.participant, &f.enclave, Some(1)).is_err());
    }
}
