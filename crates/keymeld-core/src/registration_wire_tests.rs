use super::*;
use crate::authorization::{
    RegistrationAuthorization, RegistrationContext, SessionAuthorizationManifest,
    SignedSessionManifest,
};

#[derive(Debug, Serialize, Deserialize)]
struct LegacyParticipantRegistrationData {
    user_id: UserId,
    registration_authorization: RegistrationAuthorization,
    enclave_encrypted_data: String,
    auth_pubkey: Vec<u8>,
    require_signing_approval: bool,
}

fn registration() -> ValidateRegistrationCommand {
    let session = SessionId::new_v7();
    let user = UserId::new_v7();
    ValidateRegistrationCommand {
        authorization_manifest: Box::new(SignedSessionManifest {
            manifest: SessionAuthorizationManifest {
                keygen_session_id: session.clone(),
                coordinator_user_id: user.clone(),
                creator_pubkey: vec![],
                signing_pubkey: vec![],
                session_public_key: vec![],
                participant_verifiers: Default::default(),
                timeout_secs: 60,
                subset_definitions: vec![],
                max_signing_sessions: None,
                encrypted_taproot_tweak: "opaque tweak".into(),
            },
            signature: vec![],
        }),
        participant: ParticipantRegistrationData {
            user_id: user.clone(),
            enclave_encrypted_data: "opaque ciphertext".into(),
            auth_pubkey: vec![1],
            require_signing_approval: true,
            registration_authorization: RegistrationAuthorization {
                context: RegistrationContext {
                    keygen_session_id: session,
                    manifest_hash: vec![2],
                    user_id: user,
                    enclave_id: EnclaveId::new(1),
                    enclave_key_epoch: 1,
                    public_key: vec![3],
                    auth_pubkey: vec![1],
                    require_signing_approval: true,
                },
                ciphertext_hash: vec![4],
                signature: vec![5],
            },
        },
    }
}

#[test]
fn legacy_nested_registration_layout_and_command_discriminants_are_unchanged() {
    let registration = registration();
    let bytes = bincode::serialize(&vec![
        registration.participant.clone(),
        registration.participant.clone(),
    ])
    .unwrap();
    let old: Vec<LegacyParticipantRegistrationData> = bincode::deserialize(&bytes).unwrap();
    assert_eq!(old.len(), 2);
    assert_eq!(bincode::serialize(&old).unwrap(), bytes);
    assert_eq!(
        bincode::serialize(&SystemCommand::Ping).unwrap(),
        2_u32.to_le_bytes()
    );
    let command = SystemCommand::ValidateRegistration(registration);
    let encoded = bincode::serialize(&command).unwrap();
    assert_eq!(&encoded[..4], &1_u32.to_le_bytes());
    let decoded: SystemCommand = bincode::deserialize(&encoded).unwrap();
    assert!(matches!(decoded, SystemCommand::ValidateRegistration(_)));
}
