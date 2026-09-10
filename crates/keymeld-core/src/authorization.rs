//! Authorization credentials are independent of the shared session decryption secret.
use crate::{
    crypto::SecureCrypto,
    protocol::{EnclaveBatchItem, SubsetDefinition, TaprootTweak},
    EnclaveId, KeyMeldError, SessionId, UserId,
};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zeroize::Zeroize;

pub const ROSTER_CONTEXT: &str = "authorized_participant_roster_v1";
pub const SUBSET_AGGREGATE_CONTEXT: &str = "subset_aggregate_public_key";

/// The creator attests every recipient before authorizing enclave-to-enclave fanout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnclaveRecipientAuthorization {
    pub keygen_session_id: SessionId,
    pub manifest_hash: Vec<u8>,
    pub user_enclave_assignments: BTreeMap<UserId, EnclaveId>,
    pub recipient_public_keys: BTreeMap<EnclaveId, Vec<u8>>,
    pub signature: Vec<u8>,
}

impl EnclaveRecipientAuthorization {
    fn payload(&self) -> impl Serialize + '_ {
        (
            &self.keygen_session_id,
            &self.manifest_hash,
            &self.user_enclave_assignments,
            &self.recipient_public_keys,
        )
    }

    pub fn sign(
        manifest: &SignedSessionManifest,
        user_enclave_assignments: BTreeMap<UserId, EnclaveId>,
        recipient_public_keys: BTreeMap<EnclaveId, Vec<u8>>,
        creator_secret: &[u8; 32],
    ) -> Result<Self, KeyMeldError> {
        let mut authorization = Self {
            keygen_session_id: manifest.manifest.keygen_session_id.clone(),
            manifest_hash: manifest.digest()?,
            user_enclave_assignments,
            recipient_public_keys,
            signature: Vec::new(),
        };
        let signature = sign_authorization(
            creator_secret,
            "enclave-recipients",
            &authorization.payload(),
        )?;
        authorization.signature = signature;
        authorization.verify(manifest)?;
        Ok(authorization)
    }

    pub fn verify(&self, manifest: &SignedSessionManifest) -> Result<(), KeyMeldError> {
        manifest.verify()?;
        let participants: BTreeSet<_> = manifest.manifest.participant_verifiers.keys().collect();
        let assigned: BTreeSet<_> = self.user_enclave_assignments.keys().collect();
        let enclave_ids: BTreeSet<_> = self.user_enclave_assignments.values().collect();
        let recipients: BTreeSet<_> = self.recipient_public_keys.keys().collect();
        if self.keygen_session_id != manifest.manifest.keygen_session_id
            || self.manifest_hash != manifest.digest()?
            || participants != assigned
            || recipients != enclave_ids
            || recipients.is_empty()
        {
            return Err(invalid(
                "Enclave recipients do not match the session participant assignments",
            ));
        }
        let mut public_keys = BTreeSet::new();
        for key in self.recipient_public_keys.values() {
            let public = PublicKey::from_slice(key).map_err(KeyMeldError::InvalidKey)?;
            if public.serialize().as_slice() != key || !public_keys.insert(public.serialize()) {
                return Err(invalid(
                    "Enclave recipient keys must be distinct canonical public keys",
                ));
            }
        }
        verify_authorization(
            &manifest.manifest.creator_pubkey,
            "enclave-recipients",
            &self.payload(),
            &self.signature,
        )
    }

    pub fn verify_recipient_keys(
        &self,
        manifest: &SignedSessionManifest,
        keys: &[crate::protocol::EnclavePublicKeyInfo],
    ) -> Result<(), KeyMeldError> {
        self.verify(manifest)?;
        if keys.len() != self.recipient_public_keys.len() {
            return Err(invalid("Enclave recipient roster was changed"));
        }
        let mut seen = BTreeSet::new();
        for key in keys {
            let key_bytes = hex::decode(&key.public_key).map_err(KeyMeldError::HexDecodeError)?;
            if !seen.insert(key.enclave_id)
                || self.recipient_public_keys.get(&key.enclave_id) != Some(&key_bytes)
            {
                return Err(invalid("Unapproved enclave recipient key"));
            }
        }
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> KeyMeldError {
    KeyMeldError::ValidationError(message.into())
}

/// Versioned, domain-separated encoding. Payloads use structs, tuples and ordered maps.
pub fn authorization_digest<T: Serialize + ?Sized>(
    domain: &str,
    payload: &T,
) -> Result<[u8; 32], KeyMeldError> {
    let bytes =
        serde_json::to_vec(payload).map_err(|e| KeyMeldError::SerializationError(e.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(b"keymeld-authorization-v1");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain.as_bytes());
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(digest.finalize().into())
}

pub fn sign_authorization<T: Serialize + ?Sized>(
    secret: &[u8; 32],
    domain: &str,
    payload: &T,
) -> Result<Vec<u8>, KeyMeldError> {
    let secret = SecretKey::from_byte_array(*secret).map_err(KeyMeldError::InvalidKey)?;
    let message = Message::from_digest(authorization_digest(domain, payload)?);
    Ok(Secp256k1::signing_only()
        .sign_ecdsa(message, &secret)
        .serialize_compact()
        .to_vec())
}

pub fn verify_authorization<T: Serialize + ?Sized>(
    public_key: &[u8],
    domain: &str,
    payload: &T,
    signature: &[u8],
) -> Result<(), KeyMeldError> {
    let public_key = PublicKey::from_slice(public_key).map_err(KeyMeldError::InvalidKey)?;
    let signature = Signature::from_compact(signature).map_err(KeyMeldError::InvalidKey)?;
    Secp256k1::verification_only()
        .verify_ecdsa(
            Message::from_digest(authorization_digest(domain, payload)?),
            &signature,
            &public_key,
        )
        .map_err(|_| invalid("Invalid authorization signature"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionAuthorizationManifest {
    pub keygen_session_id: SessionId,
    pub coordinator_user_id: UserId,
    pub creator_pubkey: Vec<u8>,
    pub signing_pubkey: Vec<u8>,
    pub session_public_key: Vec<u8>,
    pub participant_verifiers: BTreeMap<UserId, Vec<u8>>,
    pub timeout_secs: u64,
    pub max_signing_sessions: Option<u32>,
    pub encrypted_taproot_tweak: String,
    pub subset_definitions: Vec<SubsetDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SignedSessionManifest {
    pub manifest: SessionAuthorizationManifest,
    pub signature: Vec<u8>,
}

impl SignedSessionManifest {
    pub fn sign(
        manifest: SessionAuthorizationManifest,
        secret: &[u8; 32],
    ) -> Result<Self, KeyMeldError> {
        let signature = sign_authorization(secret, "session-manifest", &manifest)?;
        let signed = Self {
            manifest,
            signature,
        };
        signed.verify()?;
        Ok(signed)
    }

    pub fn verify(&self) -> Result<(), KeyMeldError> {
        let manifest = &self.manifest;
        if manifest.participant_verifiers.is_empty()
            || !manifest
                .participant_verifiers
                .contains_key(&manifest.coordinator_user_id)
        {
            return Err(invalid(
                "Manifest must authorize its coordinator and every participant",
            ));
        }
        for key in std::iter::once(&manifest.creator_pubkey)
            .chain(std::iter::once(&manifest.signing_pubkey))
            .chain(std::iter::once(&manifest.session_public_key))
            .chain(manifest.participant_verifiers.values())
        {
            PublicKey::from_slice(key).map_err(KeyMeldError::InvalidKey)?;
        }
        let canonical = |key: &[u8]| {
            PublicKey::from_slice(key)
                .map(|key| key.serialize())
                .map_err(KeyMeldError::InvalidKey)
        };
        let shared_key = canonical(&manifest.session_public_key)?;
        let creator_key = canonical(&manifest.creator_pubkey)?;
        let signing_key = canonical(&manifest.signing_pubkey)?;
        if creator_key == shared_key || signing_key == shared_key {
            return Err(invalid(
                "Authorization keys must be independent of the shared session key",
            ));
        }
        let mut slot_keys = BTreeSet::new();
        for key in manifest.participant_verifiers.values() {
            let key = canonical(key)?;
            if key == shared_key
                || key == creator_key
                || key == signing_key
                || !slot_keys.insert(key)
            {
                return Err(invalid("Each slot must have a distinct credential independent of creator, signing and shared session keys"));
            }
        }
        let mut subsets = BTreeSet::new();
        for subset in &manifest.subset_definitions {
            let participants: BTreeSet<_> = subset.participants.iter().collect();
            if !subsets.insert(subset.subset_id)
                || participants.is_empty()
                || participants.len() != subset.participants.len()
                || participants
                    .iter()
                    .any(|user| !manifest.participant_verifiers.contains_key(*user))
            {
                return Err(invalid("Invalid authorized subset definition"));
            }
        }
        verify_authorization(
            &manifest.creator_pubkey,
            "session-manifest",
            manifest,
            &self.signature,
        )
    }

    pub fn digest(&self) -> Result<Vec<u8>, KeyMeldError> {
        Ok(authorization_digest("signed-session-manifest", self)?.to_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegistrationContext {
    pub keygen_session_id: SessionId,
    pub manifest_hash: Vec<u8>,
    pub user_id: UserId,
    pub enclave_id: EnclaveId,
    pub enclave_key_epoch: u64,
    pub public_key: Vec<u8>,
    pub auth_pubkey: Vec<u8>,
    pub require_signing_approval: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RegistrationEnvelope {
    pub context: RegistrationContext,
    pub private_key: Vec<u8>,
    pub proof_signature: Vec<u8>,
}

impl std::fmt::Debug for RegistrationEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationEnvelope")
            .field("context", &self.context)
            .field("private_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Drop for RegistrationEnvelope {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl RegistrationEnvelope {
    pub fn new(context: RegistrationContext, private_key: &[u8; 32]) -> Result<Self, KeyMeldError> {
        let envelope = Self {
            proof_signature: sign_authorization(private_key, "registration-possession", &context)?,
            context,
            private_key: private_key.to_vec(),
        };
        envelope.verify()?;
        Ok(envelope)
    }

    pub fn verify(&self) -> Result<(), KeyMeldError> {
        let mut bytes: [u8; 32] = self
            .private_key
            .as_slice()
            .try_into()
            .map_err(|_| invalid("Registration private key must contain 32 bytes"))?;
        let result = (|| {
            let private_key =
                SecretKey::from_byte_array(bytes).map_err(KeyMeldError::InvalidKey)?;
            let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &private_key);
            let (_, auth_key) = SecureCrypto::derive_session_auth_keypair(
                &bytes,
                &self.context.keygen_session_id.to_string(),
            )?;
            if public_key.serialize().as_slice() != self.context.public_key
                || auth_key.serialize().as_slice() != self.context.auth_pubkey
            {
                return Err(invalid(
                    "Registration keys do not match the encrypted private key",
                ));
            }
            verify_authorization(
                &self.context.public_key,
                "registration-possession",
                &self.context,
                &self.proof_signature,
            )
        })();
        bytes.zeroize();
        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegistrationAuthorization {
    pub context: RegistrationContext,
    pub ciphertext_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

impl RegistrationAuthorization {
    pub fn sign(
        secret: &[u8; 32],
        context: RegistrationContext,
        ciphertext: &str,
    ) -> Result<Self, KeyMeldError> {
        let ciphertext_hash =
            Sha256::digest(hex::decode(ciphertext).map_err(KeyMeldError::HexDecodeError)?).to_vec();
        let signature = sign_authorization(
            secret,
            "participant-registration",
            &(&context, &ciphertext_hash),
        )?;
        Ok(Self {
            context,
            ciphertext_hash,
            signature,
        })
    }

    pub fn verify_commitment(&self, manifest: &SignedSessionManifest) -> Result<(), KeyMeldError> {
        manifest.verify()?;
        if self.context.keygen_session_id != manifest.manifest.keygen_session_id
            || self.context.manifest_hash != manifest.digest()?
            || self.ciphertext_hash.len() != 32
        {
            return Err(invalid(
                "Registration does not match the authorized session manifest",
            ));
        }
        PublicKey::from_slice(&self.context.public_key).map_err(KeyMeldError::InvalidKey)?;
        PublicKey::from_slice(&self.context.auth_pubkey).map_err(KeyMeldError::InvalidKey)?;
        let verifier = manifest
            .manifest
            .participant_verifiers
            .get(&self.context.user_id)
            .ok_or_else(|| invalid("Participant is not authorized in the session manifest"))?;
        verify_authorization(
            verifier,
            "participant-registration",
            &(&self.context, &self.ciphertext_hash),
            &self.signature,
        )
    }

    pub fn verify(
        &self,
        manifest: &SignedSessionManifest,
        ciphertext: &str,
    ) -> Result<(), KeyMeldError> {
        self.verify_commitment(manifest)?;
        let hash = Sha256::digest(hex::decode(ciphertext).map_err(KeyMeldError::HexDecodeError)?);
        if hash.as_slice() != self.ciphertext_hash {
            return Err(invalid("Registration encrypted payload was changed"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SigningAuthorization {
    pub timeout_secs: u64,
    pub signature: Vec<u8>,
}

impl SigningAuthorization {
    pub fn sign(
        secret: &[u8; 32],
        keygen_id: &SessionId,
        signing_id: &SessionId,
        timeout_secs: u64,
        batch: &[EnclaveBatchItem],
    ) -> Result<Self, KeyMeldError> {
        let signature = sign_authorization(
            secret,
            "signing-batch",
            &(keygen_id, signing_id, timeout_secs, batch),
        )?;
        Ok(Self {
            timeout_secs,
            signature,
        })
    }

    pub fn verify(
        &self,
        public_key: &[u8],
        keygen_id: &SessionId,
        signing_id: &SessionId,
        batch: &[EnclaveBatchItem],
    ) -> Result<(), KeyMeldError> {
        if batch.is_empty() {
            return Err(invalid("An authorized signing batch must not be empty"));
        }
        verify_authorization(
            public_key,
            "signing-batch",
            &(keygen_id, signing_id, self.timeout_secs, batch),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ParticipantRoster {
    pub keygen_session_id: SessionId,
    pub manifest_hash: Vec<u8>,
    pub participants: BTreeMap<UserId, Vec<u8>>,
    pub registrations: BTreeMap<UserId, RegistrationAuthorization>,
    pub aggregate_public_key: Vec<u8>,
    pub subset_aggregate_keys: BTreeMap<Uuid, Vec<u8>>,
    pub subset_definitions: Vec<SubsetDefinition>,
    pub taproot_tweak: TaprootTweak,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ParticipantApproval {
    pub user_id: UserId,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl ParticipantApproval {
    pub fn sign(
        secret: &[u8; 32],
        user_id: UserId,
        keygen_id: &SessionId,
        signing_id: &SessionId,
        timestamp: u64,
        batch: &[EnclaveBatchItem],
    ) -> Result<Self, KeyMeldError> {
        let signature = sign_authorization(
            secret,
            "participant-batch-approval",
            &(&user_id, keygen_id, signing_id, timestamp, batch),
        )?;
        Ok(Self {
            user_id,
            timestamp,
            signature,
        })
    }

    pub fn verify(
        &self,
        public_key: &[u8],
        keygen_id: &SessionId,
        signing_id: &SessionId,
        batch: &[EnclaveBatchItem],
        now_secs: u64,
    ) -> Result<(), KeyMeldError> {
        if self.timestamp > now_secs.saturating_add(30)
            || now_secs.saturating_sub(self.timestamp) > 300
        {
            return Err(invalid("Approval timestamp is expired or in the future"));
        }
        verify_authorization(
            public_key,
            "participant-batch-approval",
            &(&self.user_id, keygen_id, signing_id, self.timestamp, batch),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SignedRoster {
    pub roster: ParticipantRoster,
    pub signature: Vec<u8>,
    pub enclave_public_key: Vec<u8>,
}

impl SignedRoster {
    pub fn sign(roster: ParticipantRoster, secret: &[u8; 32]) -> Result<Self, KeyMeldError> {
        let secret_key = SecretKey::from_byte_array(*secret).map_err(KeyMeldError::InvalidKey)?;
        Ok(Self {
            signature: sign_authorization(secret, "participant-roster", &roster)?,
            enclave_public_key: PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
                .serialize()
                .to_vec(),
            roster,
        })
    }

    pub fn verify(&self, expected_enclave_public_key: &[u8]) -> Result<(), KeyMeldError> {
        if self.enclave_public_key != expected_enclave_public_key {
            return Err(invalid(
                "Roster signing key does not match the pinned enclave key",
            ));
        }
        verify_authorization(
            expected_enclave_public_key,
            "participant-roster",
            &self.roster,
            &self.signature,
        )
    }

    pub fn verify_registrations(
        &self,
        manifest: &SignedSessionManifest,
    ) -> Result<(), KeyMeldError> {
        manifest.verify()?;
        if self.roster.keygen_session_id != manifest.manifest.keygen_session_id
            || self.roster.manifest_hash != manifest.digest()?
            || self.roster.participants.len() != manifest.manifest.participant_verifiers.len()
            || self.roster.registrations.len() != self.roster.participants.len()
            || serde_json::to_vec(&self.roster.subset_definitions)
                .map_err(|e| invalid(e.to_string()))?
                != serde_json::to_vec(&manifest.manifest.subset_definitions)
                    .map_err(|e| invalid(e.to_string()))?
        {
            return Err(invalid(
                "Roster does not match the authorized session manifest",
            ));
        }
        for user_id in manifest.manifest.participant_verifiers.keys() {
            let registration = self
                .roster
                .registrations
                .get(user_id)
                .ok_or_else(|| invalid("Roster is missing a participant authorization"))?;
            registration.verify_commitment(manifest)?;
            if &registration.context.user_id != user_id
                || self.roster.participants.get(user_id) != Some(&registration.context.public_key)
            {
                return Err(invalid(
                    "Roster public key does not match its participant authorization",
                ));
            }
        }
        Ok(())
    }
}

impl ParticipantRoster {
    /// Recompute all funding keys from the authorized roster and its declared tweak.
    pub fn verify_aggregates(&self) -> Result<(), KeyMeldError> {
        let aggregate = aggregate_keys(self.participants.values(), &self.taproot_tweak)?;
        if aggregate != self.aggregate_public_key
            || self.subset_aggregate_keys.len() != self.subset_definitions.len()
        {
            return Err(invalid(
                "Roster aggregate keys do not match the participant keys",
            ));
        }
        for subset in &self.subset_definitions {
            let keys = subset
                .participants
                .iter()
                .map(|user| {
                    self.participants
                        .get(user)
                        .ok_or_else(|| invalid("Subset participant is missing from the roster"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if self.subset_aggregate_keys.get(&subset.subset_id)
                != Some(&aggregate_keys(keys, &self.taproot_tweak)?)
            {
                return Err(invalid(
                    "Subset aggregate does not match its authorized participant keys",
                ));
            }
        }
        Ok(())
    }
}

fn aggregate_keys<'a>(
    keys: impl IntoIterator<Item = &'a Vec<u8>>,
    tweak: &TaprootTweak,
) -> Result<Vec<u8>, KeyMeldError> {
    let mut public_keys = keys
        .into_iter()
        .map(|key| crate::PublicKey::from_slice(key).map_err(KeyMeldError::InvalidKey))
        .collect::<Result<Vec<_>, _>>()?;
    public_keys.sort_by_key(|key| key.serialize());
    let context = crate::KeyAggContext::new(public_keys).map_err(|e| invalid(e.to_string()))?;
    let context = match tweak {
        TaprootTweak::None => context,
        TaprootTweak::UnspendableTaproot => context
            .with_unspendable_taproot_tweak()
            .map_err(|e| invalid(e.to_string()))?,
        TaprootTweak::TaprootWithMerkleRoot { merkle_root } => context
            .with_taproot_tweak(merkle_root)
            .map_err(|e| invalid(e.to_string()))?,
        TaprootTweak::PlainTweak { tweak } => context
            .with_plain_tweak(
                secp256k1::Scalar::from_be_bytes(*tweak).map_err(|e| invalid(e.to_string()))?,
            )
            .map_err(|e| invalid(e.to_string()))?,
        TaprootTweak::XOnlyTweak { tweak } => context
            .with_xonly_tweak(
                secp256k1::Scalar::from_be_bytes(*tweak).map_err(|e| invalid(e.to_string()))?,
            )
            .map_err(|e| invalid(e.to_string()))?,
    };
    let public_key: crate::PublicKey = context.aggregated_pubkey();
    Ok(public_key.serialize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public(secret: &[u8; 32]) -> Vec<u8> {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array(*secret).unwrap(),
        )
        .serialize()
        .to_vec()
    }

    fn manifest() -> SignedSessionManifest {
        let user_a = UserId::new_v7();
        let user_b = UserId::new_v7();
        SignedSessionManifest::sign(
            SessionAuthorizationManifest {
                keygen_session_id: SessionId::new_v7(),
                coordinator_user_id: user_a.clone(),
                creator_pubkey: public(&[1; 32]),
                signing_pubkey: public(&[2; 32]),
                session_public_key: public(&[3; 32]),
                participant_verifiers: BTreeMap::from([
                    (user_a, public(&[4; 32])),
                    (user_b, public(&[5; 32])),
                ]),
                timeout_secs: 300,
                max_signing_sessions: Some(5),
                encrypted_taproot_tweak: "ciphertext".into(),
                subset_definitions: vec![],
            },
            &[1; 32],
        )
        .unwrap()
    }

    #[test]
    fn enclave_recipients_require_creator_exact_key_roster_and_session() {
        let manifest = manifest();
        let assignments = manifest
            .manifest
            .participant_verifiers
            .keys()
            .enumerate()
            .map(|(index, user)| (user.clone(), EnclaveId::from(index as u32 + 1)))
            .collect();
        let keys = BTreeMap::from([
            (EnclaveId::from(1), public(&[7; 32])),
            (EnclaveId::from(2), public(&[8; 32])),
        ]);
        let signed =
            EnclaveRecipientAuthorization::sign(&manifest, assignments, keys, &[1; 32]).unwrap();
        let recipients: Vec<_> = signed
            .recipient_public_keys
            .iter()
            .map(|(id, key)| crate::protocol::EnclavePublicKeyInfo {
                enclave_id: *id,
                public_key: hex::encode(key),
            })
            .collect();
        signed
            .verify_recipient_keys(&manifest, &recipients)
            .unwrap();
        let mut replaced = recipients.clone();
        replaced[1].public_key = hex::encode(public(&[9; 32]));
        assert!(signed.verify_recipient_keys(&manifest, &replaced).is_err());
        assert!(signed
            .verify_recipient_keys(&manifest, &recipients[..1])
            .is_err());
        let mut moved = signed.clone();
        moved
            .user_enclave_assignments
            .values_mut()
            .for_each(|id| *id = EnclaveId::from(1));
        assert!(moved.verify(&manifest).is_err());
        let mut rebound = signed.clone();
        rebound.keygen_session_id = SessionId::new_v7();
        assert!(rebound.verify(&manifest).is_err());
        let mut attacker_signed = signed.clone();
        attacker_signed.signature =
            sign_authorization(&[9; 32], "enclave-recipients", &signed.payload()).unwrap();
        assert!(attacker_signed.verify(&manifest).is_err());
    }

    fn registration(
        manifest: &SignedSessionManifest,
        user: UserId,
        key: &[u8; 32],
    ) -> RegistrationContext {
        RegistrationContext {
            keygen_session_id: manifest.manifest.keygen_session_id.clone(),
            manifest_hash: manifest.digest().unwrap(),
            user_id: user,
            enclave_id: EnclaveId::new(1),
            enclave_key_epoch: 7,
            public_key: public(key),
            auth_pubkey: SecureCrypto::derive_session_auth_keypair(
                key,
                &manifest.manifest.keygen_session_id.to_string(),
            )
            .unwrap()
            .1
            .serialize()
            .to_vec(),
            require_signing_approval: true,
        }
    }

    fn batch() -> Vec<EnclaveBatchItem> {
        (0..2)
            .map(|n| EnclaveBatchItem {
                batch_item_id: Uuid::now_v7(),
                encrypted_message: format!("message-{n}"),
                encrypted_adaptor_configs: Some(format!("adaptor-{n}")),
                encrypted_taproot_tweak: format!("tweak-{n}"),
                subset_id: Some(Uuid::now_v7()),
            })
            .collect()
    }

    #[test]
    fn submitted_key_possession_does_not_authorize_another_users_slot() {
        let manifest = manifest();
        let context = registration(
            &manifest,
            manifest.manifest.coordinator_user_id.clone(),
            &[9; 32],
        );
        // The attacker's self-generated key and contextual possession proof are valid.
        RegistrationEnvelope::new(context.clone(), &[9; 32])
            .unwrap()
            .verify()
            .unwrap();
        // They cannot authorize it using their own invitation, or the shared secret.
        for unauthorized in [[5; 32], [3; 32], [9; 32]] {
            let proof =
                RegistrationAuthorization::sign(&unauthorized, context.clone(), "aabb").unwrap();
            assert!(proof.verify(&manifest, "aabb").is_err());
        }
        let proof = RegistrationAuthorization::sign(&[4; 32], context, "aabb").unwrap();
        proof.verify(&manifest, "AABB").unwrap();
        assert!(proof.verify(&manifest, "aabc").is_err());
    }

    #[test]
    fn registration_binds_manifest_identity_enclave_keys_and_approval_policy() {
        let manifest = manifest();
        let context = registration(
            &manifest,
            manifest.manifest.coordinator_user_id.clone(),
            &[9; 32],
        );
        let proof = RegistrationAuthorization::sign(&[4; 32], context.clone(), "aabb").unwrap();
        let mut changed = proof.clone();
        changed.context.require_signing_approval = false;
        assert!(changed.verify_commitment(&manifest).is_err());
        let mut changed = proof.clone();
        changed.context.enclave_id = EnclaveId::new(2);
        assert!(changed.verify_commitment(&manifest).is_err());
        let mut changed = proof.clone();
        changed.context.enclave_key_epoch += 1;
        assert!(changed.verify_commitment(&manifest).is_err());
        let mut changed = proof.clone();
        changed.context.auth_pubkey = public(&[8; 32]);
        assert!(changed.verify_commitment(&manifest).is_err());
        let mut replaced = manifest.manifest.clone();
        replaced.creator_pubkey = public(&[8; 32]);
        replaced.signing_pubkey = public(&[8; 32]);
        let replaced = SignedSessionManifest::sign(replaced, &[8; 32]).unwrap();
        assert!(proof.verify_commitment(&replaced).is_err());
        let mut envelope = RegistrationEnvelope::new(context, &[9; 32]).unwrap();
        envelope.context.require_signing_approval = false;
        assert!(envelope.verify().is_err());
        envelope.private_key = vec![8; 32];
        assert!(envelope.verify().is_err());
    }

    #[test]
    fn authorization_roles_reject_reused_keys_and_noncanonical_encodings() {
        let original = manifest();
        for reused in [[1; 32], [2; 32], [3; 32], [5; 32]] {
            let mut replaced = original.manifest.clone();
            let alias = PublicKey::from_slice(&public(&reused))
                .unwrap()
                .serialize_uncompressed()
                .to_vec();
            replaced
                .participant_verifiers
                .insert(replaced.coordinator_user_id.clone(), alias);
            assert!(SignedSessionManifest::sign(replaced, &[1; 32]).is_err());
        }
        let mut replaced = original.manifest.clone();
        replaced.signing_pubkey = PublicKey::from_slice(&public(&[3; 32]))
            .unwrap()
            .serialize_uncompressed()
            .to_vec();
        assert!(SignedSessionManifest::sign(replaced, &[1; 32]).is_err());
        let mut replaced = original.manifest;
        replaced.creator_pubkey = public(&[3; 32]);
        assert!(SignedSessionManifest::sign(replaced, &[3; 32]).is_err());
    }

    #[test]
    fn signing_authority_covers_every_item_and_parameter() {
        let manifest = manifest();
        let keygen = manifest.manifest.keygen_session_id;
        let signing = SessionId::new_v7();
        let batch = batch();
        let authorized =
            SigningAuthorization::sign(&[2; 32], &keygen, &signing, 300, &batch).unwrap();
        authorized
            .verify(&public(&[2; 32]), &keygen, &signing, &batch)
            .unwrap();
        for key in [[3; 32], [4; 32], [5; 32]] {
            let unauthorized =
                SigningAuthorization::sign(&key, &keygen, &signing, 300, &batch).unwrap();
            assert!(unauthorized
                .verify(&public(&[2; 32]), &keygen, &signing, &batch)
                .is_err());
        }
        let mut changes = Vec::new();
        let mut changed = batch.clone();
        changed[1].encrypted_message.push('x');
        changes.push(changed);
        let mut changed = batch.clone();
        changed[1].encrypted_adaptor_configs = None;
        changes.push(changed);
        let mut changed = batch.clone();
        changed[1].encrypted_taproot_tweak.push('x');
        changes.push(changed);
        let mut changed = batch.clone();
        changed[1].subset_id = None;
        changes.push(changed);
        let mut changed = batch.clone();
        changed.reverse();
        changes.push(changed);
        let mut changed = batch.clone();
        changed.pop();
        changes.push(changed);
        for changed in changes {
            assert!(authorized
                .verify(&public(&[2; 32]), &keygen, &signing, &changed)
                .is_err());
        }
        assert!(authorized
            .verify(&public(&[2; 32]), &keygen, &SessionId::new_v7(), &batch)
            .is_err());
    }

    #[test]
    fn participant_approval_binds_all_items_identity_and_timestamp() {
        let keygen = SessionId::new_v7();
        let signing = SessionId::new_v7();
        let user = UserId::new_v7();
        let batch = batch();
        let proof =
            ParticipantApproval::sign(&[6; 32], user.clone(), &keygen, &signing, 1_000, &batch)
                .unwrap();
        proof
            .verify(&public(&[6; 32]), &keygen, &signing, &batch, 1_000)
            .unwrap();
        assert!(proof
            .verify(&public(&[6; 32]), &keygen, &signing, &batch, 1_301)
            .is_err());
        assert!(proof
            .verify(&public(&[6; 32]), &keygen, &signing, &batch, 969)
            .is_err());
        let mut changed = proof.clone();
        changed.user_id = UserId::new_v7();
        assert!(changed
            .verify(&public(&[6; 32]), &keygen, &signing, &batch, 1_000)
            .is_err());
        let mut changed = batch;
        changed[1].encrypted_message.push('x');
        assert!(proof
            .verify(&public(&[6; 32]), &keygen, &signing, &changed, 1_000)
            .is_err());
    }

    #[test]
    fn roster_cannot_make_an_empty_invalid_manifest_appear_authorized() {
        let mut manifest = manifest();
        manifest.manifest.participant_verifiers.clear();
        let roster = SignedRoster::sign(
            ParticipantRoster {
                keygen_session_id: manifest.manifest.keygen_session_id.clone(),
                manifest_hash: manifest.digest().unwrap(),
                participants: BTreeMap::new(),
                registrations: BTreeMap::new(),
                aggregate_public_key: public(&[9; 32]),
                subset_aggregate_keys: BTreeMap::new(),
                subset_definitions: vec![],
                taproot_tweak: TaprootTweak::None,
            },
            &[10; 32],
        )
        .unwrap();
        roster.verify(&public(&[10; 32])).unwrap();
        assert!(roster.verify_registrations(&manifest).is_err());
    }

    #[test]
    fn roster_requires_every_authorized_receipt_and_correct_funding_aggregates() {
        let mut manifest = manifest();
        let users: Vec<_> = manifest
            .manifest
            .participant_verifiers
            .keys()
            .cloned()
            .collect();
        manifest.manifest.subset_definitions.push(SubsetDefinition {
            subset_id: Uuid::now_v7(),
            participants: users.clone(),
        });
        manifest = SignedSessionManifest::sign(manifest.manifest, &[1; 32]).unwrap();
        let mut registrations = BTreeMap::new();
        for user in &users {
            let slot_secret = if user == &manifest.manifest.coordinator_user_id {
                [4; 32]
            } else {
                [5; 32]
            };
            let signing_secret = if user == &manifest.manifest.coordinator_user_id {
                [8; 32]
            } else {
                [9; 32]
            };
            registrations.insert(
                user.clone(),
                RegistrationAuthorization::sign(
                    &slot_secret,
                    registration(&manifest, user.clone(), &signing_secret),
                    "aabb",
                )
                .unwrap(),
            );
        }
        let participants: BTreeMap<_, _> = registrations
            .iter()
            .map(|(user, registration)| (user.clone(), registration.context.public_key.clone()))
            .collect();
        let aggregate = aggregate_keys(participants.values(), &TaprootTweak::None).unwrap();
        let roster = ParticipantRoster {
            keygen_session_id: manifest.manifest.keygen_session_id.clone(),
            manifest_hash: manifest.digest().unwrap(),
            participants,
            registrations,
            aggregate_public_key: aggregate.clone(),
            subset_aggregate_keys: BTreeMap::from([(
                manifest.manifest.subset_definitions[0].subset_id,
                aggregate,
            )]),
            subset_definitions: manifest.manifest.subset_definitions.clone(),
            taproot_tweak: TaprootTweak::None,
        };
        let signed = SignedRoster::sign(roster, &[10; 32]).unwrap();
        signed.verify(&public(&[10; 32])).unwrap();
        signed.verify_registrations(&manifest).unwrap();
        signed.roster.verify_aggregates().unwrap();
        let mut changed = signed.clone();
        changed
            .roster
            .participants
            .insert(users[0].clone(), public(&[11; 32]));
        assert!(changed.verify_registrations(&manifest).is_err());
        assert!(changed.roster.verify_aggregates().is_err());
        let mut changed = signed.clone();
        changed.roster.aggregate_public_key = public(&[11; 32]);
        assert!(changed.roster.verify_aggregates().is_err());
        let mut changed = signed;
        *changed
            .roster
            .subset_aggregate_keys
            .values_mut()
            .next()
            .unwrap() = public(&[11; 32]);
        assert!(changed.roster.verify_aggregates().is_err());
    }
}
