//! Application-independent, participant-authorized escrow primitives.
//!
//! This module verifies exact signing scopes and SHA256 hashlocks. It does not
//! infer payment, ownership, or contract completion from a caller's assertion.
//! Application adapters must verify those semantics inside the enclave before
//! using an action grant. Exporting a signing key is a separate permission.

use crate::authorization::{authorization_digest, sign_authorization, verify_authorization};
use crate::{KeyMeldError, SessionId, UserId};
use secp256k1::{PublicKey, Scalar};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[path = "escrow_protocol.rs"]
pub mod protocol;

pub const SCHEMA_VERSION: u16 = 2;
pub const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_POLICY_BYTES: usize = 256 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SECRET_BYTES: usize = 4096;
pub const MAX_SECRETS: usize = 16;
pub const MAX_ACTIONS: usize = 32;
/// Shared full-response budget for Bind/Prepare. Execution recovery is independent.
pub const MAX_PREPARATION_CACHE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PREPARATION_REQUESTS_PER_PARTICIPANT: usize = MAX_ACTIONS * 4;
/// Worst-case response reservation while asynchronous preparation runs.
pub const PREPARATION_RESPONSE_RESERVATION_BYTES: usize = MAX_PAYLOAD_BYTES * 2 + 8192;
/// Maximum authenticated renewal candidates per release permission and receipt chain.
pub const MAX_PREPARATIONS_PER_ACTION: u16 = 16;
pub const MAX_BATCH_ITEMS: usize = 256;
pub const MAX_SIGNERS: usize = 256;

fn invalid(message: &str) -> KeyMeldError {
    KeyMeldError::ValidationError(message.into())
}
fn version(value: u16) -> Result<(), KeyMeldError> {
    if value != SCHEMA_VERSION {
        return Err(invalid("Unsupported escrow schema version"));
    }
    Ok(())
}
fn name(value: &str) -> Result<(), KeyMeldError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid(
            "Escrow identifiers require 1..64 ASCII name characters",
        ));
    }
    Ok(())
}
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Bound the encrypted-envelope plaintext before deserializing any nested data.
/// The caller must additionally invoke the decoded type's validation method.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, KeyMeldError> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(invalid("Escrow message exceeds size limit"));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| KeyMeldError::SerializationError(error.to_string()))
}

/// Canonical compressed secp256k1 point; constructors and deserialization reject
/// alternate encodings, invalid points and unbounded key strings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct PublicKeyBytes(Vec<u8>);
impl PublicKeyBytes {
    pub fn new(bytes: &[u8]) -> Result<Self, KeyMeldError> {
        Self::try_from(bytes.to_vec())
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl TryFrom<Vec<u8>> for PublicKeyBytes {
    type Error = KeyMeldError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() != 33 {
            return Err(invalid("Escrow public key must be compressed"));
        }
        let key = PublicKey::from_slice(&bytes).map_err(KeyMeldError::InvalidKey)?;
        if key.serialize().as_slice() != bytes {
            return Err(invalid("Noncanonical escrow public key"));
        }
        Ok(Self(bytes))
    }
}
impl From<PublicKeyBytes> for Vec<u8> {
    fn from(key: PublicKeyBytes) -> Self {
        key.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicationContext {
    pub namespace: String,
    pub version: u16,
    pub commitment: [u8; 32],
}
impl ApplicationContext {
    pub fn commit(namespace: String, version: u16, bytes: &[u8]) -> Result<Self, KeyMeldError> {
        let context = Self {
            namespace,
            version,
            commitment: sha256(bytes),
        };
        context.validate()?;
        Ok(context)
    }
    pub fn validate(&self) -> Result<(), KeyMeldError> {
        name(&self.namespace)?;
        if self.version == 0 {
            return Err(invalid("Application context version must be explicit"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowContext {
    pub keygen_session_id: SessionId,
    pub user_id: UserId,
    pub escrow_id: Uuid,
    pub manifest_digest: [u8; 32],
    pub application: ApplicationContext,
}
impl EscrowContext {
    pub fn validate(&self) -> Result<(), KeyMeldError> {
        if self.escrow_id.is_nil()
            || self.keygen_session_id.uuid().is_nil()
            || self.user_id.uuid().is_nil()
        {
            return Err(invalid("Escrow identity must not be nil"));
        }
        self.application.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretCommitment {
    pub sha256: [u8; 32],
    pub length: u32,
}
impl SecretCommitment {
    pub fn from_secret(bytes: &[u8]) -> Result<Self, KeyMeldError> {
        check_secret_length(bytes.len())?;
        Ok(Self {
            sha256: sha256(bytes),
            length: bytes.len() as u32,
        })
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<(), KeyMeldError> {
        check_secret_length(bytes.len())?;
        if bytes.len() != self.length as usize || sha256(bytes) != self.sha256 {
            return Err(invalid("Escrow secret differs from its signed commitment"));
        }
        Ok(())
    }
}
fn check_secret_length(length: usize) -> Result<(), KeyMeldError> {
    if !(1..=MAX_SECRET_BYTES).contains(&length) {
        return Err(invalid("Invalid escrow secret length"));
    }
    Ok(())
}

/// A deposited secret is only serialized inside the encrypted registration.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretDeposit {
    pub name: String,
    pub bytes: Vec<u8>,
}
impl Drop for SecretDeposit {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl std::fmt::Debug for SecretDeposit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretDeposit")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Condition {
    /// Explicitly authorized by the participant, never an omitted default.
    Unconditional,
    HashlockSha256 {
        commitment: [u8; 32],
    },
    /// A rule supplied only by statically registered, measured enclave code.
    VerifierRule {
        rule: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConditionProof {
    None,
    HashlockPreimage { preimage: Vec<u8> },
    VerifierEvidence { evidence: protocol::Payload },
}
impl Drop for ConditionProof {
    fn drop(&mut self) {
        if let Self::HashlockPreimage { preimage } = self {
            preimage.zeroize();
        }
    }
}
impl std::fmt::Debug for ConditionProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConditionProof([REDACTED])")
    }
}
impl Condition {
    fn verify(&self, proof: &ConditionProof) -> Result<(), KeyMeldError> {
        match (self, proof) {
            (Self::Unconditional, ConditionProof::None) => Ok(()),
            (
                Self::HashlockSha256 { commitment },
                ConditionProof::HashlockPreimage { preimage },
            ) => {
                check_secret_length(preimage.len())?;
                if &sha256(preimage) == commitment {
                    Ok(())
                } else {
                    Err(invalid("Escrow condition not satisfied"))
                }
            }
            _ => Err(invalid("Escrow condition proof type differs")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyTweak {
    None,
    TaprootKeyPath,
    TaprootMerkleRoot { merkle_root: [u8; 32] },
    PlainScalar { scalar: [u8; 32] },
    XOnlyScalar { scalar: [u8; 32] },
}
impl KeyTweak {
    fn validate(&self) -> Result<(), KeyMeldError> {
        if let Self::PlainScalar { scalar } | Self::XOnlyScalar { scalar } = self {
            Scalar::from_be_bytes(*scalar).map_err(|_| invalid("Invalid escrow scalar tweak"))?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdaptorContext {
    None,
    /// v1 deliberately has no unsupported AND/OR modes or unauthenticated hints.
    Single {
        adaptor_id: Uuid,
        point: PublicKeyBytes,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSigner {
    pub user_id: UserId,
    pub public_key: PublicKeyBytes,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningItem {
    pub item_id: Uuid,
    /// SHA256 commitment to the exact bytes supplied to MuSig2. If the signed
    /// message is itself a 32-byte digest, commit to those 32 bytes here.
    pub message_digest: [u8; 32],
    pub subset_id: Option<Uuid>,
    /// Canonical ascending compressed-key order, matching Keymeld MuSig aggregation.
    pub signers: Vec<ScopeSigner>,
    /// Full-group items override the keygen tweak. Subset items must equal
    /// `SigningScope::session_tweak`, which is baked into their aggregate key.
    pub tweak: KeyTweak,
    pub adaptor: AdaptorContext,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningScope {
    /// The keygen context tweak. Per-item tweaks are not cumulative with this.
    /// This schema is MuSig2 over secp256k1; new algorithms require a new schema.
    pub session_tweak: KeyTweak,
    pub batch: Vec<SigningItem>,
}
impl SigningScope {
    pub fn validate(
        &self,
        context: &EscrowContext,
        participant_key: &PublicKeyBytes,
    ) -> Result<(), KeyMeldError> {
        if self.batch.is_empty() || self.batch.len() > MAX_BATCH_ITEMS {
            return Err(invalid("Invalid escrow signing batch size"));
        }
        self.session_tweak.validate()?;
        let mut ids = BTreeSet::new();
        for item in &self.batch {
            if item.item_id.is_nil()
                || !ids.insert(item.item_id)
                || item.subset_id.is_some_and(|id| id.is_nil())
                || item.signers.is_empty()
                || item.signers.len() > MAX_SIGNERS
                || item
                    .signers
                    .windows(2)
                    .any(|pair| pair[0].public_key >= pair[1].public_key)
            {
                return Err(invalid("Invalid escrow signing item or subset"));
            }
            item.tweak.validate()?;
            if item.subset_id.is_some() && item.tweak != self.session_tweak {
                return Err(invalid(
                    "Escrow subset tweak differs from the keygen context",
                ));
            }
            if matches!(item.adaptor, AdaptorContext::Single { adaptor_id, .. } if adaptor_id.is_nil())
            {
                return Err(invalid("Invalid escrow adaptor identity"));
            }
            let mut users = BTreeSet::new();
            let mut keys = BTreeSet::new();
            let mut participant = false;
            for signer in &item.signers {
                if signer.user_id.uuid().is_nil()
                    || !users.insert(&signer.user_id)
                    || !keys.insert(&signer.public_key)
                {
                    return Err(invalid("Duplicate or invalid escrow scope signer"));
                }
                if signer.user_id == context.user_id {
                    if &signer.public_key != participant_key {
                        return Err(invalid("Escrow scope substitutes the participant key"));
                    }
                    participant = true;
                }
            }
            if !participant {
                return Err(invalid("Escrow signing scope omits its participant"));
            }
        }
        Ok(())
    }
}

/// One BIP340 signature by the participant's own key over a 32-byte digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip340Item {
    pub item_id: Uuid,
    pub digest: [u8; 32],
}
/// Plain BIP340 signatures by the participant's untweaked key, outside any MuSig2 session.
///
/// For a taproot script-path spend, each digest is that input's BIP341 sighash.
/// A late-bound permission lets the verifier compute every digest from the transaction it authorizes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip340Scope {
    /// The signing key, which must be the participant's own.
    pub public_key: PublicKeyBytes,
    pub items: Vec<Bip340Item>,
}
impl Bip340Scope {
    pub fn validate(&self, participant_key: &PublicKeyBytes) -> Result<(), KeyMeldError> {
        if &self.public_key != participant_key {
            return Err(invalid("BIP340 scope names another participant's key"));
        }
        if self.items.is_empty() || self.items.len() > MAX_BATCH_ITEMS {
            return Err(invalid("Invalid BIP340 signing batch size"));
        }
        let mut ids = BTreeSet::new();
        if self
            .items
            .iter()
            .any(|item| item.item_id.is_nil() || !ids.insert(item.item_id))
        {
            return Err(invalid("Invalid or duplicate BIP340 item identity"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub encryption_public_key: PublicKeyBytes,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Sign {
        scope: SigningScope,
    },
    SignBip340 {
        scope: Bip340Scope,
    },
    ReleaseSecret {
        name: String,
        recipient: Recipient,
    },
    ReleaseSigningKey {
        public_key: PublicKeyBytes,
        recipient: Recipient,
    },
}
/// A participant permission, distinct from the exact action resolved later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Permission {
    Exact {
        action: Action,
    },
    Sign,
    /// BIP340 signatures by the participant's key over digests the verifier resolves.
    SignBip340,
    ReleaseSecret {
        name: String,
        recipient: Recipient,
    },
    ReleaseSigningKey {
        public_key: PublicKeyBytes,
        recipient: Recipient,
    },
}
impl Permission {
    pub fn exact(&self) -> Option<&Action> {
        match self {
            Self::Exact { action } => Some(action),
            _ => None,
        }
    }
    pub fn exact_mut(&mut self) -> Option<&mut Action> {
        match self {
            Self::Exact { action } => Some(action),
            _ => None,
        }
    }
    /// This check is independent of application verifier approval.
    pub fn validate_action(
        &self,
        action: &Action,
        policy: &EscrowPolicy,
    ) -> Result<(), KeyMeldError> {
        policy.validate_action(action)?;
        let allowed = match (self, action) {
            (Self::Exact { action: expected }, actual) => expected == actual,
            (Self::Sign, Action::Sign { .. }) => true,
            (Self::SignBip340, Action::SignBip340 { .. }) => true,
            (
                Self::ReleaseSecret { name, recipient },
                Action::ReleaseSecret {
                    name: actual,
                    recipient: target,
                },
            ) => name == actual && recipient == target,
            (
                Self::ReleaseSigningKey {
                    public_key,
                    recipient,
                },
                Action::ReleaseSigningKey {
                    public_key: actual,
                    recipient: target,
                },
            ) => public_key == actual && recipient == target,
            _ => false,
        };
        if !allowed {
            return Err(invalid("Resolved action exceeds participant permission"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierPolicy {
    pub id: String,
    pub version: u16,
    pub policy_data: protocol::Payload,
}
/// Repetition is participant consent, never a host claim that signing failed.
/// A repeated scope can produce another signature of exactly the same messages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Repetition {
    #[default]
    Once,
    RepeatIdenticalSigningScope,
    /// Each fresh attempt may prepare and execute once, with its own messages.
    /// Only for a verifier-authorized signing permission, BIP340 or MuSig2: the verifier checks
    /// every attempt's messages, and a MuSig2 attempt still needs its own signing session.
    VerifierAuthorizedAttempts,
}
/// Preparation renewal does not authorize a second execution. It permits
/// independently verifiable candidates for the same fixed-recipient release.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationPolicy {
    #[default]
    Single,
    RenewableIdenticalAction,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionGrant {
    #[serde(default)]
    pub preparation: PreparationPolicy,
    #[serde(default)]
    pub repetition: Repetition,
    pub condition: Condition,
    pub operation: Permission,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowPolicy {
    pub schema_version: u16,
    pub context: EscrowContext,
    pub participant_public_key: PublicKeyBytes,
    pub verifier: Option<VerifierPolicy>,
    pub secrets: BTreeMap<String, SecretCommitment>,
    /// Release grants permit one successful action; signing repetition requires explicit consent.
    pub grants: BTreeMap<String, ActionGrant>,
}
impl EscrowPolicy {
    pub fn validate(&self) -> Result<(), KeyMeldError> {
        version(self.schema_version)?;
        self.context.validate()?;
        if self.secrets.len() > MAX_SECRETS
            || self.grants.is_empty()
            || self.grants.len() > MAX_ACTIONS
        {
            return Err(invalid("Invalid escrow secret or action count"));
        }
        for (id, secret) in &self.secrets {
            name(id)?;
            check_secret_length(secret.length as usize)?;
        }
        if let Some(verifier) = &self.verifier {
            name(&verifier.id)?;
            if verifier.version == 0 {
                return Err(invalid("Verifier version must be explicit"));
            }
        }
        for (id, grant) in &self.grants {
            name(id)?;
            if grant.preparation == PreparationPolicy::RenewableIdenticalAction
                && !matches!(
                    grant.operation,
                    Permission::ReleaseSecret { .. }
                        | Permission::ReleaseSigningKey { .. }
                        | Permission::Exact {
                            action: Action::ReleaseSecret { .. } | Action::ReleaseSigningKey { .. }
                        }
                )
            {
                return Err(invalid(
                    "Renewable preparation requires a fixed-recipient release permission",
                ));
            }
            if grant.repetition == Repetition::RepeatIdenticalSigningScope
                && !matches!(grant.operation, Permission::Sign)
            {
                return Err(invalid(
                    "Only an explicit signing permission can authorize identical-scope repetition",
                ));
            }
            if grant.repetition == Repetition::VerifierAuthorizedAttempts
                && !(matches!(grant.operation, Permission::SignBip340 | Permission::Sign)
                    && matches!(grant.condition, Condition::VerifierRule { .. }))
            {
                return Err(invalid(
                    "Per-attempt repetition requires a verifier-authorized signing permission",
                ));
            }
            if let Condition::VerifierRule { rule } = &grant.condition {
                name(rule)?;
                if self.verifier.is_none() {
                    return Err(invalid(
                        "Verifier rule requires a registered verifier selection",
                    ));
                }
            } else if !matches!(grant.operation, Permission::Exact { .. }) {
                return Err(invalid(
                    "A late-bound permission requires a verifier condition",
                ));
            }
            match &grant.operation {
                Permission::Exact { action } => self.validate_action(action)?,
                Permission::Sign | Permission::SignBip340 => {}
                Permission::ReleaseSecret { name, recipient } => {
                    self.validate_action(&Action::ReleaseSecret {
                        name: name.clone(),
                        recipient: recipient.clone(),
                    })?
                }
                Permission::ReleaseSigningKey {
                    public_key,
                    recipient,
                } => self.validate_action(&Action::ReleaseSigningKey {
                    public_key: public_key.clone(),
                    recipient: recipient.clone(),
                })?,
            }
        }
        let encoded = Zeroizing::new(
            serde_json::to_vec(self)
                .map_err(|e| KeyMeldError::SerializationError(e.to_string()))?,
        );
        if encoded.len() > MAX_POLICY_BYTES {
            return Err(invalid("Escrow policy exceeds size limit"));
        }
        Ok(())
    }
    pub fn validate_action(&self, action: &Action) -> Result<(), KeyMeldError> {
        match action {
            Action::Sign { scope } => scope.validate(&self.context, &self.participant_public_key),
            Action::SignBip340 { scope } => scope.validate(&self.participant_public_key),
            Action::ReleaseSecret { name: secret, .. } => {
                name(secret)?;
                if !self.secrets.contains_key(secret) {
                    return Err(invalid("Escrow grant references an undeclared secret"));
                }
                Ok(())
            }
            Action::ReleaseSigningKey { public_key, .. } => {
                if public_key != &self.participant_public_key {
                    return Err(invalid(
                        "Escrow grant cannot export another participant's key",
                    ));
                }
                Ok(())
            }
        }
    }
    pub fn digest(&self) -> Result<[u8; 32], KeyMeldError> {
        self.validate()?;
        authorization_digest("escrow-policy-v2", self)
    }
    pub fn verify_deposits(&self, deposits: &[SecretDeposit]) -> Result<(), KeyMeldError> {
        self.validate()?;
        if deposits.len() != self.secrets.len() {
            return Err(invalid("Escrow deposits differ from declared secrets"));
        }
        let mut seen = BTreeSet::new();
        for deposit in deposits {
            if !seen.insert(&deposit.name) {
                return Err(invalid("Duplicate escrow deposit"));
            }
            self.secrets
                .get(&deposit.name)
                .ok_or_else(|| invalid("Undeclared escrow deposit"))?
                .verify(&deposit.bytes)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEscrowPolicy {
    pub policy: EscrowPolicy,
    pub signature: Vec<u8>,
}
impl SignedEscrowPolicy {
    pub fn sign(policy: EscrowPolicy, participant_secret: &[u8; 32]) -> Result<Self, KeyMeldError> {
        policy.validate()?;
        let signature = sign_authorization(participant_secret, "escrow-policy-v2", &policy)?;
        let signed = Self { policy, signature };
        signed.verify(
            &signed.policy.context,
            signed.policy.participant_public_key.as_bytes(),
        )?;
        Ok(signed)
    }
    pub fn verify(
        &self,
        expected_context: &EscrowContext,
        expected_participant_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        self.policy.validate()?;
        if &self.policy.context != expected_context
            || self.policy.participant_public_key.as_bytes() != expected_participant_key
        {
            return Err(invalid(
                "Escrow policy belongs to a different participant or context",
            ));
        }
        verify_authorization(
            expected_participant_key,
            "escrow-policy-v2",
            &self.policy,
            &self.signature,
        )
    }
    /// Checks exact policy scope and condition. The returned token cannot be
    /// deserialized from host input. The enclave must still enforce its manifest,
    /// key ownership, capability gates and durable execution transaction.
    pub fn authorize<'a>(
        &'a self,
        expected_context: &EscrowContext,
        expected_participant_key: &[u8],
        action_id: &str,
        attempt: &ActionAttempt,
        requested: &'a Action,
        proof: &ConditionProof,
    ) -> Result<VerifiedAction<'a>, KeyMeldError> {
        self.verify(expected_context, expected_participant_key)?;
        attempt.validate(requested, expected_context)?;
        let grant = self
            .policy
            .grants
            .get(action_id)
            .ok_or_else(|| invalid("Unknown escrow action grant"))?;
        grant.operation.validate_action(requested, &self.policy)?;
        grant.condition.verify(proof)?;
        let policy_digest = self.policy.digest()?;
        let execution_digest = authorization_digest(
            "escrow-execution-v1",
            &(
                &self.policy.context,
                policy_digest,
                action_id,
                attempt,
                requested,
                proof,
            ),
        )?;
        Ok(VerifiedAction {
            action: requested,
            policy_digest,
            action_id: action_id.to_owned(),
            attempt: attempt.clone(),
            execution_digest,
        })
    }
}

/// A verified decision, not a serializable substitute for enclave verification.
#[derive(Debug)]
pub struct VerifiedAction<'a> {
    action: &'a Action,
    policy_digest: [u8; 32],
    action_id: String,
    attempt: ActionAttempt,
    execution_digest: [u8; 32],
}
impl VerifiedAction<'_> {
    pub fn action(&self) -> &Action {
        self.action
    }
    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }
    pub fn action_id(&self) -> &str {
        &self.action_id
    }
    pub fn attempt_id(&self) -> Uuid {
        self.attempt.attempt_id
    }
    pub fn attempt(&self) -> &ActionAttempt {
        &self.attempt
    }
    pub fn execution_digest(&self) -> [u8; 32] {
        self.execution_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAttempt {
    pub attempt_id: Uuid,
    /// A signature permit is valid for exactly this future signing session.
    pub signing_session_id: Option<SessionId>,
}
impl ActionAttempt {
    pub fn validate(&self, action: &Action, context: &EscrowContext) -> Result<(), KeyMeldError> {
        if self.attempt_id.is_nil() {
            return Err(invalid("Escrow attempt identity must not be nil"));
        }
        match (action, &self.signing_session_id) {
            (Action::Sign { .. }, Some(session))
                if session != &context.keygen_session_id && !session.uuid().is_nil() =>
            {
                Ok(())
            }
            (
                Action::SignBip340 { .. }
                | Action::ReleaseSecret { .. }
                | Action::ReleaseSigningKey { .. },
                None,
            ) => Ok(()),
            _ => Err(invalid(
                "Escrow action has an invalid target signing session",
            )),
        }
    }
}

/// Only send this inside the participant-to-enclave encrypted registration.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowRegistration {
    pub policy: SignedEscrowPolicy,
    pub secrets: BTreeMap<String, Vec<u8>>,
}
impl EscrowRegistration {
    pub fn verify(
        &self,
        expected_context: &EscrowContext,
        expected_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        self.policy.verify(expected_context, expected_key)?;
        self.validate_secret_commitments()
    }
    pub fn validate_secret_commitments(&self) -> Result<(), KeyMeldError> {
        self.policy.policy.validate()?;
        if self.secrets.len() != self.policy.policy.secrets.len() {
            return Err(invalid(
                "Escrow secret inventory differs from signed policy",
            ));
        }
        for (name, bytes) in &self.secrets {
            self.policy
                .policy
                .secrets
                .get(name)
                .ok_or_else(|| invalid("Undeclared escrow registration secret"))?
                .verify(bytes)?;
        }
        Ok(())
    }
}
impl Drop for EscrowRegistration {
    fn drop(&mut self) {
        for bytes in self.secrets.values_mut() {
            bytes.zeroize();
        }
    }
}
impl std::fmt::Debug for EscrowRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EscrowRegistration")
            .field("policy", &self.policy)
            .field("secrets", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Fresh,
    Replay,
}
/// Process-local replay bookkeeping. A service must persist its execution record
/// atomically with the action/result. This is not protection from host rollback.
#[derive(Debug, Default)]
pub struct ExecutionLedger {
    executions: BTreeMap<([u8; 32], String), (ActionAttempt, [u8; 32])>,
}
impl ExecutionLedger {
    pub fn check(&self, action: &VerifiedAction<'_>) -> Result<ExecutionStatus, KeyMeldError> {
        match self
            .executions
            .get(&(action.policy_digest, action.action_id.clone()))
        {
            None => Ok(ExecutionStatus::Fresh),
            Some((attempt, digest))
                if *attempt == action.attempt && *digest == action.execution_digest =>
            {
                Ok(ExecutionStatus::Replay)
            }
            Some(_) => Err(invalid(
                "Escrow grant already executed under a different attempt",
            )),
        }
    }
    /// Call only after successful execution; store the authenticated result with
    /// this record so an exact retry returns it rather than signing a second time.
    pub fn record_success(
        &mut self,
        action: &VerifiedAction<'_>,
    ) -> Result<ExecutionStatus, KeyMeldError> {
        let status = self.check(action)?;
        self.executions.insert(
            (action.policy_digest, action.action_id.clone()),
            (action.attempt.clone(), action.execution_digest),
        );
        Ok(status)
    }
}

#[cfg(test)]
#[path = "escrow_tests.rs"]
mod tests;
