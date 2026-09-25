//! Generic participant-authorized escrow execution and MuSig2 nonce admission.
//!
//! A proof unlocks only its signed action. Signing permits are bound to one
//! signing session; they never authorize exporting keys. Receipts authenticate
//! restart recovery, but host-controlled storage is not an antirollback oracle.
use super::{context::EnclaveSharedContext, states::keygen::Completed};
use crate::escrow_verifier::{
    BindView, ExecutionView, PreparationView, PreparedAction as VerifierPreparedAction,
    RegistrationView,
};
use crate::musig::{types::SessionMetadata, MusigProcessor};
use keymeld_core::{
    authorization::{authorization_digest, SignedSessionManifest},
    crypto::SecureCrypto,
    escrow::{
        self,
        protocol::{
            BindEscrowRequest, EscrowCommand, EscrowResponse, ExecuteEscrowRequest,
            ExecutionOutput, Operation, Payload, PrepareEscrowRequest, ReceiptContext,
        },
        Action, ActionAttempt, AdaptorContext, Condition, ConditionProof, EscrowContext,
        EscrowRegistration, KeyTweak, PreparationPolicy, PublicKeyBytes, Repetition, ScopeSigner,
        SignedEscrowPolicy, SigningItem, SigningScope,
    },
    protocol::{
        AdaptorType, EnclaveError, InitSigningSessionCommand, TaprootTweak, ValidationError,
    },
    EncryptedData, SessionId, SessionSecret, UserId,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const MAX_REQUEST_CACHE_BYTES: usize = escrow::MAX_PREPARATION_CACHE_BYTES;
const MAX_CACHED_RESPONSE_BYTES: usize = escrow::PREPARATION_RESPONSE_RESERVATION_BYTES;

fn invalid(message: impl ToString) -> EnclaveError {
    EnclaveError::Validation(ValidationError::Other(message.to_string()))
}
fn preparation_exhausted(reason: impl Into<String>) -> EnclaveError {
    EnclaveError::EscrowPreparationExhausted {
        reason: reason.into(),
    }
}

#[derive(Debug, Default)]
pub struct EscrowSessionState {
    inner: Mutex<SessionState>,
}

#[derive(Debug, Default)]
struct SessionState {
    bindings: BTreeMap<UserId, [u8; 32]>,
    permits: BTreeMap<(SessionId, UserId), SigningPermit>,
    preparations: BTreeMap<(UserId, String), PreparedAction>,
    executions: BTreeMap<(UserId, String), ExecutedAction>,
    // One canonical successful receipt per permission, never one per retry.
    execution_receipts: BTreeMap<(UserId, String), Payload>,
    requests: BTreeMap<(UserId, uuid::Uuid), ([u8; 32], EscrowResponse)>,
    cached_response_bytes: usize,
    inflight_request_ids: BTreeMap<(UserId, uuid::Uuid), [u8; 32]>,
    required_bindings: BTreeMap<UserId, Binding>,
    inflight: BTreeMap<(UserId, String), ([u8; 32], Arc<tokio::sync::Notify>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningPermit {
    policy_digest: [u8; 32],
    scope: SigningScope,
}

/// Called at admission and again during restored-state validation. The policy
/// signature covers the complete application commitment, deposits and grants.
pub fn validate_registration(
    manifest: &SignedSessionManifest,
    user_id: &UserId,
    participant_public_key: &[u8],
    registration: &EscrowRegistration,
) -> Result<(), EnclaveError> {
    manifest.verify().map_err(invalid)?;
    let expected = expected_context(manifest, user_id, &registration.policy.policy.context)?;
    registration
        .verify(&expected, participant_public_key)
        .map_err(invalid)
}

fn expected_context(
    manifest: &SignedSessionManifest,
    user_id: &UserId,
    context: &EscrowContext,
) -> Result<EscrowContext, EnclaveError> {
    if !manifest
        .manifest
        .participant_verifiers
        .contains_key(user_id)
    {
        return Err(invalid(
            "Escrow participant is outside the authorized manifest",
        ));
    }
    let mut expected = context.clone();
    expected.keygen_session_id = manifest.manifest.keygen_session_id.clone();
    expected.user_id = user_id.clone();
    expected.manifest_digest = manifest
        .digest()
        .map_err(invalid)?
        .try_into()
        .map_err(|_| invalid("Invalid manifest digest length"))?;
    Ok(expected)
}

fn bind_policy(
    state: &mut SessionState,
    policy: &SignedEscrowPolicy,
) -> Result<[u8; 32], EnclaveError> {
    let digest = policy.policy.digest().map_err(invalid)?;
    let user = &policy.policy.context.user_id;
    if state.bindings.get(user).is_some_and(|old| *old != digest) {
        return Err(invalid("Escrow policy cannot be replaced within a session"));
    }
    state.bindings.insert(user.clone(), digest);
    Ok(digest)
}

fn key_tweak(tweak: &TaprootTweak) -> KeyTweak {
    match tweak {
        TaprootTweak::None => KeyTweak::None,
        TaprootTweak::UnspendableTaproot => KeyTweak::TaprootKeyPath,
        TaprootTweak::TaprootWithMerkleRoot { merkle_root } => KeyTweak::TaprootMerkleRoot {
            merkle_root: *merkle_root,
        },
        TaprootTweak::PlainTweak { tweak } => KeyTweak::PlainScalar { scalar: *tweak },
        TaprootTweak::XOnlyTweak { tweak } => KeyTweak::XOnlyScalar { scalar: *tweak },
    }
}

fn decrypt_tweak(
    value: &str,
    secret: &SessionSecret,
    purpose: &str,
) -> Result<TaprootTweak, EnclaveError> {
    if value.len() > 4096 {
        return Err(invalid("Encrypted escrow tweak exceeds size limit"));
    }
    let encrypted = EncryptedData::from_hex(value).map_err(invalid)?;
    let text = Zeroizing::new(secret.decrypt(&encrypted, purpose).map_err(invalid)?);
    serde_json::from_slice(&text).map_err(invalid)
}

/// Reconstruct the actual MuSig transcript, including canonical signer order.
/// Only items in which this participant signs form that participant's scope.
fn signing_scope(
    metadata: &SessionMetadata,
    secret: &SessionSecret,
    command: &InitSigningSessionCommand,
    user: &UserId,
) -> Result<SigningScope, EnclaveError> {
    if command.batch_items.is_empty() || command.batch_items.len() > escrow::MAX_BATCH_ITEMS {
        return Err(invalid("Invalid escrow signing batch size"));
    }
    let session_tweak = key_tweak(&decrypt_tweak(
        &command.encrypted_taproot_tweak,
        secret,
        "taproot_tweak",
    )?);
    if session_tweak != key_tweak(&metadata.taproot_tweak) {
        return Err(invalid(
            "Escrow signing session tweak differs from key generation",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut batch = Vec::new();
    for item in &command.batch_items {
        if !ids.insert(item.batch_item_id)
            || item.encrypted_message.len() > escrow::MAX_PAYLOAD_BYTES * 3
            || item
                .encrypted_adaptor_configs
                .as_ref()
                .is_some_and(|value| value.len() > 16384)
        {
            return Err(invalid("Duplicate or oversized escrow signing item"));
        }
        let users: Vec<_> = match item.subset_id {
            None => metadata.participant_public_keys.keys().cloned().collect(),
            Some(id) => metadata
                .subset_definitions
                .iter()
                .find(|subset| subset.subset_id == id)
                .ok_or_else(|| invalid("Unknown escrow signing subset"))?
                .participants
                .clone(),
        };
        let mut signers = users
            .iter()
            .map(|id| {
                let key = metadata
                    .participant_public_keys
                    .get(id)
                    .ok_or_else(|| invalid("Unknown escrow scope signer"))?;
                Ok(ScopeSigner {
                    user_id: id.clone(),
                    public_key: PublicKeyBytes::new(&key.serialize()).map_err(invalid)?,
                })
            })
            .collect::<Result<Vec<_>, EnclaveError>>()?;
        signers.sort_by(|left, right| left.public_key.as_bytes().cmp(right.public_key.as_bytes()));
        if !users.contains(user) {
            continue;
        }
        let message = Zeroizing::new(
            hex::decode(
                keymeld_core::validation::decrypt_session_data(
                    &item.encrypted_message,
                    &hex::encode(secret.as_bytes()),
                )
                .map_err(invalid)?,
            )
            .map_err(invalid)?,
        );
        if message.is_empty() || message.len() > escrow::MAX_PAYLOAD_BYTES {
            return Err(invalid("Invalid escrow message size"));
        }
        let adaptor = match &item.encrypted_adaptor_configs {
            None => AdaptorContext::None,
            Some(value) => {
                let configs = super::states::signing::decrypt_adaptor_configs(value, secret)?;
                if configs.len() != 1
                    || configs[0].adaptor_type != AdaptorType::Single
                    || configs[0].adaptor_points.len() != 1
                    || configs[0].hints.is_some()
                {
                    return Err(invalid(
                        "Escrow permits only an exact single adaptor without hints",
                    ));
                }
                let config = &configs[0];
                AdaptorContext::Single {
                    adaptor_id: config.adaptor_id,
                    point: PublicKeyBytes::new(
                        &hex::decode(&config.adaptor_points[0]).map_err(invalid)?,
                    )
                    .map_err(invalid)?,
                }
            }
        };
        let tweak = key_tweak(&decrypt_tweak(
            &item.encrypted_taproot_tweak,
            secret,
            "session_data",
        )?);
        // Existing subset aggregation uses its precomputed session tweak. A
        // claimed per-item override would not describe the actual signature.
        if item.subset_id.is_some() && tweak != session_tweak {
            return Err(invalid(
                "Subset escrow item tweak must equal the keygen session tweak",
            ));
        }
        batch.push(SigningItem {
            item_id: item.batch_item_id,
            message_digest: escrow::sha256(&message),
            subset_id: item.subset_id,
            signers,
            tweak,
            adaptor,
        });
    }
    Ok(SigningScope {
        session_tweak,
        batch,
    })
}

/// Must run after ordinary creator/participant authorization and before any
/// nonce or partial signature is generated. Missing permits always fail closed.
pub fn verify_signing_batch(
    processor: &MusigProcessor,
    secret: &SessionSecret,
    command: &InitSigningSessionCommand,
) -> Result<(), EnclaveError> {
    let metadata = processor.get_session_metadata_public();
    let mut state = metadata
        .escrow_state
        .inner
        .lock()
        .map_err(|_| invalid("Escrow state lock poisoned"))?;
    for (user, digest) in &state.bindings {
        let participant = processor
            .get_user_session_data(user)
            .ok_or_else(|| invalid("Previously registered escrow participant is missing"))?;
        let registration = participant
            .escrow
            .as_ref()
            .ok_or_else(|| invalid("Previously registered escrow policy was stripped"))?;
        if registration.policy.policy.digest().map_err(invalid)? != *digest {
            return Err(invalid("Previously registered escrow policy was replaced"));
        }
    }
    for binding in state.required_bindings.values() {
        validate_roster(processor, binding)?;
    }
    for user in processor.get_users_in_session() {
        let participant = processor
            .get_user_session_data(&user)
            .ok_or_else(|| invalid("Missing local escrow participant"))?;
        let Some(registration) = participant.escrow.as_ref() else {
            continue;
        };
        let manifest = metadata
            .authorization_manifest
            .as_ref()
            .ok_or_else(|| invalid("Escrow signing requires authorized manifest"))?;
        if command.keygen_session_id != manifest.manifest.keygen_session_id {
            return Err(invalid("Escrow signing keygen session differs"));
        }
        let key = metadata
            .participant_public_keys
            .get(&user)
            .ok_or_else(|| invalid("Missing escrow participant key"))?;
        validate_registration(manifest, &user, &key.serialize(), registration)?;
        let digest = bind_policy(&mut state, &registration.policy)?;
        let actual = signing_scope(metadata, secret, command, &user)?;
        if actual.batch.is_empty() {
            continue;
        }
        let permit = state
            .permits
            .get(&(command.signing_session_id.clone(), user.clone()))
            .ok_or_else(|| {
                invalid("Escrow signing requires a verified condition for this signing session")
            })?;
        if permit.policy_digest != digest || permit.scope != actual {
            return Err(invalid(
                "Signing batch differs from the participant-authorized escrow action",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    context: EscrowContext,
    policy_digest: [u8; 32],
    enclave_id: keymeld_core::EnclaveId,
    participant_policy_digests: BTreeMap<UserId, [u8; 32]>,
    application_state: Payload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedAction {
    binding: Binding,
    action_id: String,
    attempt: ActionAttempt,
    action: Action,
    application_state: Payload,
    output: Payload,
    predecessor: Option<[u8; 32]>,
    generation: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutedAction {
    prepared: PreparedAction,
    execution_digest: [u8; 32],
    original_request_id: uuid::Uuid,
    original_request_digest: [u8; 32],
    output: ExecutionOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum SealedState {
    Bound { binding: Binding },
    Prepared { prepared: PreparedAction },
    Executed { executed: ExecutedAction },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedEnvelope {
    schema_version: u16,
    enclave_id: keymeld_core::EnclaveId,
    state: SealedState,
}
fn unseal(context: &EnclaveSharedContext, payload: &Payload) -> Result<SealedState, EnclaveError> {
    let envelope: SealedEnvelope = decrypt(&sealing_key(context)?, payload, "escrow_state_v1")?;
    if envelope.schema_version != escrow::SCHEMA_VERSION
        || envelope.enclave_id != context.enclave_id
    {
        return Err(invalid("Escrow receipt issuer or version differs"));
    }
    Ok(envelope.state)
}

fn decrypt_request<T: serde::de::DeserializeOwned>(
    key: &SessionSecret,
    value: &Payload,
) -> Result<T, EnclaveError> {
    let encrypted = EncryptedData::from_bytes(value.as_bytes()).map_err(invalid)?;
    let plaintext = Zeroizing::new(
        key.decrypt(&encrypted, "escrow-request-v1")
            .map_err(invalid)?,
    );
    escrow::decode(&plaintext).map_err(invalid)
}

fn decrypt<T: serde::de::DeserializeOwned>(
    key: &SessionSecret,
    value: &Payload,
    purpose: &str,
) -> Result<T, EnclaveError> {
    let encrypted = EncryptedData::from_bytes(value.as_bytes()).map_err(invalid)?;
    let plaintext = Zeroizing::new(key.decrypt(&encrypted, purpose).map_err(invalid)?);
    escrow::decode(&plaintext).map_err(invalid)
}

fn sealing_key(context: &EnclaveSharedContext) -> Result<SessionSecret, EnclaveError> {
    // The gateway knows session keys, so only the enclave identity secret can
    // authenticate persisted execution/authorization state.
    if context.private_key.len() != 32 {
        return Err(invalid("Invalid enclave sealing key"));
    }
    let mut material = Zeroizing::new(b"keymeld-escrow-state-v1".to_vec());
    material.extend_from_slice(&context.private_key);
    Ok(SessionSecret::from_bytes(escrow::sha256(&material)))
}

fn response(
    context: &EnclaveSharedContext,
    command: &EscrowCommand,
    key_epoch: u64,
    output: Payload,
    state: SealedState,
) -> Result<EscrowResponse, EnclaveError> {
    let sealed = seal_state(context, state)?;
    signed_response(context, command, key_epoch, output, sealed)
}
fn seal_state(context: &EnclaveSharedContext, state: SealedState) -> Result<Payload, EnclaveError> {
    let envelope = SealedEnvelope {
        schema_version: escrow::SCHEMA_VERSION,
        enclave_id: context.enclave_id,
        state,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&envelope).map_err(invalid)?);
    let sealed = sealing_key(context)?
        .encrypt(&plaintext, "escrow_state_v1")
        .and_then(|value| value.to_bytes())
        .map_err(invalid)?;
    Payload::new(sealed).map_err(invalid)
}
fn signed_response(
    context: &EnclaveSharedContext,
    command: &EscrowCommand,
    key_epoch: u64,
    output: Payload,
    sealed: Payload,
) -> Result<EscrowResponse, EnclaveError> {
    let secret = Zeroizing::new(
        <[u8; 32]>::try_from(context.private_key.as_slice())
            .map_err(|_| invalid("Invalid enclave response signing key"))?,
    );
    EscrowResponse::sign(
        ReceiptContext {
            schema_version: escrow::SCHEMA_VERSION,
            enclave_id: context.enclave_id,
            enclave_key_epoch: key_epoch,
            request: command.context.clone(),
            request_digest: command.digest().map_err(invalid)?,
        },
        output,
        sealed,
        &secret,
    )
    .map_err(invalid)
}

fn validate_binding(binding: &Binding, command: &EscrowCommand) -> Result<(), EnclaveError> {
    if binding.context != command.context.escrow
        || binding.policy_digest != command.context.policy_digest
    {
        return Err(invalid(
            "Escrow receipt belongs to another policy, participant or application",
        ));
    }
    Ok(())
}

/// The binding of an unbound permission: the participant's own registered policy, with no
/// application roster or state. Validation derives it again rather than trusting a receipt.
fn unbound_binding(
    policy: &SignedEscrowPolicy,
    enclave_id: keymeld_core::EnclaveId,
) -> Result<Binding, EnclaveError> {
    Ok(Binding {
        context: policy.policy.context.clone(),
        policy_digest: policy.policy.digest().map_err(invalid)?,
        enclave_id,
        participant_policy_digests: BTreeMap::new(),
        application_state: Payload::default(),
    })
}

fn validate_prepared(
    prepared: &PreparedAction,
    command: &EscrowCommand,
    policy: &SignedEscrowPolicy,
) -> Result<(), EnclaveError> {
    validate_binding(&prepared.binding, command)?;
    let unbound = policy
        .policy
        .grants
        .get(&prepared.action_id)
        .is_some_and(|grant| grant.unbound);
    // Prepare derives this binding only for an unbound permission, never from a receipt.
    if unbound && prepared.binding != unbound_binding(policy, prepared.binding.enclave_id)? {
        return Err(invalid(
            "An unbound permission acts only under its derived binding",
        ));
    }
    if command.context.action_id.as_ref() != Some(&prepared.action_id)
        || command.context.attempt.as_ref() != Some(&prepared.attempt)
        || policy
            .policy
            .grants
            .get(&prepared.action_id)
            .is_none_or(|grant| {
                grant
                    .operation
                    .validate_action(&prepared.action, &policy.policy)
                    .is_err()
            })
    {
        return Err(invalid(
            "Escrow receipt action or attempt differs from request",
        ));
    }
    let grant = &policy.policy.grants[&prepared.action_id];
    let renewable = grant.preparation == PreparationPolicy::RenewableIdenticalAction;
    if prepared.predecessor.is_some()
        && !(grant.repetition == Repetition::RepeatIdenticalSigningScope
            && matches!(prepared.action, Action::Sign { .. })
            || renewable && !matches!(prepared.action, Action::Sign { .. }))
    {
        return Err(invalid(
            "Preparation renewal or signing repetition was not authorized",
        ));
    }
    if prepared.predecessor.is_some() != (prepared.generation > 0)
        || renewable && prepared.generation >= escrow::MAX_PREPARATIONS_PER_ACTION
    {
        return Err(invalid("Invalid or exhausted preparation generation"));
    }
    prepared
        .attempt
        .validate(&prepared.action, &prepared.binding.context)
        .map_err(invalid)
}

fn preparation_digest(prepared: &PreparedAction) -> Result<[u8; 32], EnclaveError> {
    authorization_digest("escrow-prepared-action-v2", prepared).map_err(invalid)
}
/// Whether `prepared` is a fresh attempt of a per-attempt permission, and so may replace `old`.
///
/// Every attempt is separately authorized by the verifier, which checks that attempt's messages.
fn fresh_attempt(
    policy: &SignedEscrowPolicy,
    old: &PreparedAction,
    prepared: &PreparedAction,
) -> bool {
    policy
        .policy
        .grants
        .get(&prepared.action_id)
        .is_some_and(|grant| grant.repetition == Repetition::VerifierAuthorizedAttempts)
        && old.binding == prepared.binding
        && old.attempt.attempt_id != prepared.attempt.attempt_id
}

fn install_preparation(
    state: &mut SessionState,
    prepared: &PreparedAction,
    policy: &SignedEscrowPolicy,
    select_for_execution: bool,
) -> Result<(), EnclaveError> {
    let key = (
        prepared.binding.context.user_id.clone(),
        prepared.action_id.clone(),
    );
    let renewable = policy.policy.grants[&prepared.action_id].preparation
        == PreparationPolicy::RenewableIdenticalAction;
    if renewable {
        if let Some(executed) = state.executions.get(&key) {
            if !select_for_execution || executed.prepared != *prepared {
                return Err(invalid(
                    "A successful execution freezes this release permission",
                ));
            }
        }
    }
    if let Some(old) = state.preparations.get(&key) {
        if old != prepared {
            let same_action = old.binding == prepared.binding && old.action == prepared.action;
            let successor = prepared.predecessor == Some(preparation_digest(old)?)
                && old.generation.checked_add(1) == Some(prepared.generation)
                && old.attempt.attempt_id != prepared.attempt.attempt_id;
            let allowed = if renewable {
                // A previously sealed candidate can win if its evidence arrives
                // late. Selecting it must never create another preparation.
                select_for_execution || successor
            } else {
                successor
                    && matches!(prepared.action, Action::Sign { .. })
                    && old.attempt.signing_session_id != prepared.attempt.signing_session_id
            };
            if !fresh_attempt(policy, old, prepared) && (!same_action || !allowed) {
                return Err(invalid(
                    "Escrow action was already prepared for another attempt",
                ));
            }
        }
    }
    state.preparations.insert(key, prepared.clone());
    Ok(())
}

fn validate_live_execution(
    state: &EscrowSessionState,
    prepared: &PreparedAction,
    policy: &SignedEscrowPolicy,
) -> Result<(), EnclaveError> {
    let state = state
        .inner
        .lock()
        .map_err(|_| invalid("Escrow state lock poisoned"))?;
    if let Some(old) = state.executions.get(&(
        prepared.binding.context.user_id.clone(),
        prepared.action_id.clone(),
    )) {
        if old.prepared != *prepared
            && !fresh_attempt(policy, &old.prepared, prepared)
            && !(prepared.predecessor.is_some()
                && matches!(prepared.action, Action::Sign { .. })
                && old.prepared.action == prepared.action
                && old.prepared.attempt.signing_session_id != prepared.attempt.signing_session_id)
        {
            return Err(invalid(
                "Permission already executed under another preparation",
            ));
        }
    }
    Ok(())
}

fn install_execution(
    state: &mut SessionState,
    executed: &ExecutedAction,
    policy: &SignedEscrowPolicy,
) -> Result<(), EnclaveError> {
    let prepared = &executed.prepared;
    let key = (
        prepared.binding.context.user_id.clone(),
        prepared.action_id.clone(),
    );
    if let Some(old) = state.executions.get(&key) {
        if (old.prepared != *prepared || old.execution_digest != executed.execution_digest)
            && !fresh_attempt(policy, &old.prepared, prepared)
            && !(prepared.predecessor.is_some()
                && matches!(prepared.action, Action::Sign { .. })
                && old.prepared.action == prepared.action
                && old.prepared.attempt.signing_session_id != prepared.attempt.signing_session_id)
        {
            return Err(invalid(
                "Escrow action already executed under another proof or attempt",
            ));
        }
    }
    if let Action::Sign { scope } = &prepared.action {
        let session = prepared
            .attempt
            .signing_session_id
            .as_ref()
            .ok_or_else(|| invalid("Escrow signing target is missing"))?;
        let key = (session.clone(), prepared.binding.context.user_id.clone());
        let permit = SigningPermit {
            policy_digest: prepared.binding.policy_digest,
            scope: scope.clone(),
        };
        if state.permits.get(&key).is_some_and(|old| old != &permit) {
            return Err(invalid(
                "Escrow signing session already has a different authorization",
            ));
        }
        state.permits.insert(key, permit);
    }
    state.executions.insert(key, executed.clone());
    Ok(())
}

/// Validate complete signed registration provenance and every locally held policy.
/// The application chooses which peers require a policy; Keymeld never infers a
/// business role from the coordinator identity.
fn validate_roster(processor: &MusigProcessor, binding: &Binding) -> Result<(), EnclaveError> {
    let metadata = processor.get_session_metadata_public();
    let manifest = metadata
        .authorization_manifest
        .as_ref()
        .ok_or_else(|| invalid("Missing escrow manifest"))?;
    manifest.verify().map_err(invalid)?;
    // Exact built-in policies remain useful without an application roster.
    if binding.participant_policy_digests.is_empty() {
        return Ok(());
    }
    if metadata.registrations.keys().collect::<Vec<_>>()
        != manifest
            .manifest
            .participant_verifiers
            .keys()
            .collect::<Vec<_>>()
    {
        return Err(invalid(
            "Binding requires the complete authenticated registration roster",
        ));
    }
    let mut local = BTreeSet::new();
    for (user, registration) in &metadata.registrations {
        registration.verify_commitment(manifest).map_err(invalid)?;
        let key = metadata
            .participant_public_keys
            .get(user)
            .ok_or_else(|| invalid("Missing authenticated participant key"))?;
        if registration.context.user_id != *user
            || registration.context.public_key != key.serialize()
        {
            return Err(invalid(
                "Participant key differs from authenticated registration",
            ));
        }
        if registration.context.enclave_id == binding.enclave_id {
            local.insert(user.clone());
        }
    }
    if local.is_empty() || local != processor.get_users_in_session().into_iter().collect() {
        return Err(invalid(
            "Local participants differ from authenticated enclave assignments",
        ));
    }
    if binding
        .participant_policy_digests
        .keys()
        .any(|user| !metadata.participant_public_keys.contains_key(user))
    {
        return Err(invalid("Foreign required escrow participant"));
    }
    for user in local {
        let participant = processor
            .get_user_session_data(&user)
            .ok_or_else(|| invalid("Missing local participant"))?;
        match (
            binding.participant_policy_digests.get(&user),
            &participant.escrow,
        ) {
            (None, None) => {}
            (Some(expected), Some(actual))
                if *expected == actual.policy.policy.digest().map_err(invalid)? =>
            {
                actual
                    .verify(
                        &expected_context(manifest, &user, &actual.policy.policy.context)?,
                        &metadata.participant_public_keys[&user].serialize(),
                    )
                    .map_err(invalid)?;
            }
            _ => {
                return Err(invalid(
                    "Required participant policy is missing or differs from sealed registration",
                ))
            }
        }
    }
    Ok(())
}

fn install_binding(state: &mut SessionState, binding: &Binding) -> Result<(), EnclaveError> {
    if let Some(old) = state.required_bindings.get(&binding.context.user_id) {
        if old != binding {
            return Err(invalid("Escrow binding cannot be replaced"));
        }
    }
    state
        .required_bindings
        .insert(binding.context.user_id.clone(), binding.clone());
    Ok(())
}

/// A dropped future releases its reservation and wakes identical waiters.
struct Reservation {
    state: Arc<EscrowSessionState>,
    key: (UserId, String),
    request_key: (UserId, uuid::Uuid),
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.inner.lock() {
            state.inflight_request_ids.remove(&self.request_key);
            if let Some((_, notify)) = state.inflight.remove(&self.key) {
                notify.notify_waiters();
            }
        }
    }
}

fn verifier_action(prepared: &PreparedAction) -> VerifierPreparedAction {
    VerifierPreparedAction {
        action: prepared.action.clone(),
        application_state: prepared.application_state.clone(),
        output: prepared.output.clone(),
    }
}
async fn verify_execution(
    context: &EnclaveSharedContext,
    manifest: &SignedSessionManifest,
    policy: &SignedEscrowPolicy,
    prepared: &PreparedAction,
    proof: &ConditionProof,
) -> Result<[u8; 32], EnclaveError> {
    let grant = policy
        .policy
        .grants
        .get(&prepared.action_id)
        .ok_or_else(|| invalid("Unknown escrow permission"))?;
    grant
        .operation
        .validate_action(&prepared.action, &policy.policy)
        .map_err(invalid)?;
    match (&grant.condition, proof) {
        (Condition::VerifierRule { rule }, ConditionProof::VerifierEvidence { evidence }) => {
            let selection = policy
                .policy
                .verifier
                .as_ref()
                .ok_or_else(|| invalid("Missing verifier selection"))?;
            let exact = verifier_action(prepared);
            tokio::time::timeout(
                std::time::Duration::from_secs(60),
                context
                    .escrow_verifiers
                    .get(&selection.id, selection.version)?
                    .verify_execution(
                        ExecutionView {
                            manifest,
                            policy,
                            rule,
                            permission_id: &prepared.action_id,
                            attempt: &prepared.attempt,
                            bound_state: &prepared.binding.application_state,
                        },
                        &exact,
                        evidence,
                    ),
            )
            .await
            .map_err(|_| invalid("Escrow verifier execution timed out"))??;
            authorization_digest("escrow-verified-execution-v2", &(prepared, proof))
                .map_err(invalid)
        }
        (Condition::VerifierRule { .. }, _) => Err(invalid("Verifier evidence is required")),
        _ => Ok(policy
            .authorize(
                &policy.policy.context,
                policy.policy.participant_public_key.as_bytes(),
                &prepared.action_id,
                &prepared.attempt,
                &prepared.action,
                proof,
            )
            .map_err(invalid)?
            .execution_digest()),
    }
}

async fn restore_execution(
    context: &EnclaveSharedContext,
    manifest: &SignedSessionManifest,
    policy: &SignedEscrowPolicy,
    prepared: &PreparedAction,
) -> Result<(), EnclaveError> {
    let grant = &policy.policy.grants[&prepared.action_id];
    if let Condition::VerifierRule { rule } = &grant.condition {
        let selection = policy
            .policy
            .verifier
            .as_ref()
            .ok_or_else(|| invalid("Missing verifier selection"))?;
        let exact = verifier_action(prepared);
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            context
                .escrow_verifiers
                .get(&selection.id, selection.version)?
                .restore_execution(
                    ExecutionView {
                        manifest,
                        policy,
                        rule,
                        permission_id: &prepared.action_id,
                        attempt: &prepared.attempt,
                        bound_state: &prepared.binding.application_state,
                    },
                    &exact,
                ),
        )
        .await
        .map_err(|_| invalid("Escrow verifier execution recovery timed out"))??;
    }
    Ok(())
}

/// Private snapshot for application work after releasing the session-map guard.
/// Custody material stays inside the enclave; shared escrow state remains shared.
pub(crate) struct EscrowSessionSnapshot {
    session_id: SessionId,
    session_secret: SessionSecret,
    processor: MusigProcessor,
    /// Before keygen completes, only unbound permissions may prepare or execute.
    keygen_complete: bool,
}
impl EscrowSessionSnapshot {
    pub(crate) fn new(completed: &Completed) -> Self {
        Self::from_parts(
            &completed.session_id,
            completed.session_secret(),
            completed.musig_processor(),
            true,
        )
    }
    /// A session whose participants are still registering, as in a pool that never fills.
    pub(crate) fn registering(
        distributing: &crate::operations::states::keygen::DistributingSecrets,
    ) -> Self {
        Self::from_parts(
            &distributing.session_id,
            distributing.session_secret(),
            distributing.musig_processor(),
            false,
        )
    }
    fn from_parts(
        session_id: &SessionId,
        session_secret: &SessionSecret,
        source: &MusigProcessor,
        keygen_complete: bool,
    ) -> Self {
        let metadata = source.get_session_metadata_public().clone();
        let mut processor = MusigProcessor::new(
            session_id,
            metadata.taproot_tweak.clone(),
            metadata.expected_participant_count,
            metadata.expected_participants.clone(),
        );
        processor.session_metadata = metadata;
        for user in source.get_users_in_session() {
            if let Some(participant) = source.get_user_session_data(&user) {
                processor.user_sessions.insert(user, participant);
            }
        }
        Self {
            session_id: session_id.clone(),
            session_secret: session_secret.clone(),
            processor,
            keygen_complete,
        }
    }
    fn musig_processor(&self) -> &MusigProcessor {
        &self.processor
    }
    fn session_secret(&self) -> &SessionSecret {
        &self.session_secret
    }
}
#[cfg(test)]
pub async fn handle(
    completed: &Completed,
    context: &EnclaveSharedContext,
    command: &EscrowCommand,
    key_epoch: u64,
) -> Result<EscrowResponse, EnclaveError> {
    handle_snapshot(
        &EscrowSessionSnapshot::new(completed),
        context,
        command,
        key_epoch,
    )
    .await
}
/// Authenticated execution. No session state mutex is held across application
/// callbacks or network awaits; a bounded reservation provides single-flight
/// preparation and rejects changed retries before invoking the verifier.
pub(crate) async fn handle_snapshot(
    completed: &EscrowSessionSnapshot,
    context: &EnclaveSharedContext,
    command: &EscrowCommand,
    key_epoch: u64,
) -> Result<EscrowResponse, EnclaveError> {
    context
        .escrow_capabilities
        .require_escrow()
        .map_err(invalid)?;
    let processor = completed.musig_processor();
    let metadata = processor.get_session_metadata_public();
    let manifest = metadata
        .authorization_manifest
        .as_ref()
        .ok_or_else(|| invalid("Escrow operations require an authorized manifest"))?;
    manifest.verify().map_err(invalid)?;
    if command.context.escrow.keygen_session_id != completed.session_id
        || manifest.manifest.keygen_session_id != completed.session_id
    {
        return Err(invalid("Escrow command belongs to another keygen session"));
    }
    let user = &command.context.escrow.user_id;
    let participant = processor
        .get_user_session_data(user)
        .ok_or_else(|| invalid("Escrow participant is not held by this enclave"))?;
    let registration = participant
        .escrow
        .as_ref()
        .ok_or_else(|| invalid("Participant did not authorize generic escrow"))?;
    let public = metadata
        .participant_public_keys
        .get(user)
        .ok_or_else(|| invalid("Missing registered escrow public key"))?;
    validate_registration(manifest, user, &public.serialize(), registration)?;
    let policy = &registration.policy;
    context
        .escrow_verifiers
        .validate_registration(RegistrationView {
            manifest,
            policy,
            restoring: true,
        })?;
    if !completed.keygen_complete {
        let unbound = command
            .context
            .action_id
            .as_ref()
            .and_then(|id| policy.policy.grants.get(id))
            .is_some_and(|grant| grant.unbound);
        if !unbound
            || !matches!(
                command.context.operation,
                Operation::Prepare | Operation::Execute
            )
        {
            return Err(invalid(
                "Before keygen completes, only an unbound permission may prepare or execute",
            ));
        }
    }
    if command.context.escrow != policy.policy.context
        || command.context.policy_digest != policy.policy.digest().map_err(invalid)?
    {
        return Err(invalid(
            "Escrow command differs from registered immutable policy",
        ));
    }
    command
        .verify(&command.context, &manifest.manifest.signing_pubkey)
        .map_err(invalid)?;
    let request_key = (user.clone(), command.context.request_id);
    let request_digest = command.digest().map_err(invalid)?;
    let reservation_key = (
        user.clone(),
        command
            .context
            .action_id
            .clone()
            .unwrap_or_else(|| "@bind".into()),
    );
    let _reservation = loop {
        let waiter = {
            let mut state = metadata
                .escrow_state
                .inner
                .lock()
                .map_err(|_| invalid("Escrow state lock poisoned"))?;
            bind_policy(&mut state, policy)?;
            if state
                .inflight_request_ids
                .get(&request_key)
                .is_some_and(|digest| *digest != request_digest)
            {
                return Err(invalid(
                    "In-flight request identity was reused with different inputs",
                ));
            }
            if state.executions.values().any(|executed| {
                executed.prepared.binding.context.user_id == *user
                    && executed.original_request_id == command.context.request_id
                    && executed.original_request_digest != request_digest
            }) {
                return Err(invalid(
                    "Successful execution request identity was reused with changed inputs",
                ));
            }
            if let Some((digest, reply)) = state.requests.get(&request_key) {
                if *digest != request_digest {
                    return Err(invalid("Escrow request ID was reused with changed inputs"));
                }
                if reply.context.enclave_key_epoch == key_epoch {
                    return Ok(reply.clone());
                }
                let mut receipt_context = reply.context.clone();
                receipt_context.enclave_key_epoch = key_epoch;
                let secret = Zeroizing::new(
                    <[u8; 32]>::try_from(context.private_key.as_slice())
                        .map_err(|_| invalid("Invalid enclave signing key"))?,
                );
                return EscrowResponse::sign(
                    receipt_context,
                    reply.output.clone(),
                    reply.sealed_state.clone(),
                    &secret,
                )
                .map_err(invalid);
            }
            if command.context.operation != Operation::Execute
                && state.requests.keys().filter(|(id, _)| id == user).count()
                    >= escrow::MAX_PREPARATION_REQUESTS_PER_PARTICIPANT
            {
                return Err(preparation_exhausted(
                    "Participant preparation request budget reached",
                ));
            }
            if let Some((digest, notify)) = state.inflight.get(&reservation_key) {
                if *digest != request_digest {
                    return Err(invalid(
                        "Escrow permission has an in-flight request with different inputs",
                    ));
                }
                // notify_waiters is retained by OwnedNotified created before unlock.
                Some(notify.clone().notified_owned())
            } else {
                if command.context.operation != Operation::Execute
                    && state.cached_response_bytes
                        + (state.inflight.len() + 1) * MAX_CACHED_RESPONSE_BYTES
                        > MAX_REQUEST_CACHE_BYTES
                {
                    return Err(preparation_exhausted(
                        "Session preparation response cache budget reached",
                    ));
                }
                state
                    .inflight_request_ids
                    .insert(request_key.clone(), request_digest);
                state.inflight.insert(
                    reservation_key.clone(),
                    (request_digest, Arc::new(tokio::sync::Notify::new())),
                );
                None
            }
        };
        if let Some(waiter) = waiter {
            waiter.await;
        } else {
            break Reservation {
                state: metadata.escrow_state.clone(),
                key: reservation_key,
                request_key: request_key.clone(),
            };
        }
    };
    let participant_keys = metadata
        .participant_public_keys
        .iter()
        .map(|(id, key)| {
            Ok((
                id.clone(),
                PublicKeyBytes::new(&key.serialize()).map_err(invalid)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, EnclaveError>>()?;
    let (result, new_binding, new_preparation, new_execution) = match command.context.operation {
        Operation::Bind => {
            let request: BindEscrowRequest =
                decrypt_request(completed.session_secret(), &command.encrypted_request)?;
            request
                .verify(&policy.policy.context, &public.serialize())
                .map_err(invalid)?;
            if request.policy.policy.digest().map_err(invalid)? != command.context.policy_digest {
                return Err(invalid(
                    "Binding tried to replace the registered escrow policy",
                ));
            }
            // Authenticate the full application roster once before sealing only
            // its commitments. Restore checks those commitments against actual
            // local deposits and the complete signed registration assignments.
            let mut participant_policy_digests = BTreeMap::new();
            for (user, required) in &request.participant_policies {
                let key = metadata
                    .participant_public_keys
                    .get(user)
                    .ok_or_else(|| invalid("Foreign required escrow participant"))?;
                required
                    .verify(
                        &expected_context(manifest, user, &required.policy.context)?,
                        &key.serialize(),
                    )
                    .map_err(invalid)?;
                participant_policy_digests
                    .insert(user.clone(), required.policy.digest().map_err(invalid)?);
            }
            let mut binding = Binding {
                context: policy.policy.context.clone(),
                policy_digest: command.context.policy_digest,
                enclave_id: context.enclave_id,
                participant_policy_digests,
                application_state: Payload::default(),
            };
            if policy.policy.verifier.is_some()
                && !binding.participant_policy_digests.contains_key(user)
            {
                return Err(invalid("Application binding must include its own policy"));
            }
            validate_roster(processor, &binding)?;
            if let Some(selection) = &policy.policy.verifier {
                binding.application_state = context
                    .escrow_verifiers
                    .get(&selection.id, selection.version)?
                    .bind(
                        BindView {
                            manifest,
                            policy,
                            participant_policies: &request.participant_policies,
                            participant_public_keys: &participant_keys,
                        },
                        &request.binding_data,
                    )?;
            } else if !request.binding_data.as_bytes().is_empty() {
                return Err(invalid(
                    "Built-in escrow cannot interpret application binding data",
                ));
            }
            let reply = response(
                context,
                command,
                key_epoch,
                Payload::encode(&escrow::protocol::BindingOutput {
                    binding_data_digest: escrow::sha256(request.binding_data.as_bytes()),
                    participant_policy_digests: binding.participant_policy_digests.clone(),
                })
                .map_err(invalid)?,
                SealedState::Bound {
                    binding: binding.clone(),
                },
            )?;
            (reply, Some(binding), None, None)
        }
        Operation::Prepare => {
            let request: PrepareEscrowRequest =
                decrypt_request(completed.session_secret(), &command.encrypted_request)?;
            request.validate(&policy.policy).map_err(invalid)?;
            let grant = &policy.policy.grants[&request.action_id];
            let binding = if grant.unbound {
                if !request.binding_receipt.as_bytes().is_empty() {
                    return Err(invalid("An unbound permission takes no binding receipt"));
                }
                unbound_binding(policy, context.enclave_id)?
            } else {
                let SealedState::Bound { binding } = unseal(context, &request.binding_receipt)?
                else {
                    return Err(invalid("Expected bound escrow receipt"));
                };
                binding
            };
            validate_binding(&binding, command)?;
            validate_roster(processor, &binding)?;
            let mut prior = BTreeMap::new();
            let mut repeated = None;
            for receipt in &request.prior_preparation_receipts {
                let prior_prepared = match unseal(context, receipt)? {
                    SealedState::Prepared { prepared } => prepared,
                    SealedState::Executed { executed } => executed.prepared,
                    _ => return Err(invalid("Expected prior prepared action")),
                };
                if prior_prepared.binding != binding
                    || prior.contains_key(&prior_prepared.action_id)
                {
                    return Err(invalid(
                        "Prior preparation belongs to another binding or repeats a permission",
                    ));
                }
                let previous_grant = policy
                    .policy
                    .grants
                    .get(&prior_prepared.action_id)
                    .ok_or_else(|| invalid("Unknown prior permission"))?;
                previous_grant
                    .operation
                    .validate_action(&prior_prepared.action, &policy.policy)
                    .map_err(invalid)?;
                if prior_prepared.action_id == request.action_id {
                    let signing_retry = grant.repetition == Repetition::RepeatIdenticalSigningScope
                        && matches!(prior_prepared.action, Action::Sign { .. })
                        && prior_prepared.attempt.signing_session_id
                            != request.attempt.signing_session_id;
                    let release_renewal = grant.preparation
                        == PreparationPolicy::RenewableIdenticalAction
                        && !matches!(prior_prepared.action, Action::Sign { .. });
                    if !(signing_retry || release_renewal)
                        || prior_prepared.attempt.attempt_id == request.attempt.attempt_id
                    {
                        return Err(invalid("Renewal requires participant consent, an authenticated predecessor and a fresh attempt"));
                    }
                    repeated = Some(prior_prepared.clone());
                } else if prior_prepared.attempt != request.attempt {
                    return Err(invalid("Sibling preparation belongs to another attempt"));
                }
                prior.insert(
                    prior_prepared.action_id.clone(),
                    verifier_action(&prior_prepared),
                );
            }
            {
                let state = metadata
                    .escrow_state
                    .inner
                    .lock()
                    .map_err(|_| invalid("Escrow state lock poisoned"))?;
                if grant.preparation == PreparationPolicy::RenewableIdenticalAction
                    && state
                        .executions
                        .contains_key(&(user.clone(), request.action_id.clone()))
                {
                    return Err(invalid("Cannot renew a release after successful execution"));
                }
                if let Some(old) = state
                    .preparations
                    .get(&(user.clone(), request.action_id.clone()))
                {
                    let fresh = grant.repetition == Repetition::VerifierAuthorizedAttempts
                        && old.binding == binding
                        && old.attempt.attempt_id != request.attempt.attempt_id;
                    if !fresh && repeated.as_ref() != Some(old) {
                        return Err(invalid("Permission already prepared; retry original request or present its exact preparation"));
                    }
                }
            }
            let generation = repeated.as_ref().map_or(Ok(0), |old| {
                old.generation
                    .checked_add(1)
                    .ok_or_else(|| invalid("Preparation generation exhausted"))
            })?;
            if grant.preparation == PreparationPolicy::RenewableIdenticalAction
                && generation >= escrow::MAX_PREPARATIONS_PER_ACTION
            {
                return Err(preparation_exhausted(
                    "Release preparation candidate limit reached",
                ));
            }
            let resolved = match &grant.condition {
                Condition::VerifierRule { rule } => {
                    let selection = policy
                        .policy
                        .verifier
                        .as_ref()
                        .ok_or_else(|| invalid("Missing verifier"))?;
                    tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        context
                            .escrow_verifiers
                            .get(&selection.id, selection.version)?
                            .prepare(
                                PreparationView {
                                    manifest,
                                    policy,
                                    rule,
                                    permission_id: &request.action_id,
                                    attempt: &request.attempt,
                                    bound_state: &binding.application_state,
                                    participant_public_keys: &participant_keys,
                                    prior_preparations: &prior,
                                },
                                &request.action_parameters,
                            ),
                    )
                    .await
                    .map_err(|_| invalid("Escrow verifier preparation timed out"))??
                }
                _ => VerifierPreparedAction {
                    action: request
                        .action
                        .ok_or_else(|| invalid("Missing exact action"))?,
                    application_state: Payload::default(),
                    output: Payload::encode(&command.context).map_err(invalid)?,
                },
            };
            if repeated
                .as_ref()
                .is_some_and(|old| old.action != resolved.action)
            {
                return Err(invalid(
                    "Renewed preparation must preserve the identical authorized action",
                ));
            }
            let predecessor = repeated.as_ref().map(preparation_digest).transpose()?;
            let prepared = PreparedAction {
                binding,
                action_id: request.action_id,
                attempt: request.attempt,
                action: resolved.action,
                application_state: resolved.application_state,
                output: resolved.output,
                predecessor,
                generation,
            };
            validate_prepared(&prepared, command, policy)?;
            let reply = response(
                context,
                command,
                key_epoch,
                prepared.output.clone(),
                SealedState::Prepared {
                    prepared: prepared.clone(),
                },
            )?;
            // An unbound permission's binding is derived, never installed.
            let binding = (!grant.unbound).then(|| prepared.binding.clone());
            (reply, binding, Some(prepared), None)
        }
        Operation::Execute => {
            let request: ExecuteEscrowRequest =
                decrypt_request(completed.session_secret(), &command.encrypted_request)?;
            request.validate().map_err(invalid)?;
            let mut recovered_receipt = None;
            let mut executed = match unseal(context, &request.prepared_receipt)? {
                SealedState::Bound { .. } => {
                    return Err(invalid("Execution requires prepared action"))
                }
                SealedState::Executed { executed } => {
                    recovered_receipt = Some(request.prepared_receipt.clone());
                    validate_prepared(&executed.prepared, command, policy)?;
                    validate_roster(processor, &executed.prepared.binding)?;
                    validate_live_execution(&metadata.escrow_state, &executed.prepared, policy)?;
                    if matches!(request.proof, ConditionProof::None) {
                        restore_execution(context, manifest, policy, &executed.prepared).await?;
                    } else if verify_execution(
                        context,
                        manifest,
                        policy,
                        &executed.prepared,
                        &request.proof,
                    )
                    .await?
                        != executed.execution_digest
                    {
                        return Err(invalid("Recovered proof differs from successful execution"));
                    }
                    executed
                }
                SealedState::Prepared { prepared } => {
                    validate_prepared(&prepared, command, policy)?;
                    validate_roster(processor, &prepared.binding)?;
                    validate_live_execution(&metadata.escrow_state, &prepared, policy)?;
                    let execution_digest =
                        verify_execution(context, manifest, policy, &prepared, &request.proof)
                            .await?;
                    let old = metadata
                        .escrow_state
                        .inner
                        .lock()
                        .map_err(|_| invalid("Escrow state lock poisoned"))?
                        .executions
                        .get(&(user.clone(), prepared.action_id.clone()))
                        .cloned();
                    if let Some(old) = old {
                        if (old.prepared != prepared || old.execution_digest != execution_digest)
                            && !fresh_attempt(policy, &old.prepared, &prepared)
                            && !(prepared.predecessor.is_some()
                                && matches!(prepared.action, Action::Sign { .. })
                                && old.prepared.action == prepared.action
                                && old.prepared.attempt.signing_session_id
                                    != prepared.attempt.signing_session_id)
                        {
                            return Err(invalid(
                                "Permission already executed under another attempt or proof",
                            ));
                        }
                        if old.prepared == prepared && old.execution_digest == execution_digest {
                            old
                        } else {
                            let output = execute_output(
                                &prepared,
                                registration,
                                participant.private_key.as_ref().map(|key| key.as_bytes()),
                            )?;
                            ExecutedAction {
                                prepared,
                                execution_digest,
                                original_request_id: command.context.request_id,
                                original_request_digest: request_digest,
                                output,
                            }
                        }
                    } else {
                        let output = execute_output(
                            &prepared,
                            registration,
                            participant.private_key.as_ref().map(|key| key.as_bytes()),
                        )?;
                        ExecutedAction {
                            prepared,
                            execution_digest,
                            original_request_id: command.context.request_id,
                            original_request_digest: request_digest,
                            output,
                        }
                    }
                }
            };
            let key = (user.clone(), executed.prepared.action_id.clone());
            let existing_receipt = {
                let state = metadata
                    .escrow_state
                    .inner
                    .lock()
                    .map_err(|_| invalid("Escrow state lock poisoned"))?;
                state
                    .executions
                    .get(&key)
                    .filter(|old| {
                        old.prepared == executed.prepared
                            && old.execution_digest == executed.execution_digest
                    })
                    .and_then(|old| {
                        state
                            .execution_receipts
                            .get(&key)
                            .map(|receipt| (old.clone(), receipt.clone()))
                    })
            };
            let canonical_receipt = match existing_receipt {
                Some((existing, receipt)) => {
                    executed = existing;
                    receipt
                }
                None => match recovered_receipt {
                    Some(receipt) => receipt,
                    None => seal_state(
                        context,
                        SealedState::Executed {
                            executed: executed.clone(),
                        },
                    )?,
                },
            };
            let reply = signed_response(
                context,
                command,
                key_epoch,
                Payload::encode(&executed.output).map_err(invalid)?,
                canonical_receipt,
            )?;
            let unbound = policy
                .policy
                .grants
                .get(&executed.prepared.action_id)
                .is_some_and(|grant| grant.unbound);
            (
                reply,
                (!unbound).then(|| executed.prepared.binding.clone()),
                Some(executed.prepared.clone()),
                Some(executed),
            )
        }
    };
    let mut state = metadata
        .escrow_state
        .inner
        .lock()
        .map_err(|_| invalid("Escrow state lock poisoned"))?;
    if state
        .inflight
        .get(&_reservation.key)
        .is_none_or(|(digest, _)| *digest != request_digest)
    {
        return Err(invalid("Escrow preparation reservation changed"));
    }
    // Check all transitions before any commit, so a failed install has no effect.
    let mut next = SessionState {
        bindings: state.bindings.clone(),
        permits: state.permits.clone(),
        preparations: state.preparations.clone(),
        executions: state.executions.clone(),
        execution_receipts: state.execution_receipts.clone(),
        required_bindings: state.required_bindings.clone(),
        ..Default::default()
    };
    if let Some(binding) = new_binding {
        install_binding(&mut next, &binding)?;
    }
    if let Some(prepared) = new_preparation {
        install_preparation(
            &mut next,
            &prepared,
            policy,
            command.context.operation == Operation::Execute,
        )?;
    }
    if let Some(executed) = new_execution {
        install_execution(&mut next, &executed, policy)?;
        next.execution_receipts.insert(
            (user.clone(), executed.prepared.action_id.clone()),
            result.sealed_state.clone(),
        );
    }
    state.required_bindings = next.required_bindings;
    state.preparations = next.preparations;
    state.executions = next.executions;
    state.execution_receipts = next.execution_receipts;
    state.permits = next.permits;
    if command.context.operation != Operation::Execute {
        state.cached_response_bytes += result.output.as_bytes().len()
            + result.sealed_state.as_bytes().len()
            + result.enclave_signature.len()
            + 4096;
        state
            .requests
            .insert(request_key, (request_digest, result.clone()));
    }
    Ok(result)
}

fn encrypt_release(recipient: &escrow::Recipient, bytes: &[u8]) -> Result<Payload, EnclaveError> {
    let key = secp256k1::PublicKey::from_slice(recipient.encryption_public_key.as_bytes())
        .map_err(invalid)?;
    Payload::new(SecureCrypto::ecies_encrypt(&key, bytes).map_err(invalid)?).map_err(invalid)
}

fn execute_output(
    prepared: &PreparedAction,
    registration: &EscrowRegistration,
    signing_key: Option<&[u8]>,
) -> Result<ExecutionOutput, EnclaveError> {
    match &prepared.action {
        Action::Sign { scope } => Ok(ExecutionOutput::SigningPermit {
            signing_session_id: prepared
                .attempt
                .signing_session_id
                .clone()
                .ok_or_else(|| invalid("Missing signing session"))?,
            scope_digest: authorization_digest("escrow-signing-scope-v1", scope)
                .map_err(invalid)?,
        }),
        Action::SignBip340 { scope } => {
            let secret = Zeroizing::new(
                <[u8; 32]>::try_from(
                    signing_key.ok_or_else(|| invalid("Signing key is unavailable"))?,
                )
                .map_err(|_| invalid("Invalid escrow signing key length"))?,
            );
            let secp = secp256k1::Secp256k1::new();
            let key = secp256k1::SecretKey::from_byte_array(*secret).map_err(invalid)?;
            let keypair = secp256k1::Keypair::from_secret_key(&secp, &key);
            if keypair.public_key().serialize().as_slice() != scope.public_key.as_bytes() {
                return Err(invalid(
                    "BIP340 signing key differs from participant authorization",
                ));
            }
            // Script-path signatures use the untweaked key. Keypair handles its odd-Y parity.
            let signatures = scope
                .items
                .iter()
                .map(|item| escrow::protocol::Bip340Signature {
                    item_id: item.item_id,
                    signature: secp
                        .sign_schnorr(&item.digest, &keypair)
                        .to_byte_array()
                        .to_vec(),
                })
                .collect();
            Ok(ExecutionOutput::Bip340Signatures {
                public_key: scope.public_key.clone(),
                signatures,
            })
        }
        Action::ReleaseSecret { name, recipient } => {
            let secret = registration
                .secrets
                .get(name)
                .ok_or_else(|| invalid("Authorized escrow secret is unavailable"))?;
            registration
                .policy
                .policy
                .secrets
                .get(name)
                .ok_or_else(|| invalid("Missing secret commitment"))?
                .verify(secret)
                .map_err(invalid)?;
            Ok(ExecutionOutput::ReleasedSecret {
                name: name.clone(),
                recipient: recipient.clone(),
                encrypted_secret: encrypt_release(recipient, secret)?,
            })
        }
        Action::ReleaseSigningKey {
            public_key,
            recipient,
        } => {
            let secret = Zeroizing::new(
                <[u8; 32]>::try_from(
                    signing_key.ok_or_else(|| invalid("Signing key is unavailable"))?,
                )
                .map_err(|_| invalid("Invalid escrow signing key length"))?,
            );
            let key = secp256k1::SecretKey::from_byte_array(*secret).map_err(invalid)?;
            let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &key);
            if public.serialize().as_slice() != public_key.as_bytes() {
                return Err(invalid(
                    "Escrow release key differs from participant authorization",
                ));
            }
            Ok(ExecutionOutput::ReleasedSigningKey {
                public_key: public_key.clone(),
                recipient: recipient.clone(),
                encrypted_key: encrypt_release(recipient, secret.as_ref())?,
            })
        }
    }
}

#[cfg(test)]
#[path = "escrow_tests.rs"]
mod tests;
