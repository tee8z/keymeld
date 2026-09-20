//! Trusted, statically registered application rules inside the measured enclave.
//! These callbacks receive authenticated public inputs, never custody keys or
//! deposited secret bytes. They propose actions; the engine enforces permissions.
use keymeld_core::{
    authorization::SignedSessionManifest,
    escrow::{protocol::Payload, Action, ActionAttempt, PublicKeyBytes, SignedEscrowPolicy},
    protocol::{EnclaveError, ValidationError},
    UserId,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

pub type VerificationError = EnclaveError;
pub type VerificationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, VerificationError>> + Send + 'a>>;

pub use keymeld_core::escrow::protocol::VerifierDescriptor;

pub struct RegistrationView<'a> {
    pub manifest: &'a SignedSessionManifest,
    pub policy: &'a SignedEscrowPolicy,
    /// Existing paid preparations must remain recoverable when fresh network
    /// requests are disabled. Unknown verifier code always fails closed.
    pub restoring: bool,
}
pub struct BindView<'a> {
    pub manifest: &'a SignedSessionManifest,
    pub policy: &'a SignedEscrowPolicy,
    pub participant_policies: &'a BTreeMap<UserId, SignedEscrowPolicy>,
    pub participant_public_keys: &'a BTreeMap<UserId, PublicKeyBytes>,
}
pub struct PreparationView<'a> {
    pub manifest: &'a SignedSessionManifest,
    pub policy: &'a SignedEscrowPolicy,
    pub rule: &'a str,
    pub permission_id: &'a str,
    pub attempt: &'a ActionAttempt,
    pub bound_state: &'a Payload,
    pub participant_public_keys: &'a BTreeMap<UserId, PublicKeyBytes>,
    /// Authenticated preparations for this binding. Other permissions must share
    /// this attempt; the same permission may carry its explicitly authorized
    /// predecessor for identical-scope signing or renewable release preparation.
    pub prior_preparations: &'a BTreeMap<String, PreparedAction>,
}
pub struct ExecutionView<'a> {
    pub manifest: &'a SignedSessionManifest,
    pub policy: &'a SignedEscrowPolicy,
    pub rule: &'a str,
    pub permission_id: &'a str,
    pub attempt: &'a ActionAttempt,
    pub bound_state: &'a Payload,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAction {
    pub action: Action,
    pub application_state: Payload,
    pub output: Payload,
}

pub trait EscrowVerifier: Send + Sync {
    fn descriptor(&self) -> VerifierDescriptor;
    /// Application capabilities are exposed only through an authenticated encrypted query.
    fn capabilities(&self) -> Result<Payload, VerificationError> {
        Ok(Payload::default())
    }
    fn validate_registration(&self, context: RegistrationView<'_>)
        -> Result<(), VerificationError>;
    fn bind(
        &self,
        context: BindView<'_>,
        binding_data: &Payload,
    ) -> Result<Payload, VerificationError>;
    fn prepare<'a>(
        &'a self,
        context: PreparationView<'a>,
        action_parameters: &'a Payload,
    ) -> VerificationFuture<'a, PreparedAction>;
    /// Complete application authorization before the engine installs a permit or
    /// releases custody. The engine holds no ledger or session-map lock while
    /// awaiting this future. External witnesses must make retries idempotent by
    /// authenticated context, permission, attempt and exact prepared action;
    /// cancellation does not prove an external commit did not happen.
    fn verify_execution<'a>(
        &'a self,
        context: ExecutionView<'a>,
        prepared: &'a PreparedAction,
        evidence: &'a Payload,
    ) -> VerificationFuture<'a, ()>;
    /// Reestablish application state from an enclave-authenticated successful
    /// execution before its effect becomes available again. This is recovery of
    /// an earlier authorization, not evidence of a new payment or permission.
    /// Stateful applications must restore cross-permission invariants here;
    /// external witnesses may require reconciliation before returning success.
    fn restore_execution<'a>(
        &'a self,
        _context: ExecutionView<'a>,
        _prepared: &'a PreparedAction,
    ) -> VerificationFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// Immutable after construction. The default enclave installs no application rules.
#[derive(Default)]
pub struct VerifierRegistry {
    entries: BTreeMap<VerifierDescriptor, Arc<dyn EscrowVerifier>>,
}
impl VerifierRegistry {
    pub fn new(verifiers: Vec<Arc<dyn EscrowVerifier>>) -> Result<Self, VerificationError> {
        if verifiers.len() > 32 {
            return Err(invalid("Too many installed escrow verifiers"));
        }
        let mut entries = BTreeMap::new();
        for verifier in verifiers {
            let descriptor = verifier.descriptor();
            if descriptor.id.is_empty()
                || descriptor.id.len() > 64
                || descriptor.version == 0
                || !descriptor
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(invalid("Invalid verifier descriptor"));
            }
            if entries.insert(descriptor, verifier).is_some() {
                return Err(invalid("Duplicate verifier registration"));
            }
        }
        Ok(Self { entries })
    }
    pub fn get(
        &self,
        id: &str,
        version: u16,
    ) -> Result<&Arc<dyn EscrowVerifier>, VerificationError> {
        self.entries
            .get(&VerifierDescriptor {
                id: id.into(),
                version,
            })
            .ok_or_else(|| {
                invalid("Escrow verifier is not installed or its version is unsupported")
            })
    }
    pub fn describe(
        &self,
    ) -> Result<Vec<keymeld_core::escrow::protocol::VerifierInfo>, VerificationError> {
        self.entries
            .iter()
            .map(|(descriptor, verifier)| {
                let capabilities = verifier.capabilities()?;
                if capabilities.as_bytes().len() > 8192 {
                    return Err(invalid("Verifier capabilities exceed size limit"));
                }
                Ok(keymeld_core::escrow::protocol::VerifierInfo {
                    descriptor: descriptor.clone(),
                    capabilities,
                })
            })
            .collect()
    }
    pub fn validate_registration(
        &self,
        context: RegistrationView<'_>,
    ) -> Result<(), VerificationError> {
        context
            .policy
            .policy
            .validate()
            .map_err(|e| invalid(&e.to_string()))?;
        if let Some(selection) = &context.policy.policy.verifier {
            self.get(&selection.id, selection.version)?
                .validate_registration(context)?;
        }
        Ok(())
    }
}
impl std::fmt::Debug for VerifierRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierRegistry")
            .field("count", &self.entries.len())
            .finish_non_exhaustive()
    }
}
fn invalid(message: &str) -> VerificationError {
    EnclaveError::Validation(ValidationError::Other(message.into()))
}
