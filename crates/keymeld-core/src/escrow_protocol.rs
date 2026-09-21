//! Versioned wire envelopes. Every service can decode these types even when
//! execution is disabled; service-owned capability checks must fail closed.
use super::*;
use crate::EnclaveId;
use base64::{engine::general_purpose::STANDARD as PAYLOAD_ENCODING, Engine};

/// Length-bounded opaque bytes. Encrypted requests/receipts remain opaque to the
/// gateway. Callers must still bound the entire encoded transport message.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Payload(Vec<u8>);
impl Serialize for Payload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // Policies and sealed receipts nest opaque payloads. JSON integer
            // arrays multiply their size at every nesting level.
            let encoded = Zeroizing::new(PAYLOAD_ENCODING.encode(&self.0));
            serializer.serialize_str(&encoded)
        } else {
            self.0.serialize(serializer)
        }
    }
}
impl<'de> Deserialize<'de> for Payload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = if deserializer.is_human_readable() {
            let encoded = Zeroizing::new(String::deserialize(deserializer)?);
            if encoded.len() > MAX_PAYLOAD_BYTES.div_ceil(3) * 4 {
                return Err(serde::de::Error::custom(
                    "Escrow payload exceeds size limit",
                ));
            }
            PAYLOAD_ENCODING
                .decode(encoded.as_bytes())
                .map_err(serde::de::Error::custom)?
        } else {
            Vec::<u8>::deserialize(deserializer)?
        };
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}
impl Payload {
    pub fn new(bytes: Vec<u8>) -> Result<Self, KeyMeldError> {
        Self::try_from(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn encode<T: Serialize>(value: &T) -> Result<Self, KeyMeldError> {
        Self::new(
            serde_json::to_vec(value)
                .map_err(|e| KeyMeldError::SerializationError(e.to_string()))?,
        )
    }
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, KeyMeldError> {
        super::decode(&self.0)
    }
}
impl TryFrom<Vec<u8>> for Payload {
    type Error = KeyMeldError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(invalid("Escrow payload exceeds size limit"));
        }
        Ok(Self(bytes))
    }
}
impl From<Payload> for Vec<u8> {
    fn from(mut payload: Payload) -> Self {
        std::mem::take(&mut payload.0)
    }
}
impl Drop for Payload {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Payload")
            .field("length", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Bind,
    Prepare,
    Execute,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    pub schema_version: u16,
    pub operation: Operation,
    pub escrow: EscrowContext,
    pub policy_digest: [u8; 32],
    pub request_id: Uuid,
    pub action_id: Option<String>,
    pub attempt: Option<ActionAttempt>,
}
impl RequestContext {
    pub fn validate(&self) -> Result<(), KeyMeldError> {
        version(self.schema_version)?;
        self.escrow.validate()?;
        if self.request_id.is_nil() {
            return Err(invalid("Escrow request identity must not be nil"));
        }
        match (&self.operation, &self.action_id, &self.attempt) {
            (Operation::Bind, None, None) => Ok(()),
            (Operation::Prepare | Operation::Execute, Some(action), Some(attempt))
                if !attempt.attempt_id.is_nil() =>
            {
                name(action)
            }
            _ => Err(invalid(
                "Escrow operation context has invalid action or attempt",
            )),
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowCommand {
    pub context: RequestContext,
    pub encrypted_request: Payload,
    pub authorization: Vec<u8>,
}
impl EscrowCommand {
    pub fn sign(
        context: RequestContext,
        encrypted_request: Payload,
        authority_secret: &[u8; 32],
    ) -> Result<Self, KeyMeldError> {
        context.validate()?;
        if encrypted_request.as_bytes().is_empty() {
            return Err(invalid("Escrow request must be encrypted"));
        }
        let authorization = sign_authorization(
            authority_secret,
            "escrow-request-v1",
            &(&context, &encrypted_request),
        )?;
        Ok(Self {
            context,
            encrypted_request,
            authorization,
        })
    }
    pub fn verify(
        &self,
        expected: &RequestContext,
        authority_public_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        self.context.validate()?;
        if &self.context != expected || self.encrypted_request.as_bytes().is_empty() {
            return Err(invalid(
                "Escrow command belongs to a different request context",
            ));
        }
        verify_authorization(
            authority_public_key,
            "escrow-request-v1",
            &(&self.context, &self.encrypted_request),
            &self.authorization,
        )
    }
    pub fn digest(&self) -> Result<[u8; 32], KeyMeldError> {
        self.context.validate()?;
        authorization_digest(
            "escrow-command-v1",
            &(&self.context, &self.encrypted_request),
        )
    }
}

/// Plaintext of an encrypted bind command. Deposits belong in participant ECIES
/// registration, never in a session-encrypted request readable by a coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindEscrowRequest {
    pub schema_version: u16,
    pub policy: SignedEscrowPolicy,
    /// Exact base escrow context. An optional trusted adapter must verify its
    /// own preauthorized template semantics instead of accepting host approval.
    pub application_context: Payload,
    /// Complete participant-signed policy roster, authenticated by the command authority.
    pub participant_policies: BTreeMap<UserId, SignedEscrowPolicy>,
    pub binding_data: Payload,
}
impl BindEscrowRequest {
    pub fn verify(
        &self,
        context: &EscrowContext,
        participant_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        version(self.schema_version)?;
        self.policy.verify(context, participant_key)?;
        if sha256(self.application_context.as_bytes()) != context.application.commitment {
            return Err(invalid("Escrow application context commitment differs"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareEscrowRequest {
    pub schema_version: u16,
    pub binding_receipt: Payload,
    pub action_id: String,
    pub attempt: ActionAttempt,
    /// Built-in exact grants use this value; verifier rules derive it internally.
    pub action: Option<Action>,
    pub action_parameters: Payload,
    pub prior_preparation_receipts: Vec<Payload>,
}
impl PrepareEscrowRequest {
    pub fn validate(&self, policy: &EscrowPolicy) -> Result<(), KeyMeldError> {
        version(self.schema_version)?;
        policy.validate()?;
        if self.prior_preparation_receipts.len() > MAX_ACTIONS {
            return Err(invalid("Too many prior preparations"));
        }
        name(&self.action_id)?;
        if self.binding_receipt.as_bytes().is_empty() {
            return Err(invalid("Escrow binding receipt is required"));
        }
        let grant = policy
            .grants
            .get(&self.action_id)
            .ok_or_else(|| invalid("Unknown escrow permission"))?;
        match (&grant.condition, &self.action) {
            (Condition::VerifierRule { .. }, None) => {
                if self.attempt.attempt_id.is_nil() {
                    return Err(invalid("Escrow attempt identity must not be nil"));
                }
            }
            (Condition::VerifierRule { .. }, Some(_)) => {
                return Err(invalid("Verifier action cannot be supplied by the caller"))
            }
            (_, Some(action)) => {
                self.attempt.validate(action, &policy.context)?;
                grant.operation.validate_action(action, policy)?;
                if !self.action_parameters.as_bytes().is_empty() {
                    return Err(invalid(
                        "Built-in action has unexpected application parameters",
                    ));
                }
            }
            _ => return Err(invalid("Built-in permission requires its exact action")),
        }
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteEscrowRequest {
    pub schema_version: u16,
    pub prepared_receipt: Payload,
    pub proof: ConditionProof,
}
impl ExecuteEscrowRequest {
    pub fn validate(&self) -> Result<(), KeyMeldError> {
        version(self.schema_version)?;
        if self.prepared_receipt.as_bytes().is_empty() {
            return Err(invalid("Prepared escrow receipt is required"));
        }
        if let ConditionProof::HashlockPreimage { preimage } = &self.proof {
            check_secret_length(preimage.len())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptContext {
    pub schema_version: u16,
    pub enclave_id: EnclaveId,
    pub enclave_key_epoch: u64,
    pub request: RequestContext,
    pub request_digest: [u8; 32],
}
impl ReceiptContext {
    pub fn validate(&self) -> Result<(), KeyMeldError> {
        version(self.schema_version)?;
        self.request.validate()
    }
}
/// The signature authenticates all public output and the exact sealed state.
/// The seal must use an enclave-only key; the shared session secret is not a seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowResponse {
    pub context: ReceiptContext,
    pub output: Payload,
    pub sealed_state: Payload,
    pub enclave_signature: Vec<u8>,
}
impl EscrowResponse {
    pub fn sign(
        context: ReceiptContext,
        output: Payload,
        sealed_state: Payload,
        enclave_secret: &[u8; 32],
    ) -> Result<Self, KeyMeldError> {
        context.validate()?;
        if sealed_state.as_bytes().is_empty() {
            return Err(invalid("Escrow response requires authenticated state"));
        }
        let enclave_signature = sign_authorization(
            enclave_secret,
            "escrow-response-v1",
            &(&context, &output, &sealed_state),
        )?;
        Ok(Self {
            context,
            output,
            sealed_state,
            enclave_signature,
        })
    }
    pub fn verify(
        &self,
        expected: &ReceiptContext,
        pinned_enclave_public_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        self.context.validate()?;
        if &self.context != expected || self.sealed_state.as_bytes().is_empty() {
            return Err(invalid(
                "Escrow response belongs to a different issuer, request or action",
            ));
        }
        verify_authorization(
            pinned_enclave_public_key,
            "escrow-response-v1",
            &(&self.context, &self.output, &self.sealed_state),
            &self.enclave_signature,
        )
    }
}

/// Generic encrypted execution results contain only explicitly authorized data.
/// A BIP340 signature over one item of a [`crate::escrow::Bip340Scope`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bip340Signature {
    pub item_id: Uuid,
    /// 64 bytes. The caller verifies it against the scope's key and the item's digest.
    pub signature: Vec<u8>,
}

/// A signing action installs a permit for one session; it never exports a key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionOutput {
    SigningPermit {
        signing_session_id: SessionId,
        scope_digest: [u8; 32],
    },
    /// One signature per authorized item, in scope order.
    Bip340Signatures {
        public_key: PublicKeyBytes,
        signatures: Vec<Bip340Signature>,
    },
    ReleasedSecret {
        name: String,
        recipient: Recipient,
        encrypted_secret: Payload,
    },
    ReleasedSigningKey {
        public_key: PublicKeyBytes,
        recipient: Recipient,
        encrypted_key: Payload,
    },
}

/// Authenticated binding facts, returned only inside confidential transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingOutput {
    pub binding_data_digest: [u8; 32],
    pub participant_policy_digests: BTreeMap<UserId, [u8; 32]>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierDescriptor {
    pub id: String,
    pub version: u16,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierInfo {
    pub descriptor: VerifierDescriptor,
    pub capabilities: Payload,
}
