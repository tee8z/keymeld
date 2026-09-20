//! Low-level confidential command transport. Only `envelope` is sent to the
//! gateway; prepared command records belong in the authorized application's
//! private storage and contain private command/verification data.
use crate::{AuthorizationCredentials, SdkError};
use keymeld_core::{
    confidential::{
        ConfidentialRequest, ConfidentialResponse, EnclaveEnvelope, RoutingHeader,
        TRANSPORT_VERSION,
    },
    protocol::{Command, Outcome},
    EnclaveId,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Constructed only after the client's attestation policy verifies the key.
#[derive(Clone)]
pub struct PinnedEnclave {
    enclave_id: EnclaveId,
    public_key: Vec<u8>,
    key_epoch: u64,
}

impl PinnedEnclave {
    pub fn enclave_id(&self) -> EnclaveId {
        self.enclave_id
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub fn key_epoch(&self) -> u64 {
        self.key_epoch
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedConfidentialCommand {
    envelope: EnclaveEnvelope,
    request: ConfidentialRequest,
}

impl PreparedConfidentialCommand {
    pub fn envelope(&self) -> &EnclaveEnvelope {
        &self.envelope
    }
    pub fn request(&self) -> &ConfidentialRequest {
        &self.request
    }

    fn validate(&self, recipient: &PinnedEnclave) -> Result<(), SdkError> {
        self.envelope.validate_bounds()?;
        if self.envelope.destination_enclave != recipient.enclave_id {
            return Err(SdkError::InvalidInput(
                "Confidential recipient mismatch".into(),
            ));
        }
        self.request.verify(
            &self.envelope.header(),
            &recipient.public_key,
            recipient.key_epoch,
        )?;
        Ok(())
    }

    /// Verify the attested enclave signature and complete request/response binding
    /// before exposing any native result, including detailed errors.
    pub fn decrypt_response(
        &self,
        recipient: &PinnedEnclave,
        response: &EnclaveEnvelope,
        response_key: &AuthorizationCredentials,
    ) -> Result<Outcome, SdkError> {
        self.validate(recipient)?;
        let secret_bytes = Zeroizing::new(response_key.export_secret());
        let secret = secp256k1::SecretKey::from_byte_array(*secret_bytes)
            .map_err(|_| SdkError::InvalidInput("Invalid confidential response key".into()))?;
        Ok(ConfidentialResponse::decrypt(response, &self.request, &secret)?.outcome)
    }
}

#[cfg(feature = "client")]
pub struct ConfidentialTransport<'a> {
    client: &'a crate::KeyMeldClient,
}

#[cfg(feature = "client")]
impl<'a> ConfidentialTransport<'a> {
    pub fn new(client: &'a crate::KeyMeldClient) -> Self {
        Self { client }
    }

    pub async fn attest(&self, enclave_id: EnclaveId) -> Result<PinnedEnclave, SdkError> {
        let verified = self
            .client
            .health()
            .get_enclave_key(enclave_id.as_u32())
            .await?;
        let public_key = hex::decode(verified.public_key)
            .map_err(|_| SdkError::InvalidInput("Invalid attested enclave key".into()))?;
        Ok(PinnedEnclave {
            enclave_id,
            public_key,
            key_epoch: verified.key_epoch,
        })
    }

    pub fn prepare(
        &self,
        recipient: &PinnedEnclave,
        opaque_route_id: Uuid,
        command: Command,
        authority: &AuthorizationCredentials,
        response_key: &AuthorizationCredentials,
    ) -> Result<PreparedConfidentialCommand, SdkError> {
        prepare(recipient, opaque_route_id, command, authority, response_key)
    }

    /// Exact retries reuse `prepared`, rather than regenerating IDs or encryption.
    pub async fn execute(
        &self,
        recipient: &PinnedEnclave,
        prepared: &PreparedConfidentialCommand,
        response_key: &AuthorizationCredentials,
    ) -> Result<Outcome, SdkError> {
        prepared.validate(recipient)?;
        let response = self
            .client
            .http()
            .post_bounded(
                &self.client.url("/api/v1/confidential"),
                prepared.envelope(),
                keymeld_core::confidential::MAX_WIRE_BYTES,
            )
            .await?;
        prepared.decrypt_response(recipient, &response, response_key)
    }
}

pub fn prepare(
    recipient: &PinnedEnclave,
    opaque_route_id: Uuid,
    command: Command,
    authority: &AuthorizationCredentials,
    response_key: &AuthorizationCredentials,
) -> Result<PreparedConfidentialCommand, SdkError> {
    let secret = Zeroizing::new(authority.export_secret());
    let request = ConfidentialRequest::sign(
        RoutingHeader {
            transport_version: TRANSPORT_VERSION,
            destination_enclave: recipient.enclave_id,
            opaque_route_id,
            correlation_id: String::new(),
        },
        recipient.public_key.clone(),
        recipient.key_epoch,
        &secret,
        response_key.public_key_bytes(),
        command,
    )?;
    let envelope = request.encrypt()?;
    Ok(PreparedConfidentialCommand { envelope, request })
}
