//! Authenticated gateway commands and attested, per-boot enclave responses.
use crate::{
    authorization::{authorization_digest, sign_authorization, verify_authorization},
    protocol::{Command, Outcome},
    AttestationDocument, EnclaveId, KeyMeldError,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const COMMAND_MAX_AGE_SECONDS: u64 = 300;
pub const COMMAND_MAX_FUTURE_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelRequest {
    Challenge { nonce: [u8; 32] },
    Execute(Box<SignedCommand>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelResponse {
    Challenge(Box<ChannelChallenge>),
    Executed(Box<SignedOutcome>),
    Rejected(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelChallenge {
    pub enclave_id: EnclaveId,
    pub boot_id: [u8; 32],
    pub public_key: Vec<u8>,
    pub attestation: Option<AttestationDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommand {
    pub enclave_id: EnclaveId,
    pub boot_id: [u8; 32],
    pub command: Command,
    pub signature: Vec<u8>,
}

impl SignedCommand {
    pub fn sign(
        command: Command,
        challenge: &ChannelChallenge,
        gateway_secret: &[u8; 32],
    ) -> Result<Self, KeyMeldError> {
        let signature = sign_authorization(
            gateway_secret,
            "enclave-command",
            &(challenge.enclave_id, challenge.boot_id, &command),
        )?;
        Ok(Self {
            enclave_id: challenge.enclave_id,
            boot_id: challenge.boot_id,
            command,
            signature,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], KeyMeldError> {
        authorization_digest(
            "enclave-command",
            &(self.enclave_id, self.boot_id, &self.command),
        )
    }

    pub fn verify(
        &self,
        gateway_public_key: &[u8],
        enclave_id: EnclaveId,
        boot_id: &[u8; 32],
        now: SystemTime,
    ) -> Result<(), KeyMeldError> {
        let reject = |message: &str| KeyMeldError::ValidationError(message.to_owned());
        if self.enclave_id != enclave_id || &self.boot_id != boot_id {
            return Err(reject("Command targets another enclave or enclave boot"));
        }
        let now = now
            .duration_since(UNIX_EPOCH)
            .map_err(KeyMeldError::TimeError)?;
        let created = self
            .command
            .created_at
            .duration_since(UNIX_EPOCH)
            .map_err(KeyMeldError::TimeError)?;
        if now.as_secs().saturating_sub(created.as_secs()) > COMMAND_MAX_AGE_SECONDS
            || created.as_secs().saturating_sub(now.as_secs()) > COMMAND_MAX_FUTURE_SECONDS
        {
            return Err(reject(
                "Enclave command timestamp is outside the accepted window",
            ));
        }
        verify_authorization(
            gateway_public_key,
            "enclave-command",
            &(self.enclave_id, self.boot_id, &self.command),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedOutcome {
    pub request_digest: [u8; 32],
    pub outcome: Outcome,
    pub signature: Vec<u8>,
}

impl SignedOutcome {
    pub fn sign(
        request: &SignedCommand,
        outcome: Outcome,
        enclave_secret: &[u8; 32],
    ) -> Result<Self, KeyMeldError> {
        let request_digest = request.digest()?;
        let signature = sign_authorization(
            enclave_secret,
            "enclave-outcome",
            &(request_digest, &outcome),
        )?;
        Ok(Self {
            request_digest,
            outcome,
            signature,
        })
    }

    pub fn verify(
        &self,
        request: &SignedCommand,
        enclave_public_key: &[u8],
    ) -> Result<(), KeyMeldError> {
        if self.request_digest != request.digest()?
            || self.outcome.command_id != request.command.command_id
        {
            return Err(KeyMeldError::ValidationError(
                "Enclave response does not match the command".into(),
            ));
        }
        verify_authorization(
            enclave_public_key,
            "enclave-outcome",
            &(self.request_digest, &self.outcome),
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{EnclaveCommand, EnclaveOutcome, SystemCommand, SystemOutcome};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::time::Duration;

    fn public(secret: [u8; 32]) -> Vec<u8> {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array(secret).unwrap(),
        )
        .serialize()
        .to_vec()
    }

    #[test]
    fn commands_require_the_pinned_gateway_and_current_boot_and_fresh_body() {
        let now = SystemTime::now();
        let challenge = ChannelChallenge {
            enclave_id: EnclaveId::new(1),
            boot_id: [8; 32],
            public_key: public([2; 32]),
            attestation: None,
        };
        let signed = SignedCommand::sign(
            Command::new(EnclaveCommand::System(SystemCommand::Ping)),
            &challenge,
            &[1; 32],
        )
        .unwrap();
        assert!(signed
            .verify(
                &public([1; 32]),
                challenge.enclave_id,
                &challenge.boot_id,
                now
            )
            .is_ok());
        assert!(signed
            .verify(
                &public([3; 32]),
                challenge.enclave_id,
                &challenge.boot_id,
                now
            )
            .is_err());
        assert!(signed
            .verify(&public([1; 32]), EnclaveId::new(2), &challenge.boot_id, now)
            .is_err());
        assert!(signed
            .verify(&public([1; 32]), challenge.enclave_id, &[9; 32], now)
            .is_err());
        let mut changed = signed.clone();
        changed.command.command = EnclaveCommand::System(SystemCommand::GetPublicInfo);
        assert!(changed
            .verify(
                &public([1; 32]),
                challenge.enclave_id,
                &challenge.boot_id,
                now
            )
            .is_err());
        assert!(signed
            .verify(
                &public([1; 32]),
                challenge.enclave_id,
                &challenge.boot_id,
                now + Duration::from_secs(301)
            )
            .is_err());
        assert!(signed
            .verify(
                &public([1; 32]),
                challenge.enclave_id,
                &challenge.boot_id,
                now - Duration::from_secs(31)
            )
            .is_err());
    }

    #[test]
    fn responses_cannot_be_forged_or_substituted_between_requests() {
        let challenge = ChannelChallenge {
            enclave_id: EnclaveId::new(1),
            boot_id: [8; 32],
            public_key: public([2; 32]),
            attestation: None,
        };
        let request = SignedCommand::sign(
            Command::new(EnclaveCommand::System(SystemCommand::Ping)),
            &challenge,
            &[1; 32],
        )
        .unwrap();
        let outcome = SignedOutcome::sign(
            &request,
            Outcome::new(
                request.command.clone(),
                EnclaveOutcome::System(SystemOutcome::Pong),
            ),
            &[2; 32],
        )
        .unwrap();
        assert!(outcome.verify(&request, &challenge.public_key).is_ok());
        assert!(outcome.verify(&request, &public([3; 32])).is_err());
        let mut another = request.clone();
        another.command.command_id = uuid::Uuid::now_v7();
        assert!(outcome.verify(&another, &challenge.public_key).is_err());
        let mut tampered = outcome;
        tampered.outcome.response = EnclaveOutcome::System(SystemOutcome::Success);
        assert!(tampered.verify(&request, &challenge.public_key).is_err());
    }
}
