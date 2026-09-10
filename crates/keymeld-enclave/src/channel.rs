//! The only socket entry point. Authentication precedes every operator command.
use crate::{attestation::AttestationManager, operator::EnclaveOperator};
use keymeld_core::{
    enclave_channel::{
        ChannelChallenge, ChannelRequest, ChannelResponse, SignedCommand, SignedOutcome,
        COMMAND_MAX_AGE_SECONDS,
    },
    managed_socket::ServerCommandHandler,
    protocol::{EnclaveCommand, EnclaveOutcome, ErrorResponse, Outcome, SystemCommand},
    EnclaveId,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OnceCell};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_RETAINED_COMMANDS: usize = 100_000;

pub struct ChannelPolicy {
    pub gateway_public_key: Vec<u8>,
    pub kms_endpoint: String,
    pub kms_key_id: String,
}

impl ChannelPolicy {
    pub fn from_env() -> anyhow::Result<Self> {
        let gateway_public_key =
            hex::decode(std::env::var("ENCLAVE_GATEWAY_PUBLIC_KEY").map_err(|_| {
                anyhow::anyhow!(
                    "ENCLAVE_GATEWAY_PUBLIC_KEY must be provisioned before starting the enclave"
                )
            })?)?;
        PublicKey::from_slice(&gateway_public_key)?;
        let kms_key_id = std::env::var("ENCLAVE_KMS_KEY_ID").map_err(|_| {
            anyhow::anyhow!("ENCLAVE_KMS_KEY_ID must be pinned before starting the enclave")
        })?;
        anyhow::ensure!(
            !kms_key_id.is_empty(),
            "ENCLAVE_KMS_KEY_ID must not be empty"
        );
        let kms_endpoint =
            std::env::var("ENCLAVE_KMS_ENDPOINT").unwrap_or_else(|_| "aws-kms".into());
        Ok(Self {
            gateway_public_key,
            kms_endpoint,
            kms_key_id,
        })
    }

    fn check_command(&self, request: &SignedCommand, enclave_id: EnclaveId) -> anyhow::Result<()> {
        if let EnclaveCommand::System(SystemCommand::Configure(command)) = &request.command.command
        {
            anyhow::ensure!(
                command.enclave_id == enclave_id,
                "Configure enclave identity mismatch"
            );
            anyhow::ensure!(
                command.kms_endpoint.as_deref() == Some(self.kms_endpoint.as_str())
                    && command.kms_key_id.as_deref() == Some(self.kms_key_id.as_str()),
                "Configure must use the enclave's provisioned KMS endpoint and key"
            );
            anyhow::ensure!(
                command.encrypted_dek.is_some() == command.encrypted_private_key.is_some(),
                "Incomplete restored key hierarchy"
            );
            anyhow::ensure!(
                command
                    .key_epoch
                    .is_none_or(|epoch| epoch > 0 && epoch <= u32::MAX as u64),
                "Invalid key epoch"
            );
        }
        Ok(())
    }
}

struct CachedCommand {
    digest: [u8; 32],
    expires_at: u64,
    outcome: Arc<OnceCell<ChannelResponse>>,
}

pub struct AuthenticatedCommandHandler {
    operator: Arc<EnclaveOperator>,
    policy: ChannelPolicy,
    boot_id: [u8; 32],
    secret_key: Zeroizing<[u8; 32]>,
    public_key: Vec<u8>,
    completed: Mutex<HashMap<Uuid, CachedCommand>>,
}

impl AuthenticatedCommandHandler {
    pub fn new(operator: Arc<EnclaveOperator>, policy: ChannelPolicy) -> Self {
        let secret_key = SecretKey::new(&mut rand::rng());
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key)
            .serialize()
            .to_vec();
        Self {
            operator,
            policy,
            public_key,
            boot_id: rand::random(),
            secret_key: Zeroizing::new(secret_key.secret_bytes()),
            completed: Mutex::new(HashMap::new()),
        }
    }

    async fn execute(&self, request: SignedCommand) -> anyhow::Result<ChannelResponse> {
        let now = SystemTime::now();
        request.verify(
            &self.policy.gateway_public_key,
            self.operator.enclave_id,
            &self.boot_id,
            now,
        )?;
        self.policy
            .check_command(&request, self.operator.enclave_id)?;
        let digest = request.digest()?;
        let now_seconds = now.duration_since(UNIX_EPOCH)?.as_secs();
        let expires_at = request
            .command
            .created_at
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .saturating_add(COMMAND_MAX_AGE_SECONDS);
        let cell = {
            let mut completed = self.completed.lock().await;
            // Never evict an in-flight operation or an unexpired replay claim.
            completed.retain(|_, entry| {
                entry.expires_at >= now_seconds || entry.outcome.get().is_none()
            });
            if let Some(entry) = completed.get(&request.command.command_id) {
                anyhow::ensure!(
                    entry.digest == digest,
                    "Command ID already used for a different command"
                );
                entry.outcome.clone()
            } else {
                anyhow::ensure!(
                    completed.len() < MAX_RETAINED_COMMANDS,
                    "Enclave command replay cache is full"
                );
                let outcome = Arc::new(OnceCell::new());
                completed.insert(
                    request.command.command_id,
                    CachedCommand {
                        digest,
                        expires_at,
                        outcome: outcome.clone(),
                    },
                );
                outcome
            }
        };
        Ok(cell
            .get_or_init(|| async {
                let outcome = match self.operator.handle_command(request.command.clone()).await {
                    Ok(outcome) => outcome,
                    Err(error) => Outcome::new(
                        request.command.clone(),
                        EnclaveOutcome::Error(ErrorResponse { error }),
                    ),
                };
                match SignedOutcome::sign(&request, outcome, &self.secret_key) {
                    Ok(outcome) => ChannelResponse::Executed(Box::new(outcome)),
                    Err(_) => {
                        ChannelResponse::Rejected("Unable to authenticate enclave response".into())
                    }
                }
            })
            .await
            .clone())
    }

    fn challenge(&self, nonce: &[u8; 32]) -> anyhow::Result<ChannelResponse> {
        let attestation = self
            .operator
            .attestation_manager
            .as_ref()
            .map(|manager: &AttestationManager| {
                manager.get_identity_attestation_with_nonce(&self.public_key, nonce)
            })
            .transpose()?
            .flatten();
        Ok(ChannelResponse::Challenge(Box::new(ChannelChallenge {
            enclave_id: self.operator.enclave_id,
            boot_id: self.boot_id,
            public_key: self.public_key.clone(),
            attestation,
        })))
    }
}

impl ServerCommandHandler<ChannelRequest, ChannelResponse> for AuthenticatedCommandHandler {
    fn handle_command(
        &self,
        request: ChannelRequest,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ChannelResponse>> + Send + '_>> {
        Box::pin(async move {
            let result = match request {
                ChannelRequest::Challenge { nonce } => self.challenge(&nonce),
                ChannelRequest::Execute(request) => self.execute(*request).await,
            };
            // Transport errors have no typed error frame. Reject without executing.
            Ok(result.unwrap_or_else(|_| {
                ChannelResponse::Rejected(
                    "Enclave channel authentication or policy rejected the request".into(),
                )
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keymeld_core::protocol::{ClearSessionCommand, Command, ConfigureCommand};
    fn fixture() -> AuthenticatedCommandHandler {
        let gateway_public_key = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_byte_array([1; 32]).unwrap(),
        )
        .serialize()
        .to_vec();
        AuthenticatedCommandHandler::new(
            Arc::new(EnclaveOperator::new(EnclaveId::new(1)).unwrap()),
            ChannelPolicy {
                gateway_public_key,
                kms_endpoint: "http://trusted-kms".into(),
                kms_key_id: "trusted-key".into(),
            },
        )
    }
    fn challenge(handler: &AuthenticatedCommandHandler) -> ChannelChallenge {
        match handler.challenge(&[7; 32]).unwrap() {
            ChannelResponse::Challenge(value) => *value,
            _ => unreachable!(),
        }
    }
    #[tokio::test]
    async fn unauthorized_bootstrap_and_clear_never_reach_operator() {
        let handler = fixture();
        let challenge = challenge(&handler);
        for command in [
            EnclaveCommand::System(SystemCommand::Configure(ConfigureCommand {
                enclave_id: EnclaveId::new(1),
                key_epoch: None,
                kms_endpoint: Some("http://attacker-kms".into()),
                kms_key_id: Some("attacker-key".into()),
                encrypted_dek: None,
                encrypted_private_key: None,
            })),
            EnclaveCommand::System(SystemCommand::ClearSession(ClearSessionCommand {
                keygen_session_id: Some(keymeld_core::SessionId::new_v7()),
                signing_session_id: None,
            })),
        ] {
            let request = SignedCommand::sign(Command::new(command), &challenge, &[2; 32]).unwrap();
            assert!(handler.execute(request).await.is_err());
        }
        assert!(handler.operator.get_public_key().is_empty());
        assert!(handler.completed.lock().await.is_empty());
    }
    #[tokio::test]
    async fn trusted_gateway_cannot_redirect_kms_and_retries_are_immutable() {
        let handler = fixture();
        let challenge = challenge(&handler);
        let configure = Command::new(EnclaveCommand::System(SystemCommand::Configure(
            ConfigureCommand {
                enclave_id: EnclaveId::new(1),
                key_epoch: None,
                kms_endpoint: Some("http://attacker-kms".into()),
                kms_key_id: Some("trusted-key".into()),
                encrypted_dek: None,
                encrypted_private_key: None,
            },
        )));
        assert!(handler
            .execute(SignedCommand::sign(configure, &challenge, &[1; 32]).unwrap())
            .await
            .is_err());
        let request = SignedCommand::sign(
            Command::new(EnclaveCommand::System(SystemCommand::Ping)),
            &challenge,
            &[1; 32],
        )
        .unwrap();
        let first = handler.execute(request.clone()).await.unwrap();
        let second = handler.execute(request.clone()).await.unwrap();
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
        let mut changed = request.command.clone();
        changed.command = EnclaveCommand::System(SystemCommand::GetPublicInfo);
        assert!(handler
            .execute(SignedCommand::sign(changed, &challenge, &[1; 32]).unwrap())
            .await
            .is_err());
        let restarted = fixture();
        assert!(restarted.execute(request).await.is_err());
    }

    #[tokio::test]
    async fn socket_rejects_command_injection_before_and_after_authenticated_commands() {
        use keymeld_core::managed_socket::{
            create_server_handler, RequestRateTracker, SocketClient, TimeoutConfig,
        };
        use std::sync::atomic::AtomicU32;
        let handler = Arc::new(fixture());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_handler = handler.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let connection =
                    create_server_handler(server_handler.clone(), Arc::new(AtomicU32::new(0)));
                tokio::spawn(async move {
                    connection
                        .handle(
                            stream,
                            Arc::new(RequestRateTracker::new()),
                            TimeoutConfig::default(),
                        )
                        .await
                        .unwrap();
                });
            }
        });
        let client: SocketClient<ChannelRequest, ChannelResponse> =
            SocketClient::tcp("127.0.0.1", address.port());
        let ChannelResponse::Challenge(challenge) = client
            .send_command(ChannelRequest::Challenge { nonce: [7; 32] }.into())
            .await
            .unwrap()
            .response
        else {
            panic!("missing challenge")
        };
        for secret in [[2; 32], [1; 32], [2; 32]] {
            let command = SignedCommand::sign(
                Command::new(EnclaveCommand::System(SystemCommand::Ping)),
                &challenge,
                &secret,
            )
            .unwrap();
            let result = client
                .send_command(ChannelRequest::Execute(Box::new(command.clone())).into())
                .await
                .unwrap()
                .response;
            if secret == [1; 32] {
                let ChannelResponse::Executed(outcome) = result else {
                    panic!("authorized request rejected")
                };
                outcome.verify(&command, &challenge.public_key).unwrap();
            } else {
                assert!(matches!(result, ChannelResponse::Rejected(_)));
            }
        }
        let attack = Command::new(EnclaveCommand::System(SystemCommand::Configure(
            ConfigureCommand {
                enclave_id: EnclaveId::new(1),
                key_epoch: None,
                kms_endpoint: Some("http://attacker-kms".into()),
                kms_key_id: Some("attacker-key".into()),
                encrypted_dek: None,
                encrypted_private_key: None,
            },
        )));
        let request = SignedCommand::sign(attack, &challenge, &[2; 32]).unwrap();
        let result = client
            .send_command(ChannelRequest::Execute(Box::new(request)).into())
            .await
            .unwrap();
        assert!(matches!(result.response, ChannelResponse::Rejected(_)));
        assert!(handler.operator.get_public_key().is_empty());
        assert_eq!(handler.completed.lock().await.len(), 1);
        server.abort();
    }
}
