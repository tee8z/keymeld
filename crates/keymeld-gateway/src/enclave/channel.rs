use keymeld_core::{
    attestation::AttestationPolicy,
    enclave_channel::{ChannelChallenge, ChannelRequest, ChannelResponse, SignedCommand},
    managed_socket::{
        client::SocketClient,
        config::{RetryConfig, TimeoutConfig},
        connection::{Request, Response},
        transport::SocketConnector,
    },
    protocol::{Command, Outcome},
    EnclaveId, KeyMeldError,
};
use std::{
    collections::BTreeMap,
    ops::Deref,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

/// Create a new credential without overwriting an existing file. Only the public key is returned.
pub fn generate_gateway_credential(path: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let mut secret = secp256k1::SecretKey::new(&mut rand::rng());
    let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
    let encoded = Zeroizing::new(hex::encode(secret.secret_bytes()));
    secret.non_secure_erase();
    file.write_all(encoded.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(hex::encode(public.serialize()))
}

pub fn gateway_credential_public_key(path: &std::path::Path) -> anyhow::Result<String> {
    let encoded = Zeroizing::new(std::fs::read_to_string(path)?);
    let bytes = Zeroizing::new(hex::decode(encoded.trim())?);
    let mut secret = secp256k1::SecretKey::from_byte_array(bytes.as_slice().try_into()?)?;
    let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
    secret.non_secure_erase();
    Ok(hex::encode(public.serialize()))
}

pub struct ChannelCredentials {
    secret: Zeroizing<[u8; 32]>,
    attestation: Option<AttestationPolicy>,
}

impl ChannelCredentials {
    pub fn new(secret: [u8; 32], attestation: AttestationPolicy) -> Result<Self, KeyMeldError> {
        secp256k1::SecretKey::from_byte_array(secret).map_err(KeyMeldError::InvalidKey)?;
        Ok(Self {
            secret: Zeroizing::new(secret),
            attestation: Some(attestation),
        })
    }

    /// Explicit opt-in for local simulation. Never use this credential policy with real keys.
    pub fn dangerous_trust_unattested_enclaves(secret: [u8; 32]) -> Result<Self, KeyMeldError> {
        secp256k1::SecretKey::from_byte_array(secret).map_err(KeyMeldError::InvalidKey)?;
        Ok(Self {
            secret: Zeroizing::new(secret),
            attestation: None,
        })
    }
    pub fn from_env() -> Result<Self, KeyMeldError> {
        let invalid = |message: &str| KeyMeldError::InvalidConfiguration(message.into());
        let path = std::env::var("KEYMELD_GATEWAY_SIGNING_KEY_FILE").map_err(|_| {
            invalid("Set KEYMELD_GATEWAY_SIGNING_KEY_FILE to the provisioned gateway credential")
        })?;
        let encoded = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|_| invalid("Cannot read the gateway channel credential file"))?,
        );
        let bytes = Zeroizing::new(
            hex::decode(encoded.trim())
                .map_err(|_| invalid("Invalid gateway channel credential hex"))?,
        );
        let secret: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid("Gateway channel credential must contain 32 bytes"))?;
        secp256k1::SecretKey::from_byte_array(secret).map_err(KeyMeldError::InvalidKey)?;
        let development =
            std::env::var("KEYMELD_DANGEROUS_TRUST_UNATTESTED_ENCLAVES").as_deref() == Ok("true");
        let attestation = if development {
            tracing::warn!(
                "Explicit development mode: enclave channel attestation verification is disabled"
            );
            None
        } else {
            let mut measurements = BTreeMap::new();
            for index in [0, 8] {
                if let Ok(value) = std::env::var(format!("KEYMELD_ENCLAVE_PCR{index}")) {
                    if !value.trim().is_empty() {
                        measurements.insert(format!("PCR{index}"), value);
                    }
                }
            }
            Some(AttestationPolicy::from_hex_measurements(&measurements)?)
        };
        Ok(Self {
            secret: Zeroizing::new(secret),
            attestation,
        })
    }
}

pub struct AuthenticatedEnclaveClient {
    client: SocketClient<ChannelRequest, ChannelResponse>,
    enclave_id: EnclaveId,
    credentials: Arc<ChannelCredentials>,
    challenge: Mutex<Option<ChannelChallenge>>,
}

impl AuthenticatedEnclaveClient {
    pub fn new(
        enclave_id: EnclaveId,
        connector: SocketConnector,
        timeout: &TimeoutConfig,
        credentials: Arc<ChannelCredentials>,
    ) -> Self {
        Self {
            client: SocketClient::with_config(connector, timeout, &RetryConfig::default()),
            enclave_id,
            credentials,
            challenge: Mutex::new(None),
        }
    }

    async fn authenticated_challenge(&self) -> Result<ChannelChallenge, KeyMeldError> {
        let mut cached = self.challenge.lock().await;
        if let Some(challenge) = cached.as_ref() {
            return Ok(challenge.clone());
        }
        let nonce = rand::random::<[u8; 32]>();
        let response = self
            .client
            .send_command(ChannelRequest::Challenge { nonce }.into())
            .await?;
        let ChannelResponse::Challenge(challenge) = response.response else {
            return Err(KeyMeldError::EnclaveError(
                "Enclave did not return a channel challenge".into(),
            ));
        };
        if challenge.enclave_id != self.enclave_id {
            return Err(KeyMeldError::EnclaveError(
                "Channel challenge identifies a different enclave".into(),
            ));
        }
        secp256k1::PublicKey::from_slice(&challenge.public_key)
            .map_err(KeyMeldError::InvalidKey)?;
        if let Some(policy) = &self.credentials.attestation {
            let document = challenge.attestation.as_ref().ok_or_else(|| {
                KeyMeldError::EnclaveError("Missing enclave channel attestation".into())
            })?;
            policy.verify(
                &document.raw_document,
                &challenge.public_key,
                &nonce,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(KeyMeldError::TimeError)?
                    .as_secs(),
            )?;
        }
        *cached = Some(*challenge.clone());
        Ok(*challenge)
    }

    pub async fn send_command(
        &self,
        request: Request<Command>,
    ) -> Result<Response<Outcome>, KeyMeldError> {
        let challenge = self.authenticated_challenge().await?;
        let signed = SignedCommand::sign(request.command, &challenge, &self.credentials.secret)?;
        let response = self
            .client
            .send_command(ChannelRequest::Execute(Box::new(signed.clone())).into())
            .await?;
        if let ChannelResponse::Executed(outcome) = response.response {
            if outcome.verify(&signed, &challenge.public_key).is_ok() {
                return Ok(Response::from_with_id(request.request_id, outcome.outcome));
            }
        }
        // A restart changes the attested channel key. Re-attest before the next command.
        // Do not automatically resubmit a state mutation into another enclave boot.
        *self.challenge.lock().await = None;
        Err(KeyMeldError::EnclaveError("Enclave channel rejected the command or returned an unauthenticated response; re-attestation required".into()))
    }
}

impl Deref for AuthenticatedEnclaveClient {
    type Target = SocketClient<ChannelRequest, ChannelResponse>;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisioning_creates_a_private_file_and_never_replaces_existing_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("gateway.key");
        let public = generate_gateway_credential(&path).unwrap();
        assert_eq!(gateway_credential_public_key(&path).unwrap(), public);
        assert!(generate_gateway_credential(&path).is_err());
        assert_eq!(gateway_credential_public_key(&path).unwrap(), public);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn an_unattested_socket_cannot_receive_bootstrap_commands() {
        use keymeld_core::managed_socket::{
            create_server_handler, RequestRateTracker, ServerCommandHandler,
        };
        use keymeld_core::protocol::{ConfigureCommand, EnclaveCommand, SystemCommand};
        use std::{
            future::Future,
            pin::Pin,
            sync::atomic::{AtomicU32, Ordering},
        };
        struct UntrustedEnclave(Arc<AtomicU32>);
        impl ServerCommandHandler<ChannelRequest, ChannelResponse> for UntrustedEnclave {
            fn handle_command(
                &self,
                request: ChannelRequest,
            ) -> Pin<Box<dyn Future<Output = anyhow::Result<ChannelResponse>> + Send + '_>>
            {
                Box::pin(async move {
                    if matches!(request, ChannelRequest::Execute(_)) {
                        self.0.fetch_add(1, Ordering::SeqCst);
                    }
                    let public = secp256k1::PublicKey::from_secret_key(
                        &secp256k1::Secp256k1::new(),
                        &secp256k1::SecretKey::from_byte_array([2; 32]).unwrap(),
                    );
                    Ok(ChannelResponse::Challenge(Box::new(ChannelChallenge {
                        enclave_id: EnclaveId::new(1),
                        boot_id: [3; 32],
                        public_key: public.serialize().to_vec(),
                        attestation: None,
                    })))
                })
            }
        }
        let received_commands = Arc::new(AtomicU32::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handler = Arc::new(UntrustedEnclave(received_commands.clone()));
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let connection =
                    create_server_handler(handler.clone(), Arc::new(AtomicU32::new(0)));
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
        let policy = AttestationPolicy::new(BTreeMap::from([(0, vec![9; 48])])).unwrap();
        let credentials = Arc::new(ChannelCredentials::new([1; 32], policy).unwrap());
        let client = AuthenticatedEnclaveClient::new(
            EnclaveId::new(1),
            SocketConnector::tcp("127.0.0.1", port),
            &TimeoutConfig::default(),
            credentials,
        );
        let configure = Command::new(EnclaveCommand::System(SystemCommand::Configure(
            ConfigureCommand {
                enclave_id: EnclaveId::new(1),
                key_epoch: None,
                kms_endpoint: Some("http://trusted-kms".into()),
                kms_key_id: Some("trusted-key".into()),
                encrypted_dek: None,
                encrypted_private_key: None,
            },
        )));
        assert!(client.send_command(configure.into()).await.is_err());
        assert_eq!(received_commands.load(Ordering::SeqCst), 0);
        server.abort();
    }
}
