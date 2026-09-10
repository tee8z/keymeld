use crate::config::{HttpConfig, PollingConfig};
use crate::credentials::UserCredentials;
use crate::error::SdkError;
use crate::http::HttpClient;
use crate::managers::{HealthManager, KeygenManager, SigningManager};
use crate::types::UserId;

#[derive(Debug)]
pub struct KeyMeldClient {
    http: HttpClient,
    base_url: String,
    user_id: UserId,
    user_credentials: Option<UserCredentials>,
    polling_config: PollingConfig,
    attestation_policy: Option<keymeld_core::attestation::AttestationPolicy>,
    trust_unattested_enclaves: bool,
}

impl KeyMeldClient {
    pub fn builder(gateway_url: &str, user_id: UserId) -> KeyMeldClientBuilder {
        KeyMeldClientBuilder::new(gateway_url, user_id)
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn polling_config(&self) -> &PollingConfig {
        &self.polling_config
    }

    pub(crate) fn verify_enclave_key(
        &self,
        response: &crate::types::EnclavePublicKeyResponse,
        expected_enclave_id: u32,
        nonce: &[u8],
    ) -> Result<(), SdkError> {
        if response.enclave_id != expected_enclave_id || !response.healthy {
            return Err(SdkError::InvalidInput(
                "Wrong or unhealthy enclave identity".into(),
            ));
        }
        let key = hex::decode(&response.public_key)
            .map_err(|_| SdkError::InvalidInput("Invalid enclave public key".into()))?;
        secp256k1::PublicKey::from_slice(&key)
            .map_err(|_| SdkError::InvalidInput("Invalid enclave public key".into()))?;
        if self.trust_unattested_enclaves {
            return Ok(());
        }
        let policy = self.attestation_policy.as_ref().ok_or_else(|| SdkError::InvalidInput(
            "Configure trusted enclave PCR measurements with attestation_policy() before transferring secrets".into()
        ))?;
        let document = hex::decode(&response.attestation_document).map_err(|_| {
            SdkError::InvalidInput("Expected an original hex-encoded Nitro COSE document".into())
        })?;
        policy.verify(
            &document,
            &key,
            nonce,
            keymeld_core::request_auth::now_timestamp_secs()?,
        )?;
        Ok(())
    }

    pub fn has_credentials(&self) -> bool {
        self.user_credentials.is_some()
    }

    pub fn set_credentials(&mut self, credentials: UserCredentials) {
        self.user_credentials = Some(credentials);
    }

    pub fn health(&self) -> HealthManager<'_> {
        HealthManager::new(self)
    }

    pub fn keygen(&self) -> KeygenManager<'_> {
        KeygenManager::new(self)
    }

    pub fn signer(&self) -> SigningManager<'_> {
        SigningManager::new(self)
    }

    pub fn http(&self) -> &HttpClient {
        &self.http
    }

    pub fn credentials(&self) -> Option<&UserCredentials> {
        self.user_credentials.as_ref()
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

#[derive(Debug)]
pub struct KeyMeldClientBuilder {
    gateway_url: String,
    user_id: UserId,
    http_client: Option<reqwest::Client>,
    credentials: Option<UserCredentials>,
    http_config: HttpConfig,
    polling_config: PollingConfig,
    attestation_policy: Option<keymeld_core::attestation::AttestationPolicy>,
    trust_unattested_enclaves: bool,
}

impl KeyMeldClientBuilder {
    fn new(gateway_url: &str, user_id: UserId) -> Self {
        Self {
            gateway_url: gateway_url.to_string(),
            user_id,
            http_client: None,
            credentials: None,
            http_config: HttpConfig::default(),
            polling_config: PollingConfig::default(),
            attestation_policy: None,
            trust_unattested_enclaves: false,
        }
    }

    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn credentials(mut self, credentials: UserCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn http_config(mut self, config: HttpConfig) -> Self {
        self.http_config = config;
        self
    }

    pub fn polling_config(mut self, config: PollingConfig) -> Self {
        self.polling_config = config;
        self
    }

    pub fn attestation_policy(
        mut self,
        policy: keymeld_core::attestation::AttestationPolicy,
    ) -> Self {
        self.attestation_policy = Some(policy);
        self.trust_unattested_enclaves = false;
        self
    }

    /// Disable hardware attestation for local simulated enclaves. Never use with real keys.
    pub fn dangerous_trust_unattested_enclaves(mut self) -> Self {
        self.trust_unattested_enclaves = true;
        self.attestation_policy = None;
        self
    }

    pub fn build(self) -> Result<KeyMeldClient, SdkError> {
        let http = match self.http_client {
            Some(client) => HttpClient::with_reqwest_client(client, self.http_config),
            None => HttpClient::with_config(self.http_config)?,
        };

        let base_url = self.gateway_url.trim_end_matches('/').to_string();

        Ok(KeyMeldClient {
            http,
            base_url,
            user_id: self.user_id,
            user_credentials: self.credentials,
            polling_config: self.polling_config,
            attestation_policy: self.attestation_policy,
            trust_unattested_enclaves: self.trust_unattested_enclaves,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let user_id = UserId::new_v7();
        let client = KeyMeldClient::builder("https://gateway.example.com/", user_id.clone())
            .build()
            .unwrap();

        assert_eq!(client.base_url(), "https://gateway.example.com");
        assert_eq!(client.user_id(), &user_id);
        assert!(!client.has_credentials());
    }

    #[test]
    fn test_url_building() {
        let user_id = UserId::new_v7();
        let client = KeyMeldClient::builder("https://gateway.example.com", user_id)
            .build()
            .unwrap();

        assert_eq!(
            client.url("/api/v1/health"),
            "https://gateway.example.com/api/v1/health"
        );
    }

    #[test]
    fn test_with_credentials() {
        let user_id = UserId::new_v7();
        let private_key = [0x42u8; 32];
        let credentials = UserCredentials::from_private_key(&private_key).unwrap();

        let client = KeyMeldClient::builder("https://gateway.example.com", user_id)
            .credentials(credentials)
            .build()
            .unwrap();

        assert!(client.has_credentials());
    }

    #[test]
    fn test_set_credentials() {
        let user_id = UserId::new_v7();
        let mut client = KeyMeldClient::builder("https://gateway.example.com", user_id)
            .build()
            .unwrap();

        assert!(!client.has_credentials());

        let private_key = [0x42u8; 32];
        let credentials = UserCredentials::from_private_key(&private_key).unwrap();
        client.set_credentials(credentials);

        assert!(client.has_credentials());
    }

    #[test]
    fn unconfigured_and_forged_attestation_fail_closed() {
        use crate::AttestationPolicy;
        use std::collections::BTreeMap;
        let user = UserId::new_v7();
        let key = keymeld_core::crypto::SecureCrypto::generate_enclave_keypair()
            .unwrap()
            .1;
        let response = crate::types::EnclavePublicKeyResponse {
            enclave_id: 1,
            public_key: hex::encode(key.serialize()),
            attestation_document: "a0".into(),
            pcr_measurements: Default::default(),
            timestamp: 0,
            healthy: true,
            key_epoch: 1,
        };
        let client = KeyMeldClient::builder("http://localhost", user.clone())
            .build()
            .unwrap();
        assert!(client.verify_enclave_key(&response, 1, &[42; 32]).is_err());
        let policy = AttestationPolicy::new(BTreeMap::from([(0, vec![1; 48])])).unwrap();
        let client = KeyMeldClient::builder("http://localhost", user.clone())
            .attestation_policy(policy)
            .build()
            .unwrap();
        assert!(client.verify_enclave_key(&response, 1, &[42; 32]).is_err());
        let development = KeyMeldClient::builder("http://localhost", user)
            .dangerous_trust_unattested_enclaves()
            .build()
            .unwrap();
        development
            .verify_enclave_key(&response, 1, &[42; 32])
            .unwrap();
        assert!(development
            .verify_enclave_key(&response, 2, &[42; 32])
            .is_err());
    }

    #[tokio::test]
    async fn forged_gateway_key_never_receives_a_private_key_upload() {
        use crate::{AttestationPolicy, EnclaveId, KeyId, KeySlotReservation, SingleSignerOps};
        use std::collections::BTreeMap;
        let mut server = mockito::Server::new_async().await;
        let credentials = UserCredentials::from_private_key(&[42; 32]).unwrap();
        let attacker_key = keymeld_core::crypto::SecureCrypto::generate_enclave_keypair()
            .unwrap()
            .1;
        let response = crate::types::EnclavePublicKeyResponse {
            enclave_id: 1,
            public_key: hex::encode(attacker_key.serialize()),
            attestation_document: "a0".into(),
            pcr_measurements: Default::default(),
            timestamp: 0,
            healthy: true,
            key_epoch: 1,
        };
        let key_response = server
            .mock("GET", "/api/v1/enclaves/1/public-key")
            .match_query(mockito::Matcher::Regex("^nonce=[0-9a-f]{64}$".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::to_vec(&response).unwrap())
            .create_async()
            .await;
        let upload = server
            .mock("POST", "/api/v1/keys/import")
            .expect(0)
            .create_async()
            .await;
        let policy = AttestationPolicy::new(BTreeMap::from([(0, vec![1; 48])])).unwrap();
        let client = KeyMeldClient::builder(&server.url(), UserId::new_v7())
            .credentials(credentials)
            .attestation_policy(policy)
            .build()
            .unwrap();
        let reservation = KeySlotReservation {
            key_id: KeyId::new_v7(),
            enclave_id: EnclaveId::from(1),
            enclave_public_key: response.public_key,
            enclave_key_epoch: 1,
        };
        assert!(client.import_key(&reservation, &[42; 32]).await.is_err());
        key_response.assert_async().await;
        upload.assert_async().await;
    }

    #[tokio::test]
    async fn unverified_keygen_recipient_never_receives_session_secret() {
        use crate::{
            AttestationPolicy, EnclaveId, KeygenOptions, ReserveKeygenSessionRequest,
            ReserveKeygenSessionResponse,
        };
        use std::collections::BTreeMap;
        let mut server = mockito::Server::new_async().await;
        let owner = UserId::new_v7();
        let attacker_key = keymeld_core::crypto::SecureCrypto::generate_enclave_keypair()
            .unwrap()
            .1;
        let public_key = hex::encode(attacker_key.serialize());
        let reserve_public_key = public_key.clone();
        let reservation = server
            .mock("POST", "/api/v1/keygen/reserve")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |request| {
                let request: ReserveKeygenSessionRequest =
                    serde_json::from_slice(request.body().unwrap()).unwrap();
                serde_json::to_vec(&ReserveKeygenSessionResponse {
                    keygen_session_id: request.keygen_session_id,
                    user_enclave_assignments: request
                        .expected_participants
                        .iter()
                        .map(|user| (user.clone(), EnclaveId::from(1)))
                        .collect(),
                    coordinator_enclave_id: EnclaveId::from(1),
                    coordinator_public_key: reserve_public_key.clone(),
                    coordinator_key_epoch: 1,
                    expected_participants: request.expected_participants.len(),
                    expires_at: u64::MAX,
                })
                .unwrap()
            })
            .create_async()
            .await;
        let key_response = server
            .mock("GET", "/api/v1/enclaves/1/public-key")
            .match_query(mockito::Matcher::Regex("^nonce=[0-9a-f]{64}$".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::to_vec(&crate::types::EnclavePublicKeyResponse {
                    enclave_id: 1,
                    public_key,
                    attestation_document: "a0".into(),
                    pcr_measurements: Default::default(),
                    timestamp: 0,
                    healthy: true,
                    key_epoch: 1,
                })
                .unwrap(),
            )
            .create_async()
            .await;
        let initialize = server
            .mock(
                "POST",
                mockito::Matcher::Regex("/api/v1/keygen/.*/initialize".into()),
            )
            .expect(0)
            .create_async()
            .await;
        let policy = AttestationPolicy::new(BTreeMap::from([(0, vec![1; 48])])).unwrap();
        let client = KeyMeldClient::builder(&server.url(), owner.clone())
            .credentials(UserCredentials::from_private_key(&[42; 32]).unwrap())
            .http_config(HttpConfig {
                compression_threshold: usize::MAX,
                ..Default::default()
            })
            .attestation_policy(policy)
            .build()
            .unwrap();
        assert!(client
            .keygen()
            .create_session(vec![owner], KeygenOptions::default())
            .await
            .is_err());
        reservation.assert_async().await;
        key_response.assert_async().await;
        initialize.assert_async().await;
    }
}
