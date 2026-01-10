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
}
