use crate::client::KeyMeldClient;
use crate::error::SdkError;
use crate::types::{
    ApiVersionResponse, EnclaveHealthResponse, EnclavePublicKeyResponse, HealthCheckResponse,
    ListEnclavesResponse,
};

pub struct HealthManager<'a> {
    client: &'a KeyMeldClient,
}

impl<'a> HealthManager<'a> {
    pub(crate) fn new(client: &'a KeyMeldClient) -> Self {
        Self { client }
    }

    pub async fn is_healthy(&self) -> Result<bool, SdkError> {
        let response: HealthCheckResponse = self
            .client
            .http()
            .get(&self.client.url("/api/v1/health"), &[])
            .await?;

        Ok(response.status == "healthy")
    }

    pub async fn check_detailed(&self) -> Result<HealthCheckResponse, SdkError> {
        self.client
            .http()
            .get(&self.client.url("/api/v1/health"), &[])
            .await
    }

    pub async fn list_enclaves(&self) -> Result<ListEnclavesResponse, SdkError> {
        self.client
            .http()
            .get(&self.client.url("/api/v1/enclaves"), &[])
            .await
    }

    pub async fn get_enclave(&self, enclave_id: u32) -> Result<EnclaveHealthResponse, SdkError> {
        self.client
            .http()
            .get(
                &self.client.url(&format!("/api/v1/enclaves/{}", enclave_id)),
                &[],
            )
            .await
    }

    pub async fn get_enclave_key(
        &self,
        enclave_id: u32,
    ) -> Result<EnclavePublicKeyResponse, SdkError> {
        self.client
            .http()
            .get(
                &self
                    .client
                    .url(&format!("/api/v1/enclaves/{}/public-key", enclave_id)),
                &[],
            )
            .await
    }

    pub async fn version(&self) -> Result<ApiVersionResponse, SdkError> {
        self.client
            .http()
            .get(&self.client.url("/api/v1/version"), &[])
            .await
    }
}
