use crate::config::HttpConfig;
use crate::error::{ApiError, NetworkError, SdkError};
use crate::types::ErrorResponse;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
    config: HttpConfig,
}

impl HttpClient {
    pub fn new() -> Result<Self, SdkError> {
        Self::with_config(HttpConfig::default())
    }

    pub fn with_config(config: HttpConfig) -> Result<Self, SdkError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .gzip(true)
            .build()
            .map_err(|e| SdkError::Network(NetworkError::ConnectionFailed(e.to_string())))?;

        Ok(Self { client, config })
    }

    pub fn with_reqwest_client(client: reqwest::Client, config: HttpConfig) -> Self {
        Self { client, config }
    }

    pub async fn get<T: DeserializeOwned>(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<T, SdkError> {
        let mut request = self.client.get(url).header("Accept", "application/json");

        // Add custom headers
        for (key, value) in headers {
            request = request.header(*key, *value);
        }

        request = request.header("Accept-Encoding", "gzip");

        let response = request.send().await?;
        self.handle_response(response).await
    }

    pub async fn post<Req: Serialize, Res: DeserializeOwned>(
        &self,
        url: &str,
        body: &Req,
        headers: &[(&str, &str)],
    ) -> Result<Res, SdkError> {
        let json_body = serde_json::to_vec(body)?;

        let mut request = self.client.post(url).header("Accept", "application/json");

        // Add custom headers
        for (key, value) in headers {
            request = request.header(*key, *value);
        }

        request = request.header("Accept-Encoding", "gzip");

        if json_body.len() >= self.config.compression_threshold {
            let compressed = Self::gzip_compress(&json_body)?;
            request = request
                .header("Content-Type", "application/json")
                .header("Content-Encoding", "gzip")
                .body(compressed);
        } else {
            request = request
                .header("Content-Type", "application/json")
                .body(json_body);
        }

        let response = request.send().await?;
        self.handle_response(response).await
    }

    pub async fn post_empty<Res: DeserializeOwned>(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<Res, SdkError> {
        let mut request = self.client.post(url).header("Accept", "application/json");

        // Add custom headers
        for (key, value) in headers {
            request = request.header(*key, *value);
        }

        request = request.header("Accept-Encoding", "gzip");

        let response = request.send().await?;
        self.handle_response(response).await
    }

    pub async fn post_no_response(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<(), SdkError> {
        let mut request = self.client.post(url);

        // Add custom headers
        for (key, value) in headers {
            request = request.header(*key, *value);
        }

        let response = request.send().await?;
        let status = response.status();

        if status.is_success() {
            Ok(())
        } else {
            let status_code = status.as_u16();
            let body = response.text().await.unwrap_or_default();

            if status_code == 429 {
                return Err(SdkError::Api(ApiError::RateLimited {
                    retry_after_secs: 60,
                }));
            }

            if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&body) {
                return Err(SdkError::Api(ApiError::ServerError {
                    error_code: error_response.error_code,
                    message: error_response.message,
                }));
            }

            Err(SdkError::Api(ApiError::HttpError {
                status: status_code,
                message: if body.is_empty() {
                    status.canonical_reason().unwrap_or("Unknown").to_string()
                } else {
                    body
                },
            }))
        }
    }

    pub async fn delete<T: DeserializeOwned>(
        &self,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<T, SdkError> {
        let mut request = self.client.delete(url).header("Accept", "application/json");

        // Add custom headers
        for (key, value) in headers {
            request = request.header(*key, *value);
        }

        request = request.header("Accept-Encoding", "gzip");

        let response = request.send().await?;
        self.handle_response(response).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, SdkError> {
        let status = response.status();

        if status.is_success() {
            let body = response.bytes().await?;
            let result: T = serde_json::from_slice(&body)?;
            Ok(result)
        } else {
            let status_code = status.as_u16();
            let body = response.text().await.unwrap_or_default();

            if status_code == 429 {
                return Err(SdkError::Api(ApiError::RateLimited {
                    retry_after_secs: 60,
                }));
            }

            if let Ok(error_response) = serde_json::from_str::<ErrorResponse>(&body) {
                return Err(SdkError::Api(ApiError::ServerError {
                    error_code: error_response.error_code,
                    message: error_response.message,
                }));
            }

            Err(SdkError::Api(ApiError::HttpError {
                status: status_code,
                message: if body.is_empty() {
                    status.canonical_reason().unwrap_or("Unknown").to_string()
                } else {
                    body
                },
            }))
        }
    }

    fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, SdkError> {
        use std::io::Write;

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(data)
            .map_err(|e| SdkError::Network(NetworkError::Compression(e.to_string())))?;
        encoder
            .finish()
            .map_err(|e| SdkError::Network(NetworkError::Compression(e.to_string())))
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("Failed to create default HTTP client")
    }
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("config", &self.config)
            .finish()
    }
}
