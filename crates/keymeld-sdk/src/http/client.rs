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
        let builder = reqwest::Client::builder();

        // timeout() is not available on WASM
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.timeout(config.timeout);

        // gzip() is not available on WASM (browser handles compression)
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder.gzip(true);

        let client = builder
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

    /// Bounded, uncompressed confidential transport. Never include response
    /// bodies in public transport errors; native error details are encrypted.
    pub(crate) async fn post_bounded<Req: Serialize, Res: DeserializeOwned>(
        &self,
        url: &str,
        body: &Req,
        max_bytes: usize,
    ) -> Result<Res, SdkError> {
        let bytes = serde_json::to_vec(body)?;
        if bytes.len() > max_bytes {
            return Err(SdkError::InvalidInput(
                "Confidential request exceeds transport limit".into(),
            ));
        }
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .body(bytes)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(SdkError::Internal(
                "Confidential relay rejected request".into(),
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            return Err(SdkError::InvalidInput(
                "Confidential response exceeds transport limit".into(),
            ));
        }
        #[cfg(not(target_arch = "wasm32"))]
        let bytes = {
            let mut response = response;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                if chunk.len() > max_bytes.saturating_sub(bytes.len()) {
                    return Err(SdkError::InvalidInput(
                        "Confidential response exceeds transport limit".into(),
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            bytes
        };
        #[cfg(target_arch = "wasm32")]
        let bytes = {
            // Browser fetch owns the response buffering; reject before decoding.
            let bytes = response.bytes().await?;
            if bytes.len() > max_bytes {
                return Err(SdkError::InvalidInput(
                    "Confidential response exceeds transport limit".into(),
                ));
            }
            bytes
        };
        serde_json::from_slice(&bytes)
            .map_err(|_| SdkError::InvalidInput("Invalid confidential response".into()))
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

    pub async fn post_json_no_response<Req: Serialize>(
        &self,
        url: &str,
        body: &Req,
        headers: &[(&str, &str)],
    ) -> Result<(), SdkError> {
        let mut request = self.client.post(url).json(body);
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let response = request.send().await?;
        self.handle_empty_response(response).await
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
        self.handle_empty_response(response).await
    }

    async fn handle_empty_response(&self, response: reqwest::Response) -> Result<(), SdkError> {
        let status = response.status();

        if status.is_success() {
            Ok(())
        } else {
            let status_code = status.as_u16();
            if status_code == 429 {
                return Err(SdkError::Api(ApiError::RateLimited {
                    retry_after_secs: Self::retry_after_secs(response.headers()),
                }));
            }
            let body = response.text().await.unwrap_or_default();

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
            if status_code == 429 {
                return Err(SdkError::Api(ApiError::RateLimited {
                    retry_after_secs: Self::retry_after_secs(response.headers()),
                }));
            }
            let body = response.text().await.unwrap_or_default();

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

    fn retry_after_secs(headers: &reqwest::header::HeaderMap) -> u64 {
        headers
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap_or(60)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limit_responses_preserve_gateway_retry_delay_for_both_response_paths() {
        let mut server = mockito::Server::new_async().await;
        let limited = server
            .mock("GET", "/limited")
            .with_status(429)
            .with_header("retry-after", "2")
            .expect(2)
            .create_async()
            .await;
        let client = HttpClient::default();
        for empty in [false, true] {
            let response = reqwest::get(format!("{}/limited", server.url()))
                .await
                .unwrap();
            let error = if empty {
                client.handle_empty_response(response).await.unwrap_err()
            } else {
                client
                    .handle_response::<serde_json::Value>(response)
                    .await
                    .unwrap_err()
            };
            assert!(matches!(
                error,
                SdkError::Api(ApiError::RateLimited {
                    retry_after_secs: 2
                })
            ));
        }
        limited.assert_async().await;
    }
}
