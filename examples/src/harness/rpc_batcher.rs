//! RPC Batcher - Queue-based Bitcoin RPC for high-concurrency stress tests
//!
//! Instead of making direct RPC calls that can overwhelm bitcoind,
//! this module writes requests to queue files that are processed
//! by a background batcher script (bitcoin-rpc-batcher.sh).
//!
//! The batcher script batches multiple requests together:
//! - send_to_address requests -> batched into sendmany calls
//! - send_raw_transaction requests -> processed in controlled batches

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};
use uuid::Uuid;

/// Request to fund an address (maps to send_to_address)
#[derive(Debug, Serialize, Deserialize)]
pub struct FundingRequest {
    pub request_id: String,
    pub address: String,
    pub amount: f64,
}

/// Request to broadcast a raw transaction
#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcastRequest {
    pub request_id: String,
    pub raw_tx: String,
}

/// Request to check transaction confirmation
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub request_id: String,
    pub txid: String,
    pub min_confirmations: u32,
}

/// Request to generate blocks to an address
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateRequest {
    pub request_id: String,
    pub num_blocks: u64,
    pub address: String,
}

/// Response for generate blocks
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub success: bool,
    pub block_hashes: Option<Vec<String>>,
    pub error: Option<String>,
}

/// Response from the batcher
#[derive(Debug, Serialize, Deserialize)]
pub struct BatcherResponse {
    pub success: bool,
    pub txid: Option<String>,
    pub error: Option<String>,
}

/// Response for confirmation check
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmResponse {
    pub success: bool,
    pub confirmations: Option<u32>,
    pub confirmed: Option<bool>,
    pub error: Option<String>,
}

/// RPC Batcher client for queue-based Bitcoin RPC
pub struct RpcBatcher {
    queue_dir: String,
    poll_interval_ms: u64,
    max_wait_secs: u64,
}

impl RpcBatcher {
    pub fn new(queue_dir: &str) -> Self {
        Self {
            queue_dir: queue_dir.to_string(),
            poll_interval_ms: 50,
            max_wait_secs: 180,
        }
    }

    /// Submit a funding request and wait for response
    pub async fn send_to_address(&self, address: &str, amount_btc: f64) -> Result<String> {
        let request_id = Uuid::now_v7().to_string();
        let request = FundingRequest {
            request_id: request_id.clone(),
            address: address.to_string(),
            amount: amount_btc,
        };

        let req_dir = format!("{}/funding/requests", self.queue_dir);
        let resp_dir = format!("{}/funding/responses", self.queue_dir);

        // Ensure directories exist
        fs::create_dir_all(&req_dir)?;
        fs::create_dir_all(&resp_dir)?;

        // Write request file
        let req_file = format!("{}/{}.req", req_dir, request_id);
        let req_json = serde_json::to_string(&request)?;
        fs::write(&req_file, &req_json)?;

        info!(
            "📝 Queued funding request {} for {} BTC to {}",
            &request_id[..8],
            amount_btc,
            &address[..20]
        );

        // Wait for response
        self.wait_for_response(&resp_dir, &request_id).await
    }

    /// Submit a broadcast request and wait for response
    pub async fn send_raw_transaction(&self, raw_tx_hex: &str) -> Result<String> {
        let request_id = Uuid::now_v7().to_string();
        let request = BroadcastRequest {
            request_id: request_id.clone(),
            raw_tx: raw_tx_hex.to_string(),
        };

        let req_dir = format!("{}/broadcast/requests", self.queue_dir);
        let resp_dir = format!("{}/broadcast/responses", self.queue_dir);

        // Ensure directories exist
        fs::create_dir_all(&req_dir)?;
        fs::create_dir_all(&resp_dir)?;

        // Write request file
        let req_file = format!("{}/{}.req", req_dir, request_id);
        let req_json = serde_json::to_string(&request)?;
        fs::write(&req_file, &req_json)?;

        info!("📝 Queued broadcast request {}", &request_id[..8]);

        // Wait for response
        self.wait_for_response(&resp_dir, &request_id).await
    }

    /// Wait for transaction confirmation via the batcher
    /// Each caller gets a unique request_id so responses aren't shared
    pub async fn wait_for_confirmation(&self, txid: &str, min_confirmations: u32) -> Result<u32> {
        let req_dir = format!("{}/confirm/requests", self.queue_dir);
        let resp_dir = format!("{}/confirm/responses", self.queue_dir);

        // Ensure directories exist
        fs::create_dir_all(&req_dir)?;
        fs::create_dir_all(&resp_dir)?;

        let start = std::time::Instant::now();
        let max_wait = Duration::from_secs(self.max_wait_secs);
        let check_interval = Duration::from_millis(500);

        // Use a unique request_id per caller to avoid response collision
        let request_id = Uuid::now_v7().to_string();
        let req_file = format!("{}/{}.req", req_dir, request_id);
        let resp_file = format!("{}/{}.resp", resp_dir, request_id);

        // Track if we've logged recently to avoid duplicate logs
        let mut last_log_secs = 0u64;

        while start.elapsed() < max_wait {
            // Check if response exists for our unique request
            if Path::new(&resp_file).exists() {
                if let Ok(resp_content) = fs::read_to_string(&resp_file) {
                    let _ = fs::remove_file(&resp_file);

                    if let Ok(response) = serde_json::from_str::<ConfirmResponse>(&resp_content) {
                        if response.success {
                            if response.confirmed.unwrap_or(false) {
                                return Ok(response.confirmations.unwrap_or(0));
                            }
                            // Not confirmed yet - submit new request
                        } else {
                            let error = response
                                .error
                                .unwrap_or_else(|| "Unknown error".to_string());
                            return Err(anyhow!("Confirm check error: {}", error));
                        }
                    }
                }
            }

            // Submit a new request if we don't have one pending
            if !Path::new(&req_file).exists() {
                let request = ConfirmRequest {
                    request_id: request_id.clone(),
                    txid: txid.to_string(),
                    min_confirmations,
                };
                let req_json = serde_json::to_string(&request)?;
                fs::write(&req_file, &req_json)?;
            }

            // Log progress every 10 seconds (but only once per 10s window)
            let elapsed = start.elapsed().as_secs();
            if elapsed > 0 && elapsed.is_multiple_of(10) && elapsed != last_log_secs {
                last_log_secs = elapsed;
                warn!(
                    "⏳ Still waiting for confirmation of {} ({}s)...",
                    &txid[..16.min(txid.len())],
                    elapsed
                );
            }

            // Wait before next check
            sleep(check_interval).await;
        }

        // Clean up any pending request on timeout
        let _ = fs::remove_file(&req_file);

        Err(anyhow!(
            "Timeout waiting for confirmation after {}s",
            self.max_wait_secs
        ))
    }

    /// Generate blocks to an address and wait for response
    pub async fn generate_to_address(&self, num_blocks: u64, address: &str) -> Result<Vec<String>> {
        let request_id = Uuid::now_v7().to_string();
        let request = GenerateRequest {
            request_id: request_id.clone(),
            num_blocks,
            address: address.to_string(),
        };

        let req_dir = format!("{}/generate/requests", self.queue_dir);
        let resp_dir = format!("{}/generate/responses", self.queue_dir);

        // Ensure directories exist
        fs::create_dir_all(&req_dir)?;
        fs::create_dir_all(&resp_dir)?;

        // Write request file
        let req_file = format!("{}/{}.req", req_dir, request_id);
        let req_json = serde_json::to_string(&request)?;
        fs::write(&req_file, &req_json)?;

        info!(
            "📝 Queued generate request {} for {} blocks to {}",
            &request_id[..8],
            num_blocks,
            &address[..20.min(address.len())]
        );

        // Wait for response
        self.wait_for_generate_response(&resp_dir, &request_id)
            .await
    }

    /// Wait for a generate response file to appear and read it
    async fn wait_for_generate_response(
        &self,
        resp_dir: &str,
        request_id: &str,
    ) -> Result<Vec<String>> {
        let resp_file = format!("{}/{}.resp", resp_dir, request_id);
        let max_attempts = (self.max_wait_secs * 1000) / self.poll_interval_ms;

        for attempt in 0..max_attempts {
            if Path::new(&resp_file).exists() {
                let resp_content = fs::read_to_string(&resp_file)?;

                // Clean up response file
                let _ = fs::remove_file(&resp_file);

                let response: GenerateResponse = serde_json::from_str(&resp_content)
                    .map_err(|e| anyhow!("Failed to parse generate response: {}", e))?;

                if response.success {
                    return Ok(response.block_hashes.unwrap_or_default());
                } else {
                    let error = response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    return Err(anyhow!("Generate error: {}", error));
                }
            }

            // Log progress every 10 seconds
            if attempt > 0 && attempt % (10000 / self.poll_interval_ms) == 0 {
                warn!(
                    "⏳ Still waiting for generate response {} ({}s)...",
                    &request_id[..8],
                    (attempt * self.poll_interval_ms) / 1000
                );
            }

            sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }

        Err(anyhow!(
            "Timeout waiting for generate response after {}s",
            self.max_wait_secs
        ))
    }

    /// Wait for a response file to appear and read it
    async fn wait_for_response(&self, resp_dir: &str, request_id: &str) -> Result<String> {
        let resp_file = format!("{}/{}.resp", resp_dir, request_id);
        let max_attempts = (self.max_wait_secs * 1000) / self.poll_interval_ms;

        for attempt in 0..max_attempts {
            if Path::new(&resp_file).exists() {
                let resp_content = fs::read_to_string(&resp_file)?;

                // Clean up response file
                let _ = fs::remove_file(&resp_file);

                let response: BatcherResponse = serde_json::from_str(&resp_content)
                    .map_err(|e| anyhow!("Failed to parse batcher response: {}", e))?;

                if response.success {
                    let txid = response.txid.unwrap_or_else(|| "unknown".to_string());
                    return Ok(txid);
                } else {
                    let error = response
                        .error
                        .unwrap_or_else(|| "Unknown error".to_string());
                    return Err(anyhow!("Batcher error: {}", error));
                }
            }

            // Log progress every 10 seconds
            if attempt > 0 && attempt % (10000 / self.poll_interval_ms) == 0 {
                warn!(
                    "⏳ Still waiting for batcher response {} ({}s)...",
                    &request_id[..8],
                    (attempt * self.poll_interval_ms) / 1000
                );
            }

            sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }

        Err(anyhow!(
            "Timeout waiting for batcher response after {}s",
            self.max_wait_secs
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_funding_request_serialization() {
        let req = FundingRequest {
            request_id: "test-123".to_string(),
            address: "bcrt1qtest".to_string(),
            amount: 0.001,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("test-123"));
        assert!(json.contains("bcrt1qtest"));
    }
}
