//! Keygen with stored key end-to-end test harness
//!
//! This test exercises the flow of:
//! 1. Complete a keygen session (using existing keygen flow)
//! 2. Store the key from keygen to user_keys
//! 3. Verify the stored key appears in list_keys
//!
//! Future extension (Phase H): Use stored key in new keygen session
//!
//! This test will initially fail until the backend implementation is complete.

use anyhow::{anyhow, Result};
use keymeld_sdk::{
    KeyId, ListUserKeysResponse, SecureCrypto, StoreKeyFromKeygenRequest,
    StoreKeyFromKeygenResponse, UserId,
};
use reqwest::Client;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use crate::{ExampleConfig, KeyMeldE2ETest};

/// Keygen with stored key E2E test harness
pub struct KeygenWithStoredKeyE2ETest {
    pub config: ExampleConfig,
    pub client: Client,
    /// The underlying KeyMeld E2E test for keygen operations
    pub keygen_test: KeyMeldE2ETest,
    /// User ID for the coordinator (who will store their key)
    pub coordinator_user_id: UserId,
    /// Auth keypair for the coordinator
    pub coordinator_auth_private_key: SecretKey,
    pub coordinator_auth_public_key: PublicKey,
    /// Stored key ID after storing from keygen
    pub stored_key_id: Option<KeyId>,
}

impl KeygenWithStoredKeyE2ETest {
    pub async fn new(config: ExampleConfig) -> Result<Self> {
        info!("Initializing Keygen with Stored Key E2E Test");
        info!("Gateway: {}", config.gateway_url);

        let client = Client::new();

        // Create the underlying keygen test with a minimal amount (we're not broadcasting)
        let keygen_test = KeyMeldE2ETest::new(config.clone(), 10000, None).await?;

        let coordinator_user_id = keygen_test.coordinator_user_id.clone();

        // Derive auth keypair from the coordinator's private key
        let coordinator_private_key_bytes =
            keygen_test.coordinator_derived_private_key.secret_bytes();
        let (coordinator_auth_private_key, coordinator_auth_public_key) =
            SecureCrypto::derive_session_auth_keypair(
                &coordinator_private_key_bytes,
                "stored_key_auth",
            )
            .map_err(|e| anyhow!("Failed to derive auth keypair: {}", e))?;

        info!("Coordinator User ID: {}", coordinator_user_id);

        Ok(Self {
            config,
            client,
            keygen_test,
            coordinator_user_id,
            coordinator_auth_private_key,
            coordinator_auth_public_key,
            stored_key_id: None,
        })
    }

    /// Step 1: Run the keygen session
    pub async fn run_keygen(&mut self) -> Result<String> {
        info!("Step 1: Running keygen session...");

        // Load participants
        self.keygen_test.load_participants().await?;

        // Fund coordinator (minimal amount)
        self.keygen_test.fund_coordinator_from_master().await?;

        // Create and complete keygen session
        let keygen_session_id = self.keygen_test.create_keygen_session().await?;
        info!("Created keygen session: {}", keygen_session_id);

        self.keygen_test
            .register_keygen_participants(&keygen_session_id)
            .await?;

        let aggregate_key = self
            .keygen_test
            .wait_for_keygen_completion(&keygen_session_id)
            .await?;

        info!("Keygen complete:");
        info!("  Session ID: {}", keygen_session_id);
        info!("  Aggregate Key: {}", aggregate_key);

        Ok(keygen_session_id.to_string())
    }

    /// Step 2: Store the key from keygen
    pub async fn store_key_from_keygen(
        &mut self,
        keygen_session_id: &str,
    ) -> Result<StoreKeyFromKeygenResponse> {
        info!("Step 2: Storing key from keygen session...");

        // Generate a new key_id for the stored key
        let key_id = KeyId::new_v7();

        // Generate auth signature for the request
        let auth_signature =
            self.generate_auth_signature(&format!("store_key:{}", keygen_session_id))?;

        let request = StoreKeyFromKeygenRequest {
            key_id: key_id.clone(),
        };

        let response = self
            .client
            .post(format!(
                "{}/api/v1/keys/{}/keygen/{}",
                self.config.gateway_url, self.coordinator_user_id, keygen_session_id
            ))
            .header("X-Auth-Signature", auth_signature)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to store key from keygen (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let store_response: StoreKeyFromKeygenResponse = response.json().await?;

        info!("Key stored successfully:");
        info!("  Key ID: {}", store_response.key_id);
        info!("  User ID: {}", store_response.user_id);
        info!("  From Keygen Session: {}", keygen_session_id);

        self.stored_key_id = Some(store_response.key_id.clone());

        Ok(store_response)
    }

    /// Step 3: List user keys and verify stored key
    pub async fn list_and_verify_stored_key(&self) -> Result<ListUserKeysResponse> {
        info!("Step 3: Listing keys and verifying stored key...");

        let stored_key_id = self
            .stored_key_id
            .clone()
            .ok_or(anyhow!("No stored key - call store_key_from_keygen first"))?;

        // Generate auth signature for the request
        let auth_signature = self.generate_auth_signature("list_keys")?;

        let response = self
            .client
            .get(format!(
                "{}/api/v1/keys/{}",
                self.config.gateway_url, self.coordinator_user_id
            ))
            .header("X-Auth-Signature", auth_signature)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await?;
            return Err(anyhow!(
                "Failed to list keys (HTTP {}): {}",
                status,
                error_text
            ));
        }

        let list_response: ListUserKeysResponse = response.json().await?;

        info!(
            "Listed {} keys for user {}",
            list_response.keys.len(),
            self.coordinator_user_id
        );

        // Verify our stored key is in the list
        let found_key = list_response
            .keys
            .iter()
            .find(|k| k.key_id == stored_key_id);

        if let Some(key) = found_key {
            info!("Found stored key:");
            info!("  Key ID: {}", key.key_id);
            info!("  Created At: {}", key.created_at);
            info!(
                "  Origin Keygen Session: {:?}",
                key.origin_keygen_session_id
            );

            // Verify the origin_keygen_session_id is set (not None, since this came from keygen)
            if key.origin_keygen_session_id.is_none() {
                return Err(anyhow!(
                    "Expected origin_keygen_session_id to be set for key from keygen"
                ));
            }
        } else {
            return Err(anyhow!(
                "Stored key {} not found in list response",
                stored_key_id
            ));
        }

        Ok(list_response)
    }

    /// Generate auth signature for a request
    fn generate_auth_signature(&self, action: &str) -> Result<String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Sign: SHA256(user_id || action || timestamp)
        let mut hasher = Sha256::new();
        hasher.update(self.coordinator_user_id.to_string().as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash = hasher.finalize();

        let hash_array: [u8; 32] = hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Hash is not 32 bytes"))?;

        let secp = Secp256k1::signing_only();
        let message = Message::from_digest(hash_array);
        let signature = secp.sign_ecdsa(message, &self.coordinator_auth_private_key);

        // Return: signature_hex:timestamp
        Ok(format!(
            "{}:{}",
            hex::encode(signature.serialize_compact()),
            timestamp
        ))
    }
}

/// Run the keygen with stored key e2e test
pub async fn run_keygen_with_stored_key_test(config: ExampleConfig) -> Result<()> {
    info!("Keygen with Stored Key E2E Test");
    info!("================================");

    let mut test = KeygenWithStoredKeyE2ETest::new(config).await?;

    // Step 1: Run keygen
    let keygen_session_id = test.run_keygen().await?;

    // Step 2: Store the key from keygen
    test.store_key_from_keygen(&keygen_session_id).await?;

    // Step 3: List and verify stored key
    test.list_and_verify_stored_key().await?;

    info!("");
    info!("Keygen with Stored Key E2E Test PASSED!");
    info!("  - Completed keygen session");
    info!("  - Stored key from keygen");
    info!("  - Verified stored key in list");

    // Future: Phase H will add tests for using stored key in new keygen session
    info!("");
    info!("NOTE: Using stored keys in new keygen sessions will be tested after Phase H implementation");

    Ok(())
}
