use anyhow::Result;
use keymeld_examples::ExampleConfig;
use keymeld_sdk::prelude::*;
use std::fs::read_to_string;
use tracing::info;

pub async fn run_with_args(config_path: String) -> Result<()> {
    let config_content = read_to_string(&config_path)?;
    let config: ExampleConfig = serde_yaml::from_str(&config_content)?;

    info!("Stored Key / Session Restore Example");
    info!("Gateway: {}", config.gateway_url);

    // Generate a random private key
    let mut private_key_bytes = [0u8; 32];
    rand::fill(&mut private_key_bytes);

    let user_id = UserId::new_v7();

    // Create credentials from the private key
    let credentials = UserCredentials::from_private_key(&private_key_bytes)?;
    info!("User ID: {}", user_id);
    info!(
        "Public key: {}",
        hex::encode(credentials.public_key_bytes())
    );

    // =========================================================================
    // Phase 1: Initial setup - import key
    // =========================================================================
    info!("");
    info!("Phase 1: Initial Setup");

    let client = KeyMeldClient::builder(&config.gateway_url, user_id.clone())
        .credentials(credentials)
        .build()?;

    // Reserve and import
    let reservation = client.reserve_key_slot().await?;
    let key_id = client.import_key(&reservation, &private_key_bytes).await?;
    info!("Key imported: {}", key_id);

    // Sign something to prove it works
    let test_message = [0x42u8; 32];
    let sig1 = client
        .sign(&key_id, test_message, SignatureType::SchnorrBip340)
        .await?;
    info!("Initial signature: {}", hex::encode(&sig1[..8]));

    // =========================================================================
    // Phase 2: Simulate restart - recreate client from saved credentials
    // =========================================================================
    info!("");
    info!("Phase 2: Simulating Restart");
    info!("(In production, you'd save private_key_bytes and user_id to disk/DB)");

    // Drop the old client
    drop(client);
    info!("Original client dropped");

    // Recreate credentials from the same private key (as if loaded from storage)
    let restored_credentials = UserCredentials::from_private_key(&private_key_bytes)?;

    // Create a new client with the restored credentials
    let restored_client = KeyMeldClient::builder(&config.gateway_url, user_id)
        .credentials(restored_credentials)
        .build()?;
    info!("Client restored from saved credentials");

    // =========================================================================
    // Phase 3: Verify the stored key still works
    // =========================================================================
    info!("");
    info!("Phase 3: Verify Stored Key");

    // List keys - should find our key
    let keys = restored_client.list_keys(&key_id).await?;
    info!("Found {} key(s) after restore", keys.len());

    let found = keys.iter().any(|k| k.key_id == key_id);
    if !found {
        return Err(anyhow::anyhow!("Key not found after restore!"));
    }
    info!("Key {} found in storage", key_id);

    // Sign with the same key - should work
    let sig2 = restored_client
        .sign(&key_id, test_message, SignatureType::SchnorrBip340)
        .await?;
    info!("Post-restore signature: {}", hex::encode(&sig2[..8]));

    // Signatures should be different (randomized nonces) but both valid
    if sig1 == sig2 {
        info!("Note: Signatures are identical (deterministic signing)");
    } else {
        info!("Signatures differ as expected (randomized nonces)");
    }

    // Cleanup
    restored_client.delete_key(&key_id).await?;
    info!("Key deleted");

    info!("");
    info!("Stored Key Example Complete!");
    info!("  - Imported key in initial session");
    info!("  - Signed message");
    info!("  - Simulated restart (dropped client)");
    info!("  - Restored client from saved credentials");
    info!("  - Verified key still accessible");
    info!("  - Signed message with restored client");

    Ok(())
}
