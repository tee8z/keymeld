use anyhow::Result;
use aws_config::BehaviorVersion;
use aws_sdk_kms::Client as KmsClient;
use keymeld_core::protocol::{ConfigureCommand, SocketClient, SystemCommand};
use keymeld_core::{
    identifiers::EnclaveId,
    protocol::{Command, EnclaveCommand, EnclaveOutcome, SystemOutcome},
};
use tracing::{info, warn};

use crate::{config::KmsConfig, database::Database};

pub async fn init_kms_client(config: &KmsConfig) -> Result<Option<KmsClient>> {
    if !config.enabled {
        info!("KMS is disabled in configuration");
        return Ok(None);
    }

    info!("Initializing KMS client...");

    let aws_config = if let Some(endpoint_url) = &config.endpoint_url {
        info!("Using custom KMS endpoint: {}", endpoint_url);
        aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(endpoint_url)
            .load()
            .await
    } else {
        info!("Using default AWS KMS endpoint");
        aws_config::defaults(BehaviorVersion::latest()).load().await
    };

    let kms_client = KmsClient::new(&aws_config);

    info!(
        "KMS client initialized (key_id: {}, local: {})",
        config.key_id,
        config.is_local_kms()
    );

    Ok(Some(kms_client))
}

pub async fn configure_enclave_with_kms(
    enclave_id: EnclaveId,
    client: &SocketClient,
    db: &Database,
    kms_config: &KmsConfig,
) -> Result<()> {
    info!("Configuring enclave {} with KMS", enclave_id);

    let kms_endpoint = kms_config
        .endpoint_url
        .clone()
        .unwrap_or_else(|| "aws-kms".to_string());
    let kms_key_id = kms_config.key_id.clone();

    let existing_keys = db.get_enclave_master_key(enclave_id).await?;

    let (encrypted_dek, encrypted_private_key, key_epoch) = if let Some(keys) = existing_keys {
        if keys.kms_key_id != kms_key_id {
            warn!(
                "KMS key rotation detected for enclave {}: old_key={}, new_key={}",
                enclave_id, keys.kms_key_id, kms_key_id
            );
            info!(
                "Performing key rotation for enclave {} (current epoch: {})",
                enclave_id, keys.key_epoch
            );
            (None, None, Some(keys.key_epoch as u64))
        } else {
            info!(
                "Found existing keys for enclave {} (epoch: {}), performing restart initialization",
                enclave_id, keys.key_epoch
            );
            (
                Some(keys.kms_encrypted_dek),
                Some(keys.encrypted_private_key),
                Some(keys.key_epoch as u64),
            )
        }
    } else {
        info!(
            "No existing keys found for enclave {}, performing first-boot initialization",
            enclave_id
        );
        (None, None, None)
    };

    let configure_cmd = ConfigureCommand {
        enclave_id,
        key_epoch,
        kms_endpoint: Some(kms_endpoint),
        kms_key_id: Some(kms_key_id.clone()),
        encrypted_dek,
        encrypted_private_key,
    };

    let command = Command::new(EnclaveCommand::System(SystemCommand::Configure(
        configure_cmd,
    )));

    let response = client.send_command(command.into()).await?;

    match response.response.response {
        EnclaveOutcome::System(SystemOutcome::Configured(configured_response)) => {
            // Enclave returned encrypted keys - store them if newly generated
            if configured_response.newly_generated {
                info!(
                    "Enclave {} generated new keys, storing encrypted keys in database",
                    enclave_id
                );
                db.store_enclave_master_key(
                    enclave_id,
                    &configured_response.encrypted_dek,
                    &configured_response.encrypted_private_key,
                    &kms_key_id,
                )
                .await?;
                info!(
                    "Stored encrypted master keys for enclave {} (public_key: {})",
                    enclave_id,
                    hex::encode(
                        &configured_response.public_key
                            [..8.min(configured_response.public_key.len())]
                    )
                );
            } else {
                info!(
                    "Enclave {} restored existing keys (public_key: {})",
                    enclave_id,
                    hex::encode(
                        &configured_response.public_key
                            [..8.min(configured_response.public_key.len())]
                    )
                );
            }
            Ok(())
        }
        EnclaveOutcome::System(SystemOutcome::Success) => {
            // Simple epoch sync without KMS - no keys to store
            info!("Enclave {} configured successfully (no KMS)", enclave_id);
            Ok(())
        }
        other => {
            warn!(
                "Unexpected response from enclave {} during KMS configuration: {:?}",
                enclave_id, other
            );
            Err(anyhow::anyhow!(
                "Unexpected response from enclave during KMS configuration: {:?}",
                other
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kms_disabled() {
        let config = KmsConfig {
            enabled: false,
            endpoint_url: None,
            key_id: "test-key".to_string(),
        };

        let result = init_kms_client(&config).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_kms_enabled_with_endpoint() {
        let config = KmsConfig {
            enabled: true,
            endpoint_url: Some("http://localhost:4566".to_string()),
            key_id: "arn:aws:kms:us-west-2:123456789012:key/test".to_string(),
        };

        let result = init_kms_client(&config).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }
}
