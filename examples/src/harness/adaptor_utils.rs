use anyhow::{anyhow, Result};
use keymeld_sdk::types::{AdaptorConfig, AdaptorSignatureResult, AdaptorType};
use musig2::secp256k1::{PublicKey, Secp256k1, SecretKey};
use musig2::{AdaptorSignature, BinaryEncoding, LiftedSignature};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorTestConfig {
    pub test_single: bool,
    pub test_and: bool,
    pub test_or: bool,
    pub skip_regular_signing: bool,
}

#[derive(Debug, Clone)]
pub struct AdaptorSecret {
    pub secret: SecretKey,
    pub point: PublicKey,
}

impl Default for AdaptorSecret {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptorSecret {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut rng = rand::rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);

        let secret = SecretKey::from_byte_array(secret_bytes).expect("Valid secret key");
        let point = PublicKey::from_secret_key(&Secp256k1::new(), &secret);

        Self { secret, point }
    }
}

impl Default for AdaptorTestConfig {
    fn default() -> Self {
        Self {
            test_single: true,
            test_and: false,
            test_or: false,
            skip_regular_signing: false, // Now we can do real adaptation
        }
    }
}

pub fn create_test_adaptor_configs(
    config: &AdaptorTestConfig,
) -> Result<(Vec<AdaptorConfig>, Vec<AdaptorSecret>)> {
    if config.test_and || config.test_or {
        return Err(anyhow!("And and Or adaptor modes are unsupported"));
    }
    let mut adaptor_configs = Vec::new();
    let mut adaptor_secrets = Vec::new();

    if config.test_single {
        info!("🔑 Generating secret for single adaptor signature");
        let secret = AdaptorSecret::new();
        let point_hex = hex::encode(secret.point.serialize());

        adaptor_configs.push(AdaptorConfig::single(point_hex));
        adaptor_secrets.push(secret);
    }

    if adaptor_configs.is_empty() {
        return Err(anyhow!("No adaptor configurations selected for testing"));
    }

    Ok((adaptor_configs, adaptor_secrets))
}

pub fn adapt_signatures_and_get_valid_signature(
    configs: &[AdaptorConfig],
    signatures: &BTreeMap<Uuid, AdaptorSignatureResult>,
    secrets: &[AdaptorSecret],
    aggregate_pubkey: PublicKey,
    message_hash: &[u8],
) -> Result<Vec<u8>> {
    info!("🔓 Adapting adaptor signatures with revealed secrets...");

    for (i, config) in configs.iter().enumerate() {
        let Some(signature) = signatures.get(&config.adaptor_id) else {
            continue;
        };

        info!(
            "🔓 Adapting {:?} signature for config {}",
            config.adaptor_type, config.adaptor_id
        );

        // Get the adaptor signature bytes
        let adaptor_sig_bytes = &signature.signature_scalar;
        if adaptor_sig_bytes.len() != 65 {
            return Err(anyhow!(
                "Invalid adaptor signature length: expected 65 bytes, got {}",
                adaptor_sig_bytes.len()
            ));
        }

        // Parse the adaptor signature using BinaryEncoding::from_bytes
        let adaptor_signature = AdaptorSignature::from_bytes(adaptor_sig_bytes)
            .map_err(|e| anyhow!("Failed to parse adaptor signature: {e}"))?;

        // Get the appropriate secret for this config
        let secret = match config.adaptor_type {
            AdaptorType::Single => {
                if i < secrets.len() {
                    secrets[i].secret
                } else {
                    return Err(anyhow!("No secret available for single adaptor"));
                }
            }
            AdaptorType::And | AdaptorType::Or => {
                return Err(anyhow!("And and Or adaptor modes are unsupported"));
            }
        };

        info!("🔓 Applying secret to adapt signature...");
        let adapted_signature: LiftedSignature = adaptor_signature
            .adapt(secret)
            .ok_or_else(|| anyhow!("Failed to adapt signature - invalid secret or result"))?;

        // Verify the adapted signature
        info!("🔍 Verifying adapted signature...");
        musig2::verify_single(aggregate_pubkey, adapted_signature, message_hash)
            .map_err(|e| anyhow!("Adapted signature verification failed: {e}"))?;

        info!(
            "✅ {:?} signature adapted and verified successfully!",
            config.adaptor_type
        );

        // Return the first valid adapted signature for broadcasting
        return Ok(adapted_signature.to_bytes().to_vec());
    }

    Err(anyhow!("No adaptor signatures to adapt"))
}

pub fn validate_adaptor_signatures(
    configs: &[AdaptorConfig],
    signatures: &BTreeMap<Uuid, AdaptorSignatureResult>,
) -> Result<()> {
    keymeld_sdk::validation::validate_decrypted_adaptor_configs(configs)?;
    info!("Validating adaptor signatures...");

    if configs.len() != signatures.len() {
        return Err(anyhow!(
            "Mismatch between configs ({}) and signatures ({})",
            configs.len(),
            signatures.len()
        ));
    }

    for config in configs.iter() {
        let signature = signatures
            .get(&config.adaptor_id)
            .ok_or_else(|| anyhow!("Missing signature for adaptor ID {}", config.adaptor_id))?;

        if std::mem::discriminant(&config.adaptor_type)
            != std::mem::discriminant(&signature.adaptor_type)
        {
            return Err(anyhow!(
                "Adaptor type mismatch for ID {}",
                config.adaptor_id
            ));
        }

        // For adaptor signatures, be more flexible with validation since sizes may vary
        if signature.signature_scalar.len() < 64 {
            return Err(anyhow!(
                "Invalid adaptor signature length for ID {}: expected at least 64 bytes, got {}",
                config.adaptor_id,
                signature.signature_scalar.len()
            ));
        }

        if signature.nonce_point.len() < 33 {
            return Err(anyhow!(
                "Invalid nonce point length for ID {}: expected at least 33 bytes, got {}",
                config.adaptor_id,
                signature.nonce_point.len()
            ));
        }

        if signature.aggregate_adaptor_point.len() != 33 {
            return Err(anyhow!(
                "Invalid aggregate adaptor point length for ID {}: expected 33 bytes, got {}",
                config.adaptor_id,
                signature.aggregate_adaptor_point.len()
            ));
        }

        let config_points_bytes: Vec<Vec<u8>> = config
            .adaptor_points
            .iter()
            .map(|hex| hex::decode(hex).unwrap_or_default())
            .collect();
        if config_points_bytes != signature.adaptor_points {
            return Err(anyhow!(
                "Adaptor points mismatch for ID {}",
                config.adaptor_id
            ));
        }

        info!(
            "✅ {:?} adaptor signature validated: ID={}",
            signature.adaptor_type, signature.adaptor_id
        );
    }

    info!("✅ All adaptor signatures validated successfully");
    Ok(())
}

/// Print a comprehensive success summary for adaptor signature tests
pub fn print_success_summary(
    configs: &[AdaptorConfig],
    signatures: &BTreeMap<Uuid, AdaptorSignatureResult>,
    aggregate_key: &str,
) {
    println!("\n🎉 All Adaptor Signature Tests Completed Successfully!");
    println!("===============================================");
    println!("✅ Aggregate key: {aggregate_key}");

    for (i, config) in configs.iter().enumerate() {
        if let Some(signature) = signatures.get(&config.adaptor_id) {
            println!("📋 Adaptor Signature {} Details:", i + 1);
            println!("   Type: {:?}", signature.adaptor_type);
            println!("   ID: {}", signature.adaptor_id);
            println!(
                "   Points: {} adaptor points",
                signature.adaptor_points.len()
            );
            if let Some(hints) = &signature.hints {
                println!("   Hints: {} hints provided", hints.len());
            }
            println!(
                "   Signature scalar: {}...",
                &hex::encode(&signature.signature_scalar)[..16]
            );
            println!(
                "   Nonce point: {}...",
                &hex::encode(&signature.nonce_point)[..16]
            );
            println!(
                "   Aggregate adaptor point: {}...",
                &hex::encode(&signature.aggregate_adaptor_point)[..16]
            );
            println!();
        }
    }
}
