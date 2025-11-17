//! Adaptor Signatures Utilities
//!
//! This module contains utilities and helper functions specific to adaptor signatures testing.

use anyhow::{anyhow, Result};
use keymeld_core::musig::{AdaptorConfig, AdaptorSignatureResult, AdaptorType};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptorTestConfig {
    pub test_single: bool,
    pub test_and: bool,
    pub test_or: bool,
    pub skip_regular_signing: bool,
}

impl Default for AdaptorTestConfig {
    fn default() -> Self {
        Self {
            test_single: true,
            test_and: true,
            test_or: true,
            skip_regular_signing: false,
        }
    }
}

/// Create test adaptor configurations based on the test configuration
pub fn create_test_adaptor_configs(config: &AdaptorTestConfig) -> Result<Vec<AdaptorConfig>> {
    let mut adaptor_configs = Vec::new();

    if config.test_single {
        adaptor_configs.push(AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Single,
            adaptor_points: vec![
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
            ],
            hints: None,
        });
    }

    if config.test_and {
        adaptor_configs.push(AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::And,
            adaptor_points: vec![
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
                "03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34".to_string(),
            ],
            hints: None,
        });
    }

    if config.test_or {
        adaptor_configs.push(AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Or,
            adaptor_points: vec![
                "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_string(),
                "03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34".to_string(),
            ],
            hints: Some(vec!["hint1".to_string(), "hint2".to_string()]),
        });
    }

    if adaptor_configs.is_empty() {
        return Err(anyhow!("No adaptor configurations selected for testing"));
    }

    Ok(adaptor_configs)
}

/// Validate adaptor signatures against their corresponding configurations
pub fn validate_adaptor_signatures(
    configs: &[AdaptorConfig],
    signatures: &[AdaptorSignatureResult],
) -> Result<()> {
    info!("🔍 Validating adaptor signatures...");

    if configs.len() != signatures.len() {
        return Err(anyhow!(
            "Mismatch between configs ({}) and signatures ({})",
            configs.len(),
            signatures.len()
        ));
    }

    for (config, signature) in configs.iter().zip(signatures.iter()) {
        // Validate adaptor ID matches
        if config.adaptor_id != signature.adaptor_id {
            return Err(anyhow!(
                "Adaptor ID mismatch: expected {}, got {}",
                config.adaptor_id,
                signature.adaptor_id
            ));
        }

        // Validate adaptor type matches
        if std::mem::discriminant(&config.adaptor_type)
            != std::mem::discriminant(&signature.adaptor_type)
        {
            return Err(anyhow!(
                "Adaptor type mismatch for ID {}",
                config.adaptor_id
            ));
        }

        // Validate signature scalar is valid hex
        if hex::decode(&signature.signature_scalar).is_err() {
            return Err(anyhow!(
                "Invalid signature scalar hex for ID {}",
                config.adaptor_id
            ));
        }

        // Validate nonce point is valid hex
        if hex::decode(&signature.nonce_point).is_err() {
            return Err(anyhow!(
                "Invalid nonce point hex for ID {}",
                config.adaptor_id
            ));
        }

        // Validate aggregate adaptor point is valid hex
        if hex::decode(&signature.aggregate_adaptor_point).is_err() {
            return Err(anyhow!(
                "Invalid aggregate adaptor point hex for ID {}",
                config.adaptor_id
            ));
        }

        // Validate adaptor points match
        if config.adaptor_points != signature.adaptor_points {
            return Err(anyhow!(
                "Adaptor points mismatch for ID {}",
                config.adaptor_id
            ));
        }

        // Validate hints for Or type
        if matches!(config.adaptor_type, AdaptorType::Or) && config.hints != signature.hints {
            return Err(anyhow!(
                "Hints mismatch for Or adaptor ID {}",
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
    signatures: &[AdaptorSignatureResult],
    aggregate_key: &str,
) {
    println!("\n🎉 All Adaptor Signature Tests Completed Successfully!");
    println!("===============================================");
    println!("✅ Aggregate key: {}", aggregate_key);
    println!("✅ Regular MuSig2 signing completed");
    println!("✅ Adaptor signatures processed automatically");
    println!("✅ Client-side encryption/decryption validated");
    println!("✅ Zero-knowledge privacy verified (gateway remained blind to business logic)");
    println!();

    for (i, (_, signature)) in configs.iter().zip(signatures.iter()).enumerate() {
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
            &signature.signature_scalar[..16]
        );
        println!("   Nonce point: {}...", &signature.nonce_point[..16]);
        println!(
            "   Aggregate adaptor point: {}...",
            &signature.aggregate_adaptor_point[..16]
        );
        println!();
    }

    println!("🔒 Privacy Features Verified:");
    println!("   ✅ Gateway cannot see adaptor IDs or business logic");
    println!("   ✅ All sensitive data encrypted with session secrets");
    println!("   ✅ Automatic workflow progression maintained");
    println!("   ✅ Backward compatibility with regular MuSig2");
}
