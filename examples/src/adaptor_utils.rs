use anyhow::{anyhow, Result};
use keymeld_core::musig::{AdaptorConfig, AdaptorHint, AdaptorSignatureResult, AdaptorType};
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

pub fn create_test_adaptor_configs(config: &AdaptorTestConfig) -> Result<Vec<AdaptorConfig>> {
    let mut adaptor_configs = Vec::new();

    if config.test_single {
        let point =
            hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .map_err(|e| anyhow!("Invalid hex in single adaptor point: {}", e))?;

        adaptor_configs.push(AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Single,
            adaptor_points: vec![hex::encode(point)],
            hints: None,
        });
    }

    if config.test_and {
        let point1 =
            hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .map_err(|e| anyhow!("Invalid hex in and adaptor point 1: {}", e))?;
        let point2 =
            hex::decode("03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34")
                .map_err(|e| anyhow!("Invalid hex in and adaptor point 2: {}", e))?;

        adaptor_configs.push(AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::And,
            adaptor_points: vec![hex::encode(point1), hex::encode(point2)],
            hints: None,
        });
    }

    if config.test_or {
        let point1 =
            hex::decode("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .map_err(|e| anyhow!("Invalid hex in or adaptor point 1: {}", e))?;
        let point2 =
            hex::decode("03defdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34")
                .map_err(|e| anyhow!("Invalid hex in or adaptor point 2: {}", e))?;

        // Example hints: scalar difference and verification point
        let hint_scalar = vec![
            0x2d, 0xa7, 0x28, 0x35, 0x3f, 0x43, 0xe6, 0x4d, 0x2b, 0x0b, 0x6e, 0x6b, 0xa7, 0x64,
            0xc9, 0xcb, 0x6e, 0x69, 0x45, 0x29, 0xb4, 0x1f, 0x39, 0x2b, 0x4c, 0x2e, 0x37, 0xc9,
            0xc4, 0x3d, 0x1b, 0x1f,
        ];

        let hint_point =
            hex::decode("02044464b55284e5f5a5f4f06a71da2f5fa3e0b625f423aa8e41bfd4c14294e6f")
                .map_err(|e| anyhow!("Invalid hex in or adaptor hint point: {}", e))?;

        adaptor_configs.push(AdaptorConfig {
            adaptor_id: Uuid::now_v7(),
            adaptor_type: AdaptorType::Or,
            adaptor_points: vec![hex::encode(point1), hex::encode(point2)],
            hints: Some(vec![
                AdaptorHint::Scalar(hint_scalar),
                AdaptorHint::Point(hint_point),
            ]),
        });
    }

    if adaptor_configs.is_empty() {
        return Err(anyhow!("No adaptor configurations selected for testing"));
    }

    Ok(adaptor_configs)
}

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
        if config.adaptor_id != signature.adaptor_id {
            return Err(anyhow!(
                "Adaptor ID mismatch: expected {}, got {}",
                config.adaptor_id,
                signature.adaptor_id
            ));
        }

        if std::mem::discriminant(&config.adaptor_type)
            != std::mem::discriminant(&signature.adaptor_type)
        {
            return Err(anyhow!(
                "Adaptor type mismatch for ID {}",
                config.adaptor_id
            ));
        }

        if signature.signature_scalar.len() != 32 {
            return Err(anyhow!(
                "Invalid signature scalar length for ID {}: expected 32 bytes, got {}",
                config.adaptor_id,
                signature.signature_scalar.len()
            ));
        }

        if signature.nonce_point.len() != 33 {
            return Err(anyhow!(
                "Invalid nonce point length for ID {}: expected 33 bytes, got {}",
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

        // Validate hints for Or type
        if matches!(config.adaptor_type, AdaptorType::Or) {
            match (&config.hints, &signature.hints) {
                (Some(config_hints), Some(sig_hints)) => {
                    if config_hints.len() != sig_hints.len() {
                        return Err(anyhow!(
                            "Hints length mismatch for Or adaptor ID {}: config has {}, signature has {}",
                            config.adaptor_id,
                            config_hints.len(),
                            sig_hints.len()
                        ));
                    }
                    // Note: We could add more detailed hint validation here if needed
                }
                (None, Some(_)) | (Some(_), None) => {
                    return Err(anyhow!(
                        "Hints presence mismatch for Or adaptor ID {}",
                        config.adaptor_id
                    ));
                }
                (None, None) => {
                    // Both None is fine for Or type (though unusual)
                }
            }
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
