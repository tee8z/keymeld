use anyhow::Result;
use keymeld_examples::KeyMeldE2ETest;
use tracing::{error, info};
use tracing_subscriber::fmt::init;

pub async fn run_with_args(
    config_path: String,
    amount: u64,
    destination: Option<String>,
) -> Result<()> {
    use keymeld_examples::ExampleConfig;
    use std::fs::read_to_string;

    init();

    let config_content = read_to_string(&config_path)?;
    let config = serde_yaml::from_str::<ExampleConfig>(&config_content)?;
    info!("Loaded configuration from {}", config_path);

    if destination.is_none() {
        info!("No destination address provided, will generate from coordinator wallet");
    }

    let mut test = KeyMeldE2ETest::new(config, amount, destination).await?;

    tokio::select! {
        result = run_test(&mut test) => {
            match result {
                Ok(()) => {
                    println!("\n✅ KeyMeld end-to-end test completed successfully!");
                }
                Err(e) => {
                    error!("End-to-end test failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\n🛑 Received Ctrl+C, shutting down gracefully...");
            std::process::exit(0);
        }
    }

    Ok(())
}

async fn run_test(test: &mut KeyMeldE2ETest) -> Result<()> {
    info!("🧪 KeyMeld End-to-End Test - Two-Phase Flow");
    info!("============================================");
    info!("Network: {}", test.config.network);
    info!("Gateway: {}", test.config.gateway_url);
    info!("Participants: {}", test.config.num_signers);

    test.load_participants().await?;

    test.fund_coordinator_from_master().await?;

    info!("🔑 Starting Phase 1: Keygen Session");
    let keygen_session_id = test.create_keygen_session().await?;

    info!("📋 Approval Configuration:");
    info!("   - Coordinator requires signing approval: YES");
    info!("   - Participant 0 requires signing approval: YES");
    if test.participants.len() > 1 {
        info!("   - Other participants require signing approval: NO");
    }

    test.register_keygen_participants(&keygen_session_id)
        .await?;
    let aggregate_key = test.wait_for_keygen_completion(&keygen_session_id).await?;
    info!("✅ Keygen complete: {}", aggregate_key);

    let aggregate_utxo = test.fund_aggregate_key_address(&aggregate_key).await?;

    let psbt = test
        .create_musig2_transaction(&aggregate_key, &aggregate_utxo)
        .await?;

    info!("✍️ Starting Phase 2: Signing Session");
    let signing_session_id = test
        .create_signing_session(&keygen_session_id, &psbt)
        .await?;

    info!("📋 Starting Phase 2a: Signing Approvals");
    info!("⚠️  Participants requiring approval before signing can proceed:");
    info!(
        "   - Coordinator: {} (requires approval: YES)",
        test.coordinator_user_id.as_str()
    );
    for idx in 0..test.participant_user_ids.len() {
        let requires_approval = test.participants_requiring_approval.contains(&idx);
        info!(
            "   - Participant {}: {} (requires approval: {})",
            idx,
            test.participant_user_ids[idx].as_str(),
            if requires_approval { "YES" } else { "NO" }
        );
    }
    info!("ℹ️  Note: Approval requests may retry if signing session initialization is still in progress");

    // Approve for coordinator (always requires approval)
    test.approve_signing_session(
        &signing_session_id,
        &test.coordinator_user_id,
        &test.coordinator_derived_private_key,
        &keygen_session_id,
    )
    .await?;

    // Approve only for participants that require approval
    for idx in &test.participants_requiring_approval {
        test.approve_signing_session(
            &signing_session_id,
            &test.participant_user_ids[*idx],
            &test.participants[*idx].derived_private_key,
            &keygen_session_id,
        )
        .await?;
    }
    info!("✅ All required approvals completed - signing can now proceed");

    let signature = test
        .wait_for_signing_completion(&signing_session_id, &keygen_session_id)
        .await?;

    let signed_tx = test.apply_signature_and_broadcast(psbt, &signature).await?;

    println!("\n🎉 Three-Phase KeyMeld Test Completed Successfully!");
    println!("✅ Phase 1: Keygen session completed");
    println!("✅ Phase 2a: Signing approvals completed (with signature authentication)");
    println!("✅ Phase 2b: Signing session completed (participants inherited from keygen)");
    println!("✅ Aggregate key: {aggregate_key}");
    println!("✅ Transaction broadcast: {}", signed_tx.compute_txid());
    println!("📋 Keygen Session ID: {keygen_session_id}");
    println!("📋 Signing Session ID: {signing_session_id}");

    Ok(())
}
