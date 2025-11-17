use anyhow::Result;
use keymeld_examples::KeyMeldE2ETest;
use tracing::{error, info};
use tracing_subscriber::fmt::init;

#[tokio::main]
async fn main() -> Result<()> {
    init();

    let (config, amount, destination) = KeyMeldE2ETest::load_basic_config()?;
    info!("Loaded configuration");
    let mut test = KeyMeldE2ETest::new(config, amount, destination).await?;

    tokio::select! {
        result = run(&mut test) => {
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

async fn run(test: &mut KeyMeldE2ETest) -> Result<()> {
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
    info!("   - Coordinator: {}", test.coordinator_user_id.as_str());
    info!(
        "   - Participant 0: {}",
        test.participant_user_ids[0].as_str()
    );

    test.approve_signing_session(
        &signing_session_id,
        test.coordinator_user_id.as_str(),
        &test.coordinator_derived_private_key,
    )
    .await?;

    test.approve_signing_session(
        &signing_session_id,
        test.participant_user_ids[0].as_str(),
        &test.participants[0].derived_private_key,
    )
    .await?;
    info!("✅ All required approvals completed - signing can now proceed");

    let signature = test
        .wait_for_signing_completion(&signing_session_id, &keygen_session_id)
        .await?;

    let signed_tx = test.apply_signature_and_broadcast(psbt, &signature).await?;

    println!("\n🎉 Three-Phase KeyMeld Test Completed Successfully!");
    println!("✅ Phase 1: Keygen session completed");
    println!("✅ Phase 2a: Signing approvals completed (with HMAC authentication)");
    println!("✅ Phase 2b: Signing session completed (participants inherited from keygen)");
    println!("✅ Aggregate key: {}", aggregate_key);
    println!("✅ Transaction broadcast: {}", signed_tx.compute_txid());
    println!("📋 Keygen Session ID: {}", keygen_session_id);
    println!("📋 Signing Session ID: {}", signing_session_id);

    Ok(())
}
