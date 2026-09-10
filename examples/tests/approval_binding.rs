//! Required-approval regressions against the real gateway and enclave stack.

use anyhow::{anyhow, ensure, Context, Result};
use keymeld_core::authorization::ParticipantApproval;
use keymeld_sdk::prelude::*;
use keymeld_sdk::{SigningSession, SigningSessionStatusResponse};
use reqwest::Client;
use secp256k1::{schnorr::Signature, PublicKey, Secp256k1};
use serde_json::json;
use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn participant(gateway: &str, scalar: u8) -> Result<KeyMeldClient> {
    let mut secret = [0; 32];
    secret[31] = scalar;
    Ok(keymeld_examples::client_builder(gateway, UserId::new_v7())?
        .credentials(UserCredentials::from_private_key(&secret)?)
        .polling_config(PollingConfig::fast())
        .build()?)
}

fn transport_signature(
    participant: &KeyMeldClient,
    keygen_id: &SessionId,
    signing_id: &SessionId,
) -> Result<String> {
    Ok(participant
        .credentials()
        .context("missing participant credentials")?
        .sign_for_session(
            &signing_id.to_string(),
            &participant.user_id().to_string(),
            &keygen_id.to_string(),
        )?)
}

async fn rejected_approval(
    label: &str,
    http: &Client,
    participant: &KeyMeldClient,
    keygen_id: &SessionId,
    signing_id: &SessionId,
    proof: &impl serde::Serialize,
) -> Result<()> {
    let response = http
        .post(participant.url(&format!(
            "/api/v1/signing/{signing_id}/approve/{}",
            participant.user_id()
        )))
        .header(
            "X-User-Signature",
            transport_signature(participant, keygen_id, signing_id)?,
        )
        .json(proof)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status.is_client_error(),
        "{label}: expected client rejection, got {status}: {body}"
    );
    println!("PASS {label} ({status})");
    Ok(())
}

async fn assert_waiting_for(
    signing: &mut SigningSession<'_>,
    missing_participant: &UserId,
) -> Result<()> {
    signing.refresh_status().await?;
    ensure!(
        matches!(signing.status(), SigningStatusKind::CollectingParticipants),
        "signing advanced without the required participant approval: {:?}",
        signing.status()
    );
    ensure!(
        !signing
            .approved_participants()
            .contains(missing_participant),
        "a rejected approval marked the participant approved"
    );
    ensure!(
        signing
            .raw_results()
            .iter()
            .all(|item| { item.signature.is_none() && item.adaptor_signatures.is_none() }),
        "signatures were returned before required approval"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires real gateway and enclave processes; use examples/run-authorization-e2e.sh"]
async fn required_approvals_bind_the_reviewed_complete_batch() -> Result<()> {
    let gateway = std::env::var("KEYMELD_TEST_GATEWAY_URL")
        .context("KEYMELD_TEST_GATEWAY_URL must identify an isolated test gateway")?;
    let http = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let creator = participant(&gateway, 41)?;
    let approver = participant(&gateway, 42)?;
    let mut keygen = creator
        .keygen()
        .create_session(
            vec![creator.user_id().clone(), approver.user_id().clone()],
            KeygenOptions::default().require_approval().timeout(300),
        )
        .await?;
    let keygen_id = keygen.session_id().clone();
    keygen
        .register_self(RegisterOptions::default().require_approval())
        .await?;
    let mut approver_keygen = approver
        .keygen()
        .join_session(
            keygen_id.clone(),
            &keygen.export_session_secret(),
            JoinOptions::default()
                .invitation(keygen.invitation(approver.user_id())?)
                .require_approval(),
        )
        .await?;
    keygen.wait_for_completion().await?;
    approver_keygen.wait_for_completion().await?;
    let roster = keygen.verify_roster()?;
    ensure!(
        roster
            .roster
            .registrations
            .values()
            .all(|registration| registration.context.require_signing_approval),
        "the verified roster lost a participant's approval policy"
    );

    // The application fixes both messages and item identities independently of
    // the gateway's pending-batch response.
    let expected = vec![
        BatchSigningItem::new([0x41; 32]),
        BatchSigningItem::new([0x42; 32]),
    ];
    let mut signing = creator
        .signer()
        .sign_batch(
            &keygen,
            expected.clone(),
            SigningOptions::default().timeout(300),
        )
        .await?;
    let signing_id = signing.session_id().clone();
    let required: BTreeSet<_> = signing
        .participants_requiring_approval()
        .iter()
        .cloned()
        .collect();
    ensure!(
        required == BTreeSet::from([creator.user_id().clone(), approver.user_id().clone()]),
        "gateway did not require both registered participants' approvals"
    );
    signing.approve(&expected).await?;
    assert_waiting_for(&mut signing, approver.user_id()).await?;

    let mut approver_signing = approver
        .signer()
        .restore_session(signing_id.clone(), &approver_keygen)
        .await?;
    let wrong_second_message = [0x43; 32];
    let changed_review = vec![
        expected[0].clone(),
        BatchSigningItem::new(wrong_second_message).with_id(expected[1].id()),
    ];
    ensure!(
        approver_signing.approve(&changed_review).await.is_err(),
        "SDK approved a batch whose second message disagreed with application review"
    );
    assert_waiting_for(&mut signing, approver.user_id()).await?;
    println!("PASS SDK rejects a mismatch in the independently reviewed second batch message");

    // Every attack below carries a valid participant transport signature.
    // The gateway must reject the body proof, not merely an absent auth header.
    rejected_approval(
        "legacy approval without a batch proof",
        &http,
        &approver,
        &keygen_id,
        &signing_id,
        &json!({}),
    )
    .await?;
    let wire_status: SigningSessionStatusResponse = http
        .get(approver.url(&format!(
            "/api/v1/signing/{signing_id}/status/{}",
            approver.user_id()
        )))
        .header(
            "X-User-Signature",
            transport_signature(&approver, &keygen_id, &signing_id)?,
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let batch: Vec<_> = wire_status
        .batch_items
        .iter()
        .map(SigningBatchItem::to_enclave_batch_item)
        .collect();
    ensure!(batch.len() == 2, "expected exactly two stored batch items");
    let (auth_key, auth_public_key) = SecureCrypto::derive_session_auth_keypair(
        &approver
            .credentials()
            .context("missing approver key")?
            .private_key_bytes(),
        &keygen_id.to_string(),
    )?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let valid_proof = ParticipantApproval::sign(
        &auth_key.secret_bytes(),
        approver.user_id().clone(),
        &keygen_id,
        &signing_id,
        now,
        &batch,
    )?;
    valid_proof.verify(
        &auth_public_key.serialize(),
        &keygen_id,
        &signing_id,
        &batch,
        now,
    )?;

    let mut altered_batch = batch.clone();
    altered_batch[1].encrypted_message = keygen
        .credentials()
        .encrypt(hex::encode(wrong_second_message).as_bytes(), "session_data")?;
    for (label, proof_session, proof_batch, timestamp) in [
        (
            "approval for a different second batch message",
            signing_id.clone(),
            &altered_batch,
            now,
        ),
        (
            "approval transplanted from another signing session",
            SessionId::new_v7(),
            &batch,
            now,
        ),
        (
            "expired participant approval",
            signing_id.clone(),
            &batch,
            now.saturating_sub(301),
        ),
        (
            "future-dated participant approval",
            signing_id.clone(),
            &batch,
            now + 3_600,
        ),
    ] {
        let proof = ParticipantApproval::sign(
            &auth_key.secret_bytes(),
            approver.user_id().clone(),
            &keygen_id,
            &proof_session,
            timestamp,
            proof_batch,
        )?;
        rejected_approval(label, &http, &approver, &keygen_id, &signing_id, &proof).await?;
        assert_waiting_for(&mut signing, approver.user_id()).await?;
    }

    // Give the background coordinator several processing ticks to demonstrate
    // that no rejected proof allows the session to leave its approval gate.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_waiting_for(&mut signing, approver.user_id()).await?;
    approver_signing.approve(&expected).await?;
    let signatures = signing.wait_for_completion().await?;
    ensure!(signatures.len() == 2, "expected both approved signatures");
    let aggregate = PublicKey::from_slice(&keygen.decrypt_aggregate_key()?)?
        .x_only_public_key()
        .0;
    for item in &expected {
        let result = signatures
            .iter()
            .find(|result| result.batch_item_id == item.id())
            .context("missing signature for a reviewed batch item")?;
        let bytes: [u8; 64] = result
            .signature
            .as_deref()
            .context("missing approved Schnorr signature")?
            .try_into()
            .map_err(|_| anyhow!("approved signature is not 64 bytes"))?;
        let signature = Signature::from_byte_array(bytes);
        Secp256k1::verification_only().verify_schnorr(&signature, item.message(), &aggregate)?;
        ensure!(
            Secp256k1::verification_only()
                .verify_schnorr(&signature, &wrong_second_message, &aggregate)
                .is_err(),
            "approved signature also verified against the substituted message"
        );
    }
    println!(
        "PASS both required approvals produce valid Schnorr signatures for the reviewed batch"
    );
    Ok(())
}
