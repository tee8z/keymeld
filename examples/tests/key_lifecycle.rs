//! Key lifecycle attacks against real gateway and enclave processes.
use anyhow::{ensure, Context, Result};
use keymeld_core::{
    crypto::SecureCrypto,
    request_auth::{delete_key_scope, now_timestamp_secs},
};
use keymeld_sdk::{
    prelude::*, ImportUserKeyRequest, KeyStatusResponse, SignSingleRequest, SignSingleResponse,
    SingleSigningStatus, SingleSigningStatusResponse, StoreKeyFromKeygenRequest,
};
use reqwest::{Client, StatusCode};
use secp256k1::{schnorr::Signature, Message, Secp256k1};
use sha2::{Digest, Sha256};
use std::time::Duration;

fn participant(gateway: &str, scalar: u8) -> Result<KeyMeldClient> {
    Ok(keymeld_examples::client_builder(gateway, UserId::new_v7())?
        .credentials(UserCredentials::from_private_key(&[scalar; 32])?)
        .polling_config(PollingConfig::fast())
        .build()?)
}

fn proof(client: &KeyMeldClient, scope: &str, keygen: Option<&SessionId>) -> Result<String> {
    let credentials = client.credentials().context("missing credentials")?;
    Ok(match keygen {
        Some(session) => credentials.sign_for_session(
            scope,
            &client.user_id().to_string(),
            &session.to_string(),
        )?,
        None => credentials.sign_user_request(scope, &client.user_id().to_string())?,
    })
}

async fn key_status(
    http: &Client,
    client: &KeyMeldClient,
    key: &KeyId,
    keygen: Option<&SessionId>,
) -> Result<KeyStatusResponse> {
    for _ in 0..300 {
        let status: KeyStatusResponse = http
            .get(client.url(&format!("/api/v1/keys/{}/{key}/status", client.user_id())))
            .header("X-User-Signature", proof(client, &key.to_string(), keygen)?)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if matches!(status.status.as_str(), "completed" | "failed") {
            return Ok(status);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("key operation timed out")
}

#[tokio::test]
#[ignore = "requires real gateway and enclave processes; use examples/run-authorization-e2e.sh"]
async fn key_lifecycle_authentication_and_ciphertext_transplant_attacks() -> Result<()> {
    let gateway = std::env::var("KEYMELD_TEST_GATEWAY_URL")?;
    let http = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let owner = participant(&gateway, 51)?;
    let attacker = participant(&gateway, 52)?;
    let owner_reservation = owner.reserve_key_slot().await?;
    let attacker_reservation = attacker.reserve_key_slot().await?;

    // A captured ciphertext carries the victim's private key. An attacker may
    // own another reserved slot but must not assign their auth key to that key.
    let stolen_ciphertext = hex::encode(SecureCrypto::ecies_encrypt_from_hex(
        &attacker_reservation.enclave_public_key,
        &owner.credentials().unwrap().private_key_bytes(),
    )?);
    let transplant = ImportUserKeyRequest {
        key_id: attacker_reservation.key_id.clone(),
        user_id: attacker.user_id().clone(),
        encrypted_private_key: stolen_ciphertext,
        auth_pubkey: attacker.credentials().unwrap().auth_public_key_bytes(),
        enclave_public_key: attacker_reservation.enclave_public_key.clone(),
    };
    http.post(format!("{gateway}/api/v1/keys/import"))
        .header(
            "X-User-Signature",
            proof(&attacker, &transplant.auth_scope()?, None)?,
        )
        .json(&transplant)
        .send()
        .await?
        .error_for_status()?;
    let failure = key_status(&http, &attacker, &attacker_reservation.key_id, None).await?;
    ensure!(
        failure.status == "failed",
        "Enclave accepted stolen private-key ciphertext under attacker auth"
    );
    println!(
        "PASS enclave rejects captured private-key ciphertext with attacker authentication key"
    );

    let owner_key = owner
        .import_key(
            &owner_reservation,
            &owner.credentials().unwrap().private_key_bytes(),
        )
        .await?;
    let message = [0x51; 32];
    let signature = owner
        .sign(&owner_key, message, SignatureType::SchnorrBip340)
        .await?;
    Secp256k1::verification_only().verify_schnorr(
        &Signature::from_byte_array(
            signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("signature size"))?,
        ),
        &message,
        &owner
            .credentials()
            .unwrap()
            .public_key()
            .x_only_public_key()
            .0,
    )?;
    println!("PASS authorized single-key import and Schnorr signing");

    // A read proof must not authorize lifecycle destruction.
    let read_proof = proof(&owner, &owner_key.to_string(), None)?;
    let response = http
        .delete(owner.url(&format!("/api/v1/keys/{}/{owner_key}", owner.user_id())))
        .header("X-User-Signature", read_proof)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::UNAUTHORIZED,
        "GET proof authorized key deletion"
    );

    let second = participant(&gateway, 53)?;
    let mut session = owner
        .keygen()
        .create_session(
            vec![owner.user_id().clone(), second.user_id().clone()],
            KeygenOptions::default().timeout(300),
        )
        .await?;
    session.register_self(RegisterOptions::default()).await?;
    let mut joined = second
        .keygen()
        .join_session(
            session.session_id().clone(),
            &session.export_session_secret(),
            JoinOptions::default().invitation(session.invitation(second.user_id())?),
        )
        .await?;
    session.wait_for_completion().await?;
    joined.wait_for_completion().await?;
    let keygen_id = session.session_id();
    let copy = StoreKeyFromKeygenRequest {
        key_id: KeyId::new_v7(),
    };
    let copy_url = owner.url(&format!(
        "/api/v1/keys/{}/keygen/{keygen_id}",
        owner.user_id()
    ));
    ensure!(
        http.post(&copy_url)
            .json(&copy)
            .send()
            .await?
            .status()
            .is_client_error(),
        "Unauthenticated key persistence succeeded"
    );
    let bad_proof = attacker.credentials().unwrap().sign_for_session(
        &copy.auth_scope(owner.user_id(), keygen_id)?,
        &owner.user_id().to_string(),
        &keygen_id.to_string(),
    )?;
    ensure!(
        http.post(&copy_url)
            .header("X-User-Signature", bad_proof)
            .json(&copy)
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "Unrelated participant credential authorized persistence"
    );
    let copy_proof = proof(
        &owner,
        &copy.auth_scope(owner.user_id(), keygen_id)?,
        Some(keygen_id),
    )?;
    let altered = StoreKeyFromKeygenRequest {
        key_id: KeyId::new_v7(),
    };
    ensure!(
        http.post(&copy_url)
            .header("X-User-Signature", &copy_proof)
            .json(&altered)
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "Persistence proof accepted a different destination key"
    );
    http.post(&copy_url)
        .header("X-User-Signature", copy_proof)
        .json(&copy)
        .send()
        .await?
        .error_for_status()?;
    let stored = key_status(&http, &owner, &copy.key_id, Some(keygen_id)).await?;
    ensure!(
        stored.status == "completed",
        "Authorized copy failed: {:?}",
        stored.error_message
    );
    println!("PASS keygen persistence requires participant proof bound to the destination");

    // Copied keys retain the participant's original session auth context.
    let enclave = owner
        .health()
        .get_enclave_key(stored.enclave_id.as_u32())
        .await?;
    let signing_secret = SessionCredentials::generate()?;
    let message = [0x53; 32];
    let encrypted_message =
        signing_secret.encrypt(hex::encode(message).as_bytes(), "session_data")?;
    let timestamp = now_timestamp_secs()?;
    let (auth_key, _) = SecureCrypto::derive_session_auth_keypair(
        &owner.credentials().unwrap().private_key_bytes(),
        &keygen_id.to_string(),
    )?;
    let mut hash = Sha256::new();
    hash.update(encrypted_message.as_bytes());
    hash.update(copy.key_id.to_string().as_bytes());
    hash.update(timestamp.to_le_bytes());
    let approval_signature = Secp256k1::signing_only()
        .sign_ecdsa(Message::from_digest(hash.finalize().into()), &auth_key)
        .serialize_compact()
        .to_vec();
    let sign = SignSingleRequest {
        user_id: owner.user_id().clone(),
        key_id: copy.key_id.clone(),
        encrypted_message,
        signature_type: SignatureType::SchnorrBip340,
        approval_signature,
        approval_timestamp: timestamp,
        encrypted_session_secret: hex::encode(SecureCrypto::ecies_encrypt_from_hex(
            &enclave.public_key,
            &signing_secret.export_session_secret(),
        )?),
    };
    let response: SignSingleResponse = http
        .post(format!("{gateway}/api/v1/sign/single"))
        .header(
            "X-User-Signature",
            proof(&owner, &sign.auth_scope()?, Some(keygen_id))?,
        )
        .json(&sign)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut signed = false;
    for _ in 0..300 {
        let result: SingleSigningStatusResponse = http
            .get(format!(
                "{gateway}/api/v1/sign/single/{}/status/{}",
                response.signing_session_id,
                owner.user_id()
            ))
            .header(
                "X-User-Signature",
                proof(&owner, &copy.key_id.to_string(), Some(keygen_id))?,
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        ensure!(
            result.status != SingleSigningStatus::Failed,
            "Copied-key signing failed: {:?}",
            result.error_message
        );
        if result.status == SingleSigningStatus::Completed {
            let bytes = signing_secret.decrypt(
                result
                    .encrypted_signature
                    .as_deref()
                    .context("missing signature")?,
                "signature",
            )?;
            Secp256k1::verification_only().verify_schnorr(
                &Signature::from_byte_array(
                    bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("signature size"))?,
                ),
                &message,
                &owner
                    .credentials()
                    .unwrap()
                    .public_key()
                    .x_only_public_key()
                    .0,
            )?;
            signed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(signed, "Copied-key signing timed out");
    println!("PASS authorized keygen copy produces a valid single-key Schnorr signature");
    // Leave the isolated runner's orphan assertion focused on participant claims.
    owner.delete_key(&owner_key).await?;
    http.delete(owner.url(&format!("/api/v1/keys/{}/{}", owner.user_id(), copy.key_id)))
        .header(
            "X-User-Signature",
            proof(
                &owner,
                &delete_key_scope(&copy.key_id.to_string()),
                Some(keygen_id),
            )?,
        )
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}
