//! Real HTTP and enclave regression tests. Run with run-authorization-e2e.sh.

use anyhow::{anyhow, ensure, Context, Result};
use keymeld_core::authorization::{sign_authorization, ROSTER_CONTEXT, SUBSET_AGGREGATE_CONTEXT};
use keymeld_sdk::prelude::*;
use keymeld_sdk::{
    AuthorizationCredentials, CreateSigningSessionRequest, EnclavePublicKeyResponse,
    GetAvailableSlotsResponse, RegisterKeygenParticipantRequest, RegistrationAuthorization,
    RegistrationContext, RegistrationEnvelope, SignedRoster, SignedSessionManifest,
};
use reqwest::{Client, StatusCode};
use secp256k1::{schnorr::Signature, PublicKey, Secp256k1};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[derive(serde::Serialize, serde::Deserialize)]
struct RestartFixture {
    coordinator_user_id: UserId,
    keygen_session_id: SessionId,
    session_secret: [u8; 32],
    signing_authority: [u8; 32],
    authorization_manifest: SignedSessionManifest,
    aggregate_public_key: Vec<u8>,
}

fn participant(gateway: &str, scalar: u8) -> Result<KeyMeldClient> {
    let mut secret = [0; 32];
    secret[31] = scalar;
    Ok(keymeld_examples::client_builder(gateway, UserId::new_v7())?
        .credentials(UserCredentials::from_private_key(&secret)?)
        .polling_config(PollingConfig::fast())
        .build()?)
}

async fn post(
    http: &Client,
    url: &str,
    credentials: &SessionCredentials,
    session_id: &SessionId,
    request: &impl serde::Serialize,
) -> Result<(StatusCode, String)> {
    let response = http
        .post(url)
        .header(
            "X-Session-Signature",
            credentials.sign_session_request(&session_id.to_string())?,
        )
        .json(request)
        .send()
        .await?;
    Ok((response.status(), response.text().await?))
}

async fn slots(
    http: &Client,
    gateway: &str,
    credentials: &SessionCredentials,
    session_id: &SessionId,
) -> Result<GetAvailableSlotsResponse> {
    Ok(http
        .get(format!("{gateway}/api/v1/keygen/{session_id}/slots"))
        .header(
            "X-Session-Signature",
            credentials.sign_session_request(&session_id.to_string())?,
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn prepared_registration(
    http: &Client,
    gateway: &str,
    session: &KeygenSession<'_>,
    user_id: &UserId,
    user: &UserCredentials,
    slot_credential: &AuthorizationCredentials,
) -> Result<RegisterKeygenParticipantRequest> {
    let available = slots(http, gateway, session.credentials(), session.session_id()).await?;
    let assigned = available
        .available_slots
        .iter()
        .find(|slot| &slot.user_id == user_id)
        .context("missing participant slot")?;
    let enclave: EnclavePublicKeyResponse = http
        .get(format!(
            "{gateway}/api/v1/enclaves/{}/public-key",
            assigned.enclave_id.as_u32()
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let context = RegistrationContext {
        keygen_session_id: session.session_id().clone(),
        manifest_hash: session.authorization_manifest().digest()?,
        user_id: user_id.clone(),
        enclave_id: assigned.enclave_id,
        enclave_key_epoch: enclave.key_epoch,
        public_key: user.public_key_bytes(),
        auth_pubkey: user.derive_session_auth_pubkey(&session.session_id().to_string())?,
        require_signing_approval: false,
    };

    // The participant can create this envelope while offline. The relay adds
    // authorization later without receiving the participant's private key.
    let encrypted_private_key = user.prepare_registration(context.clone(), &enclave.public_key)?;
    let registration_authorization = RegistrationAuthorization::sign(
        &slot_credential.export_secret(),
        context.clone(),
        &encrypted_private_key,
    )?;
    let mapping = BTreeMap::from([(user_id.clone(), context.public_key.clone())]);
    let encrypted_session_data = session.credentials().encrypt(
        &serde_json::to_vec(&json!({"participant_public_keys": mapping}))?,
        "keygen_participant_session",
    )?;
    Ok(RegisterKeygenParticipantRequest {
        registration_authorization,
        keygen_session_id: session.session_id().clone(),
        user_id: user_id.clone(),
        encrypted_private_key,
        public_key: context.public_key,
        encrypted_session_data,
        enclave_public_key: enclave.public_key,
        enclave_key_epoch: enclave.key_epoch,
        require_signing_approval: false,
        auth_pubkey: context.auth_pubkey,
    })
}

async fn rejected_without_claim(
    label: &str,
    http: &Client,
    gateway: &str,
    session: &KeygenSession<'_>,
    target_user: &UserId,
    request: &impl serde::Serialize,
) -> Result<()> {
    let url = format!(
        "{gateway}/api/v1/keygen/{}/participants",
        session.session_id()
    );
    let (status, body) = post(
        http,
        &url,
        session.credentials(),
        session.session_id(),
        request,
    )
    .await?;
    ensure!(
        status.is_client_error(),
        "{label}: expected client rejection, got {status}: {body}"
    );
    let available = slots(http, gateway, session.credentials(), session.session_id()).await?;
    ensure!(
        available
            .available_slots
            .iter()
            .any(|slot| &slot.user_id == target_user && !slot.claimed),
        "{label}: rejected registration claimed the victim slot"
    );
    println!("PASS {label} ({status})");
    Ok(())
}

fn replace_envelope(
    request: &mut RegisterKeygenParticipantRequest,
    envelope: &RegistrationEnvelope,
    authority: &AuthorizationCredentials,
) -> Result<()> {
    request.encrypted_private_key = hex::encode(SecureCrypto::ecies_encrypt_from_hex(
        &request.enclave_public_key,
        &serde_json::to_vec(envelope)?,
    )?);
    request.registration_authorization = RegistrationAuthorization::sign(
        &authority.export_secret(),
        envelope.context.clone(),
        &request.encrypted_private_key,
    )?;
    Ok(())
}

fn signing_request(
    keygen_id: &SessionId,
    credentials: &SessionCredentials,
    signing_authority: &AuthorizationCredentials,
) -> Result<CreateSigningSessionRequest> {
    let signing_session_id = SessionId::new_v7();
    let encrypted_message =
        credentials.encrypt(hex::encode([0x69; 32]).as_bytes(), "session_data")?;
    let encrypted_taproot_tweak =
        credentials.encrypt(&serde_json::to_vec(&TaprootTweak::None)?, "session_data")?;
    let item = keymeld_sdk::SigningBatchItem::new(
        vec![0x69; 32],
        encrypted_taproot_tweak,
        keymeld_sdk::SigningMode::Regular { encrypted_message },
    );
    let signing_authorization = keymeld_sdk::SigningAuthorization::sign(
        &signing_authority.export_secret(),
        keygen_id,
        &signing_session_id,
        120,
        &[item.to_enclave_batch_item()],
    )?;
    Ok(CreateSigningSessionRequest {
        signing_session_id,
        keygen_session_id: keygen_id.clone(),
        timeout_secs: 120,
        batch_items: vec![item],
        signing_authorization,
    })
}

/// Forward actual gateway replies, modifying one completed keygen response.
/// The attacker has the shared decryption secret and can encrypt replacements.
async fn status_proxy(
    gateway: String,
    replacement: Value,
) -> Result<(String, Arc<AtomicBool>, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let modified = Arc::new(AtomicBool::new(false));
    let modified_task = modified.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let gateway = gateway.clone();
            let replacement = replacement.clone();
            let modified = modified_task.clone();
            tokio::spawn(async move {
                let operation = async {
                    let mut request = Vec::new();
                    while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        ensure!(request.len() < 16384, "proxy request too large");
                        let mut chunk = [0; 2048];
                        let count = stream.read(&mut chunk).await?;
                        ensure!(count > 0, "proxy request truncated");
                        request.extend_from_slice(&chunk[..count]);
                    }
                    let request = String::from_utf8(request)?;
                    let mut lines = request.lines();
                    let path = lines
                        .next()
                        .context("missing request line")?
                        .split_whitespace()
                        .nth(1)
                        .context("missing path")?;
                    let mut upstream = Client::new().get(format!("{gateway}{path}"));
                    for line in lines {
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("x-session-signature") {
                                upstream = upstream.header(name, value.trim());
                            }
                        }
                    }
                    let response = upstream.send().await?;
                    let status = response.status();
                    let bytes = if path.contains("/keygen/")
                        && path.ends_with("/status")
                        && status.is_success()
                    {
                        modified.store(true, Ordering::SeqCst);
                        serde_json::to_vec(&replacement)?
                    } else {
                        response.bytes().await?.to_vec()
                    };
                    let header = format!(
                        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(), bytes.len(),
                    );
                    stream.write_all(header.as_bytes()).await?;
                    stream.write_all(&bytes).await?;
                    stream.shutdown().await?;
                    Ok::<_, anyhow::Error>(())
                };
                if let Err(error) = operation.await {
                    eprintln!("status proxy failed: {error}");
                }
            });
        }
    });
    Ok((url, modified, task))
}

async fn rejects_substituted_status(
    label: &str,
    gateway: &str,
    user_id: &UserId,
    session_id: &SessionId,
    secret: &[u8; 32],
    manifest: &SignedSessionManifest,
    response: Value,
) -> Result<()> {
    let (proxy_url, modified, task) = status_proxy(gateway.to_owned(), response).await?;
    let mut secret_key = [0; 32];
    secret_key[31] = 1;
    let client = keymeld_examples::client_builder(&proxy_url, user_id.clone())?
        .credentials(UserCredentials::from_private_key(&secret_key)?)
        .build()?;
    let result = client
        .keygen()
        .restore_session(
            session_id.clone(),
            SessionCredentials::from_session_secret(secret)?,
            manifest.clone(),
        )
        .await;
    task.abort();
    ensure!(
        modified.load(Ordering::SeqCst),
        "{label}: proxy never delivered altered response"
    );
    ensure!(
        result.is_err(),
        "{label}: SDK accepted a substituted completed roster or aggregate"
    );
    println!("PASS {label}");
    Ok(())
}

#[tokio::test]
#[ignore = "requires real gateway and enclave processes; use examples/run-authorization-e2e.sh"]
async fn registration_signing_and_roster_attacks() -> Result<()> {
    let gateway = std::env::var("KEYMELD_TEST_GATEWAY_URL")
        .context("KEYMELD_TEST_GATEWAY_URL must identify an isolated test gateway")?;
    let http = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let coordinator = participant(&gateway, 1)?;
    let victim = participant(&gateway, 2)?;
    let attacker = participant(&gateway, 3)?;
    let last = participant(&gateway, 4)?;
    let subset = SubsetDefinition::new(vec![
        coordinator.user_id().clone(),
        victim.user_id().clone(),
    ]);
    let subset_id = subset.subset_id;
    let mut session = coordinator
        .keygen()
        .create_session_with_subsets(
            vec![
                coordinator.user_id().clone(),
                victim.user_id().clone(),
                attacker.user_id().clone(),
                last.user_id().clone(),
            ],
            vec![subset],
            KeygenOptions::default().timeout(300).max_signings(10),
        )
        .await?;
    let session_id = session.session_id().clone();
    let secret = session.export_session_secret();
    let manifest = session.authorization_manifest().clone();
    session.register_self(RegisterOptions::default()).await?;
    attacker
        .keygen()
        .join_session(
            session_id.clone(),
            &secret,
            JoinOptions::default().invitation(session.invitation(attacker.user_id())?),
        )
        .await?;

    let slots_url = format!("{gateway}/api/v1/keygen/{session_id}/slots");
    let response = http.get(&slots_url).send().await?;
    ensure!(
        response.status().is_client_error(),
        "unauthenticated slot enumeration succeeded"
    );
    println!("PASS unauthenticated slot enumeration rejected");

    let attacker_authority = session
        .registration_credentials(attacker.user_id())
        .context("attacker slot credential")?
        .clone();
    let attack = prepared_registration(
        &http,
        &gateway,
        &session,
        victim.user_id(),
        attacker.credentials().unwrap(),
        &attacker_authority,
    )
    .await?;
    rejected_without_claim(
        "valid attacker key possession cannot claim victim slot",
        &http,
        &gateway,
        &session,
        victim.user_id(),
        &attack,
    )
    .await?;
    let mut shared_secret_attack = attack.clone();
    let shared_key = SecureCrypto::derive_private_key_from_seed(&secret)?;
    shared_secret_attack.registration_authorization = RegistrationAuthorization::sign(
        &shared_key.secret_bytes(),
        attack.registration_authorization.context.clone(),
        &attack.encrypted_private_key,
    )?;
    rejected_without_claim(
        "shared session secret cannot authorize victim registration",
        &http,
        &gateway,
        &session,
        victim.user_id(),
        &shared_secret_attack,
    )
    .await?;

    let victim_authority = session
        .registration_credentials(victim.user_id())
        .context("victim slot credential")?
        .clone();
    let honest = prepared_registration(
        &http,
        &gateway,
        &session,
        victim.user_id(),
        victim.credentials().unwrap(),
        &victim_authority,
    )
    .await?;
    let original_json = serde_json::to_value(&honest)?;
    for (label, field, replacement) in [
        (
            "changed ciphertext",
            "encrypted_private_key",
            json!("00".repeat(160)),
        ),
        (
            "changed public key",
            "public_key",
            json!(attacker.credentials().unwrap().public_key_bytes()),
        ),
        (
            "changed auth key",
            "auth_pubkey",
            json!(attacker
                .credentials()
                .unwrap()
                .derive_session_auth_pubkey(&session_id.to_string())?),
        ),
        ("changed participant ID", "user_id", json!(UserId::new_v7())),
        (
            "changed session ID",
            "keygen_session_id",
            json!(SessionId::new_v7()),
        ),
        (
            "changed approval policy",
            "require_signing_approval",
            json!(true),
        ),
        (
            "changed enclave epoch",
            "enclave_key_epoch",
            json!(honest.enclave_key_epoch + 1),
        ),
    ] {
        let mut changed = original_json.clone();
        changed[field] = replacement;
        rejected_without_claim(label, &http, &gateway, &session, victim.user_id(), &changed)
            .await?;
    }
    let mut unsigned = original_json.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("registration_authorization");
    rejected_without_claim(
        "legacy registration without slot proof",
        &http,
        &gateway,
        &session,
        victim.user_id(),
        &unsigned,
    )
    .await?;

    // Give the malicious relay genuine slot authority. Only enclave checks can
    // establish possession and key consistency inside these encrypted envelopes.
    let mut victim_private_key = [0; 32];
    victim_private_key[31] = 2;
    let mut bad_proof = RegistrationEnvelope::new(
        honest.registration_authorization.context.clone(),
        &victim_private_key,
    )?;
    bad_proof.proof_signature[0] ^= 1;
    let mut request = honest.clone();
    replace_envelope(&mut request, &bad_proof, &victim_authority)?;
    rejected_without_claim(
        "enclave rejects invalid possession proof despite slot authorization",
        &http,
        &gateway,
        &session,
        victim.user_id(),
        &request,
    )
    .await?;

    let mut bad_auth_context = honest.registration_authorization.context.clone();
    bad_auth_context.auth_pubkey = attacker
        .credentials()
        .unwrap()
        .derive_session_auth_pubkey(&session_id.to_string())?;
    let bad_auth = RegistrationEnvelope {
        proof_signature: sign_authorization(
            &victim_private_key,
            "registration-possession",
            &bad_auth_context,
        )?,
        context: bad_auth_context.clone(),
        private_key: victim_private_key.to_vec(),
    };
    let mut request = honest.clone();
    request.auth_pubkey = bad_auth_context.auth_pubkey;
    replace_envelope(&mut request, &bad_auth, &victim_authority)?;
    rejected_without_claim(
        "enclave derives auth key instead of trusting signed request",
        &http,
        &gateway,
        &session,
        victim.user_id(),
        &request,
    )
    .await?;

    let mut wrong_private_key = RegistrationEnvelope::new(
        honest.registration_authorization.context.clone(),
        &victim_private_key,
    )?;
    wrong_private_key.private_key[31] = 3;
    let mut request = honest.clone();
    replace_envelope(&mut request, &wrong_private_key, &victim_authority)?;
    rejected_without_claim(
        "enclave rejects ciphertext containing a different private key",
        &http,
        &gateway,
        &session,
        victim.user_id(),
        &request,
    )
    .await?;

    // Race distinct authorized ciphertexts for the same slot. Exactly one claim
    // must commit, and an exact retry of the winner must remain idempotent.
    let mut competing_requests = Vec::new();
    for _ in 0..6 {
        competing_requests.push(
            prepared_registration(
                &http,
                &gateway,
                &session,
                victim.user_id(),
                victim.credentials().unwrap(),
                &victim_authority,
            )
            .await?,
        );
    }
    let mut claims = tokio::task::JoinSet::new();
    for request in competing_requests {
        let http = http.clone();
        let gateway = gateway.clone();
        let session_id = session_id.clone();
        claims.spawn(async move {
            let credentials = SessionCredentials::from_session_secret(&secret)?;
            let result = post(
                &http,
                &format!("{gateway}/api/v1/keygen/{session_id}/participants"),
                &credentials,
                &session_id,
                &request,
            )
            .await?;
            Ok::<_, anyhow::Error>((request, result))
        });
    }
    let mut accepted = 0;
    let mut winning_request = None;
    while let Some(result) = claims.join_next().await {
        let (request, (status, body)) = result??;
        if status.is_success() {
            accepted += 1;
            winning_request = Some(request);
        } else {
            ensure!(
                status.is_client_error(),
                "claim race returned {status}: {body}"
            );
        }
    }
    ensure!(
        accepted == 1,
        "expected one atomic slot claim, got {accepted}"
    );
    println!("PASS delegated registration succeeds once under six concurrent claims");
    let honest = winning_request.context("no winning registration")?;

    let url = format!("{gateway}/api/v1/keygen/{session_id}/participants");
    let (status, body) = post(&http, &url, session.credentials(), &session_id, &attack).await?;
    ensure!(
        status.is_client_error(),
        "attacker overwrote accepted slot: {status}: {body}"
    );
    let (status, body) = post(&http, &url, session.credentials(), &session_id, &honest).await?;
    ensure!(
        status.is_success(),
        "exact registration retry failed: {status}: {body}"
    );
    println!("PASS accepted slots reject replacement and allow an exact idempotent retry");

    last.keygen()
        .join_session(
            session_id.clone(),
            &secret,
            JoinOptions::default().invitation(session.invitation(last.user_id())?),
        )
        .await?;
    session.wait_for_completion().await?;
    let (status, body) = post(&http, &url, session.credentials(), &session_id, &honest).await?;
    ensure!(
        status.is_client_error(),
        "completed session accepted registration: {status}: {body}"
    );
    println!("PASS completed session rejects registration");

    let status_response: Value = http
        .get(format!("{gateway}/api/v1/keygen/{session_id}/status"))
        .header(
            "X-Session-Signature",
            session
                .credentials()
                .sign_session_request(&session_id.to_string())?,
        )
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let roster: SignedRoster = serde_json::from_slice(
        &session.credentials().decrypt(
            status_response["encrypted_roster"]
                .as_str()
                .context("missing completed roster")?,
            ROSTER_CONTEXT,
        )?,
    )?;
    let expected_roster = [&coordinator, &victim, &attacker, &last]
        .into_iter()
        .map(|client| {
            (
                client.user_id().clone(),
                client.credentials().unwrap().public_key_bytes(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    ensure!(
        roster.roster.participants == expected_roster,
        "actual enclave roster differs from intended participants"
    );
    println!("PASS actual enclave roster matches every intended participant key");

    let unauthorized = signing_request(&session_id, session.credentials(), &attacker_authority)?;
    let (status, body) = post(
        &http,
        &format!("{gateway}/api/v1/signing"),
        session.credentials(),
        &session_id,
        &unauthorized,
    )
    .await?;
    ensure!(
        status.is_client_error(),
        "shared-secret attacker created arbitrary signing session: {status}: {body}"
    );
    let mut unsigned = serde_json::to_value(&unauthorized)?;
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("signing_authorization");
    let (status, body) = post(
        &http,
        &format!("{gateway}/api/v1/signing"),
        session.credentials(),
        &session_id,
        &unsigned,
    )
    .await?;
    ensure!(
        status.is_client_error(),
        "legacy shared-secret signing succeeded: {status}: {body}"
    );
    println!(
        "PASS shared-secret holder cannot sign arbitrary messages with honest participant roster"
    );

    let owner = session
        .authorization_credentials()
        .context("missing creator signing authority")?;
    let authorized = signing_request(&session_id, session.credentials(), owner)?;
    let mut changed = authorized.clone();
    changed.batch_items[0].subset_id = Some(subset_id);
    let (status, body) = post(
        &http,
        &format!("{gateway}/api/v1/signing"),
        session.credentials(),
        &session_id,
        &changed,
    )
    .await?;
    ensure!(
        status.is_client_error(),
        "modified authorized signing subset accepted: {status}: {body}"
    );
    println!("PASS signing authorization binds batch subset");

    if let Ok(port) = std::env::var("KEYMELD_TEST_ENCLAVE_PORT_BASE") {
        use keymeld_core::{
            enclave_channel::{ChannelRequest, ChannelResponse, SignedCommand},
            managed_socket::SocketClient,
            protocol::{ClearSessionCommand, Command, EnclaveCommand, SystemCommand},
        };
        let base_port: u16 = port.parse()?;
        for offset in 0..3 {
            let client: SocketClient<ChannelRequest, ChannelResponse> =
                SocketClient::tcp("127.0.0.1", base_port + offset);
            let ChannelResponse::Challenge(challenge) = client
                .send_command(ChannelRequest::Challenge { nonce: [9; 32] }.into())
                .await?
                .response
            else {
                anyhow::bail!("missing channel challenge")
            };
            let clear = Command::new(EnclaveCommand::System(SystemCommand::ClearSession(
                ClearSessionCommand {
                    keygen_session_id: Some(session_id.clone()),
                    signing_session_id: None,
                },
            )));
            let request = SignedCommand::sign(clear, &challenge, &[42; 32])?;
            let response = client
                .send_command(ChannelRequest::Execute(Box::new(request)).into())
                .await?;
            ensure!(
                matches!(response.response, ChannelResponse::Rejected(_)),
                "Direct attacker ClearSession reached enclave"
            );
        }
        println!("PASS direct unauthenticated ClearSession rejected by all three enclave sockets");
    }

    // No participant approval is required: this must stay usable by unattended
    // coordinator/oracle consumers that retain the separate signing authority.
    let full_message = [0x31; 32];
    let subset_message = [0x32; 32];
    let full_item = BatchSigningItem::new(full_message);
    let subset_item = BatchSigningItem::new(subset_message).with_subset(subset_id);
    let full_item_id = full_item.id();
    let subset_item_id = subset_item.id();
    let mut signing = coordinator
        .signer()
        .sign_batch(
            &session,
            vec![full_item, subset_item],
            SigningOptions::default().timeout(120),
        )
        .await?;
    let results = signing.wait_for_completion().await?;
    ensure!(results.len() == 2, "expected full and subset signatures");
    for (item_id, message, key) in [
        (full_item_id, full_message, session.decrypt_aggregate_key()?),
        (
            subset_item_id,
            subset_message,
            session.decrypt_subset_aggregate(&subset_id)?,
        ),
    ] {
        let result = results
            .iter()
            .find(|result| result.batch_item_id == item_id)
            .context("missing batch signing result")?;
        let bytes: [u8; 64] = result
            .signature
            .as_deref()
            .context("missing signature")?
            .try_into()
            .map_err(|_| anyhow!("signature is not 64 bytes"))?;
        let signature = Signature::from_byte_array(bytes);
        let public_key = PublicKey::from_slice(&key)?.x_only_public_key().0;
        Secp256k1::verification_only().verify_schnorr(&signature, &message, &public_key)?;
    }
    println!("PASS unattended authorized full and subset signing; both Schnorr signatures verify");

    let mut replaced_session = status_response.clone();
    replaced_session["keygen_session_id"] = json!(SessionId::new_v7());
    rejects_substituted_status(
        "SDK rejects substituted keygen session identity",
        &gateway,
        coordinator.user_id(),
        &session_id,
        &secret,
        &manifest,
        replaced_session,
    )
    .await?;

    let replacement_key = attacker.credentials().unwrap().public_key_bytes();
    let mut replaced_full = status_response.clone();
    replaced_full["aggregate_public_key"] = json!(session
        .credentials()
        .encrypt(&replacement_key, "aggregate_public_key")?);
    rejects_substituted_status(
        "SDK rejects substituted full aggregate",
        &gateway,
        coordinator.user_id(),
        &session_id,
        &secret,
        &manifest,
        replaced_full,
    )
    .await?;
    let mut replaced_subset = status_response.clone();
    replaced_subset["encrypted_subset_aggregates"][subset_id.to_string()] = json!(session
        .credentials()
        .encrypt(&replacement_key, SUBSET_AGGREGATE_CONTEXT)?);
    rejects_substituted_status(
        "SDK rejects substituted subset aggregate",
        &gateway,
        coordinator.user_id(),
        &session_id,
        &secret,
        &manifest,
        replaced_subset,
    )
    .await?;
    let mut replaced_roster = roster.clone();
    replaced_roster
        .roster
        .participants
        .insert(victim.user_id().clone(), replacement_key);
    let mut replaced_status = status_response;
    replaced_status["encrypted_roster"] = json!(session
        .credentials()
        .encrypt(&serde_json::to_vec(&replaced_roster)?, ROSTER_CONTEXT,)?);
    rejects_substituted_status(
        "SDK rejects substituted participant roster",
        &gateway,
        coordinator.user_id(),
        &session_id,
        &secret,
        &manifest,
        replaced_status,
    )
    .await?;

    if let Ok(path) = std::env::var("KEYMELD_TEST_RESTART_STATE_PATH") {
        // This fixture contains synthetic test keys only and stays inside the
        // runner's private temporary directory until the restart check ends.
        let fixture = RestartFixture {
            coordinator_user_id: coordinator.user_id().clone(),
            keygen_session_id: session_id,
            session_secret: secret,
            signing_authority: owner.export_secret(),
            authorization_manifest: manifest,
            aggregate_public_key: session.decrypt_aggregate_key()?,
        };
        std::fs::write(path, serde_json::to_vec(&fixture)?)?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "run only after the authorization runner restarts gateway and enclaves"]
async fn signing_after_enclave_restart() -> Result<()> {
    let gateway = std::env::var("KEYMELD_TEST_GATEWAY_URL")?;
    let fixture_path = std::env::var("KEYMELD_TEST_RESTART_STATE_PATH")?;
    let fixture: RestartFixture = serde_json::from_slice(&std::fs::read(fixture_path)?)?;
    let mut secret = [0; 32];
    secret[31] = 1;
    let coordinator = keymeld_examples::client_builder(&gateway, fixture.coordinator_user_id)?
        .credentials(UserCredentials::from_private_key(&secret)?)
        .polling_config(PollingConfig::fast())
        .build()?;
    let session = coordinator
        .keygen()
        .restore_session_with_authority(
            fixture.keygen_session_id,
            SessionCredentials::from_session_secret(&fixture.session_secret)?,
            fixture.authorization_manifest,
            AuthorizationCredentials::from_secret(&fixture.signing_authority)?,
        )
        .await?;
    ensure!(
        session.decrypt_aggregate_key()? == fixture.aggregate_public_key,
        "restored session changed its verified aggregate key"
    );
    let message = [0x71; 32];
    let mut signing = coordinator
        .signer()
        .sign_batch(
            &session,
            vec![BatchSigningItem::new(message)],
            SigningOptions::default().timeout(120),
        )
        .await?;
    let results = signing.wait_for_completion().await?;
    let bytes: [u8; 64] = results[0]
        .signature
        .as_deref()
        .context("restored signing did not produce a signature")?
        .try_into()
        .map_err(|_| anyhow!("restored signature is not 64 bytes"))?;
    let public_key = PublicKey::from_slice(&fixture.aggregate_public_key)?
        .x_only_public_key()
        .0;
    Secp256k1::verification_only().verify_schnorr(
        &Signature::from_byte_array(bytes),
        &message,
        &public_key,
    )?;
    println!("PASS gateway and enclave restart preserves authorized roster and valid signing");
    Ok(())
}
