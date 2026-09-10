//! Model AWS's documented KeyId enforcement independently of Moto 5.1.11, whose
//! Decrypt implementation currently ignores KeyId. Live Moto restart coverage
//! remains in examples/run-authorization-e2e.sh.
use anyhow::{ensure, Result};
use aws_sdk_kms::{
    config::{Credentials, Region},
    primitives::Blob,
    Client,
};
use axum::{body::Bytes, http::StatusCode, routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use keymeld_core::{managed_socket::config::TimeoutConfig, EnclaveId};
use keymeld_enclave::operations::EnclaveSharedContext;
use serde_json::{json, Value};
use std::collections::HashMap;

fn fresh_context() -> EnclaveSharedContext {
    // Keep the enclave ID/encryption context identical: only the KMS key differs.
    EnclaveSharedContext::new(
        EnclaveId::new(17),
        Vec::new(),
        Vec::new(),
        None,
        TimeoutConfig::default(),
    )
}

// AWS permits symmetric Decrypt without KeyId, choosing the key identified by
// CiphertextBlob. Supplying a different KeyId must yield IncorrectKeyException.
// https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html
async fn kms_fixture(body: Bytes) -> (StatusCode, Json<Value>) {
    let request: Value = serde_json::from_slice(&body).unwrap();
    let decrypt = request.get("CiphertextBlob").is_some();
    let key = if decrypt {
        match request["CiphertextBlob"].as_str() {
            Some("QQ==") => "key-a",
            Some("Qg==") => "key-b",
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"__type": "InvalidCiphertextException"})),
                )
            }
        }
    } else {
        request["KeyId"].as_str().unwrap_or_default()
    };
    if decrypt
        && request
            .get("KeyId")
            .is_some_and(|requested| requested != key)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"__type": "IncorrectKeyException", "message": "Ciphertext belongs to another KMS key"}),
            ),
        );
    }
    let (dek, ciphertext) = match key {
        "key-a" => ([0x11; 32], "QQ=="),
        "key-b" => ([0x22; 32], "Qg=="),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"__type": "NotFoundException"})),
            )
        }
    };
    (
        StatusCode::OK,
        Json(
            json!({"KeyId": key, "Plaintext": STANDARD.encode(dek), "CiphertextBlob": ciphertext}),
        ),
    )
}

struct FixtureTask(tokio::task::JoinHandle<()>);
impl Drop for FixtureTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test]
async fn restoration_rejects_ciphertext_from_another_kms_key() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let _server = FixtureTask(tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/", post(kms_fixture)))
            .await
            .unwrap();
    }));
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new("us-west-2"))
        .credentials_provider(Credentials::new("test", "test", None, None, "kms-fixture"))
        .endpoint_url(endpoint)
        .load()
        .await;
    let client = Client::new(&config);
    let pinned_key = "key-a";
    let other_key = "key-b";

    let pinned_hierarchy = fresh_context()
        .init_keys_with_kms(&client, pinned_key, None, None)
        .await?;
    let other_hierarchy = fresh_context()
        .init_keys_with_kms(&client, other_key, None, None)
        .await?;

    // Control: the old request without KeyId selects the ciphertext's own key.
    let old_request = client
        .decrypt()
        .ciphertext_blob(Blob::new(other_hierarchy.0.clone()))
        .set_encryption_context(Some(HashMap::from([("enclave_id".into(), "17".into())])))
        .send()
        .await?;
    ensure!(old_request.key_id() == Some(other_key));
    ensure!(old_request.plaintext().is_some());

    let restored = fresh_context()
        .init_keys_with_kms(
            &client,
            pinned_key,
            Some(pinned_hierarchy.0),
            Some(pinned_hierarchy.1),
        )
        .await?;
    ensure!(
        restored.2 == pinned_hierarchy.2,
        "Correct-key restoration changed the enclave public key"
    );

    let mut rejected_context = fresh_context();
    let rejected = rejected_context
        .init_keys_with_kms(
            &client,
            pinned_key,
            Some(other_hierarchy.0.clone()),
            Some(other_hierarchy.1.clone()),
        )
        .await;
    let error = rejected.expect_err("Ciphertext selected a KMS key other than the provisioned key");
    ensure!(
        error.to_string().contains("Failed to decrypt DEK from KMS"),
        "Unexpected rejection: {error}"
    );
    ensure!(
        rejected_context.private_key.is_empty()
            && rejected_context.public_key.is_empty()
            && rejected_context.master_dek.is_none(),
        "Rejected restoration installed key material"
    );

    // The rejected blobs remain valid under their own KMS key.
    let restored_other = fresh_context()
        .init_keys_with_kms(
            &client,
            other_key,
            Some(other_hierarchy.0),
            Some(other_hierarchy.1),
        )
        .await?;
    ensure!(restored_other.2 == other_hierarchy.2);
    Ok(())
}
