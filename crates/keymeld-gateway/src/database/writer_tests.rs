use super::*;
use crate::{
    config::GatewayLimits,
    enclave::{channel::ChannelCredentials, EnclaveConfig, EnclaveManager},
    handlers::{initialize_keygen_session, AppState, NonceCache},
    metrics::Metrics,
};
use axum::{
    extract::{Path, State},
    Json,
};
use keymeld_core::{
    authorization::{
        EnclaveRecipientAuthorization, SessionAuthorizationManifest, SignedSessionManifest,
    },
    managed_socket::{config::TimeoutConfig, SocketConnector},
};
use keymeld_sdk::{
    AuthorizationCredentials, InitializeKeygenSessionRequest, SessionCredentials, UserCredentials,
};
use std::future::Future;
use tokio::{task::JoinHandle, time::timeout};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn config(directory: &tempfile::TempDir) -> DatabaseConfig {
    DatabaseConfig {
        path: directory
            .path()
            .join("writer.sqlite")
            .to_string_lossy()
            .into_owned(),
        max_connections: 4,
        connection_timeout_secs: 5,
        idle_timeout_secs: Some(60),
        enable_wal_mode: Some(true),
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    timeout(TEST_TIMEOUT, future)
        .await
        .expect("database test timed out")
}

fn start(writer: DatabaseWriter) -> (oneshot::Sender<()>, JoinHandle<Result<()>>) {
    let (shutdown, receiver) = oneshot::channel();
    (shutdown, tokio::spawn(writer.run(receiver)))
}

async fn nonce_count(db: &Database) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM request_auth_nonces")
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

async fn insert(connection: &mut SqliteConnection, nonce: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO request_auth_nonces (nonce_key, expires_at) VALUES (?, 9223372036854775807)",
    )
    .bind(nonce)
    .execute(connection)
    .await?;
    Ok(())
}

// The pause is confined to temporary test databases. The signal proves an
// actual SQLite write lock is held before other callers submit their work.
async fn hold_write(db: &Database) -> (oneshot::Sender<()>, JoinHandle<Result<(), ApiError>>) {
    let (started, entered) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let db = db.clone();
    let caller = tokio::spawn(async move {
        db.execute(move |connection| {
            Box::pin(async move {
                let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
                insert(&mut transaction, "held").await?;
                started.send(()).unwrap();
                released.await.unwrap();
                transaction.commit().await?;
                Ok(())
            })
        })
        .await
    });
    bounded(entered).await.unwrap();
    (release, caller)
}

#[tokio::test]
async fn invalid_limits_fail_before_creating_the_database() {
    let directory = tempfile::tempdir().unwrap();
    let mut configuration = config(&directory);
    assert!(Database::open_with_capacity(&configuration, 0)
        .await
        .is_err());
    configuration.max_connections = 0;
    assert!(Database::open(&configuration).await.is_err());
    configuration.max_connections = 4;
    configuration.connection_timeout_secs = 0;
    assert!(Database::open(&configuration).await.is_err());
    assert!(!std::path::Path::new(&configuration.path).exists());
}

#[tokio::test]
async fn cloned_databases_serialize_writes_and_reply_only_after_commit() {
    let directory = tempfile::tempdir().unwrap();
    let (db, writer) = Database::open_with_capacity(&config(&directory), 128)
        .await
        .unwrap();
    let (shutdown, task) = start(writer);
    let (release, caller) = hold_write(&db).await;
    assert_eq!(
        nonce_count(&db).await,
        0,
        "readers observed an uncommitted write"
    );

    // A canceled request must not abort work that the writer already accepted.
    caller.abort();
    assert!(bounded(caller).await.unwrap_err().is_cancelled());
    let mut requests = Vec::new();
    for index in 0..100 {
        let db = db.clone();
        let mut request = Box::pin(async move {
            let nonce = format!("clone-{index}");
            db.claim_request_auth_nonce(nonce.clone(), DbUtils::current_timestamp() as u64)
                .await
                .unwrap();
            let committed: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM request_auth_nonces WHERE nonce_key = ?")
                    .bind(nonce)
                    .fetch_one(&db.pool)
                    .await
                    .unwrap();
            assert_eq!(committed, 1, "reply preceded commit visibility");
        });
        assert!(futures::poll!(&mut request).is_pending());
        requests.push(request);
    }
    assert_eq!(db.commands.capacity(), 28, "clones must share one queue");
    assert_eq!(nonce_count(&db).await, 0);
    release.send(()).unwrap();
    bounded(futures::future::join_all(requests)).await;
    assert_eq!(nonce_count(&db).await, 101);
    shutdown.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
    assert!(!db.is_writer_available());
}

#[tokio::test]
async fn full_queue_rejects_before_admission_and_shutdown_drains_dropped_replies() {
    let directory = tempfile::tempdir().unwrap();
    let configuration = config(&directory);
    let (db, writer) = Database::open_with_capacity(&configuration, 2)
        .await
        .unwrap();
    let migrations: Vec<(i64, bool)> =
        sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&db.pool)
            .await
            .unwrap();
    let (shutdown, task) = start(writer);
    let (release, caller) = hold_write(&db).await;
    let mut dropped = Box::pin(db.execute(|connection| Box::pin(insert(connection, "dropped"))));
    assert!(futures::poll!(&mut dropped).is_pending());
    let mut retained = Box::pin(db.execute(|connection| Box::pin(insert(connection, "retained"))));
    assert!(futures::poll!(&mut retained).is_pending());
    assert_eq!(db.commands.capacity(), 0);
    assert!(matches!(
        db.execute(|connection| Box::pin(insert(connection, "rejected")))
            .await,
        Err(ApiError::DatabaseUnavailable)
    ));
    drop(dropped);

    shutdown.send(()).unwrap();
    release.send(()).unwrap();
    bounded(caller).await.unwrap().unwrap();
    bounded(retained).await.unwrap();
    bounded(task).await.unwrap().unwrap();
    assert!(db.health_check().await.is_err());
    assert!(matches!(
        db.execute(|connection| Box::pin(insert(connection, "closed")))
            .await,
        Err(ApiError::DatabaseUnavailable)
    ));

    // Reopening must preserve admitted commits and applied migrations.
    let (reopened, writer) = Database::open(&configuration).await.unwrap();
    assert_eq!(nonce_count(&reopened).await, 3);
    let reopened_migrations: Vec<(i64, bool)> =
        sqlx::query_as("SELECT version, success FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&reopened.pool)
            .await
            .unwrap();
    assert_eq!(reopened_migrations, migrations);
    let (shutdown, task) = start(writer);
    shutdown.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn generated_enclave_keys_wait_for_capacity_and_are_archived_before_reply() {
    let directory = tempfile::tempdir().unwrap();
    let (db, writer) = Database::open_with_capacity(&config(&directory), 1)
        .await
        .unwrap();
    let (shutdown, task) = start(writer);
    let (release, caller) = hold_write(&db).await;
    let mut queued = Box::pin(db.execute(|connection| Box::pin(insert(connection, "queued"))));
    assert!(futures::poll!(&mut queued).is_pending());
    let enclave_id = EnclaveId::from(1);
    let mut waiting =
        Box::pin(db.store_enclave_master_key(enclave_id, &[1, 2, 3], &[4, 5, 6], "test-kms-key"));
    assert!(futures::poll!(&mut waiting).is_pending());
    assert_eq!(db.commands.capacity(), 0);
    release.send(()).unwrap();
    bounded(caller).await.unwrap().unwrap();
    bounded(queued).await.unwrap();
    bounded(waiting).await.unwrap();
    let archived = db
        .get_enclave_master_key(enclave_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(archived.kms_encrypted_dek, [1, 2, 3]);
    assert_eq!(archived.encrypted_private_key, [4, 5, 6]);
    assert_eq!(archived.kms_key_id, "test-kms-key");
    assert_eq!(nonce_count(&db).await, 2);
    shutdown.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn read_pool_enforces_query_only_and_read_only_connections() {
    let directory = tempfile::tempdir().unwrap();
    let (db, writer) = Database::open(&config(&directory)).await.unwrap();
    let mut reader = db.pool.acquire().await.unwrap();
    let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    assert_eq!(query_only, 1);
    assert!(insert(&mut reader, "query-only").await.is_err());
    sqlx::query("PRAGMA query_only=OFF")
        .execute(&mut *reader)
        .await
        .unwrap();
    assert!(insert(&mut reader, "read-only").await.is_err());
    drop(reader);
    assert_eq!(nonce_count(&db).await, 0);
    db.stop_readiness();
    assert!(!db.is_writer_available());
    assert!(matches!(
        db.health_check().await,
        Err(ApiError::DatabaseUnavailable)
    ));
    let (shutdown, task) = start(writer);
    shutdown.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn lost_reply_after_admission_has_a_distinct_unknown_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let (db, mut writer) = Database::open(&config(&directory)).await.unwrap();
    let mut request = Box::pin(db.execute(|connection| Box::pin(insert(connection, "unknown"))));
    assert!(futures::poll!(&mut request).is_pending());
    // Simulate a failed writer after admission by dropping the queued reply.
    drop(bounded(writer.commands.recv()).await.unwrap());
    assert!(matches!(
        bounded(request).await,
        Err(ApiError::DatabaseOutcomeUnknown)
    ));
    let (shutdown, task) = start(writer);
    shutdown.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
}

#[tokio::test]
async fn rejected_and_canceled_reservations_cannot_publish_an_uncommitted_roster() {
    let directory = tempfile::tempdir().unwrap();
    let (db, writer) = Database::open_with_capacity(&config(&directory), 1)
        .await
        .unwrap();
    let manager = || {
        Arc::new(
            EnclaveManager::new_with_credentials(
                vec![EnclaveConfig {
                    id: 1,
                    cid: 3,
                    port: 9,
                    connector: SocketConnector::tcp("127.0.0.1", 9),
                }],
                TimeoutConfig::default(),
                Arc::new(
                    ChannelCredentials::dangerous_trust_unattested_enclaves([42; 32]).unwrap(),
                ),
            )
            .unwrap(),
        )
    };
    let enclave_manager = manager();
    let session_id = SessionId::new_v7();
    let authority = AuthorizationCredentials::generate().unwrap();
    let session_credentials = SessionCredentials::generate().unwrap();
    let participants = vec![UserId::new_v7(), UserId::new_v7()];
    let manifest = SignedSessionManifest::sign(
        SessionAuthorizationManifest {
            keygen_session_id: session_id.clone(),
            coordinator_user_id: participants[0].clone(),
            creator_pubkey: authority.public_key_bytes(),
            signing_pubkey: authority.public_key_bytes(),
            session_public_key: session_credentials.public_key_bytes(),
            participant_verifiers: BTreeMap::from([
                (
                    participants[0].clone(),
                    UserCredentials::from_private_key(&[2; 32])
                        .unwrap()
                        .public_key_bytes(),
                ),
                (
                    participants[1].clone(),
                    UserCredentials::from_private_key(&[3; 32])
                        .unwrap()
                        .public_key_bytes(),
                ),
            ]),
            timeout_secs: 600,
            max_signing_sessions: None,
            encrypted_taproot_tweak: String::new(),
            subset_definitions: vec![],
        },
        &authority.export_secret(),
    )
    .unwrap();
    let request = ReserveKeygenSessionRequest {
        authorization_manifest: manifest.clone(),
        keygen_session_id: session_id.clone(),
        coordinator_user_id: participants[0].clone(),
        expected_participants: participants.clone(),
        timeout_secs: 600,
        max_signing_sessions: None,
        encrypted_taproot_tweak: String::new(),
        subset_definitions: vec![],
    };
    let planned = enclave_manager
        .plan_session_assignment_with_distributed_coordinator(
            session_id.clone(),
            &participants,
            &participants[0],
        )
        .unwrap();
    assert!(enclave_manager
        .get_session_assignment(&session_id)
        .unwrap()
        .is_none());

    // Hold admission full before the real writer starts. A rejected reservation
    // must not create a process-local assignment or a database row.
    let mut occupied = Box::pin(db.execute(|connection| Box::pin(insert(connection, "occupied"))));
    assert!(futures::poll!(&mut occupied).is_pending());
    assert!(matches!(
        db.reserve_keygen_session(&request, planned.coordinator_enclave)
            .await,
        Err(ApiError::DatabaseUnavailable)
    ));
    assert!(db
        .get_keygen_session_by_id(&session_id)
        .await
        .unwrap()
        .is_none());
    assert!(enclave_manager
        .get_session_assignment(&session_id)
        .unwrap()
        .is_none());
    drop(occupied);
    let (shutdown, task) = start(writer);
    bounded(db.execute_waiting(|connection| Box::pin(async move {
        sqlx::query("INSERT INTO enclave_public_keys (enclave_id, cached_at, expires_at, public_key) VALUES (1, 0, 9999999999, '')")
            .execute(connection).await?;
        Ok(())
    }))).await.unwrap();

    // A disconnected caller can leave a committed reservation before its cache
    // publication. Initialization must recover using that committed authority.
    let (release, caller) = hold_write(&db).await;
    let mut canceled = Box::pin(db.reserve_keygen_session(&request, planned.coordinator_enclave));
    assert!(futures::poll!(&mut canceled).is_pending());
    drop(canceled);
    release.send(()).unwrap();
    bounded(caller).await.unwrap().unwrap();
    bounded(db.execute_waiting(|_| Box::pin(async { Ok(()) })))
        .await
        .unwrap();
    assert!(enclave_manager
        .get_session_assignment(&session_id)
        .unwrap()
        .is_none());

    let recipients = EnclaveRecipientAuthorization::sign(
        &manifest,
        planned.user_enclave_assignments.clone(),
        BTreeMap::from([(EnclaveId::from(1), authority.public_key_bytes())]),
        &authority.export_secret(),
    )
    .unwrap();
    let mut initialize = InitializeKeygenSessionRequest {
        recipient_authorization: recipients,
        authorization_signature: vec![],
        coordinator_pubkey: authority.public_key_bytes(),
        session_public_key: session_credentials.public_key_bytes(),
        encrypted_session_secret: "encrypted-fixture".to_string(),
        encrypted_session_data: "{}".to_string(),
        enclave_key_epoch: 1,
    };
    initialize
        .sign_authorization(&session_id, &authority.export_secret())
        .unwrap();
    let initialized = bounded(initialize_keygen_session(
        State(AppState {
            db: db.clone(),
            enclave_manager: enclave_manager.clone(),
            metrics: Arc::new(Metrics),
            gateway_limits: GatewayLimits::default(),
            nonce_cache: NonceCache::new(),
        }),
        Path(session_id.clone()),
        Json(initialize),
    ))
    .await
    .unwrap();
    assert_eq!(initialized.0.keygen_session_id, session_id);
    let cached = enclave_manager
        .get_session_assignment(&session_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        cached.user_enclave_assignments,
        planned.user_enclave_assignments
    );

    let mut competing = planned.clone();
    competing.coordinator_user_id = participants[1].clone();
    assert!(enclave_manager
        .publish_session_assignment(competing)
        .is_err());
    let persisted = db
        .get_keygen_session_by_id(&session_id)
        .await
        .unwrap()
        .unwrap();
    let restarted = manager().assignment_for_keygen_session(&persisted).unwrap();
    assert_eq!(restarted.coordinator_user_id, planned.coordinator_user_id);
    assert_eq!(
        restarted.user_enclave_assignments,
        planned.user_enclave_assignments
    );
    shutdown.send(()).unwrap();
    bounded(task).await.unwrap().unwrap();
}
