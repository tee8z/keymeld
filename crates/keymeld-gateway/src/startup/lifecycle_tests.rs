use super::ApplicationRuntime;
use crate::{
    config::DatabaseConfig,
    database::{Database, DatabaseWriter},
    errors::ApiError,
};
use anyhow::Result;
use axum::{routing::post, Router};
use keymeld_core::request_auth::now_timestamp_secs;
use std::{future::Future, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, Notify},
    task::JoinHandle,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    timeout(TEST_TIMEOUT, future)
        .await
        .expect("application lifecycle test timed out")
}

fn config(directory: &tempfile::TempDir) -> DatabaseConfig {
    DatabaseConfig {
        path: directory
            .path()
            .join("lifecycle.sqlite")
            .to_string_lossy()
            .into_owned(),
        max_connections: 2,
        connection_timeout_secs: 5,
        idle_timeout_secs: None,
        enable_wal_mode: Some(true),
    }
}

async fn open_runtime(
    configuration: &DatabaseConfig,
) -> (ApplicationRuntime, DatabaseWriter, oneshot::Sender<()>) {
    let (db, writer) = bounded(Database::open(configuration)).await.unwrap();
    let (requested, receiver) = oneshot::channel();
    (
        ApplicationRuntime {
            db,
            requested: receiver,
            signal_task: None,
            http: None,
            http_shutdown: None,
            coordinator: None,
            coordinator_shutdown: None,
            writer: None,
            writer_shutdown: None,
            shutdown_timeout: Duration::from_secs(3),
        },
        writer,
        requested,
    )
}

fn start_writer(runtime: &mut ApplicationRuntime, writer: DatabaseWriter) {
    let (shutdown, receiver) = oneshot::channel();
    runtime.writer = Some(tokio::spawn(writer.run(receiver)));
    runtime.writer_shutdown = Some(shutdown);
}

async fn serve_http(
    runtime: &mut ApplicationRuntime,
    router: Router,
) -> (SocketAddr, oneshot::Receiver<()>, oneshot::Receiver<()>) {
    let listener = bounded(TcpListener::bind("127.0.0.1:0")).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, receiver) = oneshot::channel();
    let (observed, shutdown_observed) = oneshot::channel();
    let (finished, http_finished) = oneshot::channel();
    let db = runtime.db.clone();
    runtime.http_shutdown = Some(shutdown);
    runtime.http = Some(tokio::spawn(async move {
        let result = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                receiver.await.unwrap();
                assert!(
                    !db.is_writer_available(),
                    "HTTP drain began before readiness was disabled"
                );
                let _ = observed.send(());
            })
            .await;
        let _ = finished.send(());
        result
    }));
    (address, shutdown_observed, http_finished)
}

async fn post_nonce(address: SocketAddr) -> String {
    bounded(async {
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket
            .write_all(
                b"POST /nonce HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = String::new();
        socket.read_to_string(&mut response).await.unwrap();
        response
    })
    .await
}

async fn assert_database_closed(db: &Database) {
    assert!(!db.is_writer_available());
    assert!(matches!(
        bounded(db.get_stats()).await,
        Err(ApiError::Database(sqlx::Error::PoolClosed))
    ));
    assert!(matches!(
        bounded(
            db.claim_request_auth_nonce("after-shutdown".into(), now_timestamp_secs().unwrap())
        )
        .await,
        Err(ApiError::DatabaseUnavailable)
    ));
}

#[tokio::test]
async fn shutdown_drains_http_then_coordinator_then_writer_and_preserves_commits() {
    let directory = tempfile::tempdir().unwrap();
    let configuration = config(&directory);
    let (mut runtime, writer, requested) = open_runtime(&configuration).await;
    start_writer(&mut runtime, writer);
    let db = runtime.db.clone();
    let admitted = Arc::new(Notify::new());
    let release_http = Arc::new(Notify::new());
    let handler_db = db.clone();
    let handler_admitted = admitted.clone();
    let handler_release = release_http.clone();
    let router = Router::new().route(
        "/nonce",
        post(move || {
            let db = handler_db.clone();
            let admitted = handler_admitted.clone();
            let release = handler_release.clone();
            async move {
                admitted.notify_one();
                release.notified().await;
                db.claim_request_auth_nonce("http-commit".into(), now_timestamp_secs().unwrap())
                    .await?;
                Ok::<_, ApiError>("committed")
            }
        }),
    );
    let (address, http_stopping, mut http_finished) = serve_http(&mut runtime, router).await;
    let (coordinator_shutdown, shutdown_received) = oneshot::channel();
    let (coordinator_stopping, mut coordinator_observed) = oneshot::channel();
    let (release_coordinator, coordinator_released) = oneshot::channel();
    let coordinator_db = db.clone();
    runtime.coordinator_shutdown = Some(coordinator_shutdown);
    runtime.coordinator = Some(tokio::spawn(async move {
        shutdown_received.await.unwrap();
        assert_eq!(
            http_finished.try_recv(),
            Ok(()),
            "coordinator stopped before the HTTP server finished draining"
        );
        coordinator_stopping.send(()).unwrap();
        coordinator_released.await.unwrap();
        coordinator_db
            .claim_request_auth_nonce("coordinator-commit".into(), now_timestamp_secs().unwrap())
            .await
    }));
    let running = tokio::spawn(runtime.run_until_stopped());
    let request = tokio::spawn(post_nonce(address));
    bounded(admitted.notified()).await;
    assert!(db.is_writer_available());

    requested.send(()).unwrap();
    bounded(http_stopping).await.unwrap();
    assert!(!db.is_writer_available());
    assert!(matches!(
        coordinator_observed.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(!running.is_finished());
    assert!(bounded(db.get_stats()).await.is_ok());

    release_http.notify_one();
    let response = bounded(request).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\ncommitted"), "{response}");
    bounded(coordinator_observed).await.unwrap();
    assert!(!running.is_finished());
    // The coordinator remains a producer until it acknowledges shutdown.
    bounded(db.claim_request_auth_nonce(
        "during-coordinator-drain".into(),
        now_timestamp_secs().unwrap(),
    ))
    .await
    .unwrap();
    release_coordinator.send(()).unwrap();
    bounded(running).await.unwrap().unwrap();
    assert_database_closed(&db).await;
    assert!(bounded(TcpStream::connect(address)).await.is_err());

    let (mut reopened, writer, _requested) = open_runtime(&configuration).await;
    start_writer(&mut reopened, writer);
    for nonce in [
        "http-commit",
        "coordinator-commit",
        "during-coordinator-drain",
    ] {
        assert!(
            matches!(
                bounded(reopened.db.claim_request_auth_nonce(nonce.into(), now_timestamp_secs().unwrap())).await,
                Err(ApiError::Unauthorized(message)) if message.contains("already used")
            ),
            "committed authentication claim was lost after reopening: {nonce}"
        );
    }
    bounded(reopened.shutdown()).await.unwrap();
}

#[tokio::test]
async fn unexpected_successful_writer_completion_fails_the_application_and_stops_http() {
    let directory = tempfile::tempdir().unwrap();
    let (mut runtime, writer, _requested) = open_runtime(&config(&directory)).await;
    start_writer(&mut runtime, writer);
    let db = runtime.db.clone();
    let (address, http_stopping, http_finished) = serve_http(&mut runtime, Router::new()).await;

    // A clean writer return is still fatal unless application shutdown asked
    // for it. No process shutdown request is sent in this test.
    runtime.writer_shutdown.take().unwrap().send(()).unwrap();
    let error = bounded(runtime.run_until_stopped()).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Database writer task stopped unexpectedly"),
        "{error:#}"
    );
    bounded(http_stopping).await.unwrap();
    bounded(http_finished).await.unwrap();
    assert_database_closed(&db).await;
    assert!(bounded(TcpStream::connect(address)).await.is_err());
}

#[tokio::test]
async fn writer_panic_fails_the_application_and_stops_http() {
    let directory = tempfile::tempdir().unwrap();
    let (mut runtime, writer, _requested) = open_runtime(&config(&directory)).await;
    let (shutdown, receiver) = oneshot::channel();
    let (panic_writer, panicked) = oneshot::channel();
    runtime.writer_shutdown = Some(shutdown);
    runtime.writer = Some(tokio::spawn(async move {
        tokio::select! {
            result = writer.run(receiver) => result,
            _ = panicked => panic!("injected database writer failure"),
        }
    }));
    let db = runtime.db.clone();
    let (address, http_stopping, http_finished) = serve_http(&mut runtime, Router::new()).await;
    bounded(
        db.claim_request_auth_nonce("before-writer-panic".into(), now_timestamp_secs().unwrap()),
    )
    .await
    .unwrap();
    panic_writer.send(()).unwrap();

    let error = bounded(runtime.run_until_stopped()).await.unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("Database writer task panicked"),
        "{message}"
    );
    assert!(
        message.contains("injected database writer failure"),
        "{message}"
    );
    bounded(http_stopping).await.unwrap();
    bounded(http_finished).await.unwrap();
    assert!(!db.is_writer_available());
    assert!(matches!(
        bounded(
            db.claim_request_auth_nonce("after-writer-panic".into(), now_timestamp_secs().unwrap())
        )
        .await,
        Err(ApiError::DatabaseUnavailable)
    ));
    assert!(bounded(TcpStream::connect(address)).await.is_err());
}

#[tokio::test]
async fn unexpected_http_exit_fails_the_application_and_closes_the_writer() {
    let directory = tempfile::tempdir().unwrap();
    let (mut runtime, writer, _requested) = open_runtime(&config(&directory)).await;
    start_writer(&mut runtime, writer);
    let db = runtime.db.clone();
    let (address, _http_stopping, _http_finished) = serve_http(&mut runtime, Router::new()).await;
    runtime.http.as_ref().unwrap().abort();

    let error = bounded(runtime.run_until_stopped()).await.unwrap_err();
    assert!(error.to_string().contains("HTTP server task"), "{error:#}");
    assert_database_closed(&db).await;
    assert!(bounded(TcpStream::connect(address)).await.is_err());
}

struct DropNotice(Option<oneshot::Sender<()>>);

impl Drop for DropNotice {
    fn drop(&mut self) {
        if let Some(notice) = self.0.take() {
            let _ = notice.send(());
        }
    }
}

fn tracked_task<T: Send + 'static>(
    future: impl Future<Output = T> + Send + 'static,
) -> (JoinHandle<T>, oneshot::Receiver<()>, oneshot::Receiver<()>) {
    let (started, entered) = oneshot::channel();
    let (dropped, finished) = oneshot::channel();
    let notice = DropNotice(Some(dropped));
    let task = tokio::spawn(async move {
        let _notice = notice;
        started.send(()).unwrap();
        future.await
    });
    (task, entered, finished)
}

#[tokio::test]
async fn shutdown_timeout_aborts_and_awaits_owned_tasks_and_reports_unknown_outcomes() {
    let directory = tempfile::tempdir().unwrap();
    let (mut runtime, writer, _requested) = open_runtime(&config(&directory)).await;
    runtime.shutdown_timeout = Duration::from_millis(20);
    let db = runtime.db.clone();
    let (writer, writer_started, mut writer_dropped) = tracked_task(async move {
        // Own a real writable connection and accepted commands, but simulate
        // a writer that cannot make progress before the shutdown deadline.
        let _writer = writer;
        std::future::pending::<Result<()>>().await
    });
    let (http, http_started, mut http_dropped) =
        tracked_task(std::future::pending::<Result<(), io::Error>>());
    let (coordinator, coordinator_started, mut coordinator_dropped) =
        tracked_task(std::future::pending::<Result<(), ApiError>>());
    let (signal, signal_started, mut signal_dropped) = tracked_task(std::future::pending::<()>());
    let abort_handles = [
        writer.abort_handle(),
        http.abort_handle(),
        coordinator.abort_handle(),
        signal.abort_handle(),
    ];
    runtime.writer = Some(writer);
    runtime.http = Some(http);
    runtime.coordinator = Some(coordinator);
    runtime.signal_task = Some(signal);
    bounded(async {
        writer_started.await.unwrap();
        http_started.await.unwrap();
        coordinator_started.await.unwrap();
        signal_started.await.unwrap();
    })
    .await;
    let mut accepted = Box::pin(
        db.claim_request_auth_nonce("unknown-on-timeout".into(), now_timestamp_secs().unwrap()),
    );
    assert!(futures::poll!(&mut accepted).is_pending());

    let error = bounded(runtime.shutdown()).await.unwrap_err();
    assert!(error.to_string().contains("Shutdown exceeded"), "{error:#}");
    assert!(
        error
            .to_string()
            .contains("accepted operation outcomes may be unknown"),
        "{error:#}"
    );
    assert!(!db.is_writer_available());
    // These must already be complete when shutdown returns; another await
    // could let detached tasks finish and conceal a missing join in shutdown.
    assert_eq!(http_dropped.try_recv(), Ok(()));
    assert_eq!(coordinator_dropped.try_recv(), Ok(()));
    assert_eq!(writer_dropped.try_recv(), Ok(()));
    assert_eq!(signal_dropped.try_recv(), Ok(()));
    assert!(abort_handles.iter().all(|handle| handle.is_finished()));
    assert!(
        runtime.http.is_none()
            && runtime.coordinator.is_none()
            && runtime.writer.is_none()
            && runtime.signal_task.is_none()
    );
    assert!(matches!(
        bounded(accepted).await,
        Err(ApiError::DatabaseOutcomeUnknown)
    ));
}
