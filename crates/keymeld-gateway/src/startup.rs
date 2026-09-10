use crate::{
    config::{Config, GatewayLimits, TransportMode},
    coordinator::Coordinator,
    database::Database,
    enclave::{EnclaveConfig, EnclaveManager},
    errors::ApiError,
    handlers::{self, AppState, NonceCache},
    kms,
    metrics::Metrics,
    middleware::metrics_middleware,
    routes,
};
use anyhow::{Context, Result};
use axum::{
    middleware,
    response::Html,
    routing::{get, post},
    serve, Router,
};
use keymeld_core::managed_socket::{config::TimeoutConfig, SocketConnector};
use keymeld_sdk::{
    ApiFeatures, ApiVersionResponse, AvailableUserSlot, CreateSigningSessionRequest,
    CreateSigningSessionResponse, DatabaseStats, DeleteUserKeyResponse, EnclaveAssignmentResponse,
    EnclaveHealthResponse, EnclavePublicKeyResponse, ErrorResponse, GetAvailableSlotsResponse,
    HealthCheckResponse, ImportUserKeyRequest, ImportUserKeyResponse,
    InitializeKeygenSessionRequest, InitializeKeygenSessionResponse, KeyStatusResponse,
    KeygenSessionStatusResponse, ListEnclavesResponse, ListUserKeysResponse,
    RegisterKeygenParticipantRequest, RegisterKeygenParticipantResponse, ReserveKeySlotRequest,
    ReserveKeySlotResponse, ReserveKeygenSessionRequest, ReserveKeygenSessionResponse,
    SignSingleRequest, SignSingleResponse, SigningSessionStatusResponse, SingleSigningStatus,
    SingleSigningStatusResponse, StoreKeyFromKeygenRequest, StoreKeyFromKeygenResponse,
};

use std::{io::Error as IoError, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use tokio::{net::TcpListener, signal, task::JoinHandle, time::timeout};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::OpenApi;

use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    decompression::RequestDecompressionLayer,
    services::ServeDir,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing::{error, info, warn};

fn suggest_port_conflict_resolution(addr: SocketAddr) {
    error!("Address {} is already in use", addr);
    info!("To resolve this issue, you can:");
    info!("  1. Stop any existing KeyMeld Gateway process:");
    info!("     pkill keymeld-gateway");
    info!("  2. Find what's using the port:");
    info!(
        "     netstat -tlnp | grep {} || ss -tlnp | grep {}",
        addr.port(),
        addr.port()
    );
    info!("  3. Use a different port in your configuration");
    info!("  4. Wait a moment and try again (port may be in TIME_WAIT state)");
}

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::health_check,
        handlers::list_enclaves,
        handlers::reserve_keygen_session,
        handlers::initialize_keygen_session,
        handlers::register_keygen_participant,
        handlers::get_keygen_status,
        handlers::get_available_slots,
        handlers::create_signing_session,
        handlers::get_signing_status,
        handlers::get_enclave_public_key,
        handlers::api_version,
        // User key management
        handlers::reserve_key_slot,
        handlers::import_user_key,
        handlers::list_user_keys,
        handlers::delete_user_key,
        handlers::get_key_status,
        handlers::store_key_from_keygen,
        // Single-signer signing
        handlers::sign_single,
        handlers::get_single_signing_status,
    ),
    components(
        schemas(
            ReserveKeygenSessionRequest,
            ReserveKeygenSessionResponse,
            InitializeKeygenSessionRequest,
            InitializeKeygenSessionResponse,
            RegisterKeygenParticipantRequest,
            RegisterKeygenParticipantResponse,
            KeygenSessionStatusResponse,
            GetAvailableSlotsResponse,
            AvailableUserSlot,
            CreateSigningSessionRequest,
            CreateSigningSessionResponse,
            SigningSessionStatusResponse,
            EnclaveAssignmentResponse,
            EnclaveHealthResponse,
            EnclavePublicKeyResponse,
            ListEnclavesResponse,
            HealthCheckResponse,
            ApiVersionResponse,
            DatabaseStats,
            ApiFeatures,
            ErrorResponse,
            keymeld_sdk::EnclaveId,
            keymeld_sdk::SessionId,
            keymeld_sdk::UserId,
            keymeld_sdk::TaprootTweak,
            keymeld_sdk::KeygenStatusKind,
            keymeld_sdk::SigningStatusKind,
            // User key management types
            ReserveKeySlotRequest,
            ReserveKeySlotResponse,
            ImportUserKeyRequest,
            ImportUserKeyResponse,
            ListUserKeysResponse,
            DeleteUserKeyResponse,
            KeyStatusResponse,
            StoreKeyFromKeygenRequest,
            StoreKeyFromKeygenResponse,
            // Single-signer signing types
            SignSingleRequest,
            SignSingleResponse,
            SingleSigningStatus,
            SingleSigningStatusResponse,
            keymeld_sdk::KeyId,
            // Batch signing types
            keymeld_sdk::SigningBatchItem,
            keymeld_sdk::BatchItemResult,
            keymeld_sdk::BatchItemApproval,
        )
    ),
    tags(
        (name = "keygen", description = "Keygen session management endpoints"),
        (name = "signing", description = "Signing session management endpoints"),
        (name = "keys", description = "User key management endpoints"),
        (name = "enclaves", description = "Enclave management endpoints"),
        (name = "health", description = "Health and status endpoints"),
    ),
    info(
        title = "KeyMeld Gateway API",
        description = "Multi-party Bitcoin signing using MuSig2 in AWS Nitro Enclaves",
        version = "1.0.0",
        contact(
            name = "KeyMeld Support",
            email = "support@keymeld.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers(
        (url = "/api/v1", description = "KeyMeld Gateway API v1")
    ),
    security(
        ("SessionSignature" = []),
        ("UserSignature" = [])
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

use utoipa::Modify;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "SessionSignature",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Session-Signature"))),
            );

            components.add_security_scheme(
                "UserSignature",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-User-Signature"))),
            );
        }
    }
}

pub struct Application {
    listener: TcpListener,
    app: Router,
    coordinator_handle: JoinHandle<Result<(), ApiError>>,
    coordinator_shutdown: tokio::sync::oneshot::Sender<()>,
    db: Database,
}

impl Application {
    pub async fn build(config: Config) -> Result<Self> {
        let db = Database::new(&config.database)
            .await
            .context("Failed to initialize database")?;

        // Initialize KMS client if enabled
        let _kms_client = kms::init_kms_client(&config.kms)
            .await
            .context("Failed to initialize KMS client")?;

        let enclave_manager = Self::setup_enclave_manager(&config, &db).await?;
        let metrics = Arc::new(Metrics);
        let db_for_shutdown = db.clone();
        let app_state = AppState {
            db: db.clone(),
            enclave_manager: enclave_manager.clone(),
            metrics: metrics.clone(),
            gateway_limits: GatewayLimits::default(),
            nonce_cache: NonceCache::new(),
        };

        let app = Self::build_router(app_state, &config)?;

        let address = format!("{}:{}", config.server.host, config.server.port);
        let addr = SocketAddr::from_str(&address)
            .with_context(|| format!("Failed to parse address: {address}"))?;

        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                suggest_port_conflict_resolution(addr);
                return Err(anyhow::anyhow!(
                    "Cannot start server - address {addr} is already in use. \
                    Another instance may be running or the port is occupied by a different service."
                ));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to bind to address: {addr}"));
            }
        };

        let coordinator_config = Some(config.coordinator.clone());
        let coordinator = Coordinator::new(
            Arc::new(db.clone()),
            enclave_manager.clone(),
            coordinator_config,
            config.kms.clone(),
            metrics.clone(),
        );
        let (coordinator_handle, coordinator_shutdown) = coordinator.start_background_task();

        Ok(Self {
            listener,
            app,
            coordinator_handle,
            coordinator_shutdown,
            db: db_for_shutdown,
        })
    }

    pub async fn run_until_stopped(self) -> Result<(), IoError> {
        let socket_addr = self
            .listener
            .local_addr()
            .map_err(|e| IoError::other(format!("Failed to get local address: {e}")))?;

        let server = serve(
            self.listener,
            self.app.into_make_service_with_connect_info::<SocketAddr>(),
        );

        info!("HTTP server started on {}", socket_addr);
        info!("API Documentation:");
        info!(
            "  → Interactive docs: http://{}:{}/api/v1/docs",
            socket_addr.ip(),
            socket_addr.port()
        );
        info!(
            "  → OpenAPI spec:     http://{}:{}/api/v1/openapi.json",
            socket_addr.ip(),
            socket_addr.port()
        );

        match server.with_graceful_shutdown(shutdown_signal()).await {
            Ok(_) => {
                info!("Server on {} shut down gracefully", socket_addr);

                let _ = self.coordinator_shutdown.send(());
                match timeout(Duration::from_secs(10), self.coordinator_handle).await {
                    Ok(Ok(_)) => {
                        info!("Session coordinator shut down gracefully");
                    }
                    Ok(Err(e)) => {
                        error!("Session coordinator shutdown error: {:?}", e);
                    }
                    Err(_) => {
                        warn!("Session coordinator shutdown timed out after 10 seconds");
                    }
                }

                // Checkpoint WAL before exit so Litestream replicates a complete database
                info!("Checkpointing WAL before shutdown...");
                self.db.checkpoint().await;

                Ok(())
            }
            Err(e) => {
                error!("Server error on {}: {}", socket_addr, e);

                let _ = self.coordinator_shutdown.send(());
                self.coordinator_handle.abort();
                Err(IoError::other(e))
            }
        }
    }

    async fn setup_enclave_manager(config: &Config, db: &Database) -> Result<Arc<EnclaveManager>> {
        let enclave_configs: Vec<EnclaveConfig> = config
            .enclaves
            .enclaves
            .iter()
            .map(|enclave| {
                let connector = match enclave.transport {
                    TransportMode::Vsock => SocketConnector::vsock(enclave.cid, enclave.port),
                    TransportMode::Tcp => {
                        let host = enclave
                            .tcp_host
                            .clone()
                            .unwrap_or_else(|| "localhost".to_string());
                        SocketConnector::tcp(host, enclave.port as u16)
                    }
                };
                EnclaveConfig {
                    id: enclave.id,
                    cid: enclave.cid,
                    port: enclave.port,
                    connector,
                }
            })
            .collect();

        let timeout_config = TimeoutConfig::from(&config.enclaves);

        let enclave_manager = EnclaveManager::new_with_config(enclave_configs, timeout_config)?;

        info!(
            "Configured enclave manager with {} total enclaves",
            config.enclaves.enclaves.len()
        );

        info!("Configuring all enclaves with KMS...");
        let mut success_count = 0;
        let mut failure_count = 0;

        for enclave_id in enclave_manager.get_all_enclave_ids() {
            if let Some(client) = enclave_manager.get_enclave_client(&enclave_id) {
                match kms::configure_enclave_with_kms(enclave_id, client, db, &config.kms).await {
                    Ok(()) => {
                        success_count += 1;
                    }
                    Err(e) => {
                        failure_count += 1;
                        warn!("Failed to configure enclave {} with KMS: {}", enclave_id, e);
                    }
                }
            }
        }

        if failure_count > 0 {
            warn!(
                "Configured {}/{} enclaves successfully ({} failed)",
                success_count,
                success_count + failure_count,
                failure_count
            );
            anyhow::bail!("Refusing startup: all configured enclaves must authenticate and initialize successfully");
        } else {
            info!("Configured all {} enclaves with KMS", success_count);
        }

        info!("Initializing enclave public keys...");
        let enclave_manager = Arc::new(enclave_manager);

        let initialized_count = enclave_manager.initialize_enclave_public_keys().await?;
        anyhow::ensure!(
            initialized_count == enclave_manager.get_all_enclave_ids().len(),
            "Refusing startup: every enclave must provide its authenticated identity"
        );

        // Complete recovery before serving clients. A gateway-only restart probes live
        // completed sessions, while an enclave restart restores their authorized state.
        for enclave_id in enclave_manager.get_all_enclave_ids() {
            let stats = enclave_manager
                .restore_sessions_for_enclave(&enclave_id, db)
                .await?;
            anyhow::ensure!(
                stats.keygen_failed == 0
                    && stats.signing_failed == 0
                    && stats.user_keys_failed == 0,
                "Refusing startup: enclave {enclave_id} state recovery was incomplete"
            );
        }

        Ok(enclave_manager)
    }

    fn build_router(state: AppState, config: &Config) -> Result<Router> {
        let api_routes = Router::new()
            // Keygen routes
            .route("/keygen/reserve", post(handlers::reserve_keygen_session))
            .route(
                "/keygen/{session_id}/initialize",
                post(handlers::initialize_keygen_session),
            )
            .route(
                "/keygen/{keygen_session_id}/participants",
                post(handlers::register_keygen_participant),
            )
            .route(
                "/keygen/{keygen_session_id}/status",
                get(handlers::get_keygen_status),
            )
            .route(
                "/keygen/{keygen_session_id}/slots",
                get(handlers::get_available_slots),
            )
            // MuSig2 signing routes
            .route("/signing", post(handlers::create_signing_session))
            .route(
                "/signing/{signing_session_id}/approve/{user_id}",
                post(handlers::approve_signing_session),
            )
            .route(
                "/signing/{signing_session_id}/status/{user_id}",
                get(handlers::get_signing_status),
            )
            // User key management routes
            .route("/keys/reserve", post(handlers::reserve_key_slot))
            .route("/keys/import", post(handlers::import_user_key))
            .route("/keys/{user_id}", get(handlers::list_user_keys))
            .route(
                "/keys/{user_id}/{key_id}",
                axum::routing::delete(handlers::delete_user_key),
            )
            .route(
                "/keys/{user_id}/{key_id}/status",
                get(handlers::get_key_status),
            )
            .route(
                "/keys/{user_id}/keygen/{keygen_session_id}",
                post(handlers::store_key_from_keygen),
            )
            // Single-signer signing routes
            .route("/sign/single", post(handlers::sign_single))
            .route(
                "/sign/single/{session_id}/status/{user_id}",
                get(handlers::get_single_signing_status),
            )
            // Enclave routes
            .route("/enclaves", get(handlers::list_enclaves))
            .route(
                "/enclaves/{enclave_id}/public-key",
                get(handlers::get_enclave_public_key),
            )
            // Health and utility routes
            .route("/version", get(handlers::api_version))
            .route("/health", get(handlers::health_check))
            .route("/health/detail", get(handlers::health_check_detail))
            .route("/metrics", get(handlers::metrics))
            .route(
                "/openapi.json",
                get(|| async { axum::Json(ApiDoc::openapi()) }),
            )
            .route(
                "/docs",
                get(|| async { Html(utoipa_scalar::Scalar::new(ApiDoc::openapi()).to_html()) }),
            );

        // UI routes for admin portal
        let ui_routes = operator_routes(
            config.server.operator_token_file.as_deref(),
            Router::new()
                .route("/", get(routes::dashboard_handler))
                .route("/sessions", get(routes::sessions_handler))
                .route(
                    "/sessions/{session_id}",
                    get(routes::session_detail_handler),
                )
                .route("/enclaves", get(routes::enclaves_handler))
                // HTMX fragment routes
                .route("/fragments/stats", get(routes::stats_fragment_handler))
                .route(
                    "/fragments/sessions-rows",
                    get(routes::sessions_rows_handler),
                )
                .route(
                    "/fragments/enclaves",
                    get(routes::enclaves_fragment_handler),
                ),
        )?;

        let static_dir = std::env::var("KEYMELD_STATIC_DIR")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/static").to_string());

        let app = Router::new()
            .merge(ui_routes)
            .nest("/api/v1", api_routes)
            .merge(static_file_routes(&static_dir));

        let mut app = app
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(DefaultMakeSpan::new().level(Level::DEBUG))
                    .on_request(DefaultOnRequest::new().level(Level::DEBUG))
                    .on_response(DefaultOnResponse::new().level(Level::DEBUG)),
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                metrics_middleware,
            ))
            .with_state(state);

        if config.server.enable_compression {
            // Response compression (gzip responses when client sends Accept-Encoding: gzip)
            app = app.layer(CompressionLayer::new());
            // Request decompression (decompress requests with Content-Encoding: gzip)
            app = app.layer(RequestDecompressionLayer::new().gzip(true));
        }

        if config.server.enable_cors {
            app = app.layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods(Any)
                    .allow_headers(Any),
            );
        }

        Ok(app)
    }
}

fn operator_routes<S>(token_file: Option<&str>, routes: Router<S>) -> Result<Router<S>>
where
    S: Clone + Send + Sync + 'static,
{
    let Some(path) = token_file else {
        return Ok(Router::new());
    };
    let token = zeroize::Zeroizing::new(
        std::fs::read_to_string(path).context("Cannot read operator token file")?,
    );
    let token: [u8; 32] = hex::decode(token.trim())
        .context("Operator token must contain 64 hexadecimal characters")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Operator token must contain 32 bytes"))?;
    Ok(routes.route_layer(middleware::from_fn_with_state(
        Arc::new(token),
        authenticate_operator,
    )))
}

async fn authenticate_operator(
    axum::extract::State(expected): axum::extract::State<Arc<[u8; 32]>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    use axum::{
        http::{header, StatusCode},
        response::IntoResponse,
    };
    use subtle::ConstantTimeEq;

    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| value.len() == 64)
        .and_then(|value| hex::decode(value).ok());
    let authorized = supplied
        .as_deref()
        .is_some_and(|token| bool::from(expected.as_slice().ct_eq(token)));
    if !authorized {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
}

fn static_file_routes<S>(static_dir: impl AsRef<std::path::Path>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // ServeDir rejects decoded traversal components and uses a built-in MIME
    // table, including JavaScript and CSS, without a system MIME database.
    Router::new().nest_service(
        "/static",
        ServeDir::new(static_dir).append_index_html_on_directories(false),
    )
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            error!("Failed to install Ctrl+C handler: {}", e);
            return;
        }
        info!("Received Ctrl+C signal");
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
                info!("Received SIGTERM signal");
            }
            Err(e) => {
                error!("Failed to install SIGTERM handler: {}", e);
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, starting graceful shutdown...");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CoordinatorConfig, DatabaseConfig, DevelopmentConfig, EnclaveConfig, EnclaveInfo,
        Environment, KmsConfig, SecurityConfig, ServerConfig, TransportMode,
    };
    use keymeld_core::logging::LoggingConfig;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct StaticTestServer {
        address: SocketAddr,
        task: JoinHandle<()>,
    }

    impl StaticTestServer {
        async fn start(directory: &std::path::Path) -> Self {
            Self::start_router(static_file_routes(directory)).await
        }

        async fn start_router(router: Router) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, router).await.unwrap();
            });
            Self { address, task }
        }

        async fn request(&self, method: &str, path: &str) -> (u16, String, String) {
            self.request_with_body(method, path, "", "").await
        }

        async fn request_with_body(
            &self,
            method: &str,
            path: &str,
            headers: &str,
            body: &str,
        ) -> (u16, String, String) {
            // A raw request preserves encoded traversal bytes that URL clients
            // can normalize before the gateway receives them.
            timeout(Duration::from_secs(5), async {
                let mut stream = tokio::net::TcpStream::connect(self.address)
                    .await
                    .unwrap();
                stream
                    .write_all(
                        format!(
                            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}\r\n{body}", body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).await.unwrap();
                let response = String::from_utf8(response).unwrap();
                let (headers, body) = response.split_once("\r\n\r\n").unwrap();
                let status = headers
                    .split_whitespace()
                    .nth(1)
                    .unwrap()
                    .parse()
                    .unwrap();
                (status, headers.to_ascii_lowercase(), body.to_owned())
            })
            .await
            .expect("static file HTTP request timed out")
        }
    }

    impl Drop for StaticTestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn http_test_state(config: &Config) -> (AppState, sqlx::SqlitePool) {
        let db = Database::new(&config.database).await.unwrap();
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", config.database.path))
            .await
            .unwrap();
        let credentials =
            crate::enclave::channel::ChannelCredentials::dangerous_trust_unattested_enclaves(
                [42; 32],
            )
            .unwrap();
        let manager = EnclaveManager::new_with_credentials(
            vec![crate::enclave::EnclaveConfig {
                id: 1,
                cid: 3,
                port: 9,
                connector: SocketConnector::tcp("127.0.0.1", 9),
            }],
            TimeoutConfig::default(),
            Arc::new(credentials),
        )
        .unwrap();
        (
            AppState {
                db,
                enclave_manager: Arc::new(manager),
                metrics: Arc::new(Metrics),
                gateway_limits: GatewayLimits::default(),
                nonce_cache: NonceCache::new(),
            },
            pool,
        )
    }

    #[tokio::test]
    async fn operator_pages_and_htmx_are_disabled_by_default_and_require_operator_auth_when_enabled(
    ) {
        let (mut config, directory) = create_test_config();
        let (state, _) = http_test_state(&config).await;
        let paths = [
            "/",
            "/sessions",
            "/sessions/0193a5de-4294-7000-8000-000000000001",
            "/enclaves",
            "/fragments/stats",
            "/fragments/sessions-rows",
            "/fragments/enclaves",
        ];
        let disabled = StaticTestServer::start_router(
            Application::build_router(state.clone(), &config).unwrap(),
        )
        .await;
        for path in paths {
            assert_eq!(disabled.request("GET", path).await.0, 404, "{path}");
        }
        let token = hex::encode([42; 32]);
        let token_path = directory.path().join("operator-token");
        std::fs::write(&token_path, &token).unwrap();
        config.server.operator_token_file = Some(token_path.to_string_lossy().into_owned());
        let enabled =
            StaticTestServer::start_router(Application::build_router(state, &config).unwrap())
                .await;
        for path in paths {
            for headers in [
                "",
                "Authorization: Bearer invalid\r\n",
                "X-User-Signature: participant-token\r\n",
                "HX-Request: true\r\n",
            ] {
                let (status, _, body) = enabled.request_with_body("GET", path, headers, "").await;
                assert_eq!(status, 401, "{path}: {body}");
            }
            let (status, headers, _) = enabled
                .request_with_body(
                    "GET",
                    path,
                    &format!("Authorization: Bearer {token}\r\nHX-Request: true\r\n"),
                    "",
                )
                .await;
            assert_eq!(status, 200, "{path}");
            assert!(headers.contains("cache-control: no-store"));
        }
        // This utility route does not depend on a running enclave. The UI's
        // operator middleware must not protect the public API router.
        assert_eq!(enabled.request("GET", "/api/v1/version").await.0, 200);
    }

    #[test]
    fn invalid_operator_configuration_fails_closed() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("operator-token");
        let routes = || {
            Router::<()>::new().route("/sessions", get(|| async { "private session inventory" }))
        };
        assert!(operator_routes(Some(path.to_str().unwrap()), routes()).is_err());
        for invalid_token in ["", "password", "0011", &"ff".repeat(33)] {
            std::fs::write(&path, invalid_token).unwrap();
            assert!(operator_routes(Some(path.to_str().unwrap()), routes()).is_err());
        }
    }

    #[tokio::test]
    async fn single_key_reservation_and_import_http_proofs_cannot_be_omitted_rebound_or_replaced() {
        let (config, _directory) = create_test_config();
        let (state, pool) = http_test_state(&config).await;
        let enclave_key = secp256k1::PublicKey::from_secret_key(
            &secp256k1::Secp256k1::new(),
            &secp256k1::SecretKey::from_byte_array([9; 32]).unwrap(),
        )
        .to_string();
        sqlx::query("INSERT INTO enclave_public_keys (enclave_id, cached_at, expires_at, public_key) VALUES (1, 0, 9999999999, ?)").bind(&enclave_key).execute(&pool).await.unwrap();
        let server = StaticTestServer::start_router(
            Application::build_router(state.clone(), &config).unwrap(),
        )
        .await;
        let owner = keymeld_sdk::UserCredentials::from_private_key(&[1; 32]).unwrap();
        let attacker = keymeld_sdk::UserCredentials::from_private_key(&[2; 32]).unwrap();
        let request = ReserveKeySlotRequest {
            key_id: keymeld_sdk::KeyId::new_v7(),
            user_id: keymeld_sdk::UserId::new_v7(),
            auth_pubkey: owner.auth_public_key_bytes(),
        };
        let body = serde_json::to_string(&request).unwrap();
        assert!(
            server
                .request_with_body("POST", "/api/v1/keys/reserve", "", &body)
                .await
                .0
                >= 400
        );
        assert!(state
            .db
            .get_reserved_key_slot(&request.key_id)
            .await
            .unwrap()
            .is_none());
        let signature = owner
            .sign_user_request(&request.auth_scope().unwrap(), &request.user_id.to_string())
            .unwrap();
        let headers = format!("X-User-Signature: {signature}\r\n");
        let mut rebound = request.clone();
        rebound.user_id = keymeld_sdk::UserId::new_v7();
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    "/api/v1/keys/reserve",
                    &headers,
                    &serde_json::to_string(&rebound).unwrap()
                )
                .await
                .0,
            401
        );
        assert_eq!(
            server
                .request_with_body("POST", "/api/v1/keys/reserve", &headers, &body)
                .await
                .0,
            200
        );
        assert_eq!(
            server
                .request_with_body("POST", "/api/v1/keys/reserve", &headers, &body)
                .await
                .0,
            401
        );
        let mut stolen = request.clone();
        stolen.auth_pubkey = attacker.auth_public_key_bytes();
        let signature = attacker
            .sign_user_request(&stolen.auth_scope().unwrap(), &stolen.user_id.to_string())
            .unwrap();
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    "/api/v1/keys/reserve",
                    &format!("X-User-Signature: {signature}\r\n"),
                    &serde_json::to_string(&stolen).unwrap()
                )
                .await
                .0,
            409
        );
        let mut import = ImportUserKeyRequest {
            key_id: request.key_id.clone(),
            user_id: request.user_id.clone(),
            auth_pubkey: attacker.auth_public_key_bytes(),
            encrypted_private_key: "0102".into(),
            enclave_public_key: enclave_key,
        };
        let signature = attacker
            .sign_user_request(&import.auth_scope().unwrap(), &import.user_id.to_string())
            .unwrap();
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    "/api/v1/keys/import",
                    &format!("X-User-Signature: {signature}\r\n"),
                    &serde_json::to_string(&import).unwrap()
                )
                .await
                .0,
            401
        );
        import.auth_pubkey = owner.auth_public_key_bytes();
        let signature = owner
            .sign_user_request(&import.auth_scope().unwrap(), &import.user_id.to_string())
            .unwrap();
        let headers = format!("X-User-Signature: {signature}\r\n");
        let mut altered = import.clone();
        altered.encrypted_private_key = "0304".into();
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    "/api/v1/keys/import",
                    &headers,
                    &serde_json::to_string(&altered).unwrap()
                )
                .await
                .0,
            401
        );
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    "/api/v1/keys/import",
                    &headers,
                    &serde_json::to_string(&import).unwrap()
                )
                .await
                .0,
            200
        );
        let persisted: (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT auth_pubkey, encrypted_private_key FROM pending_key_imports WHERE key_id = ?",
        )
        .bind(&request.key_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(persisted, (owner.auth_public_key_bytes(), vec![1, 2]));
    }

    #[tokio::test]
    async fn keygen_key_persistence_http_requires_participant_proof_and_slots_survive_gateway_restart(
    ) {
        use crate::session::keygen::{
            KeygenCollectingParticipants, KeygenCompleted, KeygenSessionStatus,
        };
        use keymeld_core::{
            authorization::{SessionAuthorizationManifest, SignedSessionManifest},
            SessionId, UserId,
        };
        use std::collections::BTreeMap;
        let (config, _directory) = create_test_config();
        let (state, pool) = http_test_state(&config).await;
        let owner = keymeld_sdk::UserCredentials::from_private_key(&[1; 32]).unwrap();
        let attacker = keymeld_sdk::UserCredentials::from_private_key(&[2; 32]).unwrap();
        let session_credentials = keymeld_sdk::SessionCredentials::generate().unwrap();
        let user = UserId::new_v7();
        let session = SessionId::new_v7();
        let authority = keymeld_sdk::AuthorizationCredentials::generate().unwrap();
        let manifest = SignedSessionManifest::sign(
            SessionAuthorizationManifest {
                keygen_session_id: session.clone(),
                coordinator_user_id: user.clone(),
                creator_pubkey: authority.public_key_bytes(),
                signing_pubkey: authority.public_key_bytes(),
                session_public_key: session_credentials.public_key_bytes(),
                participant_verifiers: BTreeMap::from([(
                    user.clone(),
                    attacker.public_key_bytes(),
                )]),
                timeout_secs: 600,
                max_signing_sessions: None,
                encrypted_taproot_tweak: String::new(),
                subset_definitions: vec![],
            },
            &authority.export_secret(),
        )
        .unwrap();
        let recipient_authorization =
            keymeld_core::authorization::EnclaveRecipientAuthorization::sign(
                &manifest,
                BTreeMap::from([(user.clone(), keymeld_sdk::EnclaveId::from(1))]),
                BTreeMap::from([(keymeld_sdk::EnclaveId::from(1), owner.public_key_bytes())]),
                &authority.export_secret(),
            )
            .unwrap();
        let completed = KeygenSessionStatus::Completed(KeygenCompleted {
            recipient_authorization: Box::new(recipient_authorization),
            authorization_manifest: Box::new(manifest),
            encrypted_roster: String::new(),
            keygen_session_id: session.clone(),
            coordinator_pubkey: *owner.public_key(),
            coordinator_encrypted_private_key: String::new(),
            session_public_key: session_credentials.public_key_bytes(),
            encrypted_session_secret: String::new(),
            coordinator_enclave_id: keymeld_sdk::EnclaveId::from(1),
            expected_participants: vec![user.clone()],
            registered_participants: BTreeMap::new(),
            aggregate_public_key: String::new(),
            created_at: 0,
            completed_at: 1,
            completed_with_epochs: BTreeMap::new(),
            encrypted_taproot_tweak: String::new(),
            participant_encrypted_public_keys: vec![],
            enclave_encrypted_session_secrets: vec![],
            subset_definitions: vec![],
            encrypted_subset_aggregates: BTreeMap::new(),
        });
        sqlx::query("INSERT INTO enclave_public_keys (enclave_id, cached_at, expires_at, public_key) VALUES (1, 0, 9999999999, '')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO keygen_sessions (keygen_session_id, status_name, created_at, expires_at, expected_participants, status, session_public_key) VALUES (?, 'completed', 0, 9999999999, '[]', ?, ?)")
            .bind(&session).bind(serde_json::to_string(&completed).unwrap()).bind(session_credentials.public_key_bytes()).execute(&pool).await.unwrap();
        let key_row = state
            .db
            .store_user_key(crate::database::StoreUserKeyParams {
                user_id: &user,
                key_id: &keymeld_sdk::KeyId::new_v7(),
                enclave_id: keymeld_sdk::EnclaveId::from(1),
                enclave_key_epoch: 1,
                encrypted_private_key: &[1],
                auth_pubkey: &owner
                    .derive_session_auth_pubkey(&session.to_string())
                    .unwrap(),
                origin_keygen_session_id: Some(&session),
            })
            .await
            .unwrap();
        sqlx::query("INSERT INTO keygen_participants (keygen_session_id, user_id, user_key_id, registered_at) VALUES (?, ?, ?, 0)")
            .bind(&session).bind(&user).bind(key_row).execute(&pool).await.unwrap();
        let server = StaticTestServer::start_router(
            Application::build_router(state.clone(), &config).unwrap(),
        )
        .await;
        let request = StoreKeyFromKeygenRequest {
            key_id: keymeld_sdk::KeyId::new_v7(),
        };
        let url = format!("/api/v1/keys/{user}/keygen/{session}");
        let body = serde_json::to_string(&request).unwrap();
        assert!(server.request_with_body("POST", &url, "", &body).await.0 >= 400);
        let scope = request.auth_scope(&user, &session).unwrap();
        let bad_signature = attacker
            .sign_for_session(&scope, &user.to_string(), &session.to_string())
            .unwrap();
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    &url,
                    &format!("X-User-Signature: {bad_signature}\r\n"),
                    &body
                )
                .await
                .0,
            401
        );
        let signature = owner
            .sign_for_session(&scope, &user.to_string(), &session.to_string())
            .unwrap();
        let headers = format!("X-User-Signature: {signature}\r\n");
        let altered = StoreKeyFromKeygenRequest {
            key_id: keymeld_sdk::KeyId::new_v7(),
        };
        assert_eq!(
            server
                .request_with_body(
                    "POST",
                    &url,
                    &headers,
                    &serde_json::to_string(&altered).unwrap()
                )
                .await
                .0,
            401
        );
        assert!(state
            .db
            .get_pending_key_store(&request.key_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            server
                .request_with_body("POST", &url, &headers, &body)
                .await
                .0,
            200
        );
        let pending = state
            .db
            .get_pending_key_store(&request.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pending.authorization, signature);
        assert_eq!(pending.user_id, user);
        assert_eq!(pending.keygen_session_id, session);

        // A fresh gateway has persisted session state and an empty in-memory
        // assignment cache until background restoration finishes.
        assert!(state
            .enclave_manager
            .get_session_assignment(&session)
            .unwrap()
            .is_none());
        let KeygenSessionStatus::Completed(completed_data) = &completed else {
            unreachable!()
        };
        let collecting =
            KeygenSessionStatus::CollectingParticipants(KeygenCollectingParticipants {
                authorization_manifest: completed_data.authorization_manifest.clone(),
                recipient_authorization: completed_data.recipient_authorization.clone(),
                keygen_session_id: session.clone(),
                coordinator_pubkey: completed_data.coordinator_pubkey,
                coordinator_encrypted_private_key: String::new(),
                session_public_key: session_credentials.public_key_bytes(),
                encrypted_session_secret: String::new(),
                coordinator_enclave_id: completed_data.coordinator_enclave_id,
                expected_participants: vec![user.clone()],
                registered_participants: BTreeMap::new(),
                created_at: 0,
                expires_at: 9999999999,
                required_enclave_epochs: BTreeMap::new(),
                encrypted_taproot_tweak: String::new(),
                subset_definitions: vec![],
            });
        let slots_url = format!("/api/v1/keygen/{session}/slots");
        assert!(server.request("GET", &slots_url).await.0 >= 400);
        for (status_name, status) in [
            ("completed", completed),
            ("collecting_participants", collecting),
        ] {
            sqlx::query("UPDATE keygen_sessions SET status_name = ?, status = ? WHERE keygen_session_id = ?")
                .bind(status_name).bind(serde_json::to_string(&status).unwrap()).bind(&session).execute(&pool).await.unwrap();
            let signature = session_credentials
                .sign_session_request(&session.to_string())
                .unwrap();
            let (code, _, body) = server
                .request_with_body(
                    "GET",
                    &slots_url,
                    &format!("X-Session-Signature: {signature}\r\n"),
                    "",
                )
                .await;
            assert_eq!(code, 200, "{status_name}: {body}");
            let slots: GetAvailableSlotsResponse = serde_json::from_str(&body).unwrap();
            assert_eq!(slots.session_id, session);
            assert_eq!(slots.available_slots.len(), 1);
            assert_eq!(slots.available_slots[0].user_id, user);
            assert_eq!(
                slots.available_slots[0].enclave_id,
                keymeld_sdk::EnclaveId::from(1)
            );
            assert_eq!(slots.available_slots[0].signer_index, 0);
            assert!(slots.available_slots[0].claimed);

            for change_signature in [false, true] {
                let mut corrupted = status.clone();
                let (recipient_authorization, coordinator_enclave) = match &mut corrupted {
                    KeygenSessionStatus::Completed(s) => (
                        &mut s.recipient_authorization,
                        &mut s.coordinator_enclave_id,
                    ),
                    KeygenSessionStatus::CollectingParticipants(s) => (
                        &mut s.recipient_authorization,
                        &mut s.coordinator_enclave_id,
                    ),
                    _ => unreachable!(),
                };
                if change_signature {
                    recipient_authorization.signature[0] ^= 1;
                } else {
                    *coordinator_enclave = keymeld_sdk::EnclaveId::from(2);
                }
                sqlx::query("UPDATE keygen_sessions SET status = ? WHERE keygen_session_id = ?")
                    .bind(serde_json::to_string(&corrupted).unwrap())
                    .bind(&session)
                    .execute(&pool)
                    .await
                    .unwrap();
                let signature = session_credentials
                    .sign_session_request(&session.to_string())
                    .unwrap();
                assert_eq!(
                    server
                        .request_with_body(
                            "GET",
                            &slots_url,
                            &format!("X-Session-Signature: {signature}\r\n"),
                            ""
                        )
                        .await
                        .0,
                    500
                );
            }
        }
        assert!(state
            .enclave_manager
            .get_session_assignment(&session)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn static_assets_preserve_content_and_mime_types() {
        let directory = TempDir::new().unwrap();
        std::fs::write(directory.path().join("app.js"), "console.log('asset');").unwrap();
        std::fs::write(directory.path().join("styles.css"), "body { color: red; }").unwrap();
        std::fs::create_dir(directory.path().join("nested")).unwrap();
        std::fs::write(directory.path().join("nested/probe.txt"), "STATIC-OK").unwrap();
        std::fs::write(
            directory.path().join("nested/index.html"),
            "not an asset index",
        )
        .unwrap();
        let server = StaticTestServer::start(directory.path()).await;

        for (path, mime, expected) in [
            ("/static/app.js", "text/javascript", "console.log('asset');"),
            ("/static/styles.css", "text/css", "body { color: red; }"),
            ("/static/nested/probe.txt", "text/plain", "STATIC-OK"),
        ] {
            let (status, headers, body) = server.request("GET", path).await;
            assert_eq!(status, 200, "{path}");
            assert!(
                headers.contains(&format!("content-type: {mime}")),
                "{headers}"
            );
            assert_eq!(body, expected, "{path}");
        }

        let (status, _, body) = server.request("HEAD", "/static/app.js").await;
        assert_eq!(status, 200);
        assert!(body.is_empty());
        assert_eq!(server.request("POST", "/static/app.js").await.0, 405);
        assert_eq!(server.request("GET", "/static/missing.js").await.0, 404);
        assert_eq!(server.request("GET", "/static/nested/").await.0, 404);
    }

    #[tokio::test]
    async fn static_encoded_traversals_cannot_read_a_sibling_secret() {
        let directory = TempDir::new().unwrap();
        let asset_directory = directory.path().join("static");
        std::fs::create_dir_all(asset_directory.join("nested")).unwrap();
        std::fs::write(asset_directory.join("probe.txt"), "STATIC-OK").unwrap();
        let secret_path = directory.path().join("secret.txt");
        let secret = "OUTSIDE-THE-STATIC-ROOT";
        std::fs::write(&secret_path, secret).unwrap();
        let server = StaticTestServer::start(&asset_directory).await;
        assert_eq!(
            server.request("GET", "/static/probe.txt").await.2,
            "STATIC-OK"
        );

        let absolute_escape = format!(
            "/static/{}",
            secret_path.to_str().unwrap().replace('/', "%2f")
        );
        for path in [
            "/static/../secret.txt",
            "/static/..%2fsecret.txt",
            "/static/%2e%2e%2fsecret.txt",
            "/static/nested%2f..%2f..%2fsecret.txt",
            "/static/..%5csecret.txt",
            "/static/%252e%252e%252fsecret.txt",
            absolute_escape.as_str(),
        ] {
            let (status, _, body) = server.request("GET", path).await;
            assert_eq!(status, 404, "{path}: {body}");
            assert!(!body.contains(secret), "{path} exposed the sibling secret");
        }
    }

    fn create_test_config() -> (Config, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");

        let config = Config {
            environment: Environment::Development,
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0,
                enable_cors: true,
                enable_compression: true,
                operator_token_file: None,
            },
            database: DatabaseConfig {
                path: db_path.to_string_lossy().to_string(),
                max_connections: 5,
                connection_timeout_secs: 5,
                idle_timeout_secs: Some(30),
                enable_wal_mode: Some(false),
            },
            enclaves: EnclaveConfig {
                enclaves: vec![
                    EnclaveInfo {
                        id: 0,
                        cid: 3,
                        port: 8000,
                        transport: TransportMode::default(),
                        tcp_host: None,
                    },
                    EnclaveInfo {
                        id: 1,
                        cid: 4,
                        port: 8001,
                        transport: TransportMode::default(),
                        tcp_host: None,
                    },
                ],
                connection_load_threshold: Some(100),
                max_channel_size: Some(1000),
                pool_acquire_timeout_secs: None,
                vsock_timeout_secs: None,
                nonce_generation_timeout_secs: None,
                session_init_timeout_secs: None,
                signing_timeout_secs: None,
                network_write_timeout_secs: None,
                network_read_timeout_secs: None,
                max_message_size_bytes: None,
                connection_retry_delay_ms: None,
                max_retry_attempts: None,
                initial_retry_delay_ms: None,
                max_retry_delay_ms: None,
                retry_backoff_multiplier: None,
            },
            coordinator: CoordinatorConfig::default(),
            logging: LoggingConfig::default(),
            security: SecurityConfig::default(),
            development: Some(DevelopmentConfig::default()),
            kms: KmsConfig::default(),
        };

        (config, temp_dir)
    }

    #[tokio::test]
    async fn test_application_build() {
        const CHILD_MARKER: &str = "KEYMELD_TEST_MISSING_CHANNEL_CREDENTIAL_CHILD";
        if std::env::var_os(CHILD_MARKER).is_none() {
            // Test the actual environment-backed startup path in a subprocess.
            // Mutating this test process's environment would race other tests.
            let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "startup::tests::test_application_build",
                    "--nocapture",
                ])
                .env(CHILD_MARKER, "1")
                .env_remove("KEYMELD_GATEWAY_SIGNING_KEY_FILE")
                .output()
                .await
                .expect("Failed to launch isolated startup test");
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let (config, _temp_dir) = create_test_config();
        let result = Application::build(config).await;
        let error = match result {
            Ok(_) => panic!("Gateway started without a provisioned channel credential"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("KEYMELD_GATEWAY_SIGNING_KEY_FILE"),
            "Unexpected startup failure: {error:#}"
        );
    }

    #[tokio::test]
    async fn test_enclave_manager_setup() {
        let (config, _temp_dir) = create_test_config();
        let (state, _pool) = http_test_state(&config).await;
        // Explicit test credentials construct the intended enclave client
        // without process-wide configuration or probes to live services.
        let enclave_id = keymeld_core::EnclaveId::from(1);
        assert_eq!(
            state.enclave_manager.get_all_enclave_ids(),
            vec![enclave_id]
        );
        assert!(state
            .enclave_manager
            .get_enclave_client(&enclave_id)
            .is_some());
        assert_eq!(
            state.enclave_manager.get_enclave_key_epoch(&enclave_id),
            Some(1)
        );
    }

    #[test]
    fn test_openapi_spec_generation() {
        let openapi = ApiDoc::openapi();

        assert_eq!(openapi.info.title, "KeyMeld Gateway API");
        assert_eq!(openapi.info.version, "1.0.0");

        assert!(openapi.paths.paths.contains_key("/health"));
        assert!(openapi.paths.paths.contains_key("/keygen/reserve"));
        assert!(openapi
            .paths
            .paths
            .contains_key("/keygen/{session_id}/initialize"));
        assert!(openapi.paths.paths.contains_key("/signing"));
        assert!(openapi.paths.paths.contains_key("/version"));

        let schemas = &openapi
            .components
            .as_ref()
            .expect("OpenAPI should have components")
            .schemas;
        assert!(schemas.contains_key("ReserveKeygenSessionRequest"));
        assert!(schemas.contains_key("ReserveKeygenSessionResponse"));
        assert!(schemas.contains_key("InitializeKeygenSessionRequest"));
        assert!(schemas.contains_key("InitializeKeygenSessionResponse"));
        assert!(schemas.contains_key("CreateSigningSessionRequest"));
        assert!(schemas.contains_key("CreateSigningSessionResponse"));
        assert!(schemas.contains_key("RegisterKeygenParticipantRequest"));
        assert!(schemas.contains_key("RegisterKeygenParticipantResponse"));
        assert!(schemas.contains_key("KeygenSessionStatusResponse"));
        assert!(schemas.contains_key("SigningSessionStatusResponse"));
        assert!(schemas.contains_key("EnclavePublicKeyResponse"));
        assert!(schemas.contains_key("HealthCheckResponse"));
        assert!(schemas.contains_key("ApiVersionResponse"));
        assert!(schemas.contains_key("ErrorResponse"));
    }
}
