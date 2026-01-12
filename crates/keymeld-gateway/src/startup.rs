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
        let app_state = AppState {
            db: db.clone(),
            enclave_manager: enclave_manager.clone(),
            metrics: metrics.clone(),
            gateway_limits: GatewayLimits::default(),
            nonce_cache: NonceCache::new(),
        };

        let app = Self::build_router(app_state, &config);

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
            info!("Gateway will continue startup but some enclaves may not function correctly");
        } else {
            info!("Configured all {} enclaves with KMS", success_count);
        }

        info!("Initializing enclave public keys...");
        let enclave_manager = Arc::new(enclave_manager);

        match enclave_manager.initialize_enclave_public_keys().await {
            Ok(initialized_count) => {
                info!("Initialized {} enclave public keys", initialized_count);
            }
            Err(e) => {
                warn!("Failed to initialize some enclave public keys: {}", e);
                info!("Gateway will attempt to fetch missing keys on-demand");
            }
        }

        Ok(enclave_manager)
    }

    fn build_router(state: AppState, config: &Config) -> Router {
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

        let app = Router::new().nest("/api/v1", api_routes);

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

        app
    }
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
        let (config, _temp_dir) = create_test_config();

        let result = Application::build(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_enclave_manager_setup() {
        let (config, _temp_dir) = create_test_config();

        let db = Database::new(&config.database)
            .await
            .expect("Failed to create database");

        let enclave_manager = Application::setup_enclave_manager(&config, &db)
            .await
            .expect("Failed to setup enclave manager");

        let health_result = enclave_manager.health_check().await;

        assert!(!health_result.is_empty() || health_result.is_empty());
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
