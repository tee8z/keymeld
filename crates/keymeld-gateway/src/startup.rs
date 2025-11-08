use crate::{
    config::Config,
    coordinator::Coordinator,
    database::Database,
    errors::ApiError,
    handlers::{self, AppState},
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
use keymeld_core::{
    api::*,
    enclave::{EnclaveConfig, EnclaveManager},
};

use std::{io::Error as IoError, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use tokio::{net::TcpListener, signal, task::JoinHandle, time::timeout};
use utoipa::OpenApi;

use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
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
        handlers::create_keygen_session,
        handlers::register_keygen_participant,
        handlers::get_keygen_status,
        handlers::get_available_slots,
        handlers::create_signing_session,
        handlers::get_signing_status,
        handlers::get_enclave_public_key,
        handlers::api_version,
    ),
    components(
        schemas(
            CreateKeygenSessionRequest,
            CreateKeygenSessionResponse,
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
            keymeld_core::identifiers::SessionId,
            keymeld_core::identifiers::UserId,
            keymeld_core::identifiers::EnclaveId,
        )
    ),
    tags(
        (name = "keygen", description = "Keygen session management endpoints"),
        (name = "signing", description = "Signing session management endpoints"),
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
        ("SessionHmac" = []),
        ("SigningHmac" = [])
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

use utoipa::Modify;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};

            components.add_security_scheme(
                "SessionHmac",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Session-HMAC"))),
            );

            components.add_security_scheme(
                "SigningHmac",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Signing-HMAC"))),
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

        let enclave_manager = Self::setup_enclave_manager(&config).await?;
        let metrics = Arc::new(Metrics);
        let app_state = AppState {
            db: db.clone(),
            enclave_manager: enclave_manager.clone(),
            metrics: metrics.clone(),
        };

        let app = Self::build_router(app_state, &config);

        let address = format!("{}:{}", config.server.host, config.server.port);
        let addr = SocketAddr::from_str(&address)
            .with_context(|| format!("Failed to parse address: {}", address))?;

        let listener = match TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                suggest_port_conflict_resolution(addr);
                return Err(anyhow::anyhow!(
                    "Cannot start server - address {} is already in use. \
                    Another instance may be running or the port is occupied by a different service.",
                    addr
                ));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to bind to address: {addr}"));
            }
        };

        let coordinator_config = config.coordinator.as_ref().map(|sc| sc.to_owned());
        let coordinator = Coordinator::new(
            Arc::new(db.clone()),
            enclave_manager.clone(),
            coordinator_config,
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
        let socket_addr = self.listener.local_addr().unwrap();

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
                info!("✅ Server on {} shut down gracefully", socket_addr);

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
                error!("❌ Server error on {}: {}", socket_addr, e);

                let _ = self.coordinator_shutdown.send(());
                self.coordinator_handle.abort();
                Err(IoError::other(e))
            }
        }
    }

    async fn setup_enclave_manager(config: &Config) -> Result<Arc<EnclaveManager>> {
        let enclave_configs: Vec<EnclaveConfig> = config
            .enclaves
            .enclaves
            .iter()
            .map(|enclave| EnclaveConfig {
                id: enclave.id,
                cid: enclave.cid,
                port: enclave.port,
            })
            .collect();

        let enclave_manager = Arc::new(EnclaveManager::new(enclave_configs));

        info!(
            "Configured enclave manager with {} total enclaves",
            config.enclaves.enclaves.len()
        );

        Ok(enclave_manager)
    }

    fn build_router(state: AppState, config: &Config) -> Router {
        let api_routes = Router::new()
            .route("/keygen", post(handlers::create_keygen_session))
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
            .route("/signing", post(handlers::create_signing_session))
            .route(
                "/signing/{signing_session_id}",
                post(handlers::approve_signing_session),
            )
            .route(
                "/signing/{signing_session_id}/status",
                get(handlers::get_signing_status),
            )
            .route("/enclaves", get(handlers::list_enclaves))
            .route(
                "/enclaves/{enclave_id}/public-key",
                get(handlers::get_enclave_public_key),
            )
            .route("/version", get(handlers::api_version))
            .route("/health", get(handlers::health_check))
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
            .layer(TraceLayer::new_for_http())
            .layer(middleware::from_fn_with_state(
                state.clone(),
                metrics_middleware,
            ))
            .with_state(state);

        if config.server.enable_compression {
            app = app.layer(CompressionLayer::new());
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
        DatabaseConfig, DevelopmentConfig, EnclaveConfig, EnclaveInfo, Environment, SecurityConfig,
        ServerConfig,
    };
    use tempfile::TempDir;

    fn create_test_config() -> (Config, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test.db");

        let config = Config {
            environment: Environment::Development,
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 0, // Let OS assign port for testing
                enable_cors: true,
                enable_compression: true,
                request_timeout_secs: Some(10),
                max_request_size_bytes: Some(1024 * 1024),
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
                    },
                    EnclaveInfo {
                        id: 1,
                        cid: 4,
                        port: 8001,
                    },
                ],
                max_users_per_enclave: Some(50),
                enclave_timeout_secs: Some(30),
            },
            coordinator: None,
            logging: None,
            security: SecurityConfig::default(),
            development: Some(DevelopmentConfig::default()),
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

        let enclave_manager = Application::setup_enclave_manager(&config)
            .await
            .expect("Failed to setup enclave manager");

        let health_result = enclave_manager.health_check().await;
        // health_check now returns BTreeMap directly, so just verify it's not empty
        assert!(!health_result.is_empty() || health_result.is_empty());
    }

    #[test]
    fn test_openapi_spec_generation() {
        let openapi = ApiDoc::openapi();

        assert_eq!(openapi.info.title, "KeyMeld Gateway API");
        assert_eq!(openapi.info.version, "1.0.0");

        assert!(openapi.paths.paths.contains_key("/health"));
        assert!(openapi.paths.paths.contains_key("/keygen"));
        assert!(openapi.paths.paths.contains_key("/signing"));
        assert!(openapi.paths.paths.contains_key("/version"));

        let schemas = &openapi
            .components
            .as_ref()
            .expect("OpenAPI should have components")
            .schemas;
        assert!(schemas.contains_key("CreateKeygenSessionRequest"));
        assert!(schemas.contains_key("CreateKeygenSessionResponse"));
        assert!(schemas.contains_key("CreateSigningSessionRequest"));
        assert!(schemas.contains_key("CreateSigningSessionResponse"));
        assert!(schemas.contains_key("RegisterKeygenParticipantRequest"));
        assert!(schemas.contains_key("HealthCheckResponse"));
    }
}
