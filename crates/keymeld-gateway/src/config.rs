use std::time::Duration;

use anyhow::{Context, Result};
use keymeld_core::managed_socket::config::{RetryConfig, TimeoutConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Environment {
    #[default]
    Development,
    Production,
}

impl Environment {
    pub fn from_env() -> Self {
        match std::env::var("KEYMELD_ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "production" | "prod" => Environment::Production,
            _ => Environment::Development,
        }
    }

    pub fn is_production(&self) -> bool {
        matches!(self, Environment::Production)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub environment: Environment,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub kms: KmsConfig,
    pub enclaves: EnclaveConfig,
    pub coordinator: CoordinatorConfig,
    pub logging: LoggingConfig,
    pub security: SecurityConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub development: Option<DevelopmentConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub enable_cors: bool,
    pub enable_compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    pub max_connections: u32,
    pub connection_timeout_secs: u64,
    pub idle_timeout_secs: Option<u64>,
    pub enable_wal_mode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KmsConfig {
    pub enabled: bool,
    pub endpoint_url: Option<String>,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayLimits {
    /// Default maximum number of signing sessions per keygen session
    pub default_max_signing_sessions: u32,
    /// Maximum request body size in bytes
    pub max_request_size_bytes: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            default_max_signing_sessions: 100,
            max_request_size_bytes: 1024 * 1024, // 1MB
            request_timeout_secs: 120,           // 2 minutes for crypto operations
        }
    }
}

impl GatewayLimits {
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.request_timeout_secs)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.default_max_signing_sessions == 0 {
            return Err("Default max signing sessions must be greater than 0".to_string());
        }
        if self.max_request_size_bytes == 0 {
            return Err("Max request size must be greater than 0".to_string());
        }
        if self.request_timeout_secs == 0 {
            return Err("Request timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

impl KmsConfig {
    pub fn is_local_kms(&self) -> bool {
        self.endpoint_url
            .as_ref()
            .map(|url| url.contains("localhost") || url.contains("127.0.0.1"))
            .unwrap_or(false)
    }

    pub fn validate(&self) -> Result<()> {
        if self.enabled && self.key_id.is_empty() {
            anyhow::bail!("KMS key_id is required when KMS is enabled");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    pub enclaves: Vec<EnclaveInfo>,
    pub vsock_timeout_secs: Option<u64>,
    pub nonce_generation_timeout_secs: Option<u64>,
    pub session_init_timeout_secs: Option<u64>,
    pub signing_timeout_secs: Option<u64>,
    pub network_write_timeout_secs: Option<u64>,
    pub network_read_timeout_secs: Option<u64>,
    pub pool_acquire_timeout_secs: Option<u64>,
    pub max_message_size_bytes: Option<usize>,
    pub max_retry_attempts: Option<u32>,
    pub initial_retry_delay_ms: Option<u64>,
    pub max_retry_delay_ms: Option<u64>,
    pub retry_backoff_multiplier: Option<f64>,
    pub connection_retry_delay_ms: Option<u64>,
    pub max_channel_size: Option<usize>,
    /// Maximum concurrent requests per VSock connection before creating a new one.
    /// See config/development.yaml for detailed tuning guidance.
    pub connection_load_threshold: Option<u32>,
}

impl From<&EnclaveConfig> for TimeoutConfig {
    fn from(config: &EnclaveConfig) -> Self {
        let defaults = TimeoutConfig::default();
        TimeoutConfig {
            vsock_timeout_secs: config
                .vsock_timeout_secs
                .unwrap_or(defaults.vsock_timeout_secs),
            nonce_generation_timeout_secs: config
                .nonce_generation_timeout_secs
                .unwrap_or(defaults.nonce_generation_timeout_secs),
            session_init_timeout_secs: config
                .session_init_timeout_secs
                .unwrap_or(defaults.session_init_timeout_secs),
            signing_timeout_secs: config
                .signing_timeout_secs
                .unwrap_or(defaults.signing_timeout_secs),
            network_write_timeout_secs: config
                .network_write_timeout_secs
                .unwrap_or(defaults.network_write_timeout_secs),
            network_read_timeout_secs: config
                .network_read_timeout_secs
                .unwrap_or(defaults.network_read_timeout_secs),
            pool_acquire_timeout_secs: config
                .pool_acquire_timeout_secs
                .unwrap_or(defaults.pool_acquire_timeout_secs),
            connection_retry_delay_ms: config
                .connection_retry_delay_ms
                .unwrap_or(defaults.connection_retry_delay_ms),
            max_message_size_bytes: config
                .max_message_size_bytes
                .unwrap_or(defaults.max_message_size_bytes),
            max_channel_size: config.max_channel_size.unwrap_or(defaults.max_channel_size),
            connection_load_threshold: config
                .connection_load_threshold
                .unwrap_or(defaults.connection_load_threshold),
        }
    }
}

impl From<&EnclaveConfig> for RetryConfig {
    fn from(config: &EnclaveConfig) -> Self {
        let defaults = RetryConfig::default();
        RetryConfig {
            max_attempts: config.max_retry_attempts.unwrap_or(defaults.max_attempts),
            initial_delay_ms: config
                .initial_retry_delay_ms
                .unwrap_or(defaults.initial_delay_ms),
            max_delay_ms: config.max_retry_delay_ms.unwrap_or(defaults.max_delay_ms),
            backoff_multiplier: config
                .retry_backoff_multiplier
                .unwrap_or(defaults.backoff_multiplier),
        }
    }
}

/// Transport mode for enclave connections
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    /// Direct vsock connection (AWS Nitro Enclaves)
    #[default]
    Vsock,
    /// TCP connection via vsock-proxy/socat bridge (K8s simulation)
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveInfo {
    pub id: u32,
    /// CID for vsock mode (ignored in TCP mode)
    pub cid: u32,
    /// Port for both vsock and TCP modes
    pub port: u32,
    /// Transport mode (vsock or tcp), defaults to vsock
    #[serde(default)]
    pub transport: TransportMode,
    /// TCP host for TCP mode (e.g., K8s service name like "keymeld-enclave-0")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    pub processing_interval_ms: Option<u64>,
    pub cleanup_interval_secs: Option<u64>,
    pub batch_size: Option<u32>,
    pub max_retries: Option<u32>,
    pub processing_timeout_mins: Option<u64>,
    pub delete_sessions_older_than_secs: Option<u64>,
    pub metric_record_interval_secs: Option<u64>,
    // New fields for improved monitoring and processing
    pub max_concurrent_sessions: Option<u32>,
    pub db_operation_timeout_secs: Option<u64>,
    pub health_check_interval_secs: Option<u64>,
    pub circuit_breaker_failure_threshold: Option<u32>,
    pub circuit_breaker_reset_timeout_secs: Option<u64>,
    pub individual_session_timeout_secs: Option<u64>,
    pub stuck_session_detection_threshold_secs: Option<u64>,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            processing_interval_ms: Some(100), // Fast processing with proper message size limits
            cleanup_interval_secs: Some(300),
            batch_size: Some(20), // Moderate batches - message size was the real issue
            max_retries: Some(3),
            processing_timeout_mins: Some(5),
            // 86400 = 24 * 60 * 60; 24 hours
            delete_sessions_older_than_secs: Some(86400),
            metric_record_interval_secs: Some(30),
            // New defaults for improved monitoring and processing
            max_concurrent_sessions: Some(20),
            db_operation_timeout_secs: Some(15),
            health_check_interval_secs: Some(10),
            circuit_breaker_failure_threshold: Some(10),
            circuit_breaker_reset_timeout_secs: Some(60),
            individual_session_timeout_secs: Some(60),
            stuck_session_detection_threshold_secs: Some(300),
        }
    }
}

pub use keymeld_core::logging::LoggingConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_attestation: bool,
    pub strict_validation: bool,
    pub allow_insecure_connections: bool,
    pub require_tls: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_attestation: true,
            strict_validation: true,
            allow_insecure_connections: false,
            require_tls: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevelopmentConfig {
    pub enable_test_endpoints: bool,
    pub disable_enclave_verification: bool,
    pub extended_logging: bool,
}

impl Config {
    pub async fn load(config_path: &str) -> Result<Self> {
        let config_str = tokio::fs::read_to_string(config_path)
            .await
            .with_context(|| format!("Failed to read config file: {config_path}"))?;

        let config = if config_path.ends_with(".toml") {
            toml::from_str(&config_str)
                .with_context(|| format!("Failed to parse TOML config: {config_path}"))?
        } else if config_path.ends_with(".yaml") || config_path.ends_with(".yml") {
            serde_yaml::from_str(&config_str)
                .with_context(|| format!("Failed to parse YAML config: {config_path}"))?
        } else if config_path.ends_with(".json") {
            serde_json::from_str(&config_str)
                .with_context(|| format!("Failed to parse JSON config: {config_path}"))?
        } else {
            toml::from_str(&config_str)
                .with_context(|| format!("Failed to parse config as TOML: {config_path}"))?
        };

        Ok(config)
    }

    pub async fn load_with_env_override(config_path: Option<&str>) -> Result<Self> {
        let environment = Environment::from_env();

        let mut config = match config_path {
            Some(path) => Self::load(path).await?,
            None => match Self::find_environment_config(environment).await {
                Ok(config) => config,
                Err(_) => Self::default_for_environment(environment),
            },
        };

        config.environment = environment;
        config.override_from_env();
        config.validate()?;

        Ok(config)
    }

    async fn find_environment_config(environment: Environment) -> Result<Self> {
        let env_name = match environment {
            Environment::Development => "development",
            Environment::Production => "production",
        };

        let possible_paths = vec![
            format!("config/{}.yaml", env_name),
            format!("config/{}.yml", env_name),
            format!("config/keymeld-{}.yaml", env_name),
            format!("config/keymeld-{}.yml", env_name),
            format!("./{}.yaml", env_name),
            format!("./{}.yml", env_name),
            format!("./config.{}.yaml", env_name),
            format!("./config.{}.yml", env_name),
        ];

        for path in possible_paths {
            if tokio::fs::metadata(&path).await.is_ok() {
                return Self::load(&path)
                    .await
                    .with_context(|| format!("Found config file {path} but failed to load it"));
            }
        }

        anyhow::bail!("No environment-specific config file found for environment: {environment:?}")
    }

    pub fn default_for_environment(env: Environment) -> Self {
        let mut config = Self {
            environment: env,
            ..Default::default()
        };

        match env {
            Environment::Development => {
                config.security.enable_attestation = false;
                config.security.strict_validation = false;
                config.security.allow_insecure_connections = true;
                config.security.require_tls = false;
                config.development = Some(DevelopmentConfig {
                    enable_test_endpoints: true,
                    disable_enclave_verification: true,
                    extended_logging: true,
                });
                config.database.path = "./data/keymeld-dev.db".to_string();
                config.server.port = 8080;
            }
            Environment::Production => {
                config.security.enable_attestation = true;
                config.security.strict_validation = true;
                config.security.allow_insecure_connections = false;
                config.security.require_tls = true;
                config.development = None;

                config.database.path = "/var/lib/keymeld/keymeld.db".to_string();
                config.server.host = "0.0.0.0".to_string();
                config.server.port = 443;
                config.server.enable_cors = false;
                config.database.max_connections = 50;
            }
        }

        config
    }

    pub fn override_from_env(&mut self) {
        if let Ok(host) = std::env::var("KEYMELD_HOST") {
            self.server.host = host;
        }
        if let Ok(port) = std::env::var("KEYMELD_PORT") {
            if let Ok(port) = port.parse() {
                self.server.port = port;
            }
        }
        if let Ok(cors) = std::env::var("KEYMELD_ENABLE_CORS") {
            self.server.enable_cors = cors.parse().unwrap_or(true);
        }

        if let Ok(db_path) = std::env::var("KEYMELD_DATABASE_PATH") {
            self.database.path = db_path;
        }
        if let Ok(max_conn) = std::env::var("KEYMELD_MAX_CONNECTIONS") {
            if let Ok(max_conn) = max_conn.parse() {
                self.database.max_connections = max_conn;
            }
        }

        if let Ok(log_level) = std::env::var("RUST_LOG") {
            self.logging.level = log_level;
        }

        // Dynamic enclave configuration from environment
        // In AWS Nitro Enclaves, CIDs are assigned dynamically by AWS
        // Use environment variables to override static configuration:
        // KEYMELD_ENCLAVE_0_CID, KEYMELD_ENCLAVE_1_CID, etc.
        // For K8s/simulation mode, use:
        // KEYMELD_ENCLAVE_0_TRANSPORT=tcp
        // KEYMELD_ENCLAVE_0_TCP_HOST=keymeld-enclave-0
        for enclave in &mut self.enclaves.enclaves {
            let env_var_name = format!("KEYMELD_ENCLAVE_{}_CID", enclave.id);
            if let Ok(cid_str) = std::env::var(&env_var_name) {
                if let Ok(cid) = cid_str.parse::<u32>() {
                    enclave.cid = cid;
                }
            }

            // Port override
            let port_env_var_name = format!("KEYMELD_ENCLAVE_{}_PORT", enclave.id);
            if let Ok(port_str) = std::env::var(&port_env_var_name) {
                if let Ok(port) = port_str.parse::<u32>() {
                    enclave.port = port;
                }
            }

            // Transport mode override (vsock or tcp)
            let transport_env_var_name = format!("KEYMELD_ENCLAVE_{}_TRANSPORT", enclave.id);
            if let Ok(transport_str) = std::env::var(&transport_env_var_name) {
                match transport_str.to_lowercase().as_str() {
                    "tcp" => enclave.transport = TransportMode::Tcp,
                    "vsock" => enclave.transport = TransportMode::Vsock,
                    _ => {} // Ignore invalid values
                }
            }

            // TCP host override (for TCP mode, e.g., K8s service name)
            let tcp_host_env_var_name = format!("KEYMELD_ENCLAVE_{}_TCP_HOST", enclave.id);
            if let Ok(tcp_host) = std::env::var(&tcp_host_env_var_name) {
                enclave.tcp_host = Some(tcp_host);
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.server.port == 0 {
            anyhow::bail!("Server port cannot be 0");
        }

        if self.database.path.is_empty() {
            anyhow::bail!("Database path cannot be empty");
        }

        if self.enclaves.enclaves.is_empty() {
            anyhow::bail!("Must have at least one user enclave");
        }

        // Validate KMS configuration
        self.kms.validate()?;

        match self.environment {
            Environment::Production => {
                if !self.security.enable_attestation {
                    anyhow::bail!("Attestation must be enabled in production");
                }
                if !self.security.strict_validation {
                    anyhow::bail!("Strict validation must be enabled in production");
                }
                if self.security.allow_insecure_connections {
                    anyhow::bail!("Insecure connections are not allowed in production");
                }
                if self.development.is_some() {
                    anyhow::bail!("Development configuration is not allowed in production");
                }
                if self.server.port == 8080 || self.server.port == 3000 {
                    anyhow::bail!("Default development ports are not allowed in production");
                }
            }
            Environment::Development => {
                // No special validation needed for development
            }
        }

        // Validate enclave CIDs - allow duplicates in development mode for local VSock simulation
        match self.environment {
            Environment::Production => {
                let mut cids: Vec<u32> = self.enclaves.enclaves.iter().map(|e| e.cid).collect();
                cids.sort();
                let original_len = cids.len();
                cids.dedup();
                if cids.len() != original_len {
                    anyhow::bail!("Duplicate enclave CIDs detected in production environment");
                }
            }
            Environment::Development => {
                // In development mode, allow duplicate CIDs for local VSock simulation
                // where all enclaves run on the same host and share the host CID (2)
                // This is necessary because in local simulation, we can't assign arbitrary
                // guest VM CIDs like in real AWS Nitro Enclave environments
            }
        }

        self.validate_security_configuration()?;

        Ok(())
    }

    fn validate_security_configuration(&self) -> Result<()> {
        if self.security.require_tls && self.security.allow_insecure_connections {
            anyhow::bail!(
                "Configuration conflict: TLS is required but insecure connections are allowed"
            );
        }

        if self.environment.is_production() && !self.security.enable_attestation {
            anyhow::bail!("Attestation is required in production environment for security");
        }

        Ok(())
    }

    pub fn is_safe_for_environment(&self) -> bool {
        match self.environment {
            Environment::Production => {
                self.security.enable_attestation
                    && self.security.strict_validation
                    && !self.security.allow_insecure_connections
                    && self.security.require_tls
                    && self.development.is_none()
            }
            Environment::Development => true, // Development is always considered "safe" for its purpose
        }
    }

    pub fn security_summary(&self) -> SecuritySummary {
        SecuritySummary {
            environment: self.environment,
            attestation_enabled: self.security.enable_attestation,
            strict_validation: self.security.strict_validation,
            tls_required: self.security.require_tls,
            insecure_connections_allowed: self.security.allow_insecure_connections,
            development_features_enabled: self.development.is_some(),
            mock_services_enabled: false,
        }
    }

    pub fn validate_production_readiness(&self) -> Result<()> {
        if !matches!(self.environment, Environment::Production) {
            anyhow::bail!("Configuration is not set for production environment");
        }

        if !self.is_safe_for_environment() {
            anyhow::bail!("Configuration does not meet production security requirements");
        }

        if self.database.path.starts_with("./") || self.database.path.starts_with("../") {
            anyhow::bail!("Production database path should be absolute, not relative");
        }

        if self.server.port == 8080 || self.server.port == 3000 {
            anyhow::bail!("Production should not use default development ports");
        }

        if self.server.enable_cors {
            eprintln!("WARNING: CORS is enabled in production. This may not be intended.");
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SecuritySummary {
    pub environment: Environment,
    pub attestation_enabled: bool,
    pub strict_validation: bool,
    pub tls_required: bool,
    pub insecure_connections_allowed: bool,
    pub development_features_enabled: bool,
    pub mock_services_enabled: bool,
}

impl std::fmt::Display for SecuritySummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Environment: {:?}, Attestation: {}, Strict: {}, TLS: {}, Insecure: {}, DevFeatures: {}, MockServices: {}",
            self.environment,
            self.attestation_enabled,
            self.strict_validation,
            self.tls_required,
            self.insecure_connections_allowed,
            self.development_features_enabled,
            self.mock_services_enabled
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            kms: KmsConfig::default(),
            enclaves: EnclaveConfig::default(),
            coordinator: CoordinatorConfig::default(),
            logging: LoggingConfig::gateway_default(),
            security: SecurityConfig::default(),
            development: Some(DevelopmentConfig::default()),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            enable_cors: true,
            enable_compression: true,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "./data/keymeld.db".to_string(),
            max_connections: 50, // Increased for better concurrency handling
            connection_timeout_secs: 30,
            idle_timeout_secs: Some(300), // 5 minutes
            enable_wal_mode: Some(true),
        }
    }
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
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
                    port: 8000,
                    transport: TransportMode::default(),
                    tcp_host: None,
                },
                EnclaveInfo {
                    id: 2,
                    cid: 5,
                    port: 8000,
                    transport: TransportMode::default(),
                    tcp_host: None,
                },
            ],

            vsock_timeout_secs: Some(30),
            nonce_generation_timeout_secs: Some(10),
            session_init_timeout_secs: Some(15),
            signing_timeout_secs: Some(20),
            network_write_timeout_secs: Some(5),
            network_read_timeout_secs: Some(300),
            pool_acquire_timeout_secs: Some(30),
            max_message_size_bytes: Some(1024 * 1024),
            max_retry_attempts: Some(3),
            initial_retry_delay_ms: Some(100),
            max_retry_delay_ms: Some(5000),
            retry_backoff_multiplier: Some(2.0),
            connection_retry_delay_ms: Some(100),
            max_channel_size: Some(1000),
            connection_load_threshold: Some(50),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_load_toml_config() {
        let config_content = r#"
environment = "development"

[server]
host = "127.0.0.1"
port = 9090
enable_cors = true
enable_compression = true

[database]
path = "./test.db"
max_connections = 5
connection_timeout_secs = 60

[kms]
enabled = true
key_id = "test-key-id"

[enclaves]
kms_key_arn = "arn:aws:kms:us-west-2:123456789012:key/test-key-id"

[[enclaves.enclaves]]
id = 0
cid = 10
port = 5000

[[enclaves.enclaves]]
id = 1
cid = 11
port = 5001

[[enclaves.enclaves]]
id = 2
cid = 12
port = 5002

[coordinator]
processing_interval_ms = 1000
cleanup_interval_secs = 3600
batch_size = 10

[logging]
level = "info"
format = "compact"
enable_json = false
component = "keymeld_gateway"

[security]
enable_attestation = false
strict_validation = false
allow_insecure_connections = true
max_session_duration_secs = 3600
require_tls = false
"#;

        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        write!(temp_file, "{config_content}").expect("Failed to write to temp file");
        let config_path = temp_file
            .path()
            .to_str()
            .expect("Failed to get temp file path");

        let config = Config::load(config_path)
            .await
            .expect("Failed to load config");

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
        assert!(config.server.enable_cors);
        assert_eq!(config.database.path, "./test.db");
        assert_eq!(config.database.max_connections, 5);
        assert_eq!(config.enclaves.enclaves.len(), 3);
        assert_eq!(config.enclaves.enclaves[0].cid, 10);
        assert_eq!(config.enclaves.enclaves[0].port, 5000);
        assert_eq!(config.enclaves.enclaves[1].cid, 11);
        assert_eq!(config.enclaves.enclaves[1].port, 5001);
        assert_eq!(config.enclaves.enclaves[2].cid, 12);
        assert_eq!(config.enclaves.enclaves[2].port, 5002);
    }

    #[tokio::test]
    async fn test_config_validation() {
        let mut config = Config::default();

        assert!(config.validate().is_ok());

        config.server.port = 0;
        assert!(config.validate().is_err());
        config.server.port = 8080;

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_env_override() {
        std::env::set_var("KEYMELD_HOST", "192.168.1.100");
        std::env::set_var("KEYMELD_PORT", "3000");
        std::env::set_var("KEYMELD_DATABASE_PATH", "/custom/db.sqlite");

        let mut config = Config::default();
        config.override_from_env();

        assert_eq!(config.server.host, "192.168.1.100");
        assert_eq!(config.server.port, 3000);
        assert_eq!(config.database.path, "/custom/db.sqlite");

        std::env::remove_var("KEYMELD_HOST");
        std::env::remove_var("KEYMELD_PORT");
        std::env::remove_var("KEYMELD_DATABASE_PATH");
    }

    #[test]
    fn test_dynamic_enclave_cid_override() {
        // Set environment variables for dynamic CID assignment
        std::env::set_var("KEYMELD_ENCLAVE_0_CID", "16");
        std::env::set_var("KEYMELD_ENCLAVE_1_CID", "17");
        std::env::set_var("KEYMELD_ENCLAVE_2_CID", "18");
        std::env::set_var("KEYMELD_ENCLAVE_1_PORT", "9000");

        let mut config = Config::default();
        // Verify default values first
        assert_eq!(config.enclaves.enclaves[0].cid, 3);
        assert_eq!(config.enclaves.enclaves[1].cid, 4);
        assert_eq!(config.enclaves.enclaves[2].cid, 5);
        assert_eq!(config.enclaves.enclaves[1].port, 8000);

        // Apply environment overrides
        config.override_from_env();

        // Verify CIDs were overridden
        assert_eq!(config.enclaves.enclaves[0].cid, 16);
        assert_eq!(config.enclaves.enclaves[1].cid, 17);
        assert_eq!(config.enclaves.enclaves[2].cid, 18);

        // Verify port was overridden for enclave 1
        assert_eq!(config.enclaves.enclaves[1].port, 9000);

        // Verify other ports unchanged
        assert_eq!(config.enclaves.enclaves[0].port, 8000);
        assert_eq!(config.enclaves.enclaves[2].port, 8000);

        // Cleanup
        std::env::remove_var("KEYMELD_ENCLAVE_0_CID");
        std::env::remove_var("KEYMELD_ENCLAVE_1_CID");
        std::env::remove_var("KEYMELD_ENCLAVE_2_CID");
        std::env::remove_var("KEYMELD_ENCLAVE_1_PORT");
    }
}
