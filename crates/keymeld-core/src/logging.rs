use serde::{Deserialize, Serialize};
use std::sync::Once;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: Option<String>,
    pub enable_json: Option<bool>,
    pub enable_file_output: Option<bool>,
    pub file_path: Option<String>,
    pub component: Option<String>,
    pub disable_ansi: Option<bool>,
    pub include_target: Option<bool>,
    pub include_thread_ids: Option<bool>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: Some("compact".to_string()),
            enable_json: Some(false),
            enable_file_output: Some(false),
            file_path: None,
            component: None,
            disable_ansi: Some(false),
            include_target: Some(true),
            include_thread_ids: Some(true),
        }
    }
}

impl LoggingConfig {
    pub fn gateway_default() -> Self {
        Self {
            level: "info".to_string(),
            format: Some("compact".to_string()),
            enable_json: Some(false),
            enable_file_output: Some(false),
            file_path: None,
            component: Some("keymeld_gateway".to_string()),
            disable_ansi: Some(false),
            include_target: Some(true),
            include_thread_ids: Some(true),
        }
    }

    pub fn enclave_default() -> Self {
        Self {
            level: "info".to_string(),
            format: Some("compact".to_string()),
            enable_json: Some(false),
            enable_file_output: Some(false),
            file_path: None,
            component: Some("keymeld_enclave".to_string()),
            disable_ansi: Some(true), // VSock doesn't support ANSI colors
            include_target: Some(true),
            include_thread_ids: Some(true),
        }
    }
}

pub fn init_logging(config: &LoggingConfig) {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let component = config.component.as_deref().unwrap_or("keymeld");

        // Create environment filter with fallback
        let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let default_filter = match config.level.as_str() {
                "trace" => format!("{}=trace,tower_http=debug", component),
                "debug" => format!("{}=debug,tower_http=debug", component),
                "info" => format!("{}=info,tower_http=info", component),
                "warn" => format!("{}=warn,tower_http=warn", component),
                "error" => format!("{}=error,tower_http=error", component),
                _ => format!("{}=info,tower_http=info", component),
            };
            default_filter.into()
        });

        // Use a macro to handle different subscriber types
        macro_rules! init_subscriber {
            ($layer:expr) => {{
                let subscriber = tracing_subscriber::registry()
                    .with(env_filter.clone())
                    .with($layer);
                if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
                    eprintln!("Failed to set global tracing subscriber: {}", e);
                }
            }};
        }

        // Create the appropriate layer based on configuration
        let include_target = config.include_target.unwrap_or(true);
        let include_thread_ids = config.include_thread_ids.unwrap_or(true);
        let disable_ansi = config.disable_ansi.unwrap_or(false);

        if config.enable_json.unwrap_or(false) {
            init_subscriber!(tracing_subscriber::fmt::layer()
                .json()
                .with_target(include_target)
                .with_thread_ids(include_thread_ids)
                .with_ansi(!disable_ansi));
        } else {
            match config.format.as_deref() {
                Some("compact") => {
                    init_subscriber!(tracing_subscriber::fmt::layer()
                        .compact()
                        .with_target(include_target)
                        .with_thread_ids(include_thread_ids)
                        .with_ansi(!disable_ansi));
                }
                Some("pretty") => {
                    init_subscriber!(tracing_subscriber::fmt::layer()
                        .pretty()
                        .with_target(include_target)
                        .with_thread_ids(include_thread_ids)
                        .with_ansi(!disable_ansi));
                }
                _ => {
                    init_subscriber!(tracing_subscriber::fmt::layer()
                        .with_target(include_target)
                        .with_thread_ids(include_thread_ids)
                        .with_ansi(!disable_ansi));
                }
            }
        }

        tracing::info!(
            component = component,
            level = config.level,
            format = config.format.as_deref().unwrap_or("default"),
            json = config.enable_json.unwrap_or(false),
            ansi_disabled = config.disable_ansi.unwrap_or(false),
            "Logging initialized"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, "info");
        assert_eq!(config.format.as_deref(), Some("compact"));
        assert_eq!(config.enable_json, Some(false));
        assert_eq!(config.disable_ansi, Some(false));
    }

    #[test]
    fn test_gateway_config() {
        let config = LoggingConfig::gateway_default();
        assert_eq!(config.level, "info");
        assert_eq!(config.component.as_deref(), Some("keymeld_gateway"));
        assert_eq!(config.disable_ansi, Some(false));
    }

    #[test]
    fn test_enclave_config() {
        let config = LoggingConfig::enclave_default();
        assert_eq!(config.level, "info");
        assert_eq!(config.component.as_deref(), Some("keymeld_enclave"));
        assert_eq!(config.disable_ansi, Some(true)); // VSock compatibility
        assert_eq!(config.format.as_deref(), Some("compact"));
    }

    #[test]
    fn test_logging_initialization() {
        let config = LoggingConfig::default();
        init_logging(&config);
        // Should not panic on multiple calls
        init_logging(&config);
    }

    #[test]
    fn test_unified_logging_behavior() {
        // Test that both gateway and enclave configs work with same function
        let gateway_config = LoggingConfig::gateway_default();
        let enclave_config = LoggingConfig::enclave_default();

        // Both should initialize without issues
        init_logging(&gateway_config);
        init_logging(&enclave_config); // Should be ignored due to Once

        // Verify key differences
        assert_eq!(gateway_config.component.as_deref(), Some("keymeld_gateway"));
        assert_eq!(enclave_config.component.as_deref(), Some("keymeld_enclave"));
        assert_eq!(gateway_config.disable_ansi, Some(false));
        assert_eq!(enclave_config.disable_ansi, Some(true));
        assert_eq!(gateway_config.format.as_deref(), Some("compact"));
        assert_eq!(enclave_config.format.as_deref(), Some("compact"));
    }

    #[test]
    fn test_json_logging_config() {
        let mut config = LoggingConfig {
            enable_json: Some(true),
            ..Default::default()
        };
        config.level = "debug".to_string();

        // Should not panic with JSON configuration
        init_logging(&config);

        assert_eq!(config.enable_json, Some(true));
        assert_eq!(config.level, "debug");
    }
}
