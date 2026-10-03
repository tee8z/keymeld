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
            disable_ansi: Some(true),
            include_target: Some(true),
            include_thread_ids: Some(true),
        }
    }
}

/// Calls a hook with the target of every ERROR event that passes the filter,
/// so a service can count error lines without parsing its own logs.
struct ErrorHook(fn(&str));

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ErrorHook {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if *event.metadata().level() == tracing::Level::ERROR {
            (self.0)(event.metadata().target());
        }
    }
}

pub fn init_logging(config: &LoggingConfig) {
    init_logging_with_error_hook(config, None);
}

/// Like `init_logging`, but also reports each logged ERROR event's target to `on_error`.
pub fn init_logging_with_error_hook(config: &LoggingConfig, on_error: Option<fn(&str)>) {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let component = config.component.as_deref().unwrap_or("keymeld");

        let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            let default_filter = match config.level.as_str() {
                "trace" => format!("{component}=trace,tower_http=debug"),
                "debug" => format!("{component}=debug,tower_http=debug"),
                "info" => format!("{component}=info,tower_http=info"),
                "warn" => format!("{component}=warn,tower_http=warn"),
                "error" => format!("{component}=error,tower_http=error"),
                _ => format!("{component}=info,tower_http=info"),
            };
            default_filter.into()
        });

        macro_rules! init_subscriber {
            ($layer:expr) => {{
                let subscriber = tracing_subscriber::registry()
                    .with(env_filter.clone())
                    .with(on_error.map(ErrorHook))
                    .with($layer);
                if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
                    eprintln!("Failed to set global tracing subscriber: {}", e);
                }
            }};
        }

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

        tracing::debug!(
            component = component,
            level = config.level,
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
        assert_eq!(config.disable_ansi, Some(true));
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
    fn test_error_hook_sees_only_error_events() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ERRORS: AtomicUsize = AtomicUsize::new(0);
        fn hook(target: &str) {
            assert_eq!(target, "keymeld_core::logging::tests");
            ERRORS.fetch_add(1, Ordering::SeqCst);
        }

        let subscriber = tracing_subscriber::registry().with(ErrorHook(hook));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!("not counted");
            tracing::error!("counted");
            tracing::error!("counted");
        });
        assert_eq!(ERRORS.load(Ordering::SeqCst), 2);
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
