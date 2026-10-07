use serde::{Deserialize, Serialize};
use std::sync::Once;
use tracing_subscriber::{
    layer::{Layered, SubscriberExt},
    EnvFilter, Layer, Registry,
};

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
        if let Err(e) = tracing::subscriber::set_global_default(subscriber(config, on_error)) {
            eprintln!("Failed to set global tracing subscriber: {}", e);
        }

        tracing::debug!(
            component = config.component.as_deref().unwrap_or("keymeld"),
            level = config.level,
            "Logging initialized"
        );
    });
}

/// Logs on the calling thread until the guard is dropped. A service uses this
/// while it loads its configuration, then calls `init_logging_with_error_hook`
/// with the configured settings, which take over from there.
pub fn startup_logging(
    config: &LoggingConfig,
    on_error: Option<fn(&str)>,
) -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(subscriber(config, on_error))
}

type BaseSubscriber = Layered<Option<ErrorHook>, Layered<EnvFilter, Registry>>;

/// Directives used when RUST_LOG is unset. Request lines use the `http` target.
fn default_directives(config: &LoggingConfig) -> String {
    let component = config.component.as_deref().unwrap_or("keymeld");
    let level = match config.level.as_str() {
        level @ ("trace" | "debug" | "info" | "warn" | "error") => level,
        _ => "info",
    };
    let tower_http = if level == "trace" { "debug" } else { level };
    format!("{component}={level},http={level},tower_http={tower_http}")
}

fn subscriber(
    config: &LoggingConfig,
    on_error: Option<fn(&str)>,
) -> impl tracing::Subscriber + Send + Sync + 'static {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_directives(config)));

    let include_target = config.include_target.unwrap_or(true);
    let include_thread_ids = config.include_thread_ids.unwrap_or(true);
    let disable_ansi = config.disable_ansi.unwrap_or(false);

    let fmt_layer: Box<dyn Layer<BaseSubscriber> + Send + Sync> =
        if config.enable_json.unwrap_or(false) {
            tracing_subscriber::fmt::layer()
                .json()
                .with_target(include_target)
                .with_thread_ids(include_thread_ids)
                .with_ansi(!disable_ansi)
                .boxed()
        } else {
            match config.format.as_deref() {
                Some("compact") => tracing_subscriber::fmt::layer()
                    .compact()
                    .with_target(include_target)
                    .with_thread_ids(include_thread_ids)
                    .with_ansi(!disable_ansi)
                    .boxed(),
                Some("pretty") => tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_target(include_target)
                    .with_thread_ids(include_thread_ids)
                    .with_ansi(!disable_ansi)
                    .boxed(),
                _ => tracing_subscriber::fmt::layer()
                    .with_target(include_target)
                    .with_thread_ids(include_thread_ids)
                    .with_ansi(!disable_ansi)
                    .boxed(),
            }
        };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(on_error.map(ErrorHook))
        .with(fmt_layer)
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
    fn default_directives_include_request_lines() {
        let mut config = LoggingConfig::gateway_default();
        assert_eq!(
            default_directives(&config),
            "keymeld_gateway=info,http=info,tower_http=info"
        );
        config.level = "trace".to_string();
        assert_eq!(
            default_directives(&config),
            "keymeld_gateway=trace,http=trace,tower_http=debug"
        );
        config.level = "info,keymeld_gateway=debug".to_string();
        assert_eq!(
            default_directives(&config),
            "keymeld_gateway=info,http=info,tower_http=info"
        );
    }

    #[test]
    fn startup_logging_is_scoped_to_its_guard() {
        let guard = startup_logging(&LoggingConfig::gateway_default(), None);
        assert!(tracing::dispatcher::get_default(|dispatch| dispatch
            .downcast_ref::<tracing::subscriber::NoSubscriber>()
            .is_none()));
        drop(guard);
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
