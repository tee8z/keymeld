use anyhow::{Context, Result};
use keymeld_core::logging::{init_logging, LoggingConfig};
use keymeld_gateway::{config::Config, startup::Application};
use std::env;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging(&LoggingConfig::gateway_default());

    info!(
        "Starting KeyMeld Gateway Service v{}",
        env!("CARGO_PKG_VERSION")
    );

    let config_path = env::var("CONFIG_PATH").ok();
    let config = Config::load_with_env_override(config_path.as_deref())
        .await
        .with_context(|| match config_path {
            Some(ref path) => format!("Failed to load config from: {path}"),
            None => "Failed to load default config".to_string(),
        })?;

    init_logging(&config.logging);

    let security_summary = config.security_summary();
    info!("Configuration loaded: {}", security_summary);

    if config.environment.is_production() {
        config
            .validate_production_readiness()
            .context("Configuration failed production readiness validation")?;
        debug!("Production readiness validation passed");
    } else if !config.is_safe_for_environment() {
        warn!(
            "Configuration may not be safe for current environment: {:?}",
            config.environment
        );
    }

    let application = Application::build(config)
        .await
        .context("Failed to build application")?;

    application
        .run_until_stopped()
        .await
        .context("Application failed during runtime")?;

    info!("KeyMeld Gateway Service shutdown complete");
    Ok(())
}
