use anyhow::{Context, Result};
use config::Config;
use startup::Application;
use std::env;
use tracing::{info, warn};
use tracing_subscriber::{fmt::layer, layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod coordinator;
mod database;
mod errors;
mod handlers;
mod metrics;
mod middleware;
mod startup;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keymeld_gateway=debug,tower_http=debug".into()),
        )
        .with(layer())
        .init();

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

    let security_summary = config.security_summary();
    info!("Configuration loaded: {}", security_summary);

    if config.environment.is_production() {
        config
            .validate_production_readiness()
            .context("Configuration failed production readiness validation")?;
        tracing::debug!("Production readiness validation passed");
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
