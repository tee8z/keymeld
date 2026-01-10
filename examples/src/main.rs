use anyhow::Result;
use clap::{Parser, Subcommand};

mod adaptor;
mod dlctix;
mod plain;
mod single_signer;
mod stored_key;

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[derive(Parser)]
#[command(name = "keymeld_demo")]
#[command(version = "0.1.0")]
#[command(about = "KeyMeld Demo Application")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Basic MuSig2 keygen and signing
    Plain {
        #[arg(long)]
        config: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        destination: Option<String>,
    },
    /// Adaptor signatures
    Adaptor {
        #[arg(long)]
        config: String,
        #[arg(long)]
        amount: u64,
        #[arg(long)]
        destination: Option<String>,
        #[arg(long)]
        single_only: bool,
        #[arg(long)]
        and_only: bool,
        #[arg(long)]
        or_only: bool,
        #[arg(long)]
        skip_regular_signing: bool,
    },
    /// Single-signer key import and signing
    SingleSigner {
        #[arg(long)]
        config: String,
    },
    /// Stored key restore after restart
    StoredKey {
        #[arg(long)]
        config: String,
    },
    /// DLC batch signing with dlctix
    Dlctix {
        #[arg(long)]
        config: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Plain {
            config,
            amount,
            destination,
        } => plain::run_with_args(config, amount, destination).await,

        Commands::Adaptor {
            config,
            amount,
            destination,
            single_only,
            and_only,
            or_only,
            skip_regular_signing,
        } => {
            adaptor::run_with_args(
                config,
                amount,
                destination,
                single_only,
                and_only,
                or_only,
                skip_regular_signing,
            )
            .await
        }

        Commands::SingleSigner { config } => single_signer::run_with_args(config).await,

        Commands::StoredKey { config } => stored_key::run_with_args(config).await,

        Commands::Dlctix { config } => dlctix::run_with_args(config).await,
    }
}
