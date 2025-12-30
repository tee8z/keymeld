use anyhow::Result;
use clap::{Parser, Subcommand};

mod keymeld_adaptor;
mod keymeld_plain;

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
    Plain {
        /// Configuration file path
        #[arg(long)]
        config: String,
        /// Amount in satoshis
        #[arg(long)]
        amount: u64,
        /// Destination Bitcoin address (optional, will generate from coordinator wallet if not provided)
        #[arg(long)]
        destination: Option<String>,
    },
    Adaptor {
        /// Configuration file path
        #[arg(long)]
        config: String,
        /// Amount in satoshis
        #[arg(long)]
        amount: u64,
        /// Destination Bitcoin address (optional, will generate from coordinator wallet if not provided)
        #[arg(long)]
        destination: Option<String>,
        /// Run only single adaptor signature test
        #[arg(long)]
        single_only: bool,
        /// Run only 'And' adaptor signature test
        #[arg(long)]
        and_only: bool,
        /// Run only 'Or' adaptor signature test
        #[arg(long)]
        or_only: bool,
        /// Skip regular signing, only test adaptors
        #[arg(long)]
        skip_regular_signing: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Plain {
            config,
            amount,
            destination,
        } => keymeld_plain::run_with_args(config, amount, destination).await,
        Commands::Adaptor {
            config,
            amount,
            destination,
            single_only,
            and_only,
            or_only,
            skip_regular_signing,
        } => {
            keymeld_adaptor::run_with_args(
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
    }
}
