use clap::{Parser, Subcommand};
use colored::Colorize;

mod commands;
mod identity_store;

/// Cipher CLI — Send & receive E2EE messages from the terminal
///
/// Uses the same encryption, identity, and transport layers as the
/// Cipher mobile app. All messages are AES-256-GCM encrypted end-to-end.
/// Powered by the TKS blockchain for identity, usernames, and tokenomics.
#[derive(Parser)]
#[command(name = "cipher-cli")]
#[command(version = "0.1.0")]
#[command(about = "⚔️  Cipher CLI — Encrypted messaging from the terminal", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Identity ──────────────────────────────────────────

    /// Generate a new identity (BIP-39 seed phrase → all keypairs)
    Init {
        /// Use 24-word seed phrase instead of 12
        #[arg(long, default_value_t = false)]
        words24: bool,
    },

    /// Restore identity from an existing seed phrase
    Restore {
        /// The BIP-39 seed phrase (12 or 24 words, quoted)
        #[arg(required = true)]
        seed_phrase: Vec<String>,
    },

    /// Display your identity (addresses, public keys)
    Whoami,

    /// Export your seed phrase (use with caution!)
    Export,

    // ── Messaging ─────────────────────────────────────────

    /// Send an encrypted message to a recipient
    Send {
        /// Recipient's EVM address (0x...) or @username
        #[arg(required = true)]
        recipient: String,

        /// The message to send
        #[arg(required = true)]
        message: Vec<String>,
    },

    /// Send an encrypted file (image, video, document, etc.)
    SendFile {
        /// Recipient's EVM address (0x...) or @username
        #[arg(required = true)]
        recipient: String,

        /// Path to the file to send
        #[arg(required = true)]
        file: String,
    },

    /// Poll for incoming messages and display them
    Recv {
        /// Keep listening for new messages (live mode)
        #[arg(short, long, default_value_t = false)]
        follow: bool,

        /// Poll interval in seconds (default: 5)
        #[arg(short, long, default_value_t = 5)]
        interval: u64,
    },

    /// Interactive chat with a peer (send & receive in real-time)
    Chat {
        /// Peer's EVM address (0x...) or @username
        #[arg(required = true)]
        peer: String,
    },

    /// List all known conversation peers
    Contacts,

    /// Show transport & network status
    Status,

    // ── TKS Blockchain ────────────────────────────────────

    /// Register a @username on the TKS blockchain (FREE)
    Register {
        /// Username to register (e.g., ninja or @ninja)
        #[arg(required = true)]
        username: String,
    },

    /// Look up a @username → address (or address → @username)
    Lookup {
        /// @username or 0x... address to look up
        #[arg(required = true)]
        query: String,
    },

    /// Check TKS token balance
    Balance {
        /// Address to check (defaults to your own)
        address: Option<String>,
    },

    /// Query TKS blockchain node info (block height, runtime, pallets)
    NodeInfo,
}

fn print_banner() {
    let banner = r#"
   ╔═══════════════════════════════════════════╗
   ║          ⚔️  CIPHER CLI  ⚔️               ║
   ║     Decentralized • Anonymous • E2EE      ║
   ║       Powered by TKS Blockchain           ║
   ╚═══════════════════════════════════════════╝
"#;
    println!("{}", banner.cyan());
}

#[tokio::main]
async fn main() {
    // Initialize logging (set RUST_LOG=debug for verbose output)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let cli = Cli::parse();

    print_banner();

    let result = match cli.command {
        // Identity
        Commands::Init { words24 } => {
            commands::init::run(words24).await
        }
        Commands::Restore { seed_phrase } => {
            let phrase = seed_phrase.join(" ");
            commands::restore::run(&phrase).await
        }
        Commands::Whoami => {
            commands::whoami::run().await
        }
        Commands::Export => {
            commands::export::run().await
        }

        // Messaging
        Commands::Send { recipient, message } => {
            let msg = message.join(" ");
            commands::send::run(&recipient, &msg).await
        }
        Commands::SendFile { recipient, file } => {
            commands::send_file::run(&recipient, &file).await
        }
        Commands::Recv { follow, interval } => {
            commands::recv::run(follow, interval).await
        }
        Commands::Chat { peer } => {
            commands::chat::run(&peer).await
        }
        Commands::Contacts => {
            commands::contacts::run().await
        }
        Commands::Status => {
            commands::status::run().await
        }

        // TKS Blockchain
        Commands::Register { username } => {
            commands::register::run(&username).await
        }
        Commands::Lookup { query } => {
            commands::lookup::run(&query).await
        }
        Commands::Balance { address } => {
            commands::balance::run(address.as_deref()).await
        }
        Commands::NodeInfo => {
            commands::node_info::run().await
        }
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}
