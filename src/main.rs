use clap::{Parser, Subcommand};
use colored::Colorize;

mod commands;
mod identity_store;
mod session;

/// Cipher CLI — Send & receive E2EE messages from the terminal
///
/// Uses the same encryption, identity, and transport layers as the
/// Cipher mobile app. All messages are AES-256-GCM encrypted end-to-end.
/// Powered by the TKS blockchain for identity, usernames, and tokenomics.
#[derive(Parser)]
#[command(name = "cipher-cli")]
#[command(version = "0.2.0")]
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

    /// Unlock your identity (no password needed for 4 hours)
    Login,

    /// Lock your identity (destroy session)
    Logout,

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
    println!();
    println!("  {} {}", "⚔️ ".bold(), "CIPHER CLI".cyan().bold());
    println!("  {}", "Decentralized • Anonymous • E2EE".dimmed());
    if session::is_session_active() {
        if let Some(addr) = session::session_address() {
            let remaining = session::session_remaining_secs().unwrap_or(0);
            let hours = remaining / 3600;
            let mins = (remaining % 3600) / 60;
            let short_addr = if addr.len() > 10 {
                format!("{}...{}", &addr[..6], &addr[addr.len()-4..])
            } else {
                addr
            };
            println!("  {} {} {}", "🔓".green(), short_addr.green(), format!("({}h {}m left)", hours, mins).dimmed());
        }
    } else {
        println!("  {}", "🔒 Locked — run `cipher-cli login` to unlock".dimmed());
    }
    println!();
}

#[tokio::main]
async fn main() {
    // Default to WARN level to suppress noisy transport/crypto logs
    // Users can set RUST_LOG=info or RUST_LOG=debug for verbose output
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
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
        Commands::Login => {
            run_login().await
        }
        Commands::Logout => {
            run_logout().await
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
        eprintln!("  {} {}", "✗".red().bold(), e);
        std::process::exit(1);
    }
}

/// `cipher-cli login` — Unlock identity for 4 hours
async fn run_login() -> Result<(), String> {
    if session::is_session_active() {
        let remaining = session::session_remaining_secs().unwrap_or(0);
        let hours = remaining / 3600;
        let mins = (remaining % 3600) / 60;
        println!("  {} Already logged in ({}h {}m remaining)", "✓".green(), hours, mins);
        println!("  {}", "Run `cipher-cli logout` to lock.".dimmed());
        return Ok(());
    }

    let password = identity_store::prompt_password("  🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    session::create_session(&identity)?;

    let addr = identity.evm_address();
    let short = if addr.len() > 10 {
        format!("{}...{}", &addr[..6], &addr[addr.len()-4..])
    } else {
        addr
    };

    println!();
    println!("  {} Unlocked as {}", "✓".green().bold(), short.cyan());
    println!("  {} Session active for 4 hours", "⏱".dimmed());
    println!("  {} No password needed for subsequent commands", "💡".dimmed());
    println!();

    Ok(())
}

/// `cipher-cli logout` — Destroy active session
async fn run_logout() -> Result<(), String> {
    if !session::is_session_active() {
        println!("  {} Not logged in.", "ℹ".dimmed());
        return Ok(());
    }

    session::destroy_session()?;
    println!("  {} Session destroyed. Identity locked.", "🔒".yellow());
    println!();

    Ok(())
}
