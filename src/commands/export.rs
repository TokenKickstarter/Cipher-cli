//! `cipher-cli export` — Export seed phrase (with warning)

use colored::Colorize;
use crate::identity_store;

pub async fn run() -> Result<(), String> {
    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".red().bold());
    println!("{}", "║   ⚠️  WARNING: Your seed phrase will be shown!   ║".red().bold());
    println!("{}", "║   Make sure no one is watching your screen.      ║".red().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".red().bold());
    println!();

    let password = identity_store::prompt_password("🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    println!();
    println!("{}", "Your Seed Phrase:".yellow().bold());
    println!();

    let words: Vec<&str> = identity.mnemonic().split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("  {:>2}. {:<14}", (i + 1).to_string().cyan(), word.white().bold());
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    println!();
    println!("  {} {}", "EVM Address:".dimmed(), identity.evm_address().cyan());
    println!();
    println!("{}", "  ⚠️  Keep this phrase secret. Anyone with it can access your messages and wallet.".red());
    println!();

    Ok(())
}
