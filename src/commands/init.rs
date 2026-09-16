//! `cipher-cli init` — Generate a new Cipher identity

use colored::Colorize;
use client_core::identity::CipherIdentity;
use crate::identity_store;

pub async fn run(words24: bool) -> Result<(), String> {
    if identity_store::identity_exists() {
        return Err(format!(
            "Identity already exists at {}\nUse `cipher-cli export` to view your seed phrase, or delete the file to start fresh.",
            identity_store::identity_path().display()
        ));
    }

    let word_count = if words24 { 24 } else { 12 };
    println!("{}", format!("Generating new {word_count}-word identity...").yellow());

    let identity = CipherIdentity::generate_with_word_count(word_count)
        .map_err(|e| format!("Identity generation failed: {e}"))?;

    // Show the seed phrase
    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".red().bold());
    println!("{}", "║   ⚠️  WRITE DOWN YOUR SEED PHRASE — ONLY COPY!  ║".red().bold());
    println!("{}", "║   Anyone with this phrase can access your msgs   ║".red().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".red().bold());
    println!();

    let words: Vec<&str> = identity.mnemonic().split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        print!("  {:>2}. {:<14}", (i + 1).to_string().cyan(), word.white().bold());
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    // Show addresses
    println!();
    println!("{}", "Your Identity:".green().bold());
    println!("  {} {}", "EVM Address:".dimmed(), identity.evm_address().white().bold());
    println!("  {} {}", "Substrate:  ".dimmed(), identity.substrate_address().white());
    println!("  {} {}", "Ed25519 Pub:".dimmed(), hex::encode(identity.ed25519_public_key().as_bytes()).dimmed());
    println!();

    // Encrypt and save
    let password = identity_store::prompt_new_password()?;
    identity_store::save_identity(&identity, &password)?;

    println!();
    println!("{} Identity saved to {}", "✅".green(), identity_store::identity_path().display().to_string().dimmed());
    println!("{} Share your EVM address to receive messages: {}", "📬".green(), identity.evm_address().cyan().bold());
    println!();

    Ok(())
}
