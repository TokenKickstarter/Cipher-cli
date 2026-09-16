//! `cipher-cli restore` — Restore identity from a seed phrase

use colored::Colorize;
use client_core::identity::CipherIdentity;
use crate::identity_store;

pub async fn run(seed_phrase: &str) -> Result<(), String> {
    if identity_store::identity_exists() {
        return Err(format!(
            "Identity already exists at {}\nDelete the file first if you want to restore a different identity.",
            identity_store::identity_path().display()
        ));
    }

    println!("{}", "Restoring identity from seed phrase...".yellow());

    let identity = CipherIdentity::from_mnemonic(seed_phrase)
        .map_err(|e| format!("Invalid seed phrase: {e}"))?;

    // Show restored addresses
    println!();
    println!("{}", "Restored Identity:".green().bold());
    println!("  {} {}", "EVM Address:".dimmed(), identity.evm_address().white().bold());
    println!("  {} {}", "Substrate:  ".dimmed(), identity.substrate_address().white());
    println!();

    // Encrypt and save
    let password = identity_store::prompt_new_password()?;
    identity_store::save_identity(&identity, &password)?;

    println!();
    println!("{} Identity restored and saved to {}", "✅".green(), identity_store::identity_path().display().to_string().dimmed());
    println!();

    Ok(())
}
