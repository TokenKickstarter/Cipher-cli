//! `cipher-cli whoami` — Display your identity information

use colored::Colorize;
use crate::identity_store;

pub async fn run() -> Result<(), String> {
    let password = identity_store::prompt_password("🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    let pub_id = identity.public_identity();

    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║              Your Cipher Identity                ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".cyan().bold());
    println!();

    println!("  {} {}", "EVM Address:     ".dimmed(), pub_id.evm_address.white().bold());
    println!("  {} {}", "Substrate (SS58):".dimmed(), pub_id.substrate_address.white());
    println!("  {} {}", "Chat ID:         ".dimmed(), pub_id.display_address.cyan().bold());
    println!();

    println!("{}", "  Public Keys:".green().bold());
    println!("  {} {}", "Ed25519:  ".dimmed(), hex::encode(&pub_id.ed25519_public).dimmed());
    println!("  {} {}", "X25519:   ".dimmed(), hex::encode(&pub_id.x25519_public).dimmed());
    println!("  {} {}", "Sr25519:  ".dimmed(), hex::encode(&pub_id.sr25519_public).dimmed());
    println!("  {} {}", "secp256k1:".dimmed(), hex::encode(&pub_id.secp256k1_public).dimmed());
    println!();

    println!("  {} {}", "Identity file:".dimmed(), identity_store::identity_path().display().to_string().dimmed());
    println!();
    println!("  {} Share your {} to receive messages", "💡".green(), "Chat ID".cyan().bold());
    println!();

    Ok(())
}
