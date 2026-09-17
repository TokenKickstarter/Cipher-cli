//! `cipher-cli register` — Register a @username on the TKS blockchain

use colored::Colorize;
use client_core::username_registry::{UsernameRegistry, RegistryBackend, UsernameStatus};
use crate::identity_store;

pub async fn run(username: &str) -> Result<(), String> {
    let identity = identity_store::get_identity()?;

    let our_addr = identity.evm_address();
    let clean_name = username.trim_start_matches('@').to_lowercase();

    println!();
    println!("{}", format!("Registering @{} on TKS blockchain...", clean_name).yellow());
    println!("  {} {}", "Your Address:".dimmed(), our_addr.cyan());
    println!("  {} {}", "Backend:     ".dimmed(), "TKS Node (FREE — no gas cost)".green());
    println!();

    // Create registry with identity for signing
    let registry = UsernameRegistry::with_identity(
        our_addr.clone(),
        Some(identity.clone()),
        RegistryBackend::Substrate,
    );

    // Check availability first
    let status = registry.check_availability(&clean_name).await;
    match &status {
        UsernameStatus::Available => {
            println!("  {} @{} is available!", "✓".green(), clean_name);
        }
        UsernameStatus::Taken(addr) => {
            if addr.to_lowercase() == our_addr.to_lowercase() {
                println!("  {} @{} is already registered to you!", "✓".green(), clean_name);
                return Ok(());
            } else {
                return Err(format!("@{} is already taken by {}", clean_name, addr));
            }
        }
        UsernameStatus::Invalid(reason) => {
            return Err(format!("Invalid username: {}", reason));
        }
        UsernameStatus::Reserved => {
            return Err(format!("@{} is a reserved username", clean_name));
        }
    }

    // Register on TKS chain
    println!("  {} Submitting to TKS nodes...", "⏳".yellow());

    match registry.register(&clean_name).await {
        Ok(record) => {
            println!();
            println!("{}", "╔══════════════════════════════════════════════════╗".green().bold());
            println!("{}", "║          ✅ Username Registered!                 ║".green().bold());
            println!("{}", "╚══════════════════════════════════════════════════╝".green().bold());
            println!();
            println!("  {} @{}", "Username:".dimmed(), record.username.cyan().bold());
            println!("  {} {}", "Address: ".dimmed(), record.address.white());
            println!("  {} {}", "Via Node:".dimmed(), record.registered_via.unwrap_or("local".into()).dimmed());
            println!("  {} {}", "Synced:  ".dimmed(), format!("{} node(s)", record.sync_count).green());
            println!();
            println!("  {} Others can now find you with: {}", "💡".green(), format!("@{}", clean_name).cyan().bold());
            println!();
        }
        Err(e) => {
            return Err(format!("Registration failed: {}", e));
        }
    }

    Ok(())
}
