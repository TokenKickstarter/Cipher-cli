//! `cipher-cli send` — Send an encrypted message to a recipient

use colored::Colorize;
use std::sync::Arc;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

pub async fn run(recipient: &str, message: &str) -> Result<(), String> {
    // Resolve @username → 0x address via TKS blockchain
    let recipient = super::resolve::resolve_recipient(recipient)?;

    let password = identity_store::prompt_password("🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    let our_addr = identity.evm_address();
    println!("{}", format!("Sending as {}...", our_addr).dimmed());

    // Create SwarmClient with the identity
    let client = Arc::new(SwarmClient::new(identity));

    // Start the transport (connects to relay)
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Give transport a moment to connect
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Send the message
    println!("{}", format!("Encrypting & sending to {}...", recipient).yellow());

    let msg_id = client
        .send_text(&recipient, message)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    // Wait for the message to be flushed to the relay
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!();
    println!("{} Message sent!", "✅".green());
    println!("  {} {}", "To:        ".dimmed(), recipient.cyan());
    println!("  {} {}", "Message ID:".dimmed(), msg_id.to_string().dimmed());
    println!("  {} {}", "Encrypted: ".dimmed(), "AES-256-GCM ✓".green());
    println!();

    Ok(())
}
