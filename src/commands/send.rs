//! `cipher-cli send` — Send an encrypted message to a recipient

use colored::Colorize;
use std::sync::Arc;
use crate::identity_store;

pub async fn run(recipient: &str, message: &str) -> Result<(), String> {
    // Resolve @username → 0x address via TKS blockchain
    let recipient = super::resolve::resolve_recipient(recipient)?;

    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    let recipient_short = if recipient.len() > 10 {
        format!("{}...{}", &recipient[..6], &recipient[recipient.len()-4..])
    } else {
        recipient.clone()
    };

    println!("  {} Sending as {}...", "↑".dimmed(), our_addr[..10].to_string().dimmed());

    // Create SwarmClient with the identity
    let client = Arc::new(crate::commands::mode::create_swarm_client(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    client_core::network_bundle::ensure_federated_pools().await;

    // Send the message
    let msg_id = client
        .send_text(&recipient, message)
        .await
        .map_err(|e| format!("Send failed: {e}"))?;

    // Force flush outbox immediately so no background sleep is needed.
    let sender = client_core::transport::direct::DefaultSender {
        direct: client.transport.direct.clone(),
    };
    client
        .transport
        .direct
        .flush_outbox(&sender)
        .await
        .map_err(|e| format!("Relay store failed: {e}"))?;

    println!();
    println!("  {} Message sent!", "✓".green().bold());
    println!("    {} {}", "To:".dimmed(), recipient_short.cyan());
    println!("    {} {}", "ID:".dimmed(), msg_id.to_string()[..8].to_string().dimmed());
    println!("    {} {}", "🔐".dimmed(), "AES-256-GCM encrypted".green());
    println!();

    Ok(())
}
