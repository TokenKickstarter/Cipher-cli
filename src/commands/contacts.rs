//! `cipher-cli contacts` — List all known conversation peers

use colored::Colorize;
use std::sync::Arc;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

pub async fn run() -> Result<(), String> {
    let password = identity_store::prompt_password("🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for sync
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Process any pending incoming messages to discover peers
    client.process_incoming().await;

    let contacts = client.conversation_list().await;

    println!();
    if contacts.is_empty() {
        println!("{}", "📭 No conversations yet.".dimmed());
        println!("  {} {}", "Tip:".yellow(), "Send a message with `cipher-cli send <address> \"Hello!\"`".dimmed());
    } else {
        println!("{}", format!("📋 {} conversation(s):", contacts.len()).green().bold());
        println!();
        for (i, addr) in contacts.iter().enumerate() {
            let unread = client.unread_count(addr).await;
            let unread_badge = if unread > 0 {
                format!(" ({})", format!("{} unread", unread).red())
            } else {
                String::new()
            };
            println!(
                "  {}. {}{}",
                (i + 1).to_string().cyan(),
                addr.white().bold(),
                unread_badge
            );
        }
    }
    println!();

    Ok(())
}
