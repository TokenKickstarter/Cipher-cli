//! `cipher-cli contacts` — List all known conversation peers

use colored::Colorize;
use std::sync::Arc;
use crate::identity_store;

pub async fn run() -> Result<(), String> {
    let identity = identity_store::get_identity()?;

    let client = Arc::new(crate::commands::mode::create_swarm_client(identity));
    client_core::network_bundle::ensure_federated_pools().await;

    // Poll relay once directly instead of fixed sleep, then decode incoming peers.
    let poll_sender = client_core::transport::direct::DefaultSender {
        direct: client.transport.direct.clone(),
    };
    client.transport.direct.poll_incoming(&poll_sender).await;
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
