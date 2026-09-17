//! `cipher-cli status` — Show transport & network status

use colored::Colorize;
use std::sync::Arc;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

pub async fn run() -> Result<(), String> {
    let identity = identity_store::get_identity()?;

    let our_addr = identity.evm_address();
    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for transport to initialize
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let transport_name = client.transport.active_transport_name().await;
    let mode = client.transport.get_mode().await;
    let total_unread = client.total_unread().await;
    let contacts = client.conversation_list().await;

    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║              Network Status                      ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".cyan().bold());
    println!();

    println!("  {} {}", "Your Address:    ".dimmed(), our_addr.cyan().bold());
    println!("  {} {}", "Identity File:   ".dimmed(), identity_store::identity_path().display().to_string().dimmed());
    println!();

    println!("{}", "  Transport:".green().bold());
    println!("  {} {}", "Mode:          ".dimmed(), format!("{}", mode).white());
    println!("  {} {}", "Active Layer:  ".dimmed(), transport_name.green());
    println!();

    println!("{}", "  TKS Blockchain:".green().bold());
    println!("  {} {}", "Chain ID:      ".dimmed(), "tks_mainnet".white());
    println!("  {} {}", "RPC Port:      ".dimmed(), "9944".white());
    println!("  {} {}", "Seed Nodes:    ".dimmed(), "seed.tokenkickstarter.com, seed.tkstoken.com, seed.tksscan.com".dimmed());
    println!();

    println!("{}", "  Messaging:".green().bold());
    println!("  {} {}", "Encryption:    ".dimmed(), "AES-256-GCM (Double Ratchet)".green());
    println!("  {} {}", "Contacts:      ".dimmed(), format!("{}", contacts.len()).white());
    println!("  {} {}", "Total Unread:  ".dimmed(), if total_unread > 0 {
        format!("{}", total_unread).red().to_string()
    } else {
        "0".to_string()
    });
    println!();

    Ok(())
}
