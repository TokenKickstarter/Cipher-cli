//! `cipher-cli chat` — Interactive real-time chat with a peer

use colored::Colorize;
use std::sync::Arc;
use std::io::{self, BufRead, Write};
use client_core::message::MessageType;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

pub async fn run(peer: &str) -> Result<(), String> {
    // Resolve @username → 0x address via TKS blockchain
    let peer = super::resolve::resolve_recipient(peer)?;

    let password = identity_store::prompt_password("🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    let our_addr = identity.evm_address();

    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".green().bold());
    println!("{}", "║             Interactive Chat Mode                ║".green().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".green().bold());
    println!();
    println!("  {} {}", "You: ".dimmed(), our_addr.cyan());
    println!("  {} {}", "Peer:".dimmed(), peer.cyan().bold());
    println!("  {} {}", "Exit:".dimmed(), "Type /quit or Ctrl+C".dimmed());
    println!("  {} {}", "E2EE:".dimmed(), "AES-256-GCM ✓".green());
    println!();
    println!("{}", "─".repeat(52).dimmed());
    println!();

    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for transport to connect
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Spawn a background task to poll & display incoming messages
    let client_recv = client.clone();
    let peer_recv = peer.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            client_recv.process_incoming().await;
            let messages = client_recv.receive_all().await;

            for msg in &messages {
                // Only show messages from our chat peer
                if msg.sender.to_lowercase() == peer_recv.to_lowercase() {
                    if let MessageType::Text = &msg.msg_type {
                        let text = String::from_utf8_lossy(&msg.payload);
                        let time = msg.timestamp.format("%H:%M:%S");
                        // Move cursor, print message, re-show prompt
                        println!(
                            "\r  {} {} {}",
                            format!("[{}]", time).dimmed(),
                            "◀".cyan().bold(),
                            text.white()
                        );
                        print!("{}", "  ▶ ".green().bold());
                        let _ = io::stdout().flush();
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    });

    // Main input loop — read lines from stdin and send
    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Input error: {e}"))?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            print!("{}", "  ▶ ".green().bold());
            let _ = io::stdout().flush();
            continue;
        }

        if trimmed == "/quit" || trimmed == "/exit" || trimmed == "/q" {
            println!();
            println!("{}", "👋 Chat ended.".yellow());
            break;
        }

        // Send the message
        match client.send_text(&peer, trimmed).await {
            Ok(_) => {
                let time = chrono::Utc::now().format("%H:%M:%S");
                println!(
                    "  {} {} {}",
                    format!("[{}]", time).dimmed(),
                    "▶".green().bold(),
                    trimmed.white()
                );
            }
            Err(e) => {
                println!("  {} {}", "✗".red(), format!("Send failed: {e}").red());
            }
        }

        print!("{}", "  ▶ ".green().bold());
        let _ = io::stdout().flush();
    }

    recv_handle.abort();
    println!();
    Ok(())
}
