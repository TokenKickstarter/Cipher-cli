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

    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    let peer_short = if peer.len() > 10 {
        format!("{}...{}", &peer[..6], &peer[peer.len()-4..])
    } else {
        peer.clone()
    };
    let our_short = if our_addr.len() > 10 {
        format!("{}...{}", &our_addr[..6], &our_addr[our_addr.len()-4..])
    } else {
        our_addr.clone()
    };

    println!("  ┌─────────────────────────────────────────────┐");
    println!("  │  {}                     │", "Interactive Chat".white().bold());
    println!("  ├─────────────────────────────────────────────┤");
    println!("  │  {} {}               │", "You: ".dimmed(), our_short.cyan());
    println!("  │  {} {}               │", "Peer:".dimmed(), peer_short.cyan().bold());
    println!("  │  {} {}                      │", "E2EE:".dimmed(), "AES-256-GCM ✓".green());
    println!("  │  {} {}           │", "Exit:".dimmed(), "/quit or Ctrl+C".dimmed());
    println!("  └─────────────────────────────────────────────┘");
    println!();

    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for transport to connect
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    println!("  {} Connected to relay", "✓".green());
    println!();
    print!("  {} ", "▶".green().bold());
    let _ = io::stdout().flush();

    // Spawn a background task to poll & display incoming messages
    let client_recv = client.clone();
    let peer_recv = peer.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            client_recv.process_incoming().await;
            let messages = client_recv.receive_all().await;

            for msg in &messages {
                if msg.sender.to_lowercase() == peer_recv.to_lowercase() {
                    let time = msg.timestamp.format("%H:%M:%S");
                    match &msg.msg_type {
                        MessageType::Text => {
                            let text = String::from_utf8_lossy(&msg.payload);
                            print!("\r{}", " ".repeat(60)); // Clear current line
                            println!(
                                "\r  {} {} {}",
                                format!("[{}]", time).dimmed(),
                                "◀".cyan().bold(),
                                text.white()
                            );
                            print!("  {} ", "▶".green().bold());
                            let _ = io::stdout().flush();
                        }
                        MessageType::File(meta) => {
                            print!("\r{}", " ".repeat(60));
                            println!(
                                "\r  {} {} 📎 {} ({})",
                                format!("[{}]", time).dimmed(),
                                "◀".cyan().bold(),
                                meta.file_name.yellow(),
                                format!("{} bytes", meta.size_bytes).dimmed(),
                            );

                            // Auto-save file
                            let download_dir = dirs::download_dir()
                                .unwrap_or_else(|| std::path::PathBuf::from("."))
                                .join("cipher-files");
                            std::fs::create_dir_all(&download_dir).ok();
                            let safe_name = meta.file_name.replace('/', "_").replace('\\', "_");
                            let dest = download_dir.join(&safe_name);
                            if let Ok(_) = std::fs::write(&dest, &msg.payload) {
                                println!(
                                    "  {} {}",
                                    "  💾 Saved:".green(),
                                    dest.display().to_string().dimmed(),
                                );
                            }

                            print!("  {} ", "▶".green().bold());
                            let _ = io::stdout().flush();
                        }
                        _ => {}
                    }
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    });

    // Main input loop
    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Input error: {e}"))?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            print!("  {} ", "▶".green().bold());
            let _ = io::stdout().flush();
            continue;
        }

        match trimmed {
            "/quit" | "/exit" | "/q" => {
                println!();
                println!("  {} Chat ended.", "👋".yellow());
                break;
            }
            "/help" | "/h" => {
                println!();
                println!("  {}", "Commands:".white().bold());
                println!("  {} {}", "/quit".cyan(), "— End the chat".dimmed());
                println!("  {} {}", "/help".cyan(), "— Show this help".dimmed());
                println!("  {} {}", "/clear".cyan(), "— Clear the screen".dimmed());
                println!();
                print!("  {} ", "▶".green().bold());
                let _ = io::stdout().flush();
                continue;
            }
            "/clear" | "/cls" => {
                print!("\x1b[2J\x1b[H"); // ANSI clear screen
                print!("  {} ", "▶".green().bold());
                let _ = io::stdout().flush();
                continue;
            }
            _ => {}
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

        print!("  {} ", "▶".green().bold());
        let _ = io::stdout().flush();
    }

    recv_handle.abort();
    println!();
    Ok(())
}
