//! `cipher-cli recv` — Poll for incoming messages and display them

use colored::Colorize;
use std::sync::Arc;
use client_core::message::MessageType;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

pub async fn run(follow: bool, interval: u64) -> Result<(), String> {
    let identity = identity_store::get_identity()?;

    let our_addr = identity.evm_address();
    let short = if our_addr.len() > 10 {
        format!("{}...{}", &our_addr[..6], &our_addr[our_addr.len()-4..])
    } else {
        our_addr
    };
    println!("  {} Listening as {}...", "📡".dimmed(), short.cyan());

    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for initial sync
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    loop {
        // Process incoming messages
        client.process_incoming().await;

        let messages = client.receive_all().await;

        if messages.is_empty() {
            if !follow {
                println!("{}", "📭 No new messages.".dimmed());
                break;
            }
        } else {
            for msg in &messages {
                print_message(msg);
            }
        }

        if !follow {
            break;
        }

        // Show waiting indicator
        print!("{}", ".".dimmed());
        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }

    println!();
    Ok(())
}

fn print_message(msg: &client_core::message::CipherMessage) {
    let time = msg.timestamp.format("%H:%M:%S");
    let sender_short = if msg.sender.len() > 10 {
        format!("{}...{}", &msg.sender[..6], &msg.sender[msg.sender.len()-4..])
    } else {
        msg.sender.clone()
    };

    match &msg.msg_type {
        MessageType::Text => {
            let text = String::from_utf8_lossy(&msg.payload);
            println!();
            println!(
                "  {} {} {}",
                format!("[{}]", time).dimmed(),
                sender_short.cyan().bold(),
                "→".dimmed(),
            );
            println!("  {}", text.white());
        }
        MessageType::File(meta) => {
            // Save file to ~/Downloads/cipher-files/
            let download_dir = dirs::download_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("cipher-files");
            std::fs::create_dir_all(&download_dir).ok();

            let safe_name = meta.file_name.replace('/', "_").replace('\\', "_");
            let dest = download_dir.join(&safe_name);

            // Avoid overwriting — add suffix if exists
            let dest = if dest.exists() {
                let stem = dest.file_stem().unwrap_or_default().to_string_lossy().to_string();
                let ext = dest.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
                let ts = chrono::Utc::now().format("%H%M%S");
                download_dir.join(format!("{}-{}{}", stem, ts, ext))
            } else {
                dest
            };

            match std::fs::write(&dest, &msg.payload) {
                Ok(_) => {
                    println!();
                    println!(
                        "  {} {} {} 📎 {}",
                        format!("[{}]", time).dimmed(),
                        sender_short.cyan().bold(),
                        "→".dimmed(),
                        format!("{} ({} bytes)", meta.file_name, meta.size_bytes).yellow(),
                    );
                    println!(
                        "  {} {}",
                        "💾 Saved:".green(),
                        dest.display().to_string().white().bold(),
                    );
                }
                Err(e) => {
                    println!();
                    println!(
                        "  {} {} {} 📎 {} (save failed: {})",
                        format!("[{}]", time).dimmed(),
                        sender_short.cyan().bold(),
                        "→".dimmed(),
                        format!("{} ({} bytes)", meta.file_name, meta.size_bytes).yellow(),
                        e,
                    );
                }
            }
        }
        MessageType::CallSignal(_) => {
            println!(
                "  {} {} {} 📞 {}",
                format!("[{}]", time).dimmed(),
                sender_short.cyan().bold(),
                "→".dimmed(),
                "Call signal".yellow(),
            );
        }
        _ => {
            println!(
                "  {} {} {} {:?}",
                format!("[{}]", time).dimmed(),
                sender_short.cyan().bold(),
                "→".dimmed(),
                msg.msg_type,
            );
        }
    }
}
