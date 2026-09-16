//! `cipher-cli recv` — Poll for incoming messages and display them

use colored::Colorize;
use std::sync::Arc;
use client_core::message::MessageType;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

pub async fn run(follow: bool, interval: u64) -> Result<(), String> {
    let password = identity_store::prompt_password("🔑 Password: ");
    let identity = identity_store::load_identity(&password)?;

    let our_addr = identity.evm_address();
    println!("{}", format!("Listening as {}...", our_addr).dimmed());

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
            println!();
            println!(
                "  {} {} {} 📎 {}",
                format!("[{}]", time).dimmed(),
                sender_short.cyan().bold(),
                "→".dimmed(),
                format!("{} ({} bytes)", meta.file_name, meta.size_bytes).yellow(),
            );
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
