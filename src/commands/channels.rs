//! `cipher-cli channel` — Telegram-style 1-to-many broadcast channels

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use crate::identity_store;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRecord {
    pub id: String,
    pub name: String,
    pub handle: Option<String>,
    pub owner: String,
    pub subscribers: Vec<String>,
    pub posts: Vec<ChannelPost>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPost {
    pub id: u64,
    pub text: String,
    pub timestamp: i64,
}

pub fn channels_path() -> PathBuf {
    crate::identity_store::cipher_dir().join("channels.json")
}

pub fn load_channels() -> HashMap<String, ChannelRecord> {
    let path = channels_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(channels) = serde_json::from_str::<HashMap<String, ChannelRecord>>(&data) {
            return channels;
        }
    }
    HashMap::new()
}

pub fn save_channels(channels: &HashMap<String, ChannelRecord>) -> Result<(), String> {
    let path = channels_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let data = serde_json::to_string_pretty(channels)
        .map_err(|e| format!("Failed to serialize channels: {}", e))?;
    fs::write(&path, data).map_err(|e| format!("Failed to write channels: {}", e))?;
    Ok(())
}

pub async fn run(action: &str, args: &[String]) -> Result<(), String> {
    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    match action {
        "create" => {
            if args.is_empty() {
                return Err("Usage: cipher-cli channel create <name> [handle]".to_string());
            }
            let name = &args[0];
            let handle = if args.len() > 1 {
                Some(args[1].trim_start_matches('@').to_string())
            } else {
                None
            };

            let id = hex::encode(hash_str(&format!("{}:{}:{}", name, our_addr, chrono::Utc::now().timestamp())));
            let short_id = id[..8].to_string();

            let mut channels = load_channels();
            let record = ChannelRecord {
                id: short_id.clone(),
                name: name.clone(),
                handle: handle.clone(),
                owner: our_addr.clone(),
                subscribers: vec![our_addr.clone()],
                posts: Vec::new(),
                created_at: chrono::Utc::now().timestamp(),
            };
            channels.insert(short_id.clone(), record);
            save_channels(&channels)?;

            println!();
            println!("╔══════════════════════════════════════════════════╗");
            println!("║         📢 Broadcast Channel Created!            ║");
            println!("╚══════════════════════════════════════════════════╝");
            println!("  {} {}", "Name:      ".dimmed(), name.cyan().bold());
            if let Some(h) = handle {
                println!("  {} @{}", "Handle:    ".dimmed(), h.yellow().bold());
            }
            println!("  {} {}", "Channel ID:".dimmed(), short_id.green().bold());
            println!("  {} {}", "Owner:     ".dimmed(), our_addr.dimmed());
            println!();
            println!("  {} Post to channel: cipher-cli channel post {} \"Your broadcast message\"", "💡".yellow(), short_id);
            println!();
        }

        "list" | "ls" => {
            let channels = load_channels();
            if channels.is_empty() {
                println!();
                println!("  {} No channels yet. Create one with `cipher-cli channel create <name>`", "📭".dimmed());
                println!();
                return Ok(());
            }

            println!();
            println!("{}", "══════════════════════════════════════════════════".cyan());
            println!("  {} {}", "📢".bold(), "BROADCAST CHANNELS".cyan().bold());
            println!("{}", "══════════════════════════════════════════════════".cyan());
            for ch in channels.values() {
                let role = if ch.owner.to_lowercase() == our_addr.to_lowercase() {
                    "Owner".green().bold()
                } else {
                    "Subscriber".white()
                };
                let handle_str = ch.handle.as_ref().map(|h| format!("(@{})", h)).unwrap_or_default();
                println!("  {} {} {} [{}] ({} subs, {} posts, ID: {})",
                    "•".cyan(), ch.name.cyan().bold(), handle_str.yellow(), role, ch.subscribers.len(), ch.posts.len(), ch.id.yellow()
                );
            }
            println!();
        }

        "post" => {
            if args.len() < 2 {
                return Err("Usage: cipher-cli channel post <channel_id> <message>".to_string());
            }
            let channel_id = &args[0];
            let text = args[1..].join(" ");

            let mut channels = load_channels();
            let channel = channels.get_mut(channel_id)
                .ok_or_else(|| format!("Channel '{}' not found", channel_id))?;

            if channel.owner.to_lowercase() != our_addr.to_lowercase() {
                return Err("Only the channel owner can post broadcasts".to_string());
            }

            let post_id = (channel.posts.len() + 1) as u64;
            channel.posts.push(ChannelPost {
                id: post_id,
                text: text.clone(),
                timestamp: chrono::Utc::now().timestamp(),
            });
            let channel_name = channel.name.clone();
            let subs = channel.subscribers.clone();
            save_channels(&channels)?;

            println!();
            println!("  {} Broadcasting post #{} to {} subscribers of '{}'...", "📢".cyan(), post_id, subs.len(), channel_name);

            // Send to external subscribers
            let client = Arc::new(crate::commands::mode::create_swarm_client(identity));
            let broadcast_msg = format!("[Channel: {}] {}", channel_name, text);
            let mut sent_count = 0;

            for sub in &subs {
                if sub.to_lowercase() != our_addr.to_lowercase() {
                    if client.send_text(sub, &broadcast_msg).await.is_ok() {
                        sent_count += 1;
                    }
                }
            }

            if sent_count > 0 {
                let sender = client_core::transport::direct::DefaultSender {
                    direct: client.transport.direct.clone(),
                };
                client.transport.direct.flush_outbox(&sender).await;
            }

            println!("  {} Post published successfully!", "✓".green());
            println!();
        }

        "sub" | "subscribe" => {
            if args.is_empty() {
                return Err("Usage: cipher-cli channel sub <channel_id>".to_string());
            }
            let channel_id = &args[0];
            let mut channels = load_channels();
            let channel = channels.get_mut(channel_id)
                .ok_or_else(|| format!("Channel '{}' not found", channel_id))?;

            if channel.subscribers.iter().any(|s| s.to_lowercase() == our_addr.to_lowercase()) {
                println!("  {} You are already subscribed to '{}'", "ℹ".blue(), channel.name);
                return Ok(());
            }

            channel.subscribers.push(our_addr.clone());
            let name = channel.name.clone();
            save_channels(&channels)?;

            println!();
            println!("  {} Subscribed to channel '{}'!", "✓".green(), name);
            println!();
        }

        "unsub" | "unsubscribe" => {
            if args.is_empty() {
                return Err("Usage: cipher-cli channel unsub <channel_id>".to_string());
            }
            let channel_id = &args[0];
            let mut channels = load_channels();
            let channel = channels.get_mut(channel_id)
                .ok_or_else(|| format!("Channel '{}' not found", channel_id))?;

            channel.subscribers.retain(|s| s.to_lowercase() != our_addr.to_lowercase());
            let name = channel.name.clone();
            save_channels(&channels)?;

            println!();
            println!("  {} Unsubscribed from channel '{}'", "👋".yellow(), name);
            println!();
        }

        _ => {
            println!();
            println!("  {}", "Channel Commands:".white().bold());
            println!("    channel create <name> [handle]      — Create a broadcast channel");
            println!("    channel list                        — List channels");
            println!("    channel post <id> <message>         — Broadcast message to subscribers");
            println!("    channel sub <id>                    — Subscribe to channel");
            println!("    channel unsub <id>                  — Unsubscribe from channel");
            println!();
        }
    }

    Ok(())
}

fn hash_str(s: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let res = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&res[..16]);
    out
}
