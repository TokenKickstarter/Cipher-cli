//! `cipher-cli group` — Multi-user E2EE group messaging & management

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub members: Vec<String>,
    pub created_at: i64,
}

pub fn groups_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".cipher").join("groups.json")
}

pub fn load_groups() -> HashMap<String, GroupRecord> {
    let path = groups_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(groups) = serde_json::from_str::<HashMap<String, GroupRecord>>(&data) {
            return groups;
        }
    }
    HashMap::new()
}

pub fn save_groups(groups: &HashMap<String, GroupRecord>) -> Result<(), String> {
    let path = groups_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let data = serde_json::to_string_pretty(groups)
        .map_err(|e| format!("Failed to serialize groups: {}", e))?;
    fs::write(&path, data).map_err(|e| format!("Failed to write groups: {}", e))?;
    Ok(())
}

pub async fn run(action: &str, args: &[String]) -> Result<(), String> {
    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    match action {
        "create" => {
            if args.is_empty() {
                return Err("Usage: cipher-cli group create <name>".to_string());
            }
            let name = args.join(" ");
            let id = hex::encode(md5_hash(&format!("{}:{}:{}", name, our_addr, chrono::Utc::now().timestamp())));
            let short_id = id[..8].to_string();

            let mut groups = load_groups();
            let record = GroupRecord {
                id: short_id.clone(),
                name: name.clone(),
                owner: our_addr.clone(),
                members: vec![our_addr.clone()],
                created_at: chrono::Utc::now().timestamp(),
            };
            groups.insert(short_id.clone(), record);
            save_groups(&groups)?;

            println!();
            println!("╔══════════════════════════════════════════════════╗");
            println!("║          👥 Group Created Successfully!          ║");
            println!("╚══════════════════════════════════════════════════╝");
            println!("  {} {}", "Name:    ".dimmed(), name.cyan().bold());
            println!("  {} {}", "Group ID:".dimmed(), short_id.green().bold());
            println!("  {} {}", "Owner:   ".dimmed(), our_addr.dimmed());
            println!("  {} {}", "Members: ".dimmed(), "1 (You)".white());
            println!();
            println!("  {} Add members with: cipher-cli group add {} @username", "💡".yellow(), short_id);
            println!();
        }

        "list" | "ls" => {
            let groups = load_groups();
            if groups.is_empty() {
                println!();
                println!("  {} No groups yet. Create one with `cipher-cli group create <name>`", "📭".dimmed());
                println!();
                return Ok(());
            }

            println!();
            println!("{}", "══════════════════════════════════════════════════".cyan());
            println!("  {} {}", "👥".bold(), "YOUR GROUPS".cyan().bold());
            println!("{}", "══════════════════════════════════════════════════".cyan());
            for g in groups.values() {
                let role = if g.owner.to_lowercase() == our_addr.to_lowercase() {
                    "Owner".green().bold()
                } else {
                    "Member".white()
                };
                println!("  {} {} [{}] ({} members, ID: {})", "•".cyan(), g.name.cyan().bold(), role, g.members.len(), g.id.yellow());
            }
            println!();
        }

        "add" => {
            if args.len() < 2 {
                return Err("Usage: cipher-cli group add <group_id> <@username|0x...address>".to_string());
            }
            let group_id = &args[0];
            let member_target = &args[1];

            let resolved_addr = super::resolve::resolve_recipient(member_target)?;
            let mut groups = load_groups();

            let group = groups.get_mut(group_id)
                .ok_or_else(|| format!("Group '{}' not found", group_id))?;

            if group.owner.to_lowercase() != our_addr.to_lowercase() {
                return Err("Only the group owner can add members".to_string());
            }

            if group.members.iter().any(|m| m.to_lowercase() == resolved_addr.to_lowercase()) {
                println!("  {} {} is already a member of group '{}'", "ℹ".blue(), member_target, group.name);
                return Ok(());
            }

            group.members.push(resolved_addr.clone());
            let group_name = group.name.clone();
            save_groups(&groups)?;

            println!();
            println!("  {} Added {} to group '{}' ({})", "✓".green(), member_target.cyan().bold(), group_name, group_id);
            println!();
        }

        "info" => {
            if args.is_empty() {
                return Err("Usage: cipher-cli group info <group_id>".to_string());
            }
            let group_id = &args[0];
            let groups = load_groups();
            let group = groups.get(group_id)
                .ok_or_else(|| format!("Group '{}' not found", group_id))?;

            println!();
            println!("{}", format!("👥 Group Details: {}", group.name).cyan().bold());
            println!("  {} {}", "ID:     ".dimmed(), group.id.yellow().bold());
            println!("  {} {}", "Owner:  ".dimmed(), group.owner.cyan());
            println!("  {} {}", "Members:".dimmed(), format!("{} members", group.members.len()).bold());
            for (idx, m) in group.members.iter().enumerate() {
                let is_you = if m.to_lowercase() == our_addr.to_lowercase() { " (You)".green() } else { "".normal() };
                println!("    {}. {}{}", idx + 1, m.dimmed(), is_you);
            }
            println!();
        }

        "leave" => {
            if args.is_empty() {
                return Err("Usage: cipher-cli group leave <group_id>".to_string());
            }
            let group_id = &args[0];
            let mut groups = load_groups();
            let group = groups.get_mut(group_id)
                .ok_or_else(|| format!("Group '{}' not found", group_id))?;

            group.members.retain(|m| m.to_lowercase() != our_addr.to_lowercase());
            let name = group.name.clone();
            save_groups(&groups)?;

            println!();
            println!("  {} You left group '{}'", "👋".yellow(), name);
            println!();
        }

        "send" | "msg" => {
            if args.len() < 2 {
                return Err("Usage: cipher-cli group send <group_id> <message>".to_string());
            }
            let group_id = &args[0];
            let message = args[1..].join(" ");

            let groups = load_groups();
            let group = groups.get(group_id)
                .ok_or_else(|| format!("Group '{}' not found", group_id))?;

            if !group.members.iter().any(|m| m.to_lowercase() == our_addr.to_lowercase()) {
                return Err("You are not a member of this group".to_string());
            }

            let other_members: Vec<String> = group.members
                .iter()
                .filter(|m| m.to_lowercase() != our_addr.to_lowercase())
                .cloned()
                .collect();

            if other_members.is_empty() {
                println!("  {} You are the only member in this group. Add members first!", "ℹ".blue());
                return Ok(());
            }

            println!();
            println!("  {} Broadcasting encrypted message to {} group members...", "👥".cyan(), other_members.len());

            let client = Arc::new(SwarmClient::new(identity));
            let mut delivered = 0;
            let group_prefix = format!("[Group: {}] {}", group.name, message);

            for member in &other_members {
                if client.send_text(member, &group_prefix).await.is_ok() {
                    delivered += 1;
                }
            }

            // Flush outbox
            let sender = client_core::transport::direct::DefaultSender {
                direct: client.transport.direct.clone(),
            };
            client.transport.direct.flush_outbox(&sender).await;

            println!("  {} Message sent to {}/{} members in '{}'!", "✓".green(), delivered, other_members.len(), group.name);
            println!();
        }

        _ => {
            println!();
            println!("  {}", "Group Commands:".white().bold());
            println!("    group create <name>                 — Create a new group");
            println!("    group list                          — List your groups");
            println!("    group info <id>                     — Show group members");
            println!("    group add <id> <@user|0xaddr>       — Add a member");
            println!("    group send <id> <message>           — Broadcast message to group");
            println!("    group leave <id>                    — Leave group");
            println!();
        }
    }

    Ok(())
}

fn md5_hash(s: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let res = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&res[..16]);
    out
}
