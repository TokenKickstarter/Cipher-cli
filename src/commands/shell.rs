//! `cipher-cli shell` — Full interactive chat shell
//!
//! A unified inbox where you see ALL messages from anyone and can reply
//! to any conversation. No need to specify a peer upfront.
//!
//! Commands:
//!   @username message    — Send a message to someone
//!   /chat @username      — Focus on a single conversation
//!   /all                 — Show all conversations (unfocus)
//!   /contacts            — List contacts
//!   /send-file @user file — Send a file
//!   /help                — Show commands
//!   /quit                — Exit

use colored::Colorize;
use std::collections::HashMap;
use std::sync::Arc;
use std::io::{self, BufRead, Write};
use client_core::message::MessageType;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

/// Known contacts cache: address → username (if resolved)
type ContactMap = Arc<tokio::sync::RwLock<HashMap<String, String>>>;

pub async fn run() -> Result<(), String> {
    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    let our_short = if our_addr.len() > 10 {
        format!("{}...{}", &our_addr[..6], &our_addr[our_addr.len()-4..])
    } else {
        our_addr.clone()
    };

    println!();
    println!("  ┌─────────────────────────────────────────────────────┐");
    println!("  │  {} {}  │", "⚔️  Cipher".cyan().bold(), "Interactive Shell".white().bold());
    println!("  ├─────────────────────────────────────────────────────┤");
    println!("  │  {} {}                     │", "You:".dimmed(), our_short.cyan());
    println!("  │  {} {}                               │", "E2EE:".dimmed(), "AES-256-GCM ✓".green());
    println!("  │                                                     │");
    println!("  │  {} {}                │", "Send:".dimmed(), "@username message".white());
    println!("  │  {} {}          │", "Focus:".dimmed(), "/chat @username".white());
    println!("  │  {} {}                 │", "Help:".dimmed(), "/help".white());
    println!("  │  {} {}           │", "Exit:".dimmed(), "/quit or Ctrl+C".white());
    println!("  └─────────────────────────────────────────────────────┘");
    println!();

    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for transport
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    println!("  {} Connected to relay", "✓".green());
    println!();

    // Contacts cache
    let contacts: ContactMap = Arc::new(tokio::sync::RwLock::new(HashMap::new()));

    // Focus peer (None = show all, Some(addr) = only show that peer's messages)
    let focus_peer: Arc<tokio::sync::RwLock<Option<String>>> = Arc::new(tokio::sync::RwLock::new(None));

    // Spawn background receiver
    let client_recv = client.clone();
    let contacts_recv = contacts.clone();
    let focus_recv = focus_peer.clone();
    let recv_handle = tokio::spawn(async move {
        loop {
            client_recv.process_incoming().await;
            let messages = client_recv.receive_all().await;

            for msg in &messages {
                let time = msg.timestamp.with_timezone(&chrono::Local).format("%H:%M:%S");
                let sender_short = if msg.sender.len() > 10 {
                    format!("{}...{}", &msg.sender[..6], &msg.sender[msg.sender.len()-4..])
                } else {
                    msg.sender.clone()
                };

                // Check if we have a username for this sender
                let display_name = {
                    let c = contacts_recv.read().await;
                    c.get(&msg.sender.to_lowercase()).cloned().unwrap_or(sender_short.clone())
                };

                // Check focus filter
                let focus = focus_recv.read().await;
                if let Some(ref focused) = *focus {
                    if msg.sender.to_lowercase() != focused.to_lowercase() {
                        continue; // Skip messages not from focused peer
                    }
                }

                match &msg.msg_type {
                    MessageType::Text => {
                        let text = String::from_utf8_lossy(&msg.payload);
                        println!(); // New line — preserves what user is typing
                        println!(
                            "  {} {} {} {}",
                            format!("[{}]", time).dimmed(),
                            display_name.cyan().bold(),
                            "◀".cyan(),
                            text.white()
                        );
                        // Re-show prompt
                        let fp = focus_recv.read().await;
                        if let Some(ref f) = *fp {
                            let f_short = if f.len() > 10 {
                                format!("{}...{}", &f[..6], &f[f.len()-4..])
                            } else {
                                f.clone()
                            };
                            print!("  {} {} ", f_short.cyan(), "▶".green().bold());
                        } else {
                            print!("  {} ", "▶".green().bold());
                        }
                        let _ = io::stdout().flush();
                    }
                    MessageType::File(meta) => {
                        // Auto-save file
                        let download_dir = dirs::download_dir()
                            .unwrap_or_else(|| std::path::PathBuf::from("."))
                            .join("cipher-files");
                        std::fs::create_dir_all(&download_dir).ok();
                        let safe_name = meta.file_name.replace('/', "_").replace('\\', "_");
                        let dest = download_dir.join(&safe_name);
                        let _ = std::fs::write(&dest, &msg.payload);

                        println!();
                        println!(
                            "  {} {} {} 📎 {} ({})",
                            format!("[{}]", time).dimmed(),
                            display_name.cyan().bold(),
                            "◀".cyan(),
                            meta.file_name.yellow(),
                            format!("{} bytes", meta.size_bytes).dimmed(),
                        );
                        println!(
                            "  {} {}",
                            "  💾 Saved:".green(),
                            dest.display().to_string().dimmed(),
                        );
                        let fp = focus_recv.read().await;
                        if let Some(ref f) = *fp {
                            let f_short = if f.len() > 10 {
                                format!("{}...{}", &f[..6], &f[f.len()-4..])
                            } else {
                                f.clone()
                            };
                            print!("  {} {} ", f_short.cyan(), "▶".green().bold());
                        } else {
                            print!("  {} ", "▶".green().bold());
                        }
                        let _ = io::stdout().flush();
                    }
                    _ => {}
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
    });

    // Show initial prompt
    print!("  {} ", "▶".green().bold());
    let _ = io::stdout().flush();

    // Main input loop
    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = line.map_err(|e| format!("Input error: {e}"))?;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            let fp = focus_peer.read().await;
            if let Some(ref f) = *fp {
                let f_short = if f.len() > 10 {
                    format!("{}...{}", &f[..6], &f[f.len()-4..])
                } else {
                    f.clone()
                };
                print!("  {} {} ", f_short.cyan(), "▶".green().bold());
            } else {
                print!("  {} ", "▶".green().bold());
            }
            let _ = io::stdout().flush();
            continue;
        }

        // ── Commands (with '/' or typed directly) ────
        let is_slash_cmd = trimmed.starts_with('/');
        let (cmd, arg) = if is_slash_cmd {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            (parts[0].to_lowercase(), parts.get(1).map(|s| s.trim()).unwrap_or(""))
        } else {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            let first = parts[0].to_lowercase();
            match first.as_str() {
                "help" | "quit" | "exit" | "q" | "register" | "lookup" | "whoami" | "id" | "me" |
                "balance" | "bal" | "transfer" | "send-tks" | "pay" | "status" | "node-info" | "info" |
                "mode" | "group" | "groups" | "channel" | "channels" | "contacts" | "clear" | "all" => {
                    (format!("/{}", first), parts.get(1).map(|s| s.trim()).unwrap_or(""))
                }
                _ => ("".to_string(), "")
            }
        };

        if !cmd.is_empty() {
            match cmd.as_str() {
                "/quit" | "/exit" | "/q" => {
                    println!();
                    println!("  {} Goodbye!", "👋".yellow());
                    break;
                }
                "/help" | "/h" => {
                    println!();
                    println!("  {}", "⚔️  CIPHER CLI COMMANDS ⚔️".cyan().bold());
                    println!();
                    println!("  {}", "─── 💬 Messaging ────────────────────────────────".dimmed());
                    println!("  {} {}   {}", "@user".cyan(), "<msg>".white(), "— Send an encrypted message".dimmed());
                    println!("  {} {}  {}", "/chat".cyan(), "<@user>".white(), "— Focus on one conversation".dimmed());
                    println!("  {} {}   {}", "/all".cyan(), "".white(), "— Show all conversations (unfocus)".dimmed());
                    println!("  {} {}  {}", "/file".cyan(), "<@user> <path>".white(), "— Send an encrypted file".dimmed());
                    println!("  {} {}      {}", "/contacts".cyan(), "".white(), "— List known contacts".dimmed());
                    println!("  {} {}         {}", "/clear".cyan(), "".white(), "— Clear screen".dimmed());
                    println!();
                    println!("  {}", "─── 👥 Groups & Channels ────────────────────────".dimmed());
                    println!("  {} {}   {}", "/group".cyan(), "create <name>".white(), "— Create multi-user group".dimmed());
                    println!("  {} {}     {}", "/group".cyan(), "list".white(), "— List your groups".dimmed());
                    println!("  {} {}     {}", "/group".cyan(), "info <id>".white(), "— View group members".dimmed());
                    println!("  {} {}  {}", "/group".cyan(), "add <id> <@user>".white(), "— Add member to group".dimmed());
                    println!("  {} {}  {}", "/group".cyan(), "send <id> <msg>".white(), "— Broadcast to group".dimmed());
                    println!("  {} {}    {}", "/group".cyan(), "leave <id>".white(), "— Leave group".dimmed());
                    println!("  {} {} {}", "/channel".cyan(), "create <name> [handle]".white(), "— Create broadcast channel".dimmed());
                    println!("  {} {}   {}", "/channel".cyan(), "list".white(), "— List broadcast channels".dimmed());
                    println!("  {} {}   {}", "/channel".cyan(), "post <id> <msg>".white(), "— Publish broadcast post".dimmed());
                    println!("  {} {}    {}", "/channel".cyan(), "sub <id>".white(), "— Subscribe to channel".dimmed());
                    println!();
                    println!("  {}", "─── ⛓️  TKS Blockchain & Wallet ─────────────────".dimmed());
                    println!("  {} {}  {}", "/register".cyan(), "<@username>".white(), "— Register handle on TKS (FREE)".dimmed());
                    println!("  {} {}    {}", "/lookup".cyan(), "<@user|0xaddr>".white(), "— Query on-chain identity".dimmed());
                    println!("  {} {}        {}", "/whoami".cyan(), "".white(), "— Show your address & keys".dimmed());
                    println!("  {} {}    {}", "/balance".cyan(), "[0xaddr]".white(), "— Check TKS token balance".dimmed());
                    println!("  {} {}  {}", "/transfer".cyan(), "<@user> <amt>".white(), "— Send TKS native coins".dimmed());
                    println!("  {} {}     {}", "/node-info".cyan(), "".white(), "— Blockchain height & status".dimmed());
                    println!();
                    println!("  {}", "─── 🛡️  Privacy & Network ────────────────────────".dimmed());
                    println!("  {} {}        {}", "/status".cyan(), "".white(), "— Check relay & P2P connectivity".dimmed());
                    println!("  {} {}   {}", "/mode".cyan(), "[iroh|direct|tor|nym]".white(), "— View or toggle privacy mode".dimmed());
                    println!("  {} {}          {}", "/quit".cyan(), "".white(), "— Exit chat".dimmed());
                    println!();
                }
                "/register" | "/reg" => {
                    if arg.is_empty() {
                        println!("  {} Usage: /register @username", "!".red());
                    } else {
                        if let Err(e) = super::register::run(arg).await {
                            println!("  {} {}", "✗".red(), e);
                        }
                    }
                }
                "/lookup" | "/l" => {
                    if arg.is_empty() {
                        println!("  {} Usage: /lookup @username or 0xAddress", "!".red());
                    } else {
                        if let Err(e) = super::lookup::run(arg).await {
                            println!("  {} {}", "✗".red(), e);
                        }
                    }
                }
                "/whoami" | "/id" | "/me" => {
                    if let Err(e) = super::whoami::run().await {
                        println!("  {} {}", "✗".red(), e);
                    }
                }
                "/balance" | "/bal" => {
                    let addr_opt = if arg.is_empty() { None } else { Some(arg) };
                    if let Err(e) = super::balance::run(addr_opt).await {
                        println!("  {} {}", "✗".red(), e);
                    }
                }
                "/transfer" | "/send-tks" | "/pay" => {
                    let parts: Vec<&str> = arg.splitn(2, ' ').collect();
                    if parts.len() < 2 || parts[0].is_empty() || parts[1].trim().is_empty() {
                        println!("  {} Usage: /transfer <@user|0xaddr> <amount>", "!".red());
                    } else {
                        if let Err(e) = super::transfer::run(parts[0], parts[1].trim()).await {
                            println!("  {} {}", "✗".red(), e);
                        }
                    }
                }
                "/status" => {
                    if let Err(e) = super::status::run().await {
                        println!("  {} {}", "✗".red(), e);
                    }
                }
                "/node-info" | "/info" => {
                    if let Err(e) = super::node_info::run().await {
                        println!("  {} {}", "✗".red(), e);
                    }
                }
                "/mode" => {
                    let mode_opt = if arg.is_empty() { None } else { Some(arg) };
                    if let Err(e) = super::mode::run(mode_opt).await {
                        println!("  {} {}", "✗".red(), e);
                    }
                }
                "/group" | "/groups" | "/g" => {
                    let parts: Vec<String> = arg.split_whitespace().map(|s| s.to_string()).collect();
                    if parts.is_empty() {
                        let _ = super::groups::run("help", &[]).await;
                    } else {
                        let action = &parts[0];
                        let rest = &parts[1..];
                        if let Err(e) = super::groups::run(action, rest).await {
                            println!("  {} {}", "✗".red(), e);
                        }
                    }
                }
                "/channel" | "/channels" | "/ch" => {
                    let parts: Vec<String> = arg.split_whitespace().map(|s| s.to_string()).collect();
                    if parts.is_empty() {
                        let _ = super::channels::run("help", &[]).await;
                    } else {
                        let action = &parts[0];
                        let rest = &parts[1..];
                        if let Err(e) = super::channels::run(action, rest).await {
                            println!("  {} {}", "✗".red(), e);
                        }
                    }
                }
                "/file" | "/f" | "/send-file" => {
                    // /file @user /path/to/file
                    let file_parts: Vec<&str> = arg.splitn(2, ' ').collect();
                    if file_parts.len() < 2 || file_parts[0].is_empty() || file_parts[1].trim().is_empty() {
                        // If focused, allow just /file /path/to/file
                        let fp = focus_peer.read().await.clone();
                        if let Some(ref peer_addr) = fp {
                            if !arg.is_empty() {
                                let file_path = arg.trim();
                                match super::send_file::run_with_client(&client, peer_addr, file_path).await {
                                    Ok(_) => {}
                                    Err(e) => println!("  {} {}", "✗".red(), e),
                                }
                            } else {
                                println!("  {} Usage: /file /path/to/file", "!".red());
                            }
                        } else {
                            println!("  {} Usage: /file @username /path/to/file", "!".red());
                        }
                    } else {
                        let target = file_parts[0];
                        let file_path = file_parts[1].trim();

                        let resolved = match super::resolve::resolve_recipient(target) {
                            Ok(addr) => addr,
                            Err(e) => {
                                println!("  {} {}", "✗".red(), e);
                                print!("  {} ", "▶".green().bold());
                                let _ = io::stdout().flush();
                                continue;
                            }
                        };

                        match super::send_file::run_with_client(&client, &resolved, file_path).await {
                            Ok(_) => {
                                // Cache contact
                                let display = if target.starts_with('@') || !target.starts_with("0x") {
                                    target.trim_start_matches('@').to_string()
                                } else {
                                    if resolved.len() > 10 {
                                        format!("{}...{}", &resolved[..6], &resolved[resolved.len()-4..])
                                    } else {
                                        resolved.clone()
                                    }
                                };
                                contacts.write().await.insert(resolved.to_lowercase(), display);
                            }
                            Err(e) => println!("  {} {}", "✗".red(), e),
                        }
                    }
                }
                "/chat" | "/c" => {
                    if arg.is_empty() {
                        println!("  {} Usage: /chat @username", "!".red());
                    } else {
                        let resolved = match super::resolve::resolve_recipient(arg) {
                            Ok(addr) => addr,
                            Err(e) => {
                                println!("  {} {}", "✗".red(), e);
                                print!("  {} ", "▶".green().bold());
                                let _ = io::stdout().flush();
                                continue;
                            }
                        };
                        // Store contact mapping
                        let display = if arg.starts_with('@') || !arg.starts_with("0x") {
                            arg.trim_start_matches('@').to_string()
                        } else {
                            if resolved.len() > 10 {
                                format!("{}...{}", &resolved[..6], &resolved[resolved.len()-4..])
                            } else {
                                resolved.clone()
                            }
                        };
                        contacts.write().await.insert(resolved.to_lowercase(), display.clone());
                        *focus_peer.write().await = Some(resolved);
                        println!();
                        println!("  {} Chatting with {}", "💬".green(), display.cyan().bold());
                        println!("  {} Type /all to see all conversations", "💡".dimmed());
                        println!();
                    }
                }
                "/all" | "/a" => {
                    *focus_peer.write().await = None;
                    println!("  {} Showing all conversations", "📥".green());
                    println!();
                }
                "/contacts" | "/ls" => {
                    let c = contacts.read().await;
                    if c.is_empty() {
                        println!("  {} No contacts yet. Chat with someone first!", "📭".dimmed());
                    } else {
                        println!();
                        println!("  {}", "Contacts:".white().bold());
                        for (addr, name) in c.iter() {
                            let short = if addr.len() > 10 {
                                format!("{}...{}", &addr[..6], &addr[addr.len()-4..])
                            } else {
                                addr.clone()
                            };
                            println!("    {} {} {}", "•".cyan(), name.cyan().bold(), short.dimmed());
                        }
                        println!();
                    }
                }
                "/clear" | "/cls" => {
                    print!("\x1b[2J\x1b[H");
                }
                _ => {
                    println!("  {} Unknown command. Type /help", "?".yellow());
                }
            }

            let fp = focus_peer.read().await;
            if let Some(ref f) = *fp {
                let f_short = if f.len() > 10 {
                    format!("{}...{}", &f[..6], &f[f.len()-4..])
                } else {
                    f.clone()
                };
                print!("  {} {} ", f_short.cyan(), "▶".green().bold());
            } else {
                print!("  {} ", "▶".green().bold());
            }
            let _ = io::stdout().flush();
            continue;
        }

        // ── @username message ────────────────────────
        if trimmed.starts_with('@') || trimmed.starts_with("0x") {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() < 2 || parts[1].trim().is_empty() {
                println!("  {} Usage: @username your message here", "!".red());
                print!("  {} ", "▶".green().bold());
                let _ = io::stdout().flush();
                continue;
            }

            let target = parts[0];
            let message = parts[1].trim();

            let resolved = match super::resolve::resolve_recipient(target) {
                Ok(addr) => addr,
                Err(e) => {
                    println!("  {} {}", "✗".red(), e);
                    print!("  {} ", "▶".green().bold());
                    let _ = io::stdout().flush();
                    continue;
                }
            };

            // Cache contact
            let display = if target.starts_with('@') || !target.starts_with("0x") {
                target.trim_start_matches('@').to_string()
            } else {
                if resolved.len() > 10 {
                    format!("{}...{}", &resolved[..6], &resolved[resolved.len()-4..])
                } else {
                    resolved.clone()
                }
            };
            contacts.write().await.insert(resolved.to_lowercase(), display.clone());

            match client.send_text(&resolved, message).await {
                Ok(_) => {
                    let time = chrono::Local::now().format("%H:%M:%S");
                    print!("\x1b[A\x1b[2K\r"); // Move up to overwrite stdin echo
                    println!(
                        "  {} {} {}",
                        format!("[{}]", time).dimmed(),
                        "▶".green().bold(),
                        message.white(),
                    );
                }
                Err(e) => {
                    println!("  {} Send failed: {}", "✗".red(), e);
                }
            }

            let fp = focus_peer.read().await;
            if let Some(ref f) = *fp {
                let f_short = if f.len() > 10 {
                    format!("{}...{}", &f[..6], &f[f.len()-4..])
                } else {
                    f.clone()
                };
                print!("  {} {} ", f_short.cyan(), "▶".green().bold());
            } else {
                print!("  {} ", "▶".green().bold());
            }
            let _ = io::stdout().flush();
            continue;
        }

        // ── Focused mode: just type to send ──────────
        let fp = focus_peer.read().await.clone();
        if let Some(ref peer_addr) = fp {
            match client.send_text(peer_addr, trimmed).await {
                Ok(_) => {
                    let time = chrono::Local::now().format("%H:%M:%S");
                    print!("\x1b[A\x1b[2K\r"); // Move up to overwrite stdin echo
                    println!(
                        "  {} {} {}",
                        format!("[{}]", time).dimmed(),
                        "▶".green().bold(),
                        trimmed.white(),
                    );
                }
                Err(e) => {
                    println!("  {} Send failed: {}", "✗".red(), e);
                }
            }

            let f_short = if peer_addr.len() > 10 {
                format!("{}...{}", &peer_addr[..6], &peer_addr[peer_addr.len()-4..])
            } else {
                peer_addr.clone()
            };
            print!("  {} {} ", f_short.cyan(), "▶".green().bold());
            let _ = io::stdout().flush();
            continue;
        }

        // ── No focus, not a command, not @user ───────
        println!("  {} Type @username message, or /chat @username to focus", "💡".yellow());
        print!("  {} ", "▶".green().bold());
        let _ = io::stdout().flush();
    }

    recv_handle.abort();
    println!();
    Ok(())
}
