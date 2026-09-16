//! `cipher-cli lookup` — Resolve @username → address (or reverse) via TKS blockchain

use colored::Colorize;
use client_core::tks_rpc::TksRpcClient;


pub async fn run(query: &str) -> Result<(), String> {
    println!();
    println!("{}", format!("Looking up \"{}\" on TKS blockchain...", query).yellow());

    // Determine if this is a @username lookup or address → username reverse lookup
    if query.starts_with("0x") && query.len() >= 42 {
        // Reverse lookup: address → @username
        println!("  {} Reverse lookup: address → @username", "🔍".cyan());

        let rpc = TksRpcClient::default();

        if !rpc.is_connected() {
            return Err("Cannot connect to TKS node at rpc.tokenkickstarter.com".to_string());
        }

        match rpc.query_username_reverse(query) {
            Ok(Some(username)) => {
                println!();
                println!("  {} {} → {}", "✅".green(), query.white().bold(), format!("@{}", username).cyan().bold());
                println!();
            }
            Ok(None) => {
                println!();
                println!("  {} No username registered for {}", "📭".yellow(), query.white().bold());
                println!();
            }
            Err(e) => {
                return Err(format!("RPC query failed: {}", e));
            }
        }
    } else {
        // Forward lookup: @username → address
        let clean_name = query.trim_start_matches('@').to_lowercase();
        println!("  {} Forward lookup: @{} → address", "🔍".cyan(), clean_name);

        let rpc = TksRpcClient::default();

        if !rpc.is_connected() {
            return Err("Cannot connect to TKS node at rpc.tokenkickstarter.com".to_string());
        }

        match rpc.query_username(&clean_name) {
            Ok(Some(address)) => {
                println!();
                println!("  {} {} → {}", "✅".green(), format!("@{}", clean_name).cyan().bold(), address.white().bold());
                println!();
            }
            Ok(None) => {
                println!();
                println!("  {} @{} is not registered on TKS", "📭".yellow(), clean_name);
                println!();
            }
            Err(e) => {
                return Err(format!("RPC query failed: {}", e));
            }
        }
    }

    Ok(())
}
