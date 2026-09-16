//! Shared helper: resolve @username → 0x address via TKS blockchain

use colored::Colorize;
use client_core::tks_rpc::TksRpcClient;

/// Resolve a recipient identifier to an 0x EVM address.
///
/// - If it starts with `0x` and is 42 chars, return as-is (already an address)
/// - If it starts with `@` or is a plain name, look it up on TKS blockchain
pub fn resolve_recipient(input: &str) -> Result<String, String> {
    let trimmed = input.trim();

    // Already an 0x address
    if trimmed.starts_with("0x") && trimmed.len() == 42 {
        return Ok(trimmed.to_string());
    }

    // Treat as @username — resolve via TKS blockchain
    let username = trimmed.trim_start_matches('@').to_lowercase();
    println!("  {} Resolving @{} on TKS blockchain...", "🔍".cyan(), username);

    let rpc = TksRpcClient::default();

    if !rpc.is_connected() {
        return Err("Cannot connect to TKS node at rpc.tokenkickstarter.com".to_string());
    }

    match rpc.query_username(&username) {
        Ok(Some(address)) => {
            println!("  {} @{} → {}", "✅".green(), username, address.cyan().bold());
            Ok(address)
        }
        Ok(None) => {
            Err(format!(
                "@{} is not registered on TKS blockchain. Ask them to run: cipher-cli register @{}",
                username, username
            ))
        }
        Err(e) => {
            Err(format!("Username lookup failed: {}", e))
        }
    }
}
