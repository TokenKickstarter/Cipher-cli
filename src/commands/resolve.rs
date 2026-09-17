//! Shared helper: resolve @username → 0x address via TKS blockchain

use colored::Colorize;
use client_core::tks_rpc::TksRpcClient;
use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

/// Cache of resolved usernames → addresses (avoids repeated RPC calls + output)
static RESOLVE_CACHE: Lazy<Mutex<HashMap<String, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

/// Resolve a recipient identifier to an 0x EVM address.
///
/// - If it starts with `0x` and is 42 chars, return as-is (already an address)
/// - If it starts with `@` or is a plain name, look it up on TKS blockchain
/// - Caches results so repeated lookups are instant and silent
pub fn resolve_recipient(input: &str) -> Result<String, String> {
    let trimmed = input.trim();

    // Already an 0x address
    if trimmed.starts_with("0x") && trimmed.len() == 42 {
        return Ok(trimmed.to_string());
    }

    // Treat as @username — resolve via TKS blockchain
    let username = trimmed.trim_start_matches('@').to_lowercase();

    // Check cache first
    if let Ok(cache) = RESOLVE_CACHE.lock() {
        if let Some(addr) = cache.get(&username) {
            return Ok(addr.clone());
        }
    }

    eprint!("  {} Resolving @{}...", "🔍".dimmed(), username);

    let rpc = TksRpcClient::default();

    if !rpc.is_connected() {
        eprintln!();
        return Err("Cannot connect to TKS node at rpc.tokenkickstarter.com".to_string());
    }

    match rpc.query_username(&username) {
        Ok(Some(address)) => {
            eprintln!(" {}", "✓".green());
            // Cache it
            if let Ok(mut cache) = RESOLVE_CACHE.lock() {
                cache.insert(username, address.clone());
            }
            Ok(address)
        }
        Ok(None) => {
            eprintln!();
            Err(format!(
                "@{} is not registered on TKS blockchain. Ask them to run: cipher-cli register @{}",
                username, username
            ))
        }
        Err(e) => {
            eprintln!();
            Err(format!("Username lookup failed: {}", e))
        }
    }
}
