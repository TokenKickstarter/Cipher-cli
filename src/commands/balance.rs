//! `cipher-cli balance` — Check TKS token balance via blockchain RPC

use colored::Colorize;
use client_core::tks_rpc::TksRpcClient;
use crate::identity_store;

pub async fn run(address: Option<&str>) -> Result<(), String> {
    // If no address given, use our own
    let (query_addr, is_own) = if let Some(addr) = address {
        (addr.to_string(), false)
    } else {
    let identity = identity_store::get_identity()?;
        (identity.evm_address(), true)
    };

    println!();
    println!("{}", format!("Querying balance for {}...", query_addr).yellow());

    let rpc = TksRpcClient::default();

    if !rpc.is_connected() {
        return Err("Cannot connect to TKS node at rpc.tokenkickstarter.com".to_string());
    }

    // Query the System.Account storage for this address
    // Storage key: twox128("System") ++ twox128("Account") ++ blake2_128_concat(address_bytes)
    let clean_addr = query_addr.strip_prefix("0x").unwrap_or(&query_addr);
    let address_bytes = hex::decode(clean_addr)
        .map_err(|e| format!("Invalid address: {}", e))?;

    if address_bytes.len() != 20 {
        return Err("Address must be 20 bytes (H160)".to_string());
    }

    // Build the storage key for System.Account
    let pallet_hash = twox_128(b"System");
    let storage_hash = twox_128(b"Account");
    let key_hash = blake2_128_concat(&address_bytes);

    let storage_key = format!(
        "0x{}{}{}",
        hex::encode(&pallet_hash),
        hex::encode(&storage_hash),
        hex::encode(&key_hash),
    );

    // Query via state_getStorage RPC
    let result = query_storage(&rpc, &storage_key)?;

    let (free_balance, reserved, nonce) = match result {
        Some(data) => parse_account_info(&data)?,
        None => (0u128, 0u128, 0u32),
    };

    // Format balance (18 decimals for TKS)
    let tks_free = format_tks(free_balance);
    let tks_reserved = format_tks(reserved);

    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║              TKS Balance                         ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".cyan().bold());
    println!();

    if is_own {
        println!("  {} {}", "Your Address:".dimmed(), query_addr.cyan().bold());
    } else {
        println!("  {} {}", "Address:     ".dimmed(), query_addr.white().bold());
    }
    println!();
    println!("  {} {} TKS", "Free Balance:".dimmed(), tks_free.green().bold());
    println!("  {} {} TKS", "Reserved:    ".dimmed(), tks_reserved.yellow());
    println!("  {} {}", "Nonce:       ".dimmed(), nonce.to_string().white());
    println!();

    // Also check if they have a username
    match rpc.query_username_reverse(&query_addr) {
        Ok(Some(username)) => {
            println!("  {} {}", "Username:    ".dimmed(), format!("@{}", username).cyan().bold());
            println!();
        }
        _ => {}
    }

    Ok(())
}

/// Query storage via the TKS RPC client
fn query_storage(_rpc: &TksRpcClient, key: &str) -> Result<Option<Vec<u8>>, String> {
    // We need to use the raw RPC call mechanism
    // TksRpcClient doesn't expose a raw state_getStorage, so we use ureq directly
    let endpoint = client_core::tks_rpc::LOCAL_RPC_HTTP;
    let request = serde_json::json!({
        "id": 1,
        "jsonrpc": "2.0",
        "method": "state_getStorage",
        "params": [key]
    });

    let resp = ureq::post(endpoint)
        .timeout(std::time::Duration::from_secs(10))
        .set("Content-Type", "application/json")
        .send_string(&request.to_string())
        .map_err(|e| format!("RPC request failed: {}", e))?;

    let json: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("JSON decode error: {}", e))?;

    match json["result"].as_str() {
        Some(hex_val) if !hex_val.is_empty() && hex_val != "0x" => {
            let hex_val = hex_val.strip_prefix("0x").unwrap_or(hex_val);
            let bytes = hex::decode(hex_val)
                .map_err(|e| format!("Hex decode error: {}", e))?;
            Ok(Some(bytes))
        }
        _ => Ok(None),
    }
}

/// Parse Substrate AccountInfo (nonce + data { free, reserved, ... })
/// SCALE layout: nonce(u32) + consumers(u32) + providers(u32) + sufficients(u32) + data { free(u128), reserved(u128), ... }
fn parse_account_info(data: &[u8]) -> Result<(u128, u128, u32), String> {
    if data.len() < 32 {
        // Not enough data — account doesn't exist or has zero balance
        return Ok((0, 0, 0));
    }

    // nonce: first 4 bytes (u32 LE)
    let nonce = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // Skip: consumers(4) + providers(4) + sufficients(4) = 12 bytes
    // data.free starts at offset 16
    if data.len() < 48 {
        return Ok((0, 0, nonce));
    }

    // free: u128 LE at offset 16
    let mut free_bytes = [0u8; 16];
    free_bytes.copy_from_slice(&data[16..32]);
    let free = u128::from_le_bytes(free_bytes);

    // reserved: u128 LE at offset 32
    let mut reserved_bytes = [0u8; 16];
    reserved_bytes.copy_from_slice(&data[32..48]);
    let reserved = u128::from_le_bytes(reserved_bytes);

    Ok((free, reserved, nonce))
}

/// Format a raw balance (u128, 18 decimals) as a human-readable TKS amount
fn format_tks(raw: u128) -> String {
    let decimals = 18u32;
    let divisor = 10u128.pow(decimals);
    let whole = raw / divisor;
    let frac = raw % divisor;

    if frac == 0 {
        format!("{}", whole)
    } else {
        // Show up to 4 decimal places
        let frac_str = format!("{:018}", frac);
        let trimmed = frac_str.trim_end_matches('0');
        let display_frac = if trimmed.len() > 4 { &trimmed[..4] } else { trimmed };
        format!("{}.{}", whole, display_frac)
    }
}

// ── Substrate Hashing Helpers ──

fn twox_128(data: &[u8]) -> [u8; 16] {
    use std::hash::Hasher;
    let mut h0 = twox_hash::XxHash64::with_seed(0);
    h0.write(data);
    let r0 = h0.finish();
    let mut h1 = twox_hash::XxHash64::with_seed(1);
    h1.write(data);
    let r1 = h1.finish();
    let mut result = [0u8; 16];
    result[..8].copy_from_slice(&r0.to_le_bytes());
    result[8..].copy_from_slice(&r1.to_le_bytes());
    result
}

fn blake2_128_concat(data: &[u8]) -> Vec<u8> {
    use blake2::{Blake2b, Digest};
    type Blake2b128 = Blake2b<typenum::U16>;
    let hash = Blake2b128::digest(data);
    let mut result = hash.to_vec();
    result.extend_from_slice(data);
    result
}

// Re-export typenum for blake2 generic
use blake2::digest::typenum;
