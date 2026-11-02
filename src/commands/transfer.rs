//! `cipher-cli transfer` — Send TKS tokens to an address or @username

use colored::Colorize;
use serde_json::json;
use sha3::{Digest, Keccak256};
use crate::identity_store;

const TKS_CHAIN_ID: u64 = 7779;
const RPC_ENDPOINT: &str = "https://rpc.tokenkickstarter.com";

pub async fn run(recipient: &str, amount_str: &str) -> Result<(), String> {
    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    // 1. Resolve recipient (@username → 0x address)
    let recipient_addr = super::resolve::resolve_recipient(recipient)?;
    let clean_to = recipient_addr.strip_prefix("0x").unwrap_or(&recipient_addr);
    let to_bytes = hex::decode(clean_to)
        .map_err(|e| format!("Invalid recipient address: {}", e))?;
    if to_bytes.len() != 20 {
        return Err("Recipient address must be 20 bytes (H160)".to_string());
    }

    // 2. Parse amount (18 decimals)
    let amount_wei = parse_tks_amount(amount_str)?;

    println!();
    println!("{}", "══════════════════════════════════════════════════".cyan());
    println!("  {} {}", "💸".bold(), "TKS TOKEN TRANSFER".cyan().bold());
    println!("{}", "══════════════════════════════════════════════════".cyan());
    println!("  {} {}", "From:     ".dimmed(), our_addr.cyan());
    println!("  {} {} ({})", "To:       ".dimmed(), recipient_addr.green(), recipient);
    println!("  {} {} TKS ({} wei)", "Amount:   ".dimmed(), amount_str.bold(), amount_wei);
    println!("  {} {}", "Network:  ".dimmed(), "TKS L1 (Chain ID 7779)".white());
    println!();

    // 3. Query current nonce and gas price from RPC
    println!("  {} Querying blockchain state...", "⏳".yellow());
    let nonce = get_nonce(&our_addr)?;
    let gas_price = get_gas_price().unwrap_or(500_000_000); // 0.5 Gwei fallback
    let gas_limit = 21_000u64;

    println!("  {} Nonce: {}, Gas Price: {} Gwei", "ℹ".blue(), nonce, gas_price as f64 / 1e9);

    // 4. Build unsigned EIP-155 transaction
    // Format: [nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]
    let unsigned_rlp = encode_unsigned_eip155(
        nonce,
        gas_price,
        gas_limit,
        &to_bytes,
        amount_wei,
        &[],
        TKS_CHAIN_ID,
    );

    // 5. Sign transaction hash with secp256k1
    let tx_hash = Keccak256::digest(&unsigned_rlp);
    let signing_key = identity.secp256k1_signing_key();

    let (sig, rec_id) = signing_key
        .sign_prehash_recoverable(&tx_hash)
        .map_err(|e| format!("Failed to sign transaction: {}", e))?;

    let sig_bytes = sig.to_bytes();
    let r = &sig_bytes[..32];
    let s = &sig_bytes[32..64];
    let v = rec_id.to_byte() as u64 + TKS_CHAIN_ID * 2 + 35;

    // 6. Build signed transaction RLP
    // Format: [nonce, gas_price, gas_limit, to, value, data, v, r, s]
    let signed_rlp = encode_signed_eip155(
        nonce,
        gas_price,
        gas_limit,
        &to_bytes,
        amount_wei,
        &[],
        v,
        r,
        s,
    );

    let raw_hex = format!("0x{}", hex::encode(&signed_rlp));

    // 7. Submit transaction to RPC
    println!("  {} Broadcasting transaction to TKS network...", "📡".yellow());
    let res = rpc_call("eth_sendRawTransaction", json!([raw_hex]))?;

    let tx_hash_str = res
        .as_str()
        .ok_or_else(|| "RPC returned non-string tx hash".to_string())?;

    println!();
    println!("╔══════════════════════════════════════════════════╗");
    println!("║          ✅ Transfer Submitted!                 ║");
    println!("╚══════════════════════════════════════════════════╝");
    println!("  {} {}", "Tx Hash: ".dimmed(), tx_hash_str.green().bold());
    println!("  {} {}", "Amount:  ".dimmed(), format!("{} TKS", amount_str).bold());
    println!("  {} {}", "To:      ".dimmed(), recipient_addr.cyan());
    println!("  {} https://scan.tokenkickstarter.com/tx/{}", "Explorer:".dimmed(), tx_hash_str);
    println!();

    Ok(())
}

fn parse_tks_amount(amount_str: &str) -> Result<u128, String> {
    let clean = amount_str.trim();
    if clean.is_empty() {
        return Err("Amount cannot be empty".to_string());
    }

    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() > 2 {
        return Err("Invalid number format".to_string());
    }

    let whole: u128 = parts[0]
        .parse()
        .map_err(|_| "Invalid whole number in amount".to_string())?;

    let mut wei = whole
        .checked_mul(1_000_000_000_000_000_000)
        .ok_or_else(|| "Amount overflow".to_string())?;

    if parts.len() == 2 {
        let frac_str = parts[1];
        if frac_str.len() > 18 {
            return Err("Too many decimals (max 18)".to_string());
        }
        let padded = format!("{:0<18}", frac_str);
        let frac: u128 = padded
            .parse()
            .map_err(|_| "Invalid fraction in amount".to_string())?;
        wei = wei
            .checked_add(frac)
            .ok_or_else(|| "Amount overflow".to_string())?;
    }

    Ok(wei)
}

fn get_nonce(addr: &str) -> Result<u64, String> {
    let res = rpc_call("eth_getTransactionCount", json!([addr, "latest"]))?;
    let hex_str = res.as_str().ok_or_else(|| "Expected hex string for nonce")?;
    parse_hex_u64(hex_str)
}

fn get_gas_price() -> Result<u64, String> {
    let res = rpc_call("eth_gasPrice", json!([]))?;
    let hex_str = res.as_str().ok_or_else(|| "Expected hex string for gas price")?;
    parse_hex_u64(hex_str)
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(clean, 16).map_err(|e| format!("Invalid hex int: {e}"))
}

fn rpc_call(method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp = ureq::post(RPC_ENDPOINT)
        .set("Content-Type", "application/json")
        .set("User-Agent", "cipher-cli/0.1.1")
        .send_json(body)
        .map_err(|e| format!("RPC network error: {}", e))?;

    let json_resp: serde_json::Value = resp
        .into_json()
        .map_err(|e| format!("Failed to parse RPC response: {}", e))?;

    if let Some(err) = json_resp.get("error") {
        return Err(format!("RPC error: {}", err["message"].as_str().unwrap_or("unknown")));
    }

    json_resp
        .get("result")
        .cloned()
        .ok_or_else(|| "Missing result in RPC response".to_string())
}

// ─── Lightweight RLP Encoding ──────────────────────────────────────────

fn rlp_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        vec![data[0]]
    } else if data.len() <= 55 {
        let mut out = Vec::with_capacity(1 + data.len());
        out.push(0x80 + data.len() as u8);
        out.extend_from_slice(data);
        out
    } else {
        let len_bytes = to_min_be(data.len() as u128);
        let mut out = Vec::with_capacity(1 + len_bytes.len() + data.len());
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(data);
        out
    }
}

fn rlp_uint(val: u128) -> Vec<u8> {
    if val == 0 {
        vec![0x80]
    } else {
        let bytes = to_min_be(val);
        rlp_bytes(&bytes)
    }
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = items.iter().map(|it| it.len()).sum();
    if total_len <= 55 {
        let mut out = Vec::with_capacity(1 + total_len);
        out.push(0xc0 + total_len as u8);
        for it in items {
            out.extend_from_slice(it);
        }
        out
    } else {
        let len_bytes = to_min_be(total_len as u128);
        let mut out = Vec::with_capacity(1 + len_bytes.len() + total_len);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        for it in items {
            out.extend_from_slice(it);
        }
        out
    }
}

fn to_min_be(val: u128) -> Vec<u8> {
    let be = val.to_be_bytes();
    let first_non_zero = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    be[first_non_zero..].to_vec()
}

fn encode_unsigned_eip155(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &[u8],
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let items = vec![
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(to),
        rlp_uint(value),
        rlp_bytes(data),
        rlp_uint(chain_id as u128),
        rlp_uint(0),
        rlp_uint(0),
    ];
    rlp_list(&items)
}

fn encode_signed_eip155(
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: &[u8],
    value: u128,
    data: &[u8],
    v: u64,
    r: &[u8],
    s: &[u8],
) -> Vec<u8> {
    // Strip leading zeros on r and s as required by RLP uint encoding
    let r_trimmed = strip_leading_zeros(r);
    let s_trimmed = strip_leading_zeros(s);

    let items = vec![
        rlp_uint(nonce as u128),
        rlp_uint(gas_price as u128),
        rlp_uint(gas_limit as u128),
        rlp_bytes(to),
        rlp_uint(value),
        rlp_bytes(data),
        rlp_uint(v as u128),
        rlp_bytes(r_trimmed),
        rlp_bytes(s_trimmed),
    ];
    rlp_list(&items)
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    &bytes[start..]
}
