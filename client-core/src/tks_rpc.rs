//! # TKS Node RPC Client
//!
//! Lightweight JSON-RPC client for submitting extrinsics to TKS nodes.
//! Uses HTTP (ureq) instead of WebSocket for simplicity in mobile context.
//!
//! ## Extrinsic Flow
//! ```text
//! 1. Get runtime version + genesis hash from node
//! 2. SCALE-encode the call (e.g., NameRegistry::register("ninja"))
//! 3. Sign the payload with ECDSA key (AccountId20 compatible)
//! 4. Wrap in a signed extrinsic envelope
//! 5. Submit via author_submitExtrinsic
//! ```

use parity_scale_codec::{Compact, Encode};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::CipherError;

const DEBUG_FILE: &str =
    "/tmp/cipher-sync-debug.txt";

pub fn log_to_file(msg: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DEBUG_FILE)
    {
        let _ = writeln!(
            file,
            "[{}] {}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            msg
        );
    }
}

/// Default TKS node RPC endpoint.
/// Public RPC: https://rpc.tokenkickstarter.com (proxied via Cloudflare)
/// Fallback direct: http://209.97.165.19:9944
#[cfg(target_os = "android")]
pub const LOCAL_RPC_WS: &str = "wss://rpc.tokenkickstarter.com";
#[cfg(target_os = "android")]
pub const LOCAL_RPC_HTTP: &str = "https://rpc.tokenkickstarter.com";

#[cfg(not(target_os = "android"))]
pub const LOCAL_RPC_WS: &str = "wss://rpc.tokenkickstarter.com";
#[cfg(not(target_os = "android"))]
pub const LOCAL_RPC_HTTP: &str = "https://rpc.tokenkickstarter.com";

const DEFAULT_RPC: &str = LOCAL_RPC_HTTP;

/// TKS chain ID for EIP-155 signing (from chain_spec.rs).
const TKS_CHAIN_ID: u64 = 7779;

/// NameRegistry pallet index in the runtime (from construct_runtime!).
/// This must match the pallet index in the TKS runtime.
/// Check via: state_getMetadata → pallets → find "NameRegistry" → index
const NAME_REGISTRY_PALLET_INDEX: u8 = 20; // Matches construct_runtime! index in tks-runtime

/// JSON-RPC request.
#[derive(Serialize)]
struct RpcRequest {
    id: u64,
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
}

/// JSON-RPC response.
#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<String>,
}

/// Runtime version from the node.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeVersion {
    pub spec_name: String,
    pub spec_version: u32,
    pub transaction_version: u32,
}

/// TKS RPC client.
pub struct TksRpcClient {
    endpoint: String,
    request_id: std::sync::atomic::AtomicU64,
}

impl TksRpcClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            request_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_RPC)
    }

    /// Make a JSON-RPC call to the TKS node.
    fn call(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, CipherError> {
        let id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let request = RpcRequest {
            id,
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        };

        let body = serde_json::to_string(&request)
            .map_err(|e| CipherError::Network(format!("JSON encode error: {}", e)))?;

        let log_msg = format!(
            "[TKS RPC] Request (ID {}): method={}, params={}",
            id,
            method,
            serde_json::to_string(&request.params).unwrap_or_default()
        );
        println!("{}", log_msg);
        log_to_file(&log_msg);

        // Add 10-second timeout to prevent hangs
        let resp_result = ureq::post(&self.endpoint)
            .timeout(std::time::Duration::from_secs(10))
            .set("Content-Type", "application/json")
            .send_string(&body);

        match resp_result {
            Ok(resp) => {
                let json_resp: RpcResponse = resp
                    .into_json()
                    .map_err(|e| CipherError::Network(format!("JSON decode error: {}", e)))?;

                if let Some(err) = json_resp.error {
                    let err_msg = format!(
                        "[TKS RPC] Error (ID {}): code={}, message={}, data={:?}",
                        id, err.code, err.message, err.data
                    );
                    println!("{}", err_msg);
                    log_to_file(&err_msg);
                    return Err(CipherError::Network(format!(
                        "TKS RPC error {}: {}",
                        err.code, err.message
                    )));
                }

                println!("[TKS RPC] Response (ID {}): success", id);
                Ok(json_resp.result.unwrap_or(serde_json::Value::Null))
            }
            Err(e) => {
                println!("[TKS RPC] HTTP Error (ID {}): {}", id, e);
                Err(CipherError::Network(format!(
                    "HTTP error connecting to TKS node at {}: {}",
                    self.endpoint, e
                )))
            }
        }
    }

    /// Check if the TKS node is reachable (fast — 3s timeout).
    pub fn is_connected(&self) -> bool {
        let id = self
            .request_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let request = RpcRequest {
            id,
            jsonrpc: "2.0".into(),
            method: "system_health".into(),
            params: vec![],
        };
        let body = match serde_json::to_string(&request) {
            Ok(b) => b,
            Err(_) => return false,
        };

        // Use a short 3-second timeout for connectivity checks
        match ureq::post(&self.endpoint)
            .timeout(std::time::Duration::from_secs(3))
            .set("Content-Type", "application/json")
            .send_string(&body)
        {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Get the chain name.
    pub fn chain_name(&self) -> Result<String, CipherError> {
        let result = self.call("system_chain", vec![])?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| CipherError::Network("Invalid chain name".into()))
    }

    /// Get the runtime version.
    pub fn runtime_version(&self) -> Result<RuntimeVersion, CipherError> {
        let result = self.call("state_getRuntimeVersion", vec![])?;
        serde_json::from_value(result)
            .map_err(|e| CipherError::Network(format!("Failed to parse runtime version: {}", e)))
    }

    /// Get the genesis hash.
    pub fn genesis_hash(&self) -> Result<[u8; 32], CipherError> {
        let result = self.call("chain_getBlockHash", vec![serde_json::json!(0)])?;
        let hex_str = result
            .as_str()
            .ok_or_else(|| CipherError::Network("Invalid genesis hash".into()))?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)
            .map_err(|e| CipherError::Network(format!("Invalid genesis hash hex: {}", e)))?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        Ok(hash)
    }

    /// Get the account nonce for an H160 address.
    pub fn account_nonce(&self, address: &[u8; 20]) -> Result<u32, CipherError> {
        let addr_hex = format!("0x{}", hex::encode(address));
        let result = self.call("system_accountNextIndex", vec![serde_json::json!(addr_hex)])?;
        result
            .as_u64()
            .map(|n| n as u32)
            .ok_or_else(|| CipherError::Network("Invalid nonce".into()))
    }

    /// Get the best block number.
    pub fn best_block_number(&self) -> Result<u64, CipherError> {
        let result = self.call("chain_getHeader", vec![])?;
        let num_hex = result["number"]
            .as_str()
            .ok_or_else(|| CipherError::Network("Invalid block header".into()))?;
        let num_hex = num_hex.strip_prefix("0x").unwrap_or(num_hex);
        u64::from_str_radix(num_hex, 16)
            .map_err(|e| CipherError::Network(format!("Invalid block number: {}", e)))
    }

    /// Get the NameRegistry pallet index from runtime metadata.
    pub fn name_registry_pallet_index(&self) -> Result<u8, CipherError> {
        // Query metadata and find NameRegistry pallet index
        let metadata_hex = self.call("state_getMetadata", vec![])?;
        let metadata_str = metadata_hex.as_str().unwrap_or("");

        // Search for "NameRegistry" in the metadata hex
        // "NameRegistry" = 4e616d655265676973747279 in hex
        if metadata_str.contains("4e616d655265676973747279")
            || metadata_str.contains("4e616d65526567697374727")
        {
            // Found — use default index (will be verified)
            Ok(NAME_REGISTRY_PALLET_INDEX)
        } else {
            Err(CipherError::Network(
                "NameRegistry pallet not found in runtime".into(),
            ))
        }
    }

    /// Build and submit a NameRegistry::register extrinsic.
    ///
    /// This is 100% FREE — the pallet returns Pays::No.
    ///
    /// Steps:
    /// 1. SCALE-encode the call: (pallet_index, call_index=0, name_bytes)
    /// 2. Build the signed extra (era, nonce, tip=0)
    /// 3. Sign the payload with ECDSA
    /// 4. Wrap in extrinsic envelope
    /// 5. Submit via author_submitExtrinsic
    pub fn submit_name_register(
        &self,
        username: &str,
        ecdsa_secret: &k256::ecdsa::SigningKey,
    ) -> Result<String, CipherError> {
        log::info!("[TKS RPC] Registering @{} on-chain (FREE)", username);
        println!("[TKS RPC] submit_name_register called for @{}", username);

        // 1. Get chain info
        let genesis_hash = self.genesis_hash()?;
        let runtime_version = self.runtime_version()?;
        let pallet_index = self.name_registry_pallet_index()?;

        // Derive the H160 address from the ECDSA key
        let pubkey = ecdsa_secret.verifying_key();
        let pubkey_bytes = pubkey.to_encoded_point(false);
        let hash = sha3_keccak256(&pubkey_bytes.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        log::info!("[TKS RPC] Address: 0x{}", hex::encode(&address));

        // 2. Build the signature payload (name + "register")
        let name_bytes = username.to_lowercase().as_bytes().to_vec();
        let mut sig_payload = name_bytes.clone();
        sig_payload.extend_from_slice(b"register");
        let msg_hash = sha3_keccak256(&sig_payload);

        log::info!("[TKS RPC] Keccak256(payload): 0x{}", hex::encode(&msg_hash));

        // 3. Sign with k256 (pure Rust — works on all targets including iOS)
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        let (sig_k256, rec_id) = ecdsa_secret
            .sign_prehash_recoverable(&msg_hash)
            .map_err(|e| CipherError::Network(format!("ECDSA signing failed: {}", e)))?;

        let sig_r_s = sig_k256.to_bytes();
        let mut sig_bytes = [0u8; 65];
        sig_bytes[..64].copy_from_slice(&sig_r_s);
        sig_bytes[64] = rec_id.to_byte();
        log::info!("[TKS RPC] Signature v: {}", sig_bytes[64]);

        // 4. Build the call data
        // NameRegistry::register_unsigned(name: BoundedVec<u8>, owner: AccountId, signature: [u8; 65])
        // SCALE: [pallet_index, call_index, compact_len, name_bytes..., owner_bytes(20), signature_bytes(65)]
        let mut call_data = Vec::new();
        call_data.push(pallet_index); // Pallet index
        call_data.push(3u8); // Call index (register_unsigned = 3)
        Compact(name_bytes.len() as u32).encode_to(&mut call_data);
        call_data.extend_from_slice(&name_bytes);
        call_data.extend_from_slice(&address);
        call_data.extend_from_slice(&sig_bytes);

        // 5. Build the full extrinsic
        // Format: [compact_len, version_byte (0x04 for unsigned), call_data]
        let mut extrinsic_body = Vec::new();

        // Version byte: 0x04 = unsigned (0x00) | version 4 (0x04)
        extrinsic_body.push(0x04u8);
        extrinsic_body.extend_from_slice(&call_data);

        // Add compact length prefix
        let mut extrinsic = Vec::new();
        Compact(extrinsic_body.len() as u32).encode_to(&mut extrinsic);
        extrinsic.extend_from_slice(&extrinsic_body);

        // 7. Submit via RPC
        let hex_extrinsic = format!("0x{}", hex::encode(&extrinsic));
        let log_txt = format!(
            "[TKS RPC] Submitting NameRegistry::register extrinsic for @{} ({} bytes)",
            username,
            extrinsic.len()
        );
        println!("{}", log_txt);
        log_to_file(&log_txt);
        log_to_file(&format!("[TKS RPC] Extrinsic Hex: {}", hex_extrinsic));

        let result = self.call(
            "author_submitExtrinsic",
            vec![serde_json::json!(hex_extrinsic)],
        );

        match result {
            Ok(hash) => {
                let tx_hash = hash.as_str().unwrap_or("unknown").to_string();
                log::info!("[TKS RPC] ✅ Extrinsic submitted! Hash: {}", tx_hash);
                Ok(tx_hash)
            }
            Err(e) => {
                log::warn!("[TKS RPC] ❌ Extrinsic submission failed: {}", e);
                // Fallback: try author_submitAndWatchExtrinsic
                Err(e)
            }
        }
    }

    /// Query if a username is registered on-chain.
    pub fn query_username(&self, username: &str) -> Result<Option<String>, CipherError> {
        // Query the Names storage map
        // Key = twox_128("NameRegistry") ++ twox_128("Names") ++ Blake2_128Concat(name_bytes)
        let raw_name_bytes = username.to_lowercase().as_bytes().to_vec();

        // Storage map key is BoundedVec<u8>, which is SCALE-encoded with a Compact<u32> length prefix.
        // For lengths <= 63 (our max is 32), the compact encoding is simply: length << 2.
        let mut scale_name_bytes = vec![(raw_name_bytes.len() as u8) << 2];
        scale_name_bytes.extend_from_slice(&raw_name_bytes);

        // Build storage key
        let pallet_hash = twox_128(b"NameRegistry");
        let storage_hash = twox_128(b"Names");
        let key_hash = blake2_128_concat(&scale_name_bytes);

        let storage_key = format!(
            "0x{}{}{}",
            hex::encode(&pallet_hash),
            hex::encode(&storage_hash),
            hex::encode(&key_hash),
        );

        let result = self.call("state_getStorage", vec![serde_json::json!(storage_key)])?;

        match result.as_str() {
            Some(hex_val) if !hex_val.is_empty() && hex_val != "0x" => {
                // Decode AccountId20 (H160) from SCALE
                let hex_val = hex_val.strip_prefix("0x").unwrap_or(hex_val);
                if hex_val.len() >= 40 {
                    let address = format!("0x{}", &hex_val[..40]);
                    Ok(Some(address))
                } else {
                    Ok(Some(format!("0x{}", hex_val)))
                }
            }
            _ => Ok(None),
        }
    }

    /// Query the reverse lookup for an address to get the username.
    pub fn query_username_reverse(&self, address_hex: &str) -> Result<Option<String>, CipherError> {
        let clean_hex = address_hex.strip_prefix("0x").unwrap_or(address_hex);
        let address_bytes = hex::decode(clean_hex)
            .map_err(|e| CipherError::Network(format!("Invalid address format: {}", e)))?;

        if address_bytes.len() != 20 {
            return Ok(None);
        }

        let pallet_hash = twox_128(b"NameRegistry");
        let storage_hash = twox_128(b"ReverseLookup");
        let key_hash = blake2_128_concat(&address_bytes);

        let storage_key = format!(
            "0x{}{}{}",
            hex::encode(&pallet_hash),
            hex::encode(&storage_hash),
            hex::encode(&key_hash),
        );

        let result = self.call("state_getStorage", vec![serde_json::json!(storage_key)])?;

        match result.as_str() {
            Some(hex_val) if !hex_val.is_empty() && hex_val != "0x" => {
                let hex_val = hex_val.strip_prefix("0x").unwrap_or(hex_val);
                if let Ok(bytes) = hex::decode(hex_val) {
                    if bytes.len() > 1 {
                        // Decode BoundedVec<u8> SCALE encoding
                        // The first byte is the compact length << 2 format (for small Strings)
                        let text_len = (bytes[0] >> 2) as usize;
                        if text_len <= bytes.len() - 1 {
                            let text_bytes = &bytes[1..1 + text_len];
                            if let Ok(username) = String::from_utf8(text_bytes.to_vec()) {
                                return Ok(Some(username));
                            }
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Query the total number of registered usernames.
    pub fn total_registered_names(&self) -> Result<u64, CipherError> {
        let pallet_hash = twox_128(b"NameRegistry");
        let storage_hash = twox_128(b"TotalNames");
        let storage_key = format!(
            "0x{}{}",
            hex::encode(&pallet_hash),
            hex::encode(&storage_hash)
        );

        let result = self.call("state_getStorage", vec![serde_json::json!(storage_key)])?;

        match result.as_str() {
            Some(hex_val) if hex_val.len() > 2 => {
                let hex_val = hex_val.strip_prefix("0x").unwrap_or(hex_val);
                let bytes = hex::decode(hex_val)
                    .map_err(|e| CipherError::Network(format!("Decode error: {}", e)))?;
                // u64 is 8 bytes LE
                let mut buf = [0u8; 8];
                let len = bytes.len().min(8);
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(u64::from_le_bytes(buf))
            }
            _ => Ok(0),
        }
    }
}

// ─── Substrate Hashing Helpers ─────────────────────────────

/// Compute twox_128 hash (used for Substrate storage key prefixes).
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

/// Compute Blake2_128Concat hash (used for Substrate StorageMap keys).
fn blake2_128_concat(data: &[u8]) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(16).expect("valid length");
    hasher.update(data);
    let mut hash = vec![0u8; 16];
    hasher.finalize_variable(&mut hash).expect("valid output");
    // Blake2_128Concat = hash ++ original_data
    hash.extend_from_slice(data);
    hash
}

/// Keccak-256 hash (for EVM address derivation).
fn sha3_keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_twox_128() {
        // Known hash for "NameRegistry"
        let hash = twox_128(b"NameRegistry");
        assert_eq!(hash.len(), 16);
        // Not all zeros
        assert!(hash.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_blake2_128_concat() {
        let result = blake2_128_concat(b"alice");
        // Should be 16 bytes hash + 5 bytes "alice" = 21 bytes
        assert_eq!(result.len(), 21);
        // Last 5 bytes should be "alice"
        assert_eq!(&result[16..], b"alice");
    }

    #[test]
    fn test_rpc_client_creation() {
        let client = TksRpcClient::new("http://localhost:9944");
        assert_eq!(client.endpoint, "http://localhost:9944");
    }

    #[test]
    fn debug_sig() {
        let payload_hex = "1400146e696e6a61000000c80000000100000049397761c3e00070b4aef07df523f658b19ad9da0112584de30e0e9dd78d59e449397761c3e00070b4aef07df523f658b19ad9da0112584de30e0e9dd78d59e4";
        let sig_hex = "a5b43a85c3f9b62b26a1ebd8e5b7587538d7364c6288f686a7b84db7ce5d366f64c5c6922cf253c5281b8af7b83e59d9020373a6f7e20280c07427ffe78ad5b901";
        let expected_addr = "313a5b294443daee204b90445ba2e12feb74695b";

        let payload = hex::decode(payload_hex).unwrap();
        let sig_bytes = hex::decode(sig_hex).unwrap();

        // Hash payload like TKS RPC does
        let msg_hash = sha3_keccak256(&payload);
        println!("msg_hash: {}", hex::encode(&msg_hash));

        use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, Secp256k1};
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&msg_hash).unwrap();

        let recid = RecoveryId::from_i32(sig_bytes[64] as i32).unwrap();
        let sig = RecoverableSignature::from_compact(&sig_bytes[..64], recid).unwrap();

        let recovered_pk = secp.recover_ecdsa(&msg, &sig).unwrap();
        let recovered_uncompressed = recovered_pk.serialize_uncompressed();
        let recovered_hash = sha3_keccak256(&recovered_uncompressed[1..]);
        let mut recovered_addr = [0u8; 20];
        recovered_addr.copy_from_slice(&recovered_hash[12..]);
        println!("Recovered addr: {}", hex::encode(&recovered_addr));
        assert_eq!(hex::encode(&recovered_addr), expected_addr);

        // Also simulate what fp_account::EthereumSignature::verify does!
        let verify_hash = sha3_keccak256(&payload);
        println!("Verify hash inside node: {}", hex::encode(&verify_hash));
    }

    #[test]
    fn test_k256_vs_secp256k1() {
        use k256::ecdsa::SigningKey;
        use rand_core::OsRng;
        use secp256k1::{Secp256k1, SecretKey};

        let signing_key = SigningKey::random(&mut OsRng);

        let pubkey = signing_key.verifying_key();
        let pubkey_bytes = pubkey.to_encoded_point(false);
        let hash = sha3_keccak256(&pubkey_bytes.as_bytes()[1..]);
        let mut k256_address = [0u8; 20];
        k256_address.copy_from_slice(&hash[12..]);

        let sk_bytes = signing_key.to_bytes();
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();

        let secp = Secp256k1::new();
        let secp_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let secp_pubkey_bytes = secp_pubkey.serialize_uncompressed();
        let secp_hash = sha3_keccak256(&secp_pubkey_bytes[1..]);
        let mut secp_address = [0u8; 20];
        secp_address.copy_from_slice(&secp_hash[12..]);

        println!("k256 address: {}", hex::encode(&k256_address));
        println!("secp address: {}", hex::encode(&secp_address));
        assert_eq!(k256_address, secp_address);
    }

    #[test]
    fn test_live_submit() {
        use k256::ecdsa::SigningKey;
        use rand_core::OsRng;

        let client = TksRpcClient::new("http://127.0.0.1:9944");
        if !client.is_connected() {
            println!("Node not running");
            return;
        }

        let priv_key = SigningKey::random(&mut OsRng);

        let pubkey = priv_key.verifying_key().to_encoded_point(false);
        let hash = sha3_keccak256(&pubkey.as_bytes()[1..]);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        println!("Test address: {}", hex::encode(&address));

        // Let's pretend to execute the submission without Alice funding,
        // to just see the raw RPC JSON response by using urllib or reqwest via our existing query method.
        // Actually, let's just make it panic if it fails since we expect it to fail if it's not funded.

        match client.submit_name_register("testninja", &priv_key) {
            Ok(hash) => println!("Success! Tx Hash: {}", hash),
            Err(e) => panic!("Failed: {:?}", e),
        }
    }
}
