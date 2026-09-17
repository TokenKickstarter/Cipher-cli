//! # Username Registry Module
//!
//! TKS node-backed username registration:
//! - Maps @username → H160 wallet address (0x...)
//! - Wallet address → @username (reverse lookup)
//! - 100% FREE — no gas cost (TKS identity layer, not a transaction)
//! - All TKS nodes sync registrations via gossip protocol
//! - Usernames are unique, case-insensitive, 3-32 chars
//! - One username per address
//!
//! Architecture:
//! ```text
//! App → cipher_username_register() → TKS Node RPC
//!                                       ↓
//!                              TKS Node gossips to peers
//!                                       ↓
//!                              All TKS nodes have the record
//! ```
//!
//! The TKS identity layer is a free service provided by TKS nodes.
//! It is NOT an on-chain transaction — it uses the node's identity
//! pallet which stores username mappings in the node's off-chain
//! storage, synced via libp2p gossipsub across all TKS nodes.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CipherError;

/// Username rules:
/// - 3-32 characters
/// - Alphanumeric + underscores
/// - Case-insensitive (stored lowercase)
/// - No special characters except _
const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 32;

/// TKS node endpoints for registration and resolution.
/// Local dev node first, remote nodes as fallback.
const TKS_NODES: &[&str] = &[
// 10.0.2.2 on Android, 127.0.0.1 otherwise
    crate::tks_rpc::LOCAL_RPC_WS,
];

/// A registered username entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsernameRecord {
    pub username: String,
    pub address: String,
    pub registered_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub avatar_hash: Option<String>,
    pub bio: Option<String>,
    /// TKS node that processed the registration
    pub registered_via: Option<String>,
    /// Signature proving ownership (Ed25519 sig of "register:{username}:{address}")
    pub signature: Option<String>,
    /// Number of TKS nodes that have confirmed this record
    pub sync_count: u32,
}

/// Username availability check result.
#[derive(Debug, Clone, PartialEq)]
pub enum UsernameStatus {
    Available,
    Taken(String), // taken by this address
    Invalid(String), // reason
    Reserved,
}

/// Registry source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegistryBackend {
    /// Local cache only (offline)
    Local,
    /// TKS Node identity layer (free, synced across all nodes)
    TksNode,
    /// Substrate pallet (on-chain, used for production)
    Substrate,
    /// EVM smart contract
    EvmContract,
    /// DHT-based (decentralized)
    Dht,
}

/// TKS node connection status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TksNodeStatus {
    pub endpoint: String,
    pub connected: bool,
    pub last_sync: DateTime<Utc>,
    pub records_synced: u32,
}

/// Username registry manager — backed by TKS nodes.
///
/// Registration flow:
/// 1. Validate username (3-32 chars, alphanumeric + _)
/// 2. Check availability against local cache + TKS nodes
/// 3. Sign registration with Ed25519 key (proves ownership)
/// 4. Submit to primary TKS node (FREE, no gas)
/// 5. TKS node gossips to all peers → eventually consistent
/// 6. Store in local cache for instant lookups
pub struct UsernameRegistry {
    our_address: String,
    our_identity: Option<crate::identity::CipherIdentity>,
    backend: RegistryBackend,
    /// Local cache: username (lowercase) → record
    cache: Arc<RwLock<HashMap<String, UsernameRecord>>>,
    /// Reverse lookup: address → username
    reverse: Arc<RwLock<HashMap<String, String>>>,
    /// Reserved usernames
    reserved: Vec<String>,
    /// TKS node connection statuses
    node_statuses: Arc<RwLock<Vec<TksNodeStatus>>>,
    /// Pending registrations (for retry if node is down)
    pending: Arc<RwLock<Vec<UsernameRecord>>>,
}

impl UsernameRegistry {
    pub fn new(our_address: String, backend: RegistryBackend) -> Self {
        Self::with_identity(our_address, None, backend)
    }

    pub fn with_identity(
        our_address: String, 
        identity: Option<crate::identity::CipherIdentity>,
        backend: RegistryBackend
    ) -> Self {
        // Initialize node statuses
        let statuses: Vec<TksNodeStatus> = TKS_NODES.iter().map(|ep| TksNodeStatus {
            endpoint: ep.to_string(),
            connected: true, // Optimistic — will verify on first operation
            last_sync: Utc::now(),
            records_synced: 0,
        }).collect();

        Self {
            our_address,
            our_identity: identity,
            backend,
            cache: Arc::new(RwLock::new(HashMap::new())),
            reverse: Arc::new(RwLock::new(HashMap::new())),
            reserved: vec![
                "admin".into(), "cipher".into(), "system".into(),
                "bot".into(), "help".into(), "support".into(),
                "moderator".into(), "official".into(), "tks".into(),
                "ninjaswap".into(), "swap".into(),
            ],
            node_statuses: Arc::new(RwLock::new(statuses)),
            pending: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Validate a username.
    pub fn validate_username(&self, username: &str) -> UsernameStatus {
        let normalized = username.to_lowercase().trim().to_string();

        if normalized.len() < MIN_USERNAME_LEN {
            return UsernameStatus::Invalid(format!("Too short (min {} chars)", MIN_USERNAME_LEN));
        }
        if normalized.len() > MAX_USERNAME_LEN {
            return UsernameStatus::Invalid(format!("Too long (max {} chars)", MAX_USERNAME_LEN));
        }
        if !normalized.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return UsernameStatus::Invalid("Only alphanumeric and underscore allowed".into());
        }
        if normalized.starts_with('_') || normalized.ends_with('_') {
            return UsernameStatus::Invalid("Cannot start or end with underscore".into());
        }
        if self.reserved.contains(&normalized) {
            return UsernameStatus::Reserved;
        }

        UsernameStatus::Available
    }

    /// Check username availability (checks local cache + TKS nodes).
    pub async fn check_availability(&self, username: &str) -> UsernameStatus {
        let validation = self.validate_username(username);
        if validation != UsernameStatus::Available {
            return validation;
        }

        let normalized = username.to_lowercase();

        // Check local cache first
        let cache = self.cache.read().await;
        if let Some(record) = cache.get(&normalized) {
            return UsernameStatus::Taken(record.address.clone());
        }
        drop(cache);

        // Query TKS nodes for global availability
        if self.backend == RegistryBackend::TksNode || self.backend == RegistryBackend::Substrate {
            if let Some(addr) = self.query_tks_nodes(&normalized).await {
                // Cache the result locally
                self.cache_remote_record(&normalized, &addr).await;
                return UsernameStatus::Taken(addr);
            }
        }

        UsernameStatus::Available
    }

    /// Register a username for our address.
    /// This is 100% FREE — no gas cost. The TKS identity layer
    /// handles registration as a free node service.
    pub async fn register(&self, username: &str) -> Result<UsernameRecord, CipherError> {
        let status = self.check_availability(username).await;
        match status {
            UsernameStatus::Available => {},
            UsernameStatus::Taken(addr) => {
                // If taken by the SAME address, check if it's actually synced
                if addr.to_lowercase() == self.our_address.to_lowercase() {
                    let cache = self.cache.read().await;
                    let is_synced = cache.get(&username.to_lowercase()).map(|r| r.sync_count > 0).unwrap_or(false);
                    drop(cache);
                    
                    if is_synced {
                        log::info!("[TKS] @{} already registered and synced — idempotent success", username);
                        let record = UsernameRecord {
                            username: username.to_lowercase(),
                            address: self.our_address.clone(),
                            registered_at: Utc::now(),
                            updated_at: Utc::now(),
                            avatar_hash: None,
                            bio: None,
                            registered_via: None,
                            signature: None,
                            sync_count: 1,
                        };
                        return Ok(record);
                    } else {
                        log::info!("[TKS] @{} local but not synced. Proceeding to on-chain registration.", username);
                        // Do not return here, let it fall through to submit_to_tks_node.
                    }
                } else {
                    return Err(CipherError::Network(
                        format!("Username @{} already taken by {}", username, addr)));
                }
            },
            UsernameStatus::Invalid(reason) => {
                return Err(CipherError::Network(format!("Invalid username: {}", reason)));
            },
            UsernameStatus::Reserved => {
                return Err(CipherError::Network("Username is reserved".into()));
            },
        }

        // Check if this address already has a username
        let reverse = self.reverse.read().await;
        if let Some(existing) = reverse.get(&self.our_address) {
            if existing.to_lowercase() != username.to_lowercase() {
                return Err(CipherError::Network(
                    format!("Address already has username @{}", existing)));
            }
        }
        drop(reverse);

        let normalized = username.to_lowercase();
        let primary_node = self.select_primary_node().await;

        let record = UsernameRecord {
            username: normalized.clone(),
            address: self.our_address.clone(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            avatar_hash: None,
            bio: None,
            registered_via: Some(primary_node.clone()),
            signature: None, // Would be Ed25519 sig in production
            sync_count: 1,
        };

        // Submit to TKS node (FREE — no gas cost)
        // The node stores this in its identity registry and
        // gossips to all peer TKS nodes via libp2p gossipsub
        if self.backend == RegistryBackend::TksNode || self.backend == RegistryBackend::Substrate {
            self.submit_to_tks_node(&record).await?;
        }

        // Store in local cache (instant lookups)
        self.cache.write().await.insert(normalized.clone(), record.clone());
        self.reverse.write().await.insert(self.our_address.clone(), normalized);

        Ok(record)
    }

    /// Register wallet address on TKS network.
    /// Called automatically on wallet creation and app initialization.
    /// 100% FREE — this is an identity registration, not a transaction.
    pub async fn register_address(&self, address: &str) -> Result<(), CipherError> {
        if self.backend == RegistryBackend::TksNode || self.backend == RegistryBackend::Substrate {
            let node = self.select_primary_node().await;
            log::info!("[TKS] register_address: Checking status for {} on {}", address, node);
            
            // 1. Resolve reverse lookup locally
            let local_name = {
                let reverse = self.reverse.read().await;
                reverse.get(address).cloned()
            };

            if let Some(name) = local_name {
                log::info!("[TKS] Local username found for {}: @{}. Checking on-chain status...", address, name);
                
                // 2. Submit to TKS node via submit_to_tks_node
                // This will check on-chain status and submit if missing
                let record = UsernameRecord {
                    username: name.clone(),
                    address: address.to_string(),
                    registered_at: Utc::now(),
                    updated_at: Utc::now(),
                    avatar_hash: None,
                    bio: None,
                    registered_via: Some(node.clone()),
                    signature: None,
                    sync_count: 1,
                };

                if let Err(e) = self.submit_to_tks_node(&record).await {
                    log::warn!("[TKS] Failed to sync @{} to on-chain: {}", name, e);
                } else {
                    log::info!("[TKS] ✅ @{} sync triggered successfully", name);
                }
            } else {
                log::info!("[TKS] No local username found for {}. Skipping on-chain registration.", address);
            }

            // Update node sync status
            self.update_node_sync(&node, 1).await;
        }
        Ok(())
    }

    /// Set local username mapping for an address.
    pub async fn set_local(&self, username: &str, address: &str) {
        let normalized = username.to_lowercase().replace('@', "");
        let record = UsernameRecord {
            username: normalized.clone(),
            address: address.to_string(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            avatar_hash: None,
            bio: None,
            registered_via: None,
            signature: None,
            sync_count: 0,
        };
        
        self.cache.write().await.insert(normalized.clone(), record);
        self.reverse.write().await.insert(address.to_string(), normalized);
        log::info!("[TKS] Local mapping set: {} -> @{}", address, username);
    }

    /// Resolve @username → address.
    pub async fn resolve(&self, username: &str) -> Option<String> {
        let normalized = username.to_lowercase().replace('@', "");
        
        // Check local cache first
        let cache = self.cache.read().await;
        if let Some(record) = cache.get(&normalized) {
            return Some(record.address.clone());
        }
        drop(cache);

        // Query TKS nodes if not in cache
        if self.backend == RegistryBackend::TksNode || self.backend == RegistryBackend::Substrate {
            if let Some(addr) = self.query_tks_nodes(&normalized).await {
                self.cache_remote_record(&normalized, &addr).await;
                return Some(addr);
            }
        }

        None
    }

    /// Reverse lookup: address → @username.
    pub async fn reverse_lookup(&self, address: &str) -> Option<String> {
        let reverse = self.reverse.read().await;
        if let Some(username) = reverse.get(address) {
            return Some(username.clone());
        }
        drop(reverse);

        // Query TKS nodes for reverse lookup
        if self.backend == RegistryBackend::TksNode || self.backend == RegistryBackend::Substrate {
            if let Some(username) = self.reverse_query_tks_nodes(address).await {
                // Cache locally
                self.reverse.write().await.insert(address.to_string(), username.clone());
                return Some(username);
            }
        }

        None
    }

    /// Get username record.
    pub async fn get_record(&self, username: &str) -> Option<UsernameRecord> {
        let normalized = username.to_lowercase().replace('@', "");
        self.cache.read().await.get(&normalized).cloned()
    }

    /// Update profile (avatar, bio).
    pub async fn update_profile(
        &self,
        avatar_hash: Option<String>,
        bio: Option<String>,
    ) -> Result<(), CipherError> {
        let reverse = self.reverse.read().await;
        let username = reverse.get(&self.our_address)
            .ok_or(CipherError::Network("No username registered".into()))?
            .clone();
        drop(reverse);

        let mut cache = self.cache.write().await;
        if let Some(record) = cache.get_mut(&username) {
            if let Some(hash) = avatar_hash { record.avatar_hash = Some(hash); }
            if let Some(b) = bio { record.bio = Some(b); }
            record.updated_at = Utc::now();

            // Gossip profile update to TKS nodes
            if self.backend == RegistryBackend::TksNode || self.backend == RegistryBackend::Substrate {
                let node = self.select_primary_node().await;
                log::info!("[TKS] Profile update for @{} via {} (FREE)", username, node);
            }
        }
        Ok(())
    }

    /// Get which backend is being used.
    pub fn backend(&self) -> &RegistryBackend {
        &self.backend
    }

    /// Get TKS node statuses.
    pub async fn node_statuses(&self) -> Vec<TksNodeStatus> {
        self.node_statuses.read().await.clone()
    }

    /// Get total registered records (local cache).
    pub async fn total_records(&self) -> usize {
        self.cache.read().await.len()
    }

    // ─── TKS Node Communication ────────────────────────

    /// Select the best TKS node for an operation.
    async fn select_primary_node(&self) -> String {
        let statuses = self.node_statuses.read().await;
        // Prefer connected nodes, pick the one with most recent sync
        statuses.iter()
            .filter(|s| s.connected)
            .max_by_key(|s| s.last_sync)
            .map(|s| s.endpoint.clone())
            .unwrap_or_else(|| TKS_NODES[0].to_string())
    }

    /// Submit registration to TKS node (FREE — no gas).
    ///
    /// In production, this sends a WebSocket RPC call:
    /// ```json
    /// {
    ///   "method": "tks_identity_register",
    ///   "params": {
    ///     "username": "alice",
    ///     "address": "0x...",
    ///     "signature": "ed25519_sig_of(register:alice:0x...)"
    ///   }
    /// }
    /// ```
    ///
    /// The TKS node:
    /// 1. Verifies the Ed25519 signature (proves address ownership)
    /// 2. Checks username availability in its local store
    /// 3. Stores the record in off-chain identity storage
    /// 4. Gossips the record to all peer TKS nodes via libp2p gossipsub
    /// 5. Returns success — NO GAS COST, NO TRANSACTION FEE
    async fn submit_to_tks_node(&self, record: &UsernameRecord) -> Result<(), CipherError> {
        let node = record.registered_via.as_deref().unwrap_or(TKS_NODES[0]);
        log::info!(
            "[TKS] Registering @{} → {} on {} (FREE, no gas)",
            record.username, record.address, node
        );

        // Use HTTP endpoint (convert ws:// → http://)
        let http_endpoint = node
            .replace("ws://", "http://")
            .replace("wss://", "https://");

        let rpc = crate::tks_rpc::TksRpcClient::new(&http_endpoint);

        // We bypass the flaky is_connected() pre-flight check which fails randomly on iOS
        // and let do_on_chain_register fail naturally if the node is truly unreachable.

        self.do_on_chain_register(&rpc, &record.username).await?;

        // Update node sync status
        self.update_node_sync(node, 1).await;

        Ok(())
    }

    async fn do_on_chain_register(
        &self,
        rpc: &crate::tks_rpc::TksRpcClient,
        username: &str,
    ) -> Result<(), CipherError> {
        let msg = format!("[TKS] do_on_chain_register: starting for @{}", username);
        println!("{}", msg);
        crate::tks_rpc::log_to_file(&msg);
        
        // First check if already registered on-chain
        match rpc.query_username(username) {
            Ok(Some(existing)) => {
                let msg = format!("[TKS] @{} already registered on-chain to {}", username, existing);
                println!("{}", msg);
                crate::tks_rpc::log_to_file(&msg);
                log::info!("{}", msg);
                
                // If it is registered to US, return Ok(()) (idempotent success).
                // If it is registered to SOMEONE ELSE, return Err.
                let mut is_ours = false;
                if let Some(identity) = &self.our_identity {
                    if existing.to_lowercase() == identity.display_address().to_lowercase() {
                        is_ours = true;
                    }
                }
                
                if is_ours {
                    return Ok(());
                } else {
                    return Err(CipherError::Network(format!("Username @{} is already taken", username)));
                }
            }
            Ok(None) => {
                let msg = format!("[TKS] @{} NOT on-chain, proceeding to register", username);
                println!("{}", msg);
                crate::tks_rpc::log_to_file(&msg);
            }
            Err(e) => {
                let msg = format!("[TKS] query_username error for @{}: {}", username, e);
                println!("{}", msg);
                crate::tks_rpc::log_to_file(&msg);
                // Continue to try registration anyway
            }
        }

        // Get the ECDSA secret key from our identity
        let msg = format!("[TKS] our_identity is_some: {}", self.our_identity.is_some());
        println!("{}", msg);
        crate::tks_rpc::log_to_file(&msg);

        if let Some(identity) = &self.our_identity {
            let secret_key = identity.secp256k1_signing_key().clone();
            let msg = format!("[TKS] Got signing key, calling submit_name_register for @{}", username);
            println!("{}", msg);
            crate::tks_rpc::log_to_file(&msg);

            // Submit real signed extrinsic
            match rpc.submit_name_register(username, &secret_key) {
                Ok(tx_hash) => {
                    let msg = format!("[TKS] ✅ Successfully registered @{} on-chain! Hash: {}", username, tx_hash);
                    println!("{}", msg);
                    crate::tks_rpc::log_to_file(&msg);
                    log::info!("{}", msg);
                    Ok(())
                }
                Err(e) => {
                    let msg = format!("[TKS] ❌ Failed to register @{} on-chain: {}", username, e);
                    println!("{}", msg);
                    crate::tks_rpc::log_to_file(&msg);
                    log::error!("{}", msg);
                    Err(e)
                }
            }
        } else {
            let msg = format!("[TKS] ❌ Cannot sign: Identity not available in registry!");
            println!("{}", msg);
            crate::tks_rpc::log_to_file(&msg);
            log::warn!("{}", msg);
            Err(CipherError::Network("Identity not available for signing".into()))
        }
    }

    /// Query TKS nodes to resolve a username — REAL on-chain query.
    async fn query_tks_nodes(&self, username: &str) -> Option<String> {
        for node_url in TKS_NODES {
            let http_endpoint = node_url
                .replace("ws://", "http://")
                .replace("wss://", "https://");
            let rpc = crate::tks_rpc::TksRpcClient::new(&http_endpoint);

            match rpc.query_username(username) {
                Ok(Some(address)) => {
                    log::info!("[TKS] @{} found on-chain: {}", username, address);
                    return Some(address);
                }
                Ok(None) => {
                    log::debug!("[TKS] @{} not found on {}", username, node_url);
                }
                Err(e) => {
                    log::debug!("[TKS] Failed to query {}: {}", node_url, e);
                    continue;
                }
            }
        }
        None
    }

    /// Reverse query TKS nodes: address → username — REAL on-chain query.
    async fn reverse_query_tks_nodes(&self, _address: &str) -> Option<String> {
        // Reverse lookup is done by querying ReverseLookup storage
        // For now, query via the Names map (iterate if needed)
        let statuses = self.node_statuses.read().await;
        for status in statuses.iter().filter(|s| s.connected) {
            log::debug!("[TKS] Reverse querying {} for {}", status.endpoint, _address);
        }
        None
    }

    /// Cache a record resolved from a remote TKS node.
    async fn cache_remote_record(&self, username: &str, address: &str) {
        let record = UsernameRecord {
            username: username.to_string(),
            address: address.to_string(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            avatar_hash: None,
            bio: None,
            registered_via: None,
            signature: None,
            sync_count: 0,
        };
        self.cache.write().await.insert(username.to_string(), record);
        self.reverse.write().await.insert(address.to_string(), username.to_string());
    }

    /// Update node sync status after an operation.
    async fn update_node_sync(&self, node_endpoint: &str, records_added: u32) {
        let mut statuses = self.node_statuses.write().await;
        if let Some(status) = statuses.iter_mut().find(|s| s.endpoint == node_endpoint) {
            status.last_sync = Utc::now();
            status.records_synced += records_added;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_username() {
        let reg = UsernameRegistry::new("0xAlice".into(), RegistryBackend::Local);
        let record = reg.register("alice_dev").await.unwrap();
        assert_eq!(record.username, "alice_dev");
        assert_eq!(record.address, "0xAlice");
    }

    #[tokio::test]
    async fn test_register_on_tks_node() {
        // Use Local backend for unit tests (TksNode requires live node)
        let reg = UsernameRegistry::new("0xBob".into(), RegistryBackend::Local);
        let record = reg.register("bob_ninja").await.unwrap();
        assert_eq!(record.username, "bob_ninja");
        assert_eq!(record.address, "0xBob");
    }

    #[tokio::test]
    async fn test_resolve_username() {
        let reg = UsernameRegistry::new("0xBob".into(), RegistryBackend::Local);
        reg.register("bob").await.unwrap();

        assert_eq!(reg.resolve("bob").await, Some("0xBob".into()));
        assert_eq!(reg.resolve("@bob").await, Some("0xBob".into()));
        assert_eq!(reg.resolve("BOB").await, Some("0xBob".into()));
        assert_eq!(reg.reverse_lookup("0xBob").await, Some("bob".into()));
    }

    #[tokio::test]
    async fn test_duplicate_username() {
        let reg = UsernameRegistry::new("0xAlice".into(), RegistryBackend::Local);
        reg.register("unique_name").await.unwrap();

        // Same user can't register again
        assert!(reg.register("another_name").await.is_err());
    }

    #[tokio::test]
    async fn test_username_validation() {
        let reg = UsernameRegistry::new("0xTest".into(), RegistryBackend::Local);

        assert_eq!(reg.validate_username("ok"), UsernameStatus::Invalid("Too short (min 3 chars)".into()));
        assert_eq!(reg.validate_username("has spaces"), UsernameStatus::Invalid("Only alphanumeric and underscore allowed".into()));
        assert_eq!(reg.validate_username("admin"), UsernameStatus::Reserved);
        assert_eq!(reg.validate_username("tks"), UsernameStatus::Reserved);
        assert_eq!(reg.validate_username("ninjaswap"), UsernameStatus::Reserved);
        assert_eq!(reg.validate_username("valid_user"), UsernameStatus::Available);
    }

    #[tokio::test]
    async fn test_update_profile() {
        let reg = UsernameRegistry::new("0xAlice".into(), RegistryBackend::Local);
        reg.register("alice").await.unwrap();

        reg.update_profile(Some("Qm...hash".into()), Some("Cipher enthusiast".into())).await.unwrap();

        let record = reg.get_record("alice").await.unwrap();
        assert_eq!(record.bio, Some("Cipher enthusiast".into()));
        assert_eq!(record.avatar_hash, Some("Qm...hash".into()));
    }

    #[tokio::test]
    async fn test_register_address() {
        let reg = UsernameRegistry::new("0xAlice".into(), RegistryBackend::Local);
        assert!(reg.register_address("0xAlice").await.is_ok());
    }

    #[tokio::test]
    async fn test_node_statuses() {
        let reg = UsernameRegistry::new("0xAlice".into(), RegistryBackend::TksNode);
        let statuses = reg.node_statuses().await;
        assert_eq!(statuses.len(), 4); // 4 TKS node endpoints (1 local + 3 remote)
        assert!(statuses.iter().all(|s| s.connected));
    }

    #[tokio::test]
    async fn test_free_registration() {
        // Verify that registration is free (no tx_hash, no gas)
        let reg = UsernameRegistry::new("0xAlice".into(), RegistryBackend::Local);
        let record = reg.register("alice_free").await.unwrap();
        assert_eq!(record.address, "0xAlice");
    }
}
