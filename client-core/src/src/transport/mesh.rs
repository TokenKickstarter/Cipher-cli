//! # MANET Routing + LoRa + Mesh Coordinator
//!
//! Mobile Ad-Hoc Network routing that combines all offline transports:
//! - BLE mesh (short range, low power)
//! - Wi-Fi Direct/LAN (medium range, high bandwidth)
//! - LoRa radio (long range 5-15km, low bandwidth)
//!
//! Auto-selects the best transport based on:
//! - Peer proximity (BLE < 100m, Wi-Fi < 200m, LoRa < 15km)
//! - Bandwidth needs (file → Wi-Fi, text → BLE/LoRa)
//! - Battery level
//! - Available hardware

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;

/// Available offline transport types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub enum OfflineTransport {
    BleMesh,
    WifiDirect,
    WifiLan,
    LoRa,
}

impl OfflineTransport {
    /// Typical range in meters.
    pub fn range_meters(&self) -> u32 {
        match self {
            Self::BleMesh => 100,
            Self::WifiDirect => 200,
            Self::WifiLan => 50,  // Same network
            Self::LoRa => 15_000, // 15km
        }
    }

    /// Typical bandwidth in bytes/sec.
    pub fn bandwidth_bps(&self) -> u64 {
        match self {
            Self::BleMesh => 250_000,       // 2 Mbps
            Self::WifiDirect => 31_250_000, // 250 Mbps
            Self::WifiLan => 125_000_000,   // 1 Gbps
            Self::LoRa => 3_000,            // 24 kbps
        }
    }

    /// Priority (higher = preferred when available).
    pub fn priority(&self) -> u8 {
        match self {
            Self::WifiLan => 4,    // Best: fastest
            Self::WifiDirect => 3, // Great: fast + no router
            Self::BleMesh => 2,    // Good: low power + relay
            Self::LoRa => 1,       // Fallback: long range but slow
        }
    }
}

/// A known peer across all transports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub cipher_address: String,
    pub available_transports: Vec<OfflineTransport>,
    pub best_transport: Option<OfflineTransport>,
    pub last_seen: DateTime<Utc>,
    pub hop_count: u8,
}

/// Route entry in the MANET routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination: String,
    pub next_hop: String,
    pub transport: OfflineTransport,
    pub hop_count: u8,
    pub cost: u32,
    pub last_updated: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Mesh coordinator — manages all offline transports.
pub struct MeshCoordinator {
    pub our_address: String,
    /// Available hardware on this device
    pub available_transports: Arc<RwLock<Vec<OfflineTransport>>>,
    /// Known mesh peers
    pub peers: Arc<RwLock<HashMap<String, MeshPeer>>>,
    /// AODV-style routing table
    pub routes: Arc<RwLock<HashMap<String, RouteEntry>>>,
    /// Pending messages awaiting route
    pub pending: Arc<RwLock<Vec<PendingMeshMessage>>>,
    /// Delivered messages
    pub delivered: Arc<RwLock<Vec<String>>>,
}

/// A message waiting for a route.
#[derive(Debug, Clone)]
pub struct PendingMeshMessage {
    pub id: String,
    pub destination: String,
    pub payload: Vec<u8>,
    pub queued_at: DateTime<Utc>,
    pub min_bandwidth: u64,
}

impl MeshCoordinator {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            available_transports: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            routes: Arc::new(RwLock::new(HashMap::new())),
            pending: Arc::new(RwLock::new(Vec::new())),
            delivered: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register available hardware transports.
    pub async fn register_transport(&self, transport: OfflineTransport) {
        let mut transports = self.available_transports.write().await;
        if !transports.contains(&transport) {
            transports.push(transport);
        }
    }

    /// Auto-detect and register all available transports.
    pub async fn detect_hardware(&self) -> Vec<OfflineTransport> {
        // In real implementation: check BLE adapter, Wi-Fi Direct support, LoRa module
        // For now: register BLE and Wi-Fi as commonly available
        let detected = vec![OfflineTransport::BleMesh, OfflineTransport::WifiDirect];
        for t in &detected {
            self.register_transport(t.clone()).await;
        }
        detected
    }

    /// Register a peer seen on a specific transport.
    pub async fn peer_seen(
        &self,
        cipher_address: &str,
        transport: OfflineTransport,
        hop_count: u8,
    ) {
        let mut peers = self.peers.write().await;
        let peer = peers.entry(cipher_address.to_string()).or_insert(MeshPeer {
            cipher_address: cipher_address.to_string(),
            available_transports: Vec::new(),
            best_transport: None,
            last_seen: Utc::now(),
            hop_count,
        });

        if !peer.available_transports.contains(&transport) {
            peer.available_transports.push(transport.clone());
        }
        peer.last_seen = Utc::now();
        peer.hop_count = peer.hop_count.min(hop_count);

        // Update best transport (highest priority)
        peer.best_transport = peer
            .available_transports
            .iter()
            .max_by_key(|t| t.priority())
            .cloned();
    }

    /// Select the best transport for a message to a destination.
    pub async fn select_transport(
        &self,
        destination: &str,
        min_bandwidth: u64,
    ) -> Option<OfflineTransport> {
        let peers = self.peers.read().await;
        let peer = peers.get(destination)?;

        // Filter by bandwidth requirement and our available hardware
        let our_transports = self.available_transports.read().await;

        peer.available_transports
            .iter()
            .filter(|t| our_transports.contains(t))
            .filter(|t| t.bandwidth_bps() >= min_bandwidth)
            .max_by_key(|t| t.priority())
            .cloned()
    }

    /// Send a message via the best available offline transport.
    pub async fn send_offline(
        &self,
        destination: &str,
        payload: Vec<u8>,
        min_bandwidth: u64,
    ) -> Result<(String, OfflineTransport), CipherError> {
        let transport = self
            .select_transport(destination, min_bandwidth)
            .await
            .ok_or(CipherError::Network(
                "No offline transport available for this peer".into(),
            ))?;

        let msg_id = uuid::Uuid::new_v4().to_string();

        self.pending.write().await.push(PendingMeshMessage {
            id: msg_id.clone(),
            destination: destination.to_string(),
            payload,
            queued_at: Utc::now(),
            min_bandwidth,
        });

        Ok((msg_id, transport))
    }

    /// Update AODV routing table.
    pub async fn update_route(
        &self,
        destination: &str,
        next_hop: &str,
        transport: OfflineTransport,
        hop_count: u8,
    ) {
        let route = RouteEntry {
            destination: destination.to_string(),
            next_hop: next_hop.to_string(),
            transport,
            hop_count,
            cost: hop_count as u32 * 10,
            last_updated: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::minutes(10),
        };

        let mut routes = self.routes.write().await;
        // Only update if better route (fewer hops)
        if let Some(existing) = routes.get(destination) {
            if existing.hop_count <= hop_count {
                return;
            }
        }
        routes.insert(destination.to_string(), route);
    }

    /// Get route for a destination.
    pub async fn get_route(&self, destination: &str) -> Option<RouteEntry> {
        self.routes.read().await.get(destination).cloned()
    }

    /// Get all known peers.
    pub async fn known_peers(&self) -> Vec<MeshPeer> {
        self.peers.read().await.values().cloned().collect()
    }

    /// Get mesh network stats.
    pub async fn stats(&self) -> MeshStats {
        MeshStats {
            peer_count: self.peers.read().await.len(),
            route_count: self.routes.read().await.len(),
            pending_messages: self.pending.read().await.len(),
            available_transports: self.available_transports.read().await.clone(),
        }
    }
}

/// Mesh network statistics.
#[derive(Debug, Clone)]
pub struct MeshStats {
    pub peer_count: usize,
    pub route_count: usize,
    pub pending_messages: usize,
    pub available_transports: Vec<OfflineTransport>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_selection() {
        let coord = MeshCoordinator::new("0xAlice".into());

        // Register our hardware
        coord.register_transport(OfflineTransport::BleMesh).await;
        coord.register_transport(OfflineTransport::WifiDirect).await;

        // Bob available via both
        coord.peer_seen("0xBob", OfflineTransport::BleMesh, 1).await;
        coord
            .peer_seen("0xBob", OfflineTransport::WifiDirect, 1)
            .await;

        // Small message → BLE or Wi-Fi (prefer Wi-Fi = higher priority)
        let t = coord.select_transport("0xBob", 0).await.unwrap();
        assert_eq!(t, OfflineTransport::WifiDirect);

        // Large file → needs bandwidth → Wi-Fi Direct
        let t = coord.select_transport("0xBob", 1_000_000).await.unwrap();
        assert_eq!(t, OfflineTransport::WifiDirect);

        // Charlie only on BLE
        coord
            .peer_seen("0xCharlie", OfflineTransport::BleMesh, 3)
            .await;
        let t = coord.select_transport("0xCharlie", 0).await.unwrap();
        assert_eq!(t, OfflineTransport::BleMesh);
    }

    #[tokio::test]
    async fn test_aodv_routing() {
        let coord = MeshCoordinator::new("0xAlice".into());

        // Route to Bob via Charlie (3 hops)
        coord
            .update_route("0xBob", "0xCharlie", OfflineTransport::BleMesh, 3)
            .await;

        // Better route via Dave (1 hop)
        coord
            .update_route("0xBob", "0xDave", OfflineTransport::WifiDirect, 1)
            .await;

        let route = coord.get_route("0xBob").await.unwrap();
        assert_eq!(route.next_hop, "0xDave");
        assert_eq!(route.hop_count, 1);
    }

    #[tokio::test]
    async fn test_send_offline() {
        let coord = MeshCoordinator::new("0xAlice".into());
        coord.register_transport(OfflineTransport::BleMesh).await;
        coord.peer_seen("0xBob", OfflineTransport::BleMesh, 1).await;

        let (id, transport) = coord.send_offline("0xBob", vec![1, 2, 3], 0).await.unwrap();
        assert!(!id.is_empty());
        assert_eq!(transport, OfflineTransport::BleMesh);
    }

    #[tokio::test]
    async fn test_transport_properties() {
        assert!(OfflineTransport::WifiLan.bandwidth_bps() > OfflineTransport::LoRa.bandwidth_bps());
        assert!(OfflineTransport::LoRa.range_meters() > OfflineTransport::BleMesh.range_meters());
        assert!(OfflineTransport::WifiLan.priority() > OfflineTransport::BleMesh.priority());
    }
}
