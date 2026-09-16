//! # BLE Mesh Transport
//!
//! Bluetooth Low Energy 5.0+ mesh networking:
//! - Auto-discovery of nearby Cipher devices
//! - Multi-hop relay (up to 7 hops)
//! - Store-and-forward for offline peers
//! - ~100m range per hop, ~2 Mbps

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;

/// BLE mesh node states.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BleNodeState {
    Scanning,
    Advertising,
    Connected,
    Relaying,
    Disconnected,
}

/// A discovered BLE peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlePeer {
    pub device_id: String,
    pub cipher_address: Option<String>,
    pub rssi: i16,
    pub last_seen: DateTime<Utc>,
    pub hop_count: u8,
    pub state: BleNodeState,
}

/// BLE mesh message for relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleMeshMessage {
    pub id: String,
    pub origin: String,
    pub destination: String,
    pub payload: Vec<u8>,
    pub hop_count: u8,
    pub max_hops: u8,
    pub created_at: DateTime<Utc>,
    pub ttl_secs: u64,
}

/// BLE Mesh transport manager.
pub struct BleMeshTransport {
    pub our_address: String,
    pub state: Arc<RwLock<BleNodeState>>,
    pub peers: Arc<RwLock<HashMap<String, BlePeer>>>,
    pub relay_queue: Arc<RwLock<Vec<BleMeshMessage>>>,
    pub received: Arc<RwLock<Vec<BleMeshMessage>>>,
    pub max_hops: u8,
}

impl BleMeshTransport {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            state: Arc::new(RwLock::new(BleNodeState::Disconnected)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            relay_queue: Arc::new(RwLock::new(Vec::new())),
            received: Arc::new(RwLock::new(Vec::new())),
            max_hops: 7,
        }
    }

    /// Start scanning for nearby Cipher devices.
    pub async fn start_scanning(&self) {
        *self.state.write().await = BleNodeState::Scanning;
    }

    /// Start advertising our presence.
    pub async fn start_advertising(&self) {
        *self.state.write().await = BleNodeState::Advertising;
    }

    /// Register a discovered peer.
    pub async fn peer_discovered(&self, peer: BlePeer) {
        self.peers
            .write()
            .await
            .insert(peer.device_id.clone(), peer);
    }

    /// Send a message via BLE mesh.
    pub async fn send_mesh_message(
        &self,
        destination: &str,
        payload: Vec<u8>,
    ) -> Result<String, CipherError> {
        let msg = BleMeshMessage {
            id: uuid::Uuid::new_v4().to_string(),
            origin: self.our_address.clone(),
            destination: destination.to_string(),
            payload,
            hop_count: 0,
            max_hops: self.max_hops,
            created_at: Utc::now(),
            ttl_secs: 3600, // 1 hour for mesh messages
        };

        let id = msg.id.clone();

        // Check if destination is a direct peer
        let peers = self.peers.read().await;
        if peers
            .values()
            .any(|p| p.cipher_address.as_deref() == Some(destination))
        {
            // Direct delivery possible
            self.relay_queue.write().await.push(msg);
        } else {
            // Need relay — queue for broadcast to nearby peers
            self.relay_queue.write().await.push(msg);
        }

        Ok(id)
    }

    /// Handle a received mesh message (relay or deliver).
    pub async fn handle_received(&self, mut msg: BleMeshMessage) -> bool {
        // Is this for us?
        if msg.destination == self.our_address {
            self.received.write().await.push(msg);
            return true; // Delivered
        }

        // Should we relay?
        if msg.hop_count < msg.max_hops {
            msg.hop_count += 1;
            self.relay_queue.write().await.push(msg);
            return false; // Relayed, not for us
        }

        false // Dropped (max hops exceeded)
    }

    /// Get messages pending relay.
    pub async fn drain_relay_queue(&self) -> Vec<BleMeshMessage> {
        std::mem::take(&mut *self.relay_queue.write().await)
    }

    /// Get messages received for us.
    pub async fn drain_received(&self) -> Vec<BleMeshMessage> {
        std::mem::take(&mut *self.received.write().await)
    }

    /// Get number of discovered peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ble_mesh_direct_delivery() {
        let transport = BleMeshTransport::new("0xAlice".into());

        // Discover Bob as a direct peer
        transport
            .peer_discovered(BlePeer {
                device_id: "BLE-BOB-001".into(),
                cipher_address: Some("0xBob".into()),
                rssi: -45,
                last_seen: Utc::now(),
                hop_count: 0,
                state: BleNodeState::Connected,
            })
            .await;

        // Send to Bob
        let id = transport
            .send_mesh_message("0xBob", vec![1, 2, 3])
            .await
            .unwrap();
        assert!(!id.is_empty());

        let queue = transport.drain_relay_queue().await;
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].destination, "0xBob");
    }

    #[tokio::test]
    async fn test_ble_mesh_relay() {
        let relay_node = BleMeshTransport::new("0xRelay".into());

        // Message not for us — should be relayed
        let msg = BleMeshMessage {
            id: "msg-1".into(),
            origin: "0xAlice".into(),
            destination: "0xBob".into(),
            payload: vec![1, 2, 3],
            hop_count: 1,
            max_hops: 7,
            created_at: Utc::now(),
            ttl_secs: 3600,
        };

        let delivered = relay_node.handle_received(msg).await;
        assert!(!delivered); // Not for us

        let relayed = relay_node.drain_relay_queue().await;
        assert_eq!(relayed.len(), 1);
        assert_eq!(relayed[0].hop_count, 2); // Incremented
    }

    #[tokio::test]
    async fn test_ble_mesh_max_hops() {
        let node = BleMeshTransport::new("0xNode".into());

        let msg = BleMeshMessage {
            id: "msg-2".into(),
            origin: "0xAlice".into(),
            destination: "0xBob".into(),
            payload: vec![1],
            hop_count: 7, // At max
            max_hops: 7,
            created_at: Utc::now(),
            ttl_secs: 3600,
        };

        node.handle_received(msg).await;
        let relayed = node.drain_relay_queue().await;
        assert!(relayed.is_empty()); // Dropped — max hops
    }
}
