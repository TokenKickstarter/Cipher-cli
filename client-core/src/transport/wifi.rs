//! # Wi-Fi Transport
//!
//! Two modes:
//! - Wi-Fi Direct (P2P without router): ~250 Mbps, 200m range
//! - Wi-Fi LAN (mDNS discovery on same network): full speed
//!
//! Supports HD calls + large file transfer in offline scenarios.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;

/// Wi-Fi transport mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WifiMode {
    /// Wi-Fi Direct (P2P, no router needed)
    Direct,
    /// Wi-Fi LAN (same network, mDNS discovery)
    Lan,
}

/// A discovered Wi-Fi peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiPeer {
    pub address: String,
    pub cipher_address: String,
    pub mode: WifiMode,
    pub ip: String,
    pub port: u16,
    pub signal_strength: Option<i16>,
    pub last_seen: DateTime<Utc>,
    pub capabilities: WifiCapabilities,
}

/// What a Wi-Fi peer can do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCapabilities {
    pub max_bandwidth_mbps: u32,
    pub supports_video_call: bool,
    pub supports_file_transfer: bool,
}

impl Default for WifiCapabilities {
    fn default() -> Self {
        Self {
            max_bandwidth_mbps: 250,
            supports_video_call: true,
            supports_file_transfer: true,
        }
    }
}

/// Wi-Fi transport manager.
pub struct WifiTransport {
    pub our_address: String,
    pub mode: Arc<RwLock<Option<WifiMode>>>,
    pub peers: Arc<RwLock<HashMap<String, WifiPeer>>>,
    pub outbox: Arc<RwLock<Vec<WifiMessage>>>,
    pub inbox: Arc<RwLock<Vec<WifiMessage>>>,
    pub listen_port: u16,
}

/// A message sent over Wi-Fi.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiMessage {
    pub id: String,
    pub sender: String,
    pub recipient: String,
    pub payload: Vec<u8>,
    pub timestamp: DateTime<Utc>,
    pub mode: WifiMode,
}

impl WifiTransport {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            mode: Arc::new(RwLock::new(None)),
            peers: Arc::new(RwLock::new(HashMap::new())),
            outbox: Arc::new(RwLock::new(Vec::new())),
            inbox: Arc::new(RwLock::new(Vec::new())),
            listen_port: 7331,
        }
    }

    /// Start Wi-Fi Direct group owner mode.
    pub async fn start_wifi_direct(&self) {
        *self.mode.write().await = Some(WifiMode::Direct);
    }

    /// Start mDNS/Bonjour discovery on LAN.
    pub async fn start_lan_discovery(&self) {
        *self.mode.write().await = Some(WifiMode::Lan);
    }

    /// Register a discovered peer.
    pub async fn peer_discovered(&self, peer: WifiPeer) {
        self.peers
            .write()
            .await
            .insert(peer.cipher_address.clone(), peer);
    }

    /// Send a message to a Wi-Fi peer.
    pub async fn send(&self, recipient: &str, payload: Vec<u8>) -> Result<String, CipherError> {
        let peers = self.peers.read().await;
        let peer = peers
            .get(recipient)
            .ok_or(CipherError::Network("Wi-Fi peer not found".into()))?;

        let mode = peer.mode.clone();
        let msg = WifiMessage {
            id: uuid::Uuid::new_v4().to_string(),
            sender: self.our_address.clone(),
            recipient: recipient.to_string(),
            payload,
            timestamp: Utc::now(),
            mode,
        };

        let id = msg.id.clone();
        self.outbox.write().await.push(msg);
        Ok(id)
    }

    /// Push a received message.
    pub async fn push_received(&self, msg: WifiMessage) {
        self.inbox.write().await.push(msg);
    }

    /// Drain outbox for sending.
    pub async fn drain_outbox(&self) -> Vec<WifiMessage> {
        std::mem::take(&mut *self.outbox.write().await)
    }

    /// Drain inbox.
    pub async fn drain_inbox(&self) -> Vec<WifiMessage> {
        std::mem::take(&mut *self.inbox.write().await)
    }

    /// Get current mode.
    pub async fn current_mode(&self) -> Option<WifiMode> {
        self.mode.read().await.clone()
    }

    /// Get peer count.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wifi_direct_send() {
        let transport = WifiTransport::new("0xAlice".into());
        transport.start_wifi_direct().await;

        transport
            .peer_discovered(WifiPeer {
                address: "192.168.49.2".into(),
                cipher_address: "0xBob".into(),
                mode: WifiMode::Direct,
                ip: "192.168.49.2".into(),
                port: 7331,
                signal_strength: Some(-30),
                last_seen: Utc::now(),
                capabilities: WifiCapabilities::default(),
            })
            .await;

        let id = transport.send("0xBob", vec![1, 2, 3]).await.unwrap();
        assert!(!id.is_empty());

        let outbox = transport.drain_outbox().await;
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].mode, WifiMode::Direct);
    }

    #[tokio::test]
    async fn test_wifi_lan_discovery() {
        let transport = WifiTransport::new("0xAlice".into());
        transport.start_lan_discovery().await;

        assert_eq!(transport.current_mode().await, Some(WifiMode::Lan));

        transport
            .peer_discovered(WifiPeer {
                address: "192.168.1.50".into(),
                cipher_address: "0xCharlie".into(),
                mode: WifiMode::Lan,
                ip: "192.168.1.50".into(),
                port: 7331,
                signal_strength: None,
                last_seen: Utc::now(),
                capabilities: WifiCapabilities {
                    max_bandwidth_mbps: 1000,
                    supports_video_call: true,
                    supports_file_transfer: true,
                },
            })
            .await;

        assert_eq!(transport.peer_count().await, 1);
    }
}
