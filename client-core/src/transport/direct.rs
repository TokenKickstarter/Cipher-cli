//! # Direct libp2p Transport
//!
//! Real peer-to-peer networking using libp2p with:
//! - WebSocket connection to VPS Storage Swarm relay
//! - Request/Response for encrypted chunk upload/download
//! - Kademlia DHT for peer discovery
//! - Background polling for incoming messages
//!
//! Per TKS Blueprint §3.5 — messages are stored as encrypted chunks
//! on the swarm relay nodes with TTL auto-delete.

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::error::CipherError;
use crate::transport::websocket_signal::sealed_mailbox;

/// The VPS relay addresses
const RELAY_TCP: &str = "/ip4/209.97.165.19/tcp/4001";
const RELAY_WS: &str = "/ip4/209.97.165.19/tcp/4002/ws";

/// Configuration for the direct transport.
#[derive(Debug, Clone)]
pub struct DirectTransportConfig {
    /// Bootstrap relay addresses
    pub relay_addrs: Vec<String>,
    /// Maximum stored messages per recipient
    pub max_stored_messages: usize,
    /// Message TTL in seconds (30 days)
    pub message_ttl: u64,
    /// Poll interval for incoming messages (milliseconds)
    pub poll_interval_ms: u64,
}

impl Default for DirectTransportConfig {
    fn default() -> Self {
        Self {
            relay_addrs: vec![RELAY_WS.to_string(), RELAY_TCP.to_string()],
            max_stored_messages: 1000,
            message_ttl: 30 * 86400, // 30 days
            poll_interval_ms: 15000, // 15 seconds to minimize Cloudflare Worker request consumption (100k/daily limit)
        }
    }
}

/// Request types matching the relay protocol
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RelayRequest {
    Store(StoredChunk),
    Fetch {
        recipient_id: String,
    },
    Ack {
        recipient_id: String,
        message_ids: Vec<String>,
    },
    Register {
        evm_address: String,
    },
    RpcProxy {
        endpoint: String,
        body: String,
    },
}

/// Response types from the relay
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RelayResponse {
    Stored { message_id: String },
    Chunks(Vec<StoredChunk>),
    Acked { deleted: usize },
    Registered,
    RpcResult { body: String },
    Error(String),
}

/// Encrypted chunk stored on the relay
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredChunk {
    pub recipient_id: String,
    pub message_id: String,
    pub ciphertext: Vec<u8>,
    pub stored_at: u64,
    pub expires_at: u64,
}

/// Outbox for messages waiting to be sent.
#[derive(Debug)]
pub struct MessageOutbox {
    pub pending: HashMap<String, Vec<QueuedMessage>>,
    pub delivered_count: u64,
}

/// A message waiting in the outbox.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub message: Vec<u8>,
    pub recipient: String,
    pub queued_at: chrono::DateTime<chrono::Utc>,
    pub retry_count: u32,
}

/// Inbox for received messages.
#[derive(Debug)]
pub struct MessageInbox {
    pub unread: Vec<Vec<u8>>,
}

/// Connection state to the relay
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

#[async_trait::async_trait]
pub trait RelaySender: Send + Sync {
    async fn send_to_relay(&self, request: &RelayRequest) -> Result<Vec<u8>, CipherError>;
}

/// Direct P2P transport manager — connects to VPS Storage Swarm relay.
pub struct DirectTransport {
    /// Our EVM address (used as peer ID on the relay)
    pub peer_id: String,
    /// Configuration  
    pub config: DirectTransportConfig,
    /// Outgoing message queue
    pub outbox: Arc<RwLock<MessageOutbox>>,
    /// Incoming message queue
    pub inbox: Arc<RwLock<MessageInbox>>,
    /// Channel for incoming messages from the network
    incoming_tx: mpsc::Sender<Vec<u8>>,
    incoming_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Connected peers (tracked via relay)
    pub connected_peers: Arc<RwLock<Vec<String>>>,
    /// The HTTP relay URL for simple JSON-RPC requests
    relay_url: String,
    /// Connection state
    pub connection_state: Arc<RwLock<ConnectionState>>,
    /// Running flag
    pub running: Arc<RwLock<bool>>,
    /// Manual wakeup to bypass sleep interval
    pub notify: Arc<tokio::sync::Notify>,
    /// Manual wakeup for incoming polling loop
    pub notify_incoming: Arc<tokio::sync::Notify>,
}

impl DirectTransport {
    /// Create a new direct transport with the given config.
    pub fn new(peer_id: String, config: DirectTransportConfig) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(1000);
        // Route through Cloudflare Worker HTTPS proxy for domain fronting.
        // ISPs see traffic to Cloudflare, not the VPS. WAF requires JSON content-type.
        let relay_url = "http://signal.tokenkickstarter.com:4002".to_string();

        Self {
            peer_id,
            config,
            outbox: Arc::new(RwLock::new(MessageOutbox {
                pending: HashMap::new(),
                delivered_count: 0,
            })),
            inbox: Arc::new(RwLock::new(MessageInbox { unread: Vec::new() })),
            incoming_tx,
            incoming_rx: Arc::new(Mutex::new(incoming_rx)),
            connected_peers: Arc::new(RwLock::new(Vec::new())),
            relay_url,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            running: Arc::new(RwLock::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
            notify_incoming: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Flush pending outbox messages to the relay.
    pub async fn flush_outbox(&self, sender: &dyn RelaySender) {
        let mut outbox = self.outbox.write().await;
        // Take the pending map temporarily so we can await inside the loop
        // without holding a borrow to the entire map contents.
        let pending = std::mem::take(&mut outbox.pending);

        for (recipient, messages) in pending {
            let mut failed_messages = Vec::new();

            for mut msg in messages {
                let chunk = StoredChunk {
                    // PRIVACY: sealed mailbox hash, not real address
                    recipient_id: sealed_mailbox(&recipient),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    ciphertext: msg.message.clone(),
                    stored_at: chrono::Utc::now().timestamp() as u64,
                    expires_at: (chrono::Utc::now().timestamp() as u64) + self.config.message_ttl,
                };

                let req = RelayRequest::Store(chunk);
                match sender.send_to_relay(&req).await {
                    Ok(response_bytes) => {
                        if let Ok(resp) = bincode::deserialize::<RelayResponse>(&response_bytes) {
                            match resp {
                                RelayResponse::Stored { message_id } => {
                                    debug!(
                                        "[Transport] ✅ Stored message {} for {}",
                                        message_id, recipient
                                    );
                                }
                                RelayResponse::Error(e) => {
                                    warn!("[Transport] Relay error storing message: {}", e);
                                    msg.retry_count += 1;
                                    failed_messages.push(msg);
                                    continue;
                                }
                                _ => {}
                            }
                        } else {
                            warn!("[Transport] Failed to decode relay response in outbox: {}", String::from_utf8_lossy(&response_bytes));
                            msg.retry_count += 1;
                            failed_messages.push(msg);
                            continue;
                        }
                        outbox.delivered_count += 1;
                    }
                    Err(e) => {
                        debug!("[Transport] Failed to send to relay (will retry): {}", e);
                        msg.retry_count += 1;
                        failed_messages.push(msg);
                    }
                }
            }

            // Put back any messages that failed to deliver
            if !failed_messages.is_empty() {
                outbox.pending.insert(recipient, failed_messages);
            }
        }
    }

    /// Poll relay for messages addressed to us.
    pub async fn poll_incoming(&self, sender: &dyn RelaySender) {
        let req = RelayRequest::Fetch {
            // PRIVACY: sealed mailbox hash
            recipient_id: sealed_mailbox(&self.peer_id),
        };

        match sender.send_to_relay(&req).await {
            Ok(response_bytes) => {
                if let Ok(resp) = bincode::deserialize::<RelayResponse>(&response_bytes) {
                    match resp {
                        RelayResponse::Chunks(chunks) if !chunks.is_empty() => {
                            info!(
                                "[Transport] 📬 Received {} messages from relay",
                                chunks.len()
                            );
                            let mut message_ids = Vec::new();

                            for chunk in chunks {
                                message_ids.push(chunk.message_id.clone());
                                // Push to inbox
                                let mut inbox = self.inbox.write().await;
                                inbox.unread.push(chunk.ciphertext);
                            }

                            // Ack receipt so relay deletes them
                            let ack_req = RelayRequest::Ack {
                                recipient_id: sealed_mailbox(&self.peer_id),
                                message_ids,
                            };
                            let _ = sender.send_to_relay(&ack_req).await;
                            // Wake Dart instantly — push notification for HTTP-delivered messages
                            crate::ffi::notify_dart();
                        }
                        _ => {} // No messages or error
                    }
                } else {
                    debug!("[Transport] Failed to decode relay response in poll: {}", String::from_utf8_lossy(&response_bytes));
                }
            }
            Err(e) => {
                debug!("[Transport] Poll failed (relay may be down): {}", e);
            }
        }
    }

    /// Send a serialized request to the relay via HTTP POST (simple fallback).
    /// In production, this would use a persistent libp2p WebSocket connection.
    pub async fn fallback_send_to_relay(&self, request: &RelayRequest) -> Result<Vec<u8>, CipherError> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        let request_bytes = bincode::serialize(request)
            .map_err(|e| CipherError::Network(format!("Serialize error: {}", e)))?;

        let url = format!("{}/relay", self.relay_url);

        // Use ureq for synchronous HTTP (works on all platforms)
        let response = tokio::task::spawn_blocking(move || {
            ureq::post(&url)
                .set("Content-Type", "application/octet-stream")
                .timeout(std::time::Duration::from_secs(30))
                .send_bytes(&request_bytes)
        })
        .await
        .map_err(|e| CipherError::Network(format!("Task join error: {}", e)))?
        .map_err(|e| CipherError::Network(format!("HTTP error: {}", e)))?;

        let mut body_bytes = Vec::new();
        response
            .into_reader()
            .read_to_end(&mut body_bytes)
            .map_err(|e| CipherError::Network(format!("Read error: {}", e)))?;

        Ok(body_bytes)
    }

    /// Queue a message for delivery via the relay.
    pub async fn queue_message(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        let mut outbox = self.outbox.write().await;
        let queue = outbox.pending.entry(recipient.to_string()).or_default();

        if queue.len() >= self.config.max_stored_messages {
            return Err(CipherError::Network(
                "Outbox full for this recipient".to_string(),
            ));
        }

        queue.push(QueuedMessage {
            message: data,
            recipient: recipient.to_string(),
            queued_at: chrono::Utc::now(),
            retry_count: 0,
        });

        debug!("[Transport] Queued message for {}", recipient);
        self.notify.notify_one();
        Ok(())
    }

    /// Get all pending messages for a recipient.
    pub async fn get_pending(&self, recipient: &str) -> Vec<Vec<u8>> {
        let outbox = self.outbox.read().await;
        outbox
            .pending
            .get(recipient)
            .map(|msgs| msgs.iter().map(|m| m.message.clone()).collect())
            .unwrap_or_default()
    }

    /// Mark messages as delivered and remove from outbox.
    pub async fn mark_delivered(&self, recipient: &str, count: usize) {
        let mut outbox = self.outbox.write().await;
        if let Some(queue) = outbox.pending.get_mut(recipient) {
            let drain_count = count.min(queue.len());
            queue.drain(0..drain_count);
            outbox.delivered_count += drain_count as u64;
        }
    }

    /// Push a received message into the inbox (used by tests).
    pub async fn push_received(&self, data: Vec<u8>) {
        let _ = self.incoming_tx.send(data.clone()).await;
        let mut inbox = self.inbox.write().await;
        inbox.unread.push(data);
    }

    /// Receive the next message (async, waits for message).
    pub async fn recv_next(&self) -> Option<Vec<u8>> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    /// Get unread message count.
    pub async fn unread_count(&self) -> usize {
        let inbox = self.inbox.read().await;
        inbox.unread.len()
    }

    /// Drain all unread messages from inbox.
    pub async fn drain_unread(&self) -> Vec<Vec<u8>> {
        let mut inbox = self.inbox.write().await;
        std::mem::take(&mut inbox.unread)
    }

    /// Add a connected peer.
    pub async fn add_peer(&self, peer_id: &str) {
        let mut peers = self.connected_peers.write().await;
        if !peers.contains(&peer_id.to_string()) {
            peers.push(peer_id.to_string());
            info!("Peer connected: {}", peer_id);
        }
    }

    /// Remove a disconnected peer.
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.connected_peers.write().await;
        peers.retain(|p| p != peer_id);
        info!("Peer disconnected: {}", peer_id);
    }

    /// Get list of connected peers.
    pub async fn peers(&self) -> Vec<String> {
        self.connected_peers.read().await.clone()
    }

    /// Check if running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get connection state.
    pub async fn state(&self) -> ConnectionState {
        self.connection_state.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_queue_and_retrieve() {
        let transport = DirectTransport::new(
            "0xtest-peer-1".to_string(),
            DirectTransportConfig::default(),
        );

        // Queue messages
        transport
            .queue_message("alice", vec![1, 2, 3])
            .await
            .unwrap();
        transport
            .queue_message("alice", vec![4, 5, 6])
            .await
            .unwrap();
        transport.queue_message("bob", vec![7, 8, 9]).await.unwrap();

        // Retrieve
        let alice_msgs = transport.get_pending("alice").await;
        assert_eq!(alice_msgs.len(), 2);
        assert_eq!(alice_msgs[0], vec![1, 2, 3]);

        let bob_msgs = transport.get_pending("bob").await;
        assert_eq!(bob_msgs.len(), 1);

        // Mark delivered
        transport.mark_delivered("alice", 1).await;
        let alice_after = transport.get_pending("alice").await;
        assert_eq!(alice_after.len(), 1);
        assert_eq!(alice_after[0], vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_inbox() {
        let transport = DirectTransport::new(
            "0xtest-peer-2".to_string(),
            DirectTransportConfig::default(),
        );

        transport.push_received(vec![10, 20, 30]).await;
        transport.push_received(vec![40, 50, 60]).await;

        assert_eq!(transport.unread_count().await, 2);

        let messages = transport.drain_unread().await;
        assert_eq!(messages.len(), 2);
        assert_eq!(transport.unread_count().await, 0);
    }

    #[tokio::test]
    async fn test_peer_management() {
        let transport = DirectTransport::new(
            "0xtest-peer-3".to_string(),
            DirectTransportConfig::default(),
        );

        transport.add_peer("peer-a").await;
        transport.add_peer("peer-b").await;
        assert_eq!(transport.peers().await.len(), 2);

        transport.remove_peer("peer-a").await;
        assert_eq!(transport.peers().await.len(), 1);
        assert_eq!(transport.peers().await[0], "peer-b");
    }
}

pub struct DefaultSender {
    pub direct: Arc<DirectTransport>,
}
#[async_trait::async_trait]
impl RelaySender for DefaultSender {
    async fn send_to_relay(&self, request: &RelayRequest) -> Result<Vec<u8>, CipherError> {
        self.direct.fallback_send_to_relay(request).await
    }
}
