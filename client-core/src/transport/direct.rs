//! # Federated HTTP relay transport (store / fetch / ack)
//!
//! Ciphertext is store-and-forwarded via **many** TKS cipher-relay HTTP bases
//! (`RelayPool` — no single default hostname). Peers are merged from
//! `network_bundle.default.json`, `CIPHER_NETWORK_BUNDLE`, and `GET /discovery`.

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::error::CipherError;
use crate::network_bundle::RelayPool;
use crate::transport::websocket_signal::sealed_mailbox;

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
            relay_addrs: vec![],
            max_stored_messages: 1000,
            message_ttl: 30 * 86400, // 30 days
            poll_interval_ms: 3000,
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

#[derive(Debug, Default, Clone, Copy)]
pub struct FlushStats {
    pub delivered: usize,
    pub failed: usize,
}

fn store_response_ok(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    if v.get("Stored").is_some() {
        return true;
    }
    if v.get("error").is_some() || v.get("Error").is_some() {
        return false;
    }
    // Some relays return bare { "message_id": "..." }
    v.get("message_id").and_then(|m| m.as_str()).is_some_and(|s| !s.is_empty())
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
    /// Federated relay bases (failover + discovery merge)
    relay_pool: Arc<RelayPool>,
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
    /// Create a new direct transport with the given config and relay pool.
    pub fn new(peer_id: String, config: DirectTransportConfig, relay_pool: Arc<RelayPool>) -> Self {
        Self::new_with_notify(peer_id, config, relay_pool, Arc::new(tokio::sync::Notify::new()))
    }

    /// Create a new direct transport sharing an incoming wake notifier with `TransportRouter`.
    pub fn new_with_notify(
        peer_id: String,
        config: DirectTransportConfig,
        relay_pool: Arc<RelayPool>,
        notify_incoming: Arc<tokio::sync::Notify>,
    ) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(1000);

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
            relay_pool,
            connection_state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            running: Arc::new(RwLock::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
            notify_incoming,
        }
    }

    pub fn relay_pool(&self) -> &Arc<RelayPool> {
        &self.relay_pool
    }

    /// Flush pending outbox messages to the relay via JSON REST API.
    pub async fn flush_outbox(&self, _sender: &dyn RelaySender) -> Result<FlushStats, CipherError> {
        let mut outbox = self.outbox.write().await;
        let pending = std::mem::take(&mut outbox.pending);
        let mut stats = FlushStats::default();

        for (recipient, messages) in pending {
            let mut failed_messages = Vec::new();

            for mut msg in messages {
                let recipient_id = sealed_mailbox(&recipient);
                let message_id = uuid::Uuid::new_v4().to_string();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let payload = serde_json::json!({
                    "recipient_id": recipient_id,
                    "message_id": message_id,
                    "ciphertext": msg.message,
                    "stored_at": now,
                    "expires_at": now + self.config.message_ttl,
                });

                let body = payload.to_string();
                let pool = self.relay_pool.clone();
                let stored = pool.post_json_failover("/store", body, 30).await;

                match stored {
                    Some((_base, resp_text)) if store_response_ok(&resp_text) => {
                        debug!(
                            "[Transport] ✅ Stored {} for {}",
                            &message_id[..8.min(message_id.len())],
                            &recipient_id[..12.min(recipient_id.len())]
                        );
                        outbox.delivered_count += 1;
                        stats.delivered += 1;
                    }
                    Some((_base, resp_text)) => {
                        warn!("[Transport] Relay rejected store: {}", resp_text.chars().take(120).collect::<String>());
                        msg.retry_count += 1;
                        failed_messages.push(msg);
                        stats.failed += 1;
                    }
                    None => {
                        warn!("[Transport] Store failed on all relays");
                        msg.retry_count += 1;
                        failed_messages.push(msg);
                        stats.failed += 1;
                    }
                }
            }

            if !failed_messages.is_empty() {
                outbox.pending.insert(recipient, failed_messages);
            }
        }

        if stats.delivered == 0 && stats.failed > 0 {
            return Err(CipherError::Network(format!(
                "Could not store {} message(s) on any relay (check network / cipher-cli network)",
                stats.failed
            )));
        }
        if stats.failed > 0 {
            warn!(
                "[Transport] {} delivered, {} failed (will retry in background)",
                stats.delivered, stats.failed
            );
        }
        Ok(stats)
    }

    /// Poll relay for messages addressed to us via JSON REST API.
    pub async fn poll_incoming(&self, _sender: &dyn RelaySender) {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        let recipient_id = sealed_mailbox(&self.peer_id);
        let rid = recipient_id.clone();
        let fetch_body = serde_json::json!({ "recipient_id": rid }).to_string();
        let pool = self.relay_pool.clone();
        let responses = pool
            .post_fetch_parallel(fetch_body, 3)
            .await;
        let mut any = false;

        for (base, resp_text) in responses {
            let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_text) else {
                continue;
            };
            let chunks_opt = parsed
                .get("Chunks")
                .and_then(|v| v.as_array())
                .or_else(|| parsed.get("messages").and_then(|v| v.as_array()));

            let Some(messages) = chunks_opt else { continue };
            if messages.is_empty() {
                continue;
            }

            any = true;
            info!(
                "[Transport] 📬 {} message(s) from relay {}",
                messages.len(),
                base
            );
            let mut ack_ids: Vec<String> = Vec::new();

            for msg in messages {
                let mid = msg["message_id"].as_str().unwrap_or("").to_string();
                if !mid.is_empty() {
                    ack_ids.push(mid);
                }

                let bytes_opt = if let Some(arr) = msg["ciphertext"].as_array() {
                    Some(
                        arr.iter()
                            .filter_map(|v| v.as_u64().map(|b| b as u8))
                            .collect::<Vec<u8>>(),
                    )
                } else if let Some(data_b64) = msg["data"].as_str() {
                    BASE64.decode(data_b64).ok()
                } else {
                    None
                };

                if let Some(ciphertext) = bytes_opt {
                    let mut inbox = self.inbox.write().await;
                    inbox.unread.push(ciphertext);
                }
            }

            if !ack_ids.is_empty() {
                let ack_body = serde_json::json!({
                    "recipient_id": recipient_id,
                    "message_ids": ack_ids,
                })
                .to_string();
                let _ = RelayPool::post_to_base(&base, "/ack", ack_body, 5).await;
            }
        }

        if any {
            self.notify_incoming.notify_waiters();
            crate::ffi::notify_dart();
        }
    }

    /// Send a request to the relay (legacy fallback — not used by new JSON API).
    pub async fn fallback_send_to_relay(&self, _request: &RelayRequest) -> Result<Vec<u8>, CipherError> {
        // The new JSON API uses flush_outbox and poll_incoming directly.
        // This is kept for trait compatibility.
        Ok(vec![])
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
        drop(inbox);
        self.notify_incoming.notify_waiters();
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
    use crate::network_bundle::{NetworkBundle, RelayPool};

    fn test_pool() -> Arc<RelayPool> {
        RelayPool::from_bundle(&NetworkBundle {
            version: 1,
            bundle_id: "test".into(),
            http_relays: vec!["http://127.0.0.1:9".into()],
            signal_ws: vec![],
            rpc_http: vec![],
            iroh_relays: vec![],
            notes: None,
        })
    }

    #[tokio::test]
    async fn test_queue_and_retrieve() {
        let transport = DirectTransport::new(
            "0xtest-peer-1".to_string(),
            DirectTransportConfig::default(),
            test_pool(),
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
            test_pool(),
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
            test_pool(),
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
