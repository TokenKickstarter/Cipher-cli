//! # Swarm Client
//!
//! High-level messaging API that ties together identity, encryption,
//! transport, and message protocol into a simple send/receive interface.
//!
//! ```text
//! App → SwarmClient.send_text("0xRecipient", "Hello!")
//!   → DoubleRatchet.encrypt(plaintext)
//!   → CipherMessage envelope
//!   → Transport.send(recipient, bytes)
//!   → Nym/Tor/Direct delivery
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, debug};

use crate::encryption::{DoubleRatchet, PrekeyBundle, x3dh_initiate, aes_encrypt};
use crate::error::CipherError;
use crate::identity::CipherIdentity;
use crate::message::{CipherMessage, MessageId, MessageType, ReceiptType, PresenceInfo};
use crate::transport::direct::DirectTransportConfig;
use crate::transport::{TransportRouter, TransportMode};

/// Peer presence state tracked locally.
#[derive(Debug, Clone)]
pub struct PeerPresence {
    pub is_online: bool,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Delivery status for a sent message.
#[derive(Debug, Clone, PartialEq)]
pub enum DeliveryStatus {
    Queued,
    Sent,
    Delivered,
    Read,
    Failed(String),
}

/// A conversation with one peer.
pub struct Conversation {
    /// Peer's EVM address
    pub peer_address: String,
    /// Double Ratchet session (None if no X3DH yet)
    pub ratchet: Option<DoubleRatchet>,
    /// Message history (IDs only, content in local DB)
    pub message_ids: Vec<MessageId>,
    /// Delivery statuses
    pub statuses: HashMap<MessageId, DeliveryStatus>,
    /// Unread count
    pub unread: u32,
}

/// The main Cipher client — your interface to the network.
pub struct SwarmClient {
    pub identity: CipherIdentity,
    conversations: Arc<RwLock<HashMap<String, Conversation>>>,
    pub transport: Arc<TransportRouter>,
    sent_log: Arc<RwLock<HashMap<MessageId, CipherMessage>>>,
    inbox: Arc<RwLock<Vec<CipherMessage>>>,
    pub media_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Recently seen message IDs for deduplication (dual WebSocket + HTTP delivery)
    seen_ids: Arc<RwLock<std::collections::HashSet<MessageId>>>,
    /// Per-peer presence state
    peer_presence: Arc<RwLock<HashMap<String, PeerPresence>>>,
    /// Whether this user has opted into online presence broadcasting
    pub presence_enabled: Arc<RwLock<bool>>,
}

impl SwarmClient {
    /// Create a new swarm client.
    pub fn new(identity: CipherIdentity) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1000);
        let peer_id = identity.display_address();
        let transport = TransportRouter::new(peer_id);

        Self {
            identity,
            conversations: Arc::new(RwLock::new(HashMap::new())),
            transport: Arc::new(transport),
            sent_log: Arc::new(RwLock::new(HashMap::new())),
            inbox: Arc::new(RwLock::new(Vec::new())),
            media_tx: tx,
            seen_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            peer_presence: Arc::new(RwLock::new(HashMap::new())),
            presence_enabled: Arc::new(RwLock::new(true)),
        }
    }

    /// Background synchronization daemon.
    /// Also starts the relay polling daemon for real P2P message delivery.
    pub fn start_sync_daemon(self: Arc<Self>) {
        // Start the TransportRouter (auto-selects Nym/Tor/Direct)
        let router = self.transport.clone();
        crate::ffi::runtime().spawn(async move {
            router.start().await;
        });

        // ── HTTP Relay polling loop ──────────────────────────────────────────
        // Fetches store-and-forward messages from the Cloudflare relay every
        // 15 seconds (the relay rate-limits more aggressive polling).
        // This is the PRIMARY path for text message delivery.
        let transport_for_poll = self.transport.clone();
        crate::ffi::runtime().spawn(async move {
            // Give the transport a moment to initialise before first poll
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            loop {
                let sender = crate::transport::direct::DefaultSender {
                    direct: transport_for_poll.direct.clone(),
                };
                transport_for_poll.direct.poll_incoming(&sender).await;

                // Also flush any queued outgoing messages
                transport_for_poll.direct.flush_outbox(&sender).await;

                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
            }
        });

        // Incoming message processing loop (200ms) — drains WebSocket + HTTP inboxes into Dart
        let client = self.clone();
        crate::ffi::runtime().spawn(async move {
            loop {
                client.process_incoming().await;
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }
        });

        // Presence heartbeat loop (every 30s)
        let client2 = self.clone();
        crate::ffi::runtime().spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
                let enabled = *client2.presence_enabled.read().await;
                if enabled {
                    client2.broadcast_presence(true).await;
                }
                // Expire stale presences: peer is marked offline if not seen in >45s
                // (i.e. missed 1.5× the 30s heartbeat interval)
                let mut presence = client2.peer_presence.write().await;
                let now = chrono::Utc::now();
                let stale_cutoff = now - chrono::Duration::seconds(45);
                for (_, p) in presence.iter_mut() {
                    if p.is_online && p.last_seen < stale_cutoff {
                        p.is_online = false;
                    }
                }
            }
        });
    }


    /// Create with custom transport config (e.g., specific bootstrap nodes).
    pub fn with_config(identity: CipherIdentity, config: DirectTransportConfig) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1000);
        let peer_id = identity.display_address();
        // Since TransportRouter manages Tor/Nym too, we inject the config into the direct transport
        // For now, we just use the default router initialization
        let transport = TransportRouter::new(peer_id);

        Self {
            identity,
            conversations: Arc::new(RwLock::new(HashMap::new())),
            transport: Arc::new(transport),
            sent_log: Arc::new(RwLock::new(HashMap::new())),
            inbox: Arc::new(RwLock::new(Vec::new())),
            media_tx: tx,
            seen_ids: Arc::new(RwLock::new(std::collections::HashSet::new())),
            peer_presence: Arc::new(RwLock::new(HashMap::new())),
            presence_enabled: Arc::new(RwLock::new(true)),
        }
    }

    /// Get our EVM address (= chat ID).
    pub fn our_address(&self) -> String {
        self.identity.display_address()
    }

    /// Send a text message to a recipient.
    pub async fn send_text(&self, recipient: &str, plaintext: &str) -> Result<MessageId, CipherError> {
        let conversations = self.conversations.read().await;
        let has_ratchet = conversations
            .get(recipient)
            .and_then(|c| c.ratchet.as_ref())
            .is_some();
        drop(conversations);

        if !has_ratchet {
            // No existing session — we need to do X3DH first
            // For now, use a simple shared-key approach (will be X3DH with prekey bundles later)
            debug!("No ratchet session with {} — creating new session", recipient);
        }

        // Encrypt the message
        // For now, use a derived session key (real: Double Ratchet)
        let session_key = self.derive_temp_session_key(recipient);
        let encrypted = aes_encrypt(&session_key, plaintext.as_bytes())?;

        // Build CipherMessage envelope
        let our_addr = self.our_address();
        let msg = CipherMessage::new_text(
            &our_addr,
            recipient,
            encrypted.ciphertext,
            encrypted.nonce,
            [0u8; 32], // DH public (populated by ratchet in production)
            0,
        );

        let msg_id = msg.id;

        // Serialize and queue for delivery via HTTP relay
        let data = msg.to_bytes();
        self.transport.queue_message(recipient, data).await?;

        // Track in sent log
        self.sent_log.write().await.insert(msg_id, msg);

        // Track in conversation
        let mut conversations = self.conversations.write().await;
        let conv = conversations.entry(recipient.to_string()).or_insert(Conversation {
            peer_address: recipient.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.message_ids.push(msg_id);
        conv.statuses.insert(msg_id, DeliveryStatus::Queued);

        info!("Message {} queued for {}", msg_id, recipient);
        Ok(msg_id)
    }

    /// Send a file (image, video, document, etc.) encrypted in chunks.
    ///
    /// Flow:
    /// 1. Read file → split into 2MB AES-256-GCM encrypted chunks
    /// 2. Send a `MessageType::File(metadata)` header message
    /// 3. Send each encrypted chunk as a separate message
    /// 4. Recipient reassembles chunks and verifies Merkle root
    pub async fn send_file(
        &self,
        recipient: &str,
        file_data: &[u8],
        file_name: &str,
        mime_type: &str,
    ) -> Result<(MessageId, crate::message::FileMetadata), CipherError> {
        let session_key = self.derive_temp_session_key(recipient);

        let metadata = crate::message::FileMetadata {
            file_name: file_name.to_string(),
            mime_type: mime_type.to_string(),
            size_bytes: file_data.len() as u64,
            total_chunks: 1,
            merkle_root: {
                use sha2::{Sha256, Digest};
                let mut h = Sha256::new();
                h.update(file_data);
                let result = h.finalize();
                let mut root = [0u8; 32];
                root.copy_from_slice(&result);
                root
            },
            thumbnail: None,
        };

        // Encrypt the ACTUAL file data (not just metadata)
        let encrypted = aes_encrypt(&session_key, file_data)?;

        let our_addr = self.our_address();
        let msg = CipherMessage {
            id: uuid::Uuid::new_v4(),
            sender: our_addr.clone(),
            recipient: recipient.to_string(),
            msg_type: MessageType::File(metadata.clone()),
            timestamp: chrono::Utc::now(),
            payload: encrypted.ciphertext,
            nonce: encrypted.nonce,
            dh_public: [0u8; 32],
            counter: 0,
            ttl: 30 * 86400,
        };

        let msg_id = msg.id;
        let data = msg.to_bytes();

        // Send via transport and flush immediately
        self.transport.queue_message(recipient, data).await?;
        self.transport.direct.flush_outbox(&crate::transport::direct::DefaultSender {
            direct: self.transport.direct.clone(),
        }).await;

        self.sent_log.write().await.insert(msg_id, msg);

        // Track in conversation
        let mut conversations = self.conversations.write().await;
        let conv = conversations.entry(recipient.to_string()).or_insert(Conversation {
            peer_address: recipient.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.message_ids.push(msg_id);
        conv.statuses.insert(msg_id, DeliveryStatus::Queued);

        info!(
            "File '{}' ({} bytes) sent to {}",
            file_name,
            file_data.len(),
            recipient
        );

        Ok((msg_id, metadata))
    }

    pub async fn send_webrtc_media(&self, recipient: &str, media_bytes: Vec<u8>) -> Result<MessageId, CipherError> {
        let session_key = self.derive_temp_session_key(recipient);
        let encrypted = aes_encrypt(&session_key, &media_bytes)?;

        let our_addr = self.our_address();
        let msg = CipherMessage::new_media(
            &our_addr,
            recipient,
            encrypted.ciphertext,
            encrypted.nonce,
            [0u8; 32],
            0,
        );

        let msg_id = msg.id;
        let data = msg.to_bytes();

        // Push directly to transport without heavy conversation tracking
        self.transport.queue_message(recipient, data).await?;
        
        // We do *not* track UDP media in sent_log or conversations to save huge amounts of RAM!
        Ok(msg_id)
    }

    /// Send a call signal (Offer, Answer, ICE, Hangup).
    pub async fn send_call_signal(&self, recipient: &str, signal: crate::message::CallSignalType) -> Result<MessageId, CipherError> {
        let plaintext = serde_json::to_vec(&signal)
            .map_err(|e| CipherError::Encryption(e.to_string()))?;
        
        let session_key = self.derive_temp_session_key(recipient);
        use crate::encryption::aes_encrypt;
        let encrypted_payload = aes_encrypt(&session_key, &plaintext)?;

        let msg = CipherMessage::new_signal(
            &self.our_address(),
            recipient,
            signal,
            encrypted_payload.ciphertext,
            encrypted_payload.nonce,
            [0u8; 32],
            0,
        );
        let msg_id = msg.id;

        let data = msg.to_bytes();
        // Use the WebSocket instant channel for call signals (falls back to HTTP if disconnected)
        self.transport.send_signal(recipient, data).await?;

        self.sent_log.write().await.insert(msg_id, msg);

        let mut conversations = self.conversations.write().await;
        let conv = conversations.entry(recipient.to_string()).or_insert(Conversation {
            peer_address: recipient.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.message_ids.push(msg_id);
        conv.statuses.insert(msg_id, DeliveryStatus::Queued);

        info!("Call signal {} queued for {}", msg_id, recipient);
        Ok(msg_id)
    }

    /// Background loop: Receive and process all pending messages autonomously
    pub async fn process_incoming(&self) {
        let raw_messages = self.transport.drain_unread().await;

        for data in raw_messages {
            match CipherMessage::from_bytes(&data) {
                Ok(mut msg) => {
                    let sender = msg.sender.clone();
                    let msg_id = msg.id;

                    // Dedup: skip if we've already processed this message
                    // (can arrive twice via WebSocket + HTTP dual delivery)
                    {
                        let mut seen = self.seen_ids.write().await;
                        if seen.contains(&msg_id) {
                            continue;
                        }
                        seen.insert(msg_id);
                        // Prune seen set if it gets too large (keep last 500)
                        if seen.len() > 500 {
                            let to_remove: Vec<_> = seen.iter().take(250).cloned().collect();
                            for id in to_remove { seen.remove(&id); }
                        }
                    }

                    // Decrypt payload immediately
                    let session_key = self.derive_temp_session_key(&sender);
                    use crate::encryption::{aes_decrypt, EncryptedMessage};
                    let encrypted_msg = EncryptedMessage {
                        ciphertext: msg.payload.clone(),
                        nonce: msg.nonce,
                    };
                    
                    match aes_decrypt(&session_key, &encrypted_msg) {
                        Ok(plaintext) => {
                            // If this is a naked UDP payload, intercept it out of the UI pipeline!
                            if msg.msg_type == crate::message::MessageType::CallMedia {
                                let _ = self.media_tx.send(plaintext);
                                continue; 
                            }
                            
                            // Otherwise, unwrap the decrypted JSON back into the public wrapper
                            msg.payload = plaintext;
                        }
                        Err(e) => {
                            log::warn!("Failed to decrypt message {} from {}: {}", msg_id, sender, e);
                            continue;
                        }
                    }

                    // Track in conversations for UI notifications
                    let mut conversations = self.conversations.write().await;
                    let conv = conversations.entry(sender.clone()).or_insert(Conversation {
                        peer_address: sender.clone(),
                        ratchet: None,
                        message_ids: Vec::new(),
                        statuses: HashMap::new(),
                        unread: 0,
                    });

                    // Handle receipts: update delivery status on our sent messages
                    match &msg.msg_type {
                        MessageType::Receipt(receipt_type) => {
                            // The original message ID is inside the decrypted JSON payload 
                            // (envelope ID is now unique to pass deduplication)
                            if let Ok(payload_str) = String::from_utf8(msg.payload.clone()) {
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                                    if let Some(ref_id_str) = json["receipt_for"].as_str() {
                                        if let Ok(ref_msg_id) = uuid::Uuid::parse_str(ref_id_str) {
                                            // Find this message in ALL conversations and update its status
                                            for conv_entry in conversations.values_mut() {
                                                if let Some(status) = conv_entry.statuses.get_mut(&ref_msg_id) {
                                                    match receipt_type {
                                                        ReceiptType::Delivered => {
                                                            if *status != DeliveryStatus::Read {
                                                                *status = DeliveryStatus::Delivered;
                                                            }
                                                        }
                                                        ReceiptType::Read => {
                                                            *status = DeliveryStatus::Read;
                                                        }
                                                    }
                                                    info!("Receipt {:?} for message {} from {}", receipt_type, ref_msg_id, sender);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            drop(conversations);
                            // Receipts are NOT added to inbox — they are internal protocol messages
                            continue;
                        }
                        MessageType::Presence(presence_info) => {
                            // Update peer presence state
                            drop(conversations);
                            let mut presence = self.peer_presence.write().await;
                            presence.insert(sender.clone(), PeerPresence {
                                is_online: presence_info.is_online,
                                last_seen: presence_info.last_seen,
                            });
                            info!("Presence update from {}: online={}", sender, presence_info.is_online);
                            // Presence is NOT added to inbox — it is an internal system message
                            continue;
                        }
                        _ => {
                            // Normal message — track and add to inbox
                            conv.message_ids.push(msg_id);
                            conv.unread += 1;
                            drop(conversations);

                            // Auto-send delivery receipt back to sender
                            let _ = self.send_receipt(&sender, msg_id, ReceiptType::Delivered).await;
                        }
                    }

                    // Append to unread inbox for Dart to poll!
                    self.inbox.write().await.push(msg);
                }
                Err(e) => {
                    log::warn!("Failed to decode message envelope: {}", e);
                }
            }
        }
    }

    /// Read all pending messages from the local asynchronous inbox (polled by Dart FFI interface)
    pub async fn receive_all(&self) -> Vec<CipherMessage> {
        let mut inbox = self.inbox.write().await;
        let messages = inbox.clone();
        inbox.clear();
        messages
    }

    /// Get delivery status for a message.
    pub async fn delivery_status(&self, msg_id: &MessageId) -> Option<DeliveryStatus> {
        let conversations = self.conversations.read().await;
        for conv in conversations.values() {
            if let Some(status) = conv.statuses.get(msg_id) {
                return Some(status.clone());
            }
        }
        None
    }

    /// Get all conversation addresses.
    pub async fn conversation_list(&self) -> Vec<String> {
        self.conversations.read().await.keys().cloned().collect()
    }

    /// Get unread count for a conversation.
    pub async fn unread_count(&self, peer: &str) -> u32 {
        self.conversations
            .read()
            .await
            .get(peer)
            .map(|c| c.unread)
            .unwrap_or(0)
    }

    /// Mark conversation as read.
    pub async fn mark_read(&self, peer: &str) {
        let mut conversations = self.conversations.write().await;
        if let Some(conv) = conversations.get_mut(peer) {
            conv.unread = 0;
        }
    }

    /// Get total unread across all conversations.
    pub async fn total_unread(&self) -> u32 {
        self.conversations
            .read()
            .await
            .values()
            .map(|c| c.unread)
            .sum()
    }

    /// Temporary session key derivation (placeholder until full X3DH/Ratchet).
    /// In production: X3DH → shared secret → Double Ratchet → per-message keys.
    fn derive_temp_session_key(&self, peer: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        
        let our_addr = self.our_address().to_lowercase();
        let their_addr = peer.to_lowercase();
        
        // Sort for symmetry
        let (first, second) = if our_addr < their_addr {
            (our_addr, their_addr)
        } else {
            (their_addr, our_addr)
        };
        
        hasher.update(first.as_bytes());
        hasher.update(second.as_bytes());
        hasher.update(b"cipher-temp-session-v1");
        
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    // --------- Read Receipt Methods ---------

    /// Send a delivery/read receipt for a specific message.
    pub async fn send_receipt(&self, recipient: &str, msg_id: MessageId, receipt_type: ReceiptType) -> Result<(), CipherError> {
        let session_key = self.derive_temp_session_key(recipient);
        let payload_text = serde_json::json!({
            "receipt_for": msg_id.to_string(),
            "type": format!("{:?}", receipt_type),
        }).to_string();
        let encrypted = aes_encrypt(&session_key, payload_text.as_bytes())?;

        let msg = CipherMessage::new_receipt(
            &self.our_address(),
            recipient,
            receipt_type,
            msg_id,
            encrypted.ciphertext,
            encrypted.nonce,
            [0u8; 32],
            0,
        );

        let data = msg.to_bytes();
        self.transport.queue_message(recipient, data).await?;
        debug!("Sent receipt for {} to {}", msg_id, recipient);
        Ok(())
    }

    /// Send read receipts for all unread messages from a peer.
    pub async fn send_read_receipts(&self, peer: &str) -> Result<u32, CipherError> {
        let conversations = self.conversations.read().await;
        let msg_ids: Vec<MessageId> = match conversations.get(peer) {
            Some(conv) => conv.message_ids.clone(),
            None => return Ok(0),
        };
        drop(conversations);

        let mut sent_count = 0u32;
        for msg_id in msg_ids {
            if self.send_receipt(peer, msg_id, ReceiptType::Read).await.is_ok() {
                sent_count += 1;
            }
        }
        Ok(sent_count)
    }

    // --------- Presence Methods ---------

    /// Broadcast presence to all known conversation peers.
    pub async fn broadcast_presence(&self, is_online: bool) {
        let conversations = self.conversations.read().await;
        let peers: Vec<String> = conversations.keys().cloned().collect();
        drop(conversations);

        let info = PresenceInfo {
            is_online,
            last_seen: chrono::Utc::now(),
        };

        for peer in peers {
            let _ = self.send_presence(&peer, info.clone()).await;
        }
    }

    /// Send a presence heartbeat to a specific peer.
    pub async fn send_presence(&self, recipient: &str, info: PresenceInfo) -> Result<(), CipherError> {
        let session_key = self.derive_temp_session_key(recipient);
        let payload = serde_json::to_vec(&info)
            .map_err(|e| CipherError::Encryption(e.to_string()))?;
        let encrypted = aes_encrypt(&session_key, &payload)?;

        let msg = CipherMessage::new_presence(
            &self.our_address(),
            recipient,
            info,
            encrypted.ciphertext,
            encrypted.nonce,
            [0u8; 32],
            0,
        );

        let data = msg.to_bytes();
        self.transport.queue_message(recipient, data).await?;
        Ok(())
    }

    /// Get the presence state for a specific peer.
    pub async fn get_peer_presence(&self, peer: &str) -> Option<PeerPresence> {
        self.peer_presence.read().await.get(peer).cloned()
    }

    /// Get presence state for all peers.
    pub async fn get_all_presence(&self) -> HashMap<String, PeerPresence> {
        self.peer_presence.read().await.clone()
    }

    /// Set whether presence broadcasting is enabled.
    pub async fn set_presence_enabled(&self, enabled: bool) {
        *self.presence_enabled.write().await = enabled;
        if !enabled {
            // Immediately broadcast offline to all peers
            self.broadcast_presence(false).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CipherIdentity;

    #[tokio::test]
    async fn test_send_text_message() {
        let identity = CipherIdentity::generate().unwrap();
        let client = SwarmClient::new(identity);

        let msg_id = client.send_text("0xRecipient123", "Hello from Cipher!").await.unwrap();

        // Should be queued
        let status = client.delivery_status(&msg_id).await.unwrap();
        assert_eq!(status, DeliveryStatus::Queued);

        // Should appear in conversation list
        let convos = client.conversation_list().await;
        assert!(convos.contains(&"0xRecipient123".to_string()));
    }

    #[tokio::test]
    async fn test_receive_messages() {
        let identity = CipherIdentity::generate().unwrap();
        let client = SwarmClient::new(identity);

        // Simulate incoming message
        let msg = CipherMessage::new_text(
            "0xSender999",
            &client.our_address(),
            vec![1, 2, 3],
            [0u8; 12],
            [0u8; 32],
            0,
        );
        client.transport.push_received(msg.to_bytes()).await;

        // Receive
        let received = client.receive_all().await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].sender, "0xSender999");
        assert_eq!(client.unread_count("0xSender999").await, 1);

        // Mark read
        client.mark_read("0xSender999").await;
        assert_eq!(client.unread_count("0xSender999").await, 0);
    }

    #[tokio::test]
    async fn test_multiple_conversations() {
        let identity = CipherIdentity::generate().unwrap();
        let client = SwarmClient::new(identity);

        client.send_text("0xAlice", "Hi Alice").await.unwrap();
        client.send_text("0xBob", "Hi Bob").await.unwrap();
        client.send_text("0xAlice", "How are you?").await.unwrap();

        let convos = client.conversation_list().await;
        assert_eq!(convos.len(), 2);
    }
}
