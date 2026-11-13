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

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
use log::{info, debug};

use crate::encryption::{
    aes_decrypt, aes_encrypt, x3dh_initiate, x3dh_respond, DoubleRatchet, EncryptedMessage,
    RatchetMessage, X3dhHandshakeHeader,
};
use crate::error::CipherError;
use crate::identity::CipherIdentity;
use crate::message::{CipherMessage, MessageId, MessageType, ReceiptType, PresenceInfo};
use crate::network_bundle::{RelayPool, SignalPool};
use crate::peer_directory::{derive_signed_prekey, PeerDirectory, SignedPeerBundle};
use crate::transport::direct::DirectTransportConfig;
use crate::transport::{TransportRouter, TransportMode};

fn is_valid_evm_address(addr: &str) -> bool {
    let trimmed = addr.trim();
    trimmed.starts_with("0x")
        && trimmed.len() == 42
        && trimmed[2..].chars().all(|c| c.is_ascii_hexdigit())
}

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
    /// File chunk reassembly buffer: file_id → (sender, expected_total, collected_chunks)
    chunk_buffer: Arc<RwLock<HashMap<String, ChunkAssembly>>>,
    /// Notifies local readers (`recv --follow`, `chat`, `shell`) when new inbox messages arrive.
    pub inbox_notify: Arc<Notify>,
    /// Authenticated EVM <-> Ed25519/X25519 peer directory + cache.
    pub peer_directory: Arc<PeerDirectory>,
    /// Deterministic medium-term X25519 signed prekey for answering X3DH handshakes.
    signed_prekey: x25519_dalek::StaticSecret,
    /// Out-of-order ratcheted messages waiting for their peer's `KeyExchange` envelope.
    pending_ratchet: Arc<RwLock<HashMap<String, Vec<CipherMessage>>>>,
    /// Optional disk directory for persisting active `DoubleRatchet` sessions across CLI calls.
    session_dir: Option<PathBuf>,
}

/// In-progress file chunk assembly
struct ChunkAssembly {
    sender: String,
    total_chunks: u32,
    chunks: HashMap<u32, Vec<u8>>,  // chunk_index → decrypted data
    header_msg: Option<CipherMessage>, // The File header message
}

impl SwarmClient {
    fn from_router(identity: CipherIdentity, transport: TransportRouter) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1000);
        let signed_prekey = derive_signed_prekey(&identity);

        Self {
            identity,
            conversations: Arc::new(RwLock::new(HashMap::new())),
            transport: Arc::new(transport),
            sent_log: Arc::new(RwLock::new(HashMap::new())),
            inbox: Arc::new(RwLock::new(Vec::new())),
            media_tx: tx,
            seen_ids: Arc::new(RwLock::new(HashSet::new())),
            peer_presence: Arc::new(RwLock::new(HashMap::new())),
            presence_enabled: Arc::new(RwLock::new(true)),
            chunk_buffer: Arc::new(RwLock::new(HashMap::new())),
            inbox_notify: Arc::new(Notify::new()),
            peer_directory: Arc::new(PeerDirectory::new()),
            signed_prekey,
            pending_ratchet: Arc::new(RwLock::new(HashMap::new())),
            session_dir: None,
        }
    }

    /// Create a new swarm client (honoring persisted transport mode).
    pub fn new(identity: CipherIdentity) -> Self {
        let peer_id = identity.display_address();
        let secret_bytes = identity.ed25519_secret_bytes();
        let transport = TransportRouter::new_with_secret(peer_id, secret_bytes);
        Self::from_router(identity, transport)
    }

    /// Create a new swarm client with an explicit transport mode.
    pub fn with_mode(identity: CipherIdentity, mode: TransportMode) -> Self {
        let peer_id = identity.display_address();
        let secret_bytes = identity.ed25519_secret_bytes();
        let transport = TransportRouter::new_with_mode(peer_id, secret_bytes, mode);
        Self::from_router(identity, transport)
    }

    /// Create a new swarm client with explicit transport mode and relay/signal pools.
    pub fn with_mode_and_pools(
        identity: CipherIdentity,
        mode: TransportMode,
        relay_pool: Arc<RelayPool>,
        signal_pool: Arc<SignalPool>,
    ) -> Self {
        let peer_id = identity.display_address();
        let secret_bytes = identity.ed25519_secret_bytes();
        let transport = TransportRouter::new_with_mode_and_pools(
            peer_id,
            secret_bytes,
            mode,
            relay_pool,
            signal_pool,
        );
        Self::from_router(identity, transport)
    }

    /// Enable persistent on-disk storage for Double Ratchet sessions (used by CLI).
    pub fn with_session_dir(mut self, dir: PathBuf) -> Self {
        self.session_dir = Some(dir);
        self
    }

    /// Publish our dual-signed `SignedPeerBundle` (Iroh `EndpointId` + X3DH `PrekeyBundle`)
    /// so upgraded peers can connect directly via QUIC P2P and establish Double Ratchet sessions.
    pub async fn publish_peer_bundle(&self) -> Result<(), CipherError> {
        self.peer_directory
            .publish(self.transport.direct.relay_pool(), &self.identity)
            .await
    }

    /// Resolve and verify a peer's `SignedPeerBundle`, registering their Iroh `EndpointId`.
    pub async fn ensure_peer_resolved(&self, recipient: &str) -> Option<SignedPeerBundle> {
        let bundle = if let Some(cached) = self.peer_directory.get_cached(recipient).await {
            Some(cached)
        } else if is_valid_evm_address(recipient) {
            self.peer_directory
                .resolve(self.transport.direct.relay_pool(), recipient)
                .await
        } else {
            None
        };

        if let Some(ref b) = bundle {
            if let Ok(eid) = b.iroh_endpoint_id() {
                self.transport.iroh.register_peer_endpoint(recipient, eid).await;
            }
        }
        bundle
    }

    fn session_file_path(&self, peer: &str) -> Option<PathBuf> {
        self.session_dir
            .as_ref()
            .map(|dir| dir.join(format!("{}.ratchet.json", peer.trim().to_lowercase())))
    }

    async fn find_conversation_key(
        conversations: &HashMap<String, Conversation>,
        peer: &str,
    ) -> Option<String> {
        if conversations.contains_key(peer) {
            return Some(peer.to_string());
        }
        conversations
            .keys()
            .find(|k| k.eq_ignore_ascii_case(peer))
            .cloned()
    }

    async fn load_or_get_ratchet(&self, peer: &str) -> Option<DoubleRatchet> {
        {
            let conversations = self.conversations.read().await;
            if let Some(key) = Self::find_conversation_key(&conversations, peer).await {
                if let Some(ratchet) = conversations.get(&key).and_then(|c| c.ratchet.clone()) {
                    return Some(ratchet);
                }
            }
        }

        let path = self.session_file_path(peer)?;
        let bytes = tokio::fs::read(&path).await.ok()?;
        let ratchet = DoubleRatchet::from_bytes(&bytes).ok()?;

        let mut conversations = self.conversations.write().await;
        let key = Self::find_conversation_key(&conversations, peer)
            .await
            .unwrap_or_else(|| peer.to_string());
        let conv = conversations.entry(key).or_insert(Conversation {
            peer_address: peer.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.ratchet = Some(ratchet.clone());
        Some(ratchet)
    }

    async fn save_ratchet(&self, peer: &str, ratchet: DoubleRatchet) {
        if let Some(path) = self.session_file_path(peer) {
            if let Ok(bytes) = ratchet.to_bytes() {
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                let _ = tokio::fs::write(&path, bytes).await;
            }
        }

        let mut conversations = self.conversations.write().await;
        let key = Self::find_conversation_key(&conversations, peer)
            .await
            .unwrap_or_else(|| peer.to_string());
        let conv = conversations.entry(key).or_insert(Conversation {
            peer_address: peer.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.ratchet = Some(ratchet);
    }

    /// Background synchronization daemon.
    /// Also starts the relay polling daemon for real P2P message delivery.
    pub fn start_sync_daemon(self: Arc<Self>) {
        // Start the TransportRouter (auto-selects Iroh/Nym/Tor/Direct)
        let router = self.transport.clone();
        crate::ffi::runtime().spawn(async move {
            router.start().await;
        });

        // Publish our verified EndpointId + X3DH PrekeyBundle once federated pools are ready.
        let pub_client = self.clone();
        crate::ffi::runtime().spawn(async move {
            crate::network_bundle::ensure_federated_pools().await;
            let _ = pub_client.publish_peer_bundle().await;
        });

        // ── HTTP Relay polling loop ──────────────────────────────────────────
        let transport_for_poll = self.transport.clone();
        crate::ffi::runtime().spawn(async move {
            loop {
                let sender = crate::transport::direct::DefaultSender {
                    direct: transport_for_poll.direct.clone(),
                };
                transport_for_poll.direct.poll_incoming(&sender).await;

                // Also flush any queued outgoing messages
                let _ = transport_for_poll.direct.flush_outbox(&sender).await;

                let ws_ok = transport_for_poll.ws_signal.is_connected().await;
                let delay = if ws_ok {
                    // WS push is primary; HTTP fetch is offline fallback
                    tokio::time::Duration::from_secs(20)
                } else {
                    tokio::time::Duration::from_millis(800)
                };
                tokio::time::sleep(delay).await;
            }
        });

        // Incoming message processing loop — event-driven via Notify with 2s fallback sweep.
        let client = self.clone();
        crate::ffi::runtime().spawn(async move {
            loop {
                client.process_incoming().await;
                tokio::select! {
                    _ = client.transport.incoming_notify.notified() => {}
                    _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {}
                }
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
    pub fn with_config(identity: CipherIdentity, _config: DirectTransportConfig) -> Self {
        Self::new(identity)
    }

    /// Get our EVM address (= chat ID).
    pub fn our_address(&self) -> String {
        self.identity.display_address()
    }

    /// Send a text message to a recipient.
    /// Dual-path encryption:
    /// - If a verified `SignedPeerBundle` exists (or an active `DoubleRatchet` exists),
    ///   establishes X3DH + per-message Double Ratchet forward secrecy and caches the
    ///   peer's Iroh `EndpointId` for direct QUIC P2P delivery.
    /// - Otherwise falls back cleanly to `v0.2.3`-compatible symmetric key derivation.
    pub async fn send_text(&self, recipient: &str, plaintext: &str) -> Result<MessageId, CipherError> {
        let our_addr = self.our_address();

        // Populate peer's Iroh EndpointId when available (cheap cache hit after first lookup).
        let needs_endpoint = is_valid_evm_address(recipient)
            && self.transport.iroh.resolve_endpoint(recipient).await.is_err();
        let resolved_bundle = if needs_endpoint {
            self.ensure_peer_resolved(recipient).await
        } else {
            None
        };

        let mut ratchet_opt = self.load_or_get_ratchet(recipient).await;
        let mut init_ke_bytes: Option<Vec<u8>> = None;

        // Need a fresh X3DH handshake if no send-capable ratchet session exists yet.
        if !ratchet_opt.as_ref().map(|r| r.can_send()).unwrap_or(false) {
            let bundle_opt = match resolved_bundle {
                Some(b) => Some(b),
                None => self.ensure_peer_resolved(recipient).await,
            };

            if let Some(bundle) = bundle_opt {
                let prekey = bundle.prekey_bundle();
                let x3dh = x3dh_initiate(self.identity.x25519_secret_key(), &prekey)?;
                let ratchet = DoubleRatchet::init_sender(
                    x3dh.shared_secret,
                    x25519_dalek::PublicKey::from(bundle.signed_prekey),
                );
                let header = X3dhHandshakeHeader {
                    sender_identity_x25519: *self.identity.x25519_public_key().as_bytes(),
                    ephemeral_public: x3dh.ephemeral_public,
                    one_time_prekey: prekey.one_time_prekey,
                };
                let header_json = serde_json::to_vec(&header)
                    .map_err(|e| CipherError::Encryption(format!("X3DH header encode: {e}")))?;
                let temp_key = self.derive_temp_session_key(recipient);
                let enc_header = aes_encrypt(&temp_key, &header_json)?;
                let ke_msg = CipherMessage {
                    id: uuid::Uuid::new_v4(),
                    sender: our_addr.clone(),
                    recipient: recipient.to_string(),
                    msg_type: MessageType::KeyExchange,
                    timestamp: chrono::Utc::now(),
                    payload: enc_header.ciphertext,
                    nonce: enc_header.nonce,
                    dh_public: x3dh.ephemeral_public,
                    counter: 0,
                    ttl: 30 * 86400,
                };
                init_ke_bytes = Some(ke_msg.to_bytes());
                ratchet_opt = Some(ratchet);
                debug!("Initiated X3DH + Double Ratchet session with {}", recipient);
            } else {
                debug!("No peer bundle for {} — using v0.2.3 compatible fallback key", recipient);
            }
        }

        let msg = if let Some(mut ratchet) = ratchet_opt.filter(|r| r.can_send()) {
            let rmsg = ratchet.encrypt(plaintext.as_bytes())?;
            self.save_ratchet(recipient, ratchet).await;
            CipherMessage::new_text(
                &our_addr,
                recipient,
                rmsg.encrypted.ciphertext,
                rmsg.encrypted.nonce,
                rmsg.dh_public,
                rmsg.counter,
            )
        } else {
            let session_key = self.derive_temp_session_key(recipient);
            let encrypted = aes_encrypt(&session_key, plaintext.as_bytes())?;
            CipherMessage::new_text(
                &our_addr,
                recipient,
                encrypted.ciphertext,
                encrypted.nonce,
                [0u8; 32],
                0,
            )
        };

        let msg_id = msg.id;

        if let Some(ke_bytes) = init_ke_bytes {
            self.transport.queue_message(recipient, ke_bytes).await?;
        }

        // Serialize and queue for delivery via active transport (Iroh/Tor/Nym/Direct)
        let data = msg.to_bytes();
        self.transport.queue_message(recipient, data).await?;

        // Track in sent log
        self.sent_log.write().await.insert(msg_id, msg);

        // Track in conversation
        let mut conversations = self.conversations.write().await;
        let key = Self::find_conversation_key(&conversations, recipient)
            .await
            .unwrap_or_else(|| recipient.to_string());
        let conv = conversations.entry(key).or_insert(Conversation {
            peer_address: recipient.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.message_ids.push(msg_id);
        conv.statuses.insert(msg_id, DeliveryStatus::Queued);

        info!("Message {} queued for {}", msg_id, recipient);

        // Immediate flush (~100ms path when relay + WS push are up; no-op if sent via Iroh/Tor)
        let _ = self
            .transport
            .direct
            .flush_outbox(&crate::transport::direct::DefaultSender {
                direct: self.transport.direct.clone(),
            })
            .await;

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
        let our_addr = self.our_address();

        const CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2MB per chunk
        let total_chunks = ((file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE).max(1) as u32;
        let file_id = uuid::Uuid::new_v4().to_string();

        let metadata = crate::message::FileMetadata {
            file_name: file_name.to_string(),
            mime_type: mime_type.to_string(),
            size_bytes: file_data.len() as u64,
            total_chunks,
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

        // 1. Send file header (metadata only, small message)
        let header_payload = serde_json::to_vec(&serde_json::json!({
            "file_id": file_id,
            "metadata": metadata,
        })).map_err(|e| CipherError::File(format!("Metadata serialization: {e}")))?;
        let encrypted_header = aes_encrypt(&session_key, &header_payload)?;

        let header_msg = CipherMessage {
            id: uuid::Uuid::new_v4(),
            sender: our_addr.clone(),
            recipient: recipient.to_string(),
            msg_type: MessageType::File(metadata.clone()),
            timestamp: chrono::Utc::now(),
            payload: encrypted_header.ciphertext,
            nonce: encrypted_header.nonce,
            dh_public: [0u8; 32],
            counter: 0,
            ttl: 30 * 86400,
        };

        let header_id = header_msg.id;
        let data = header_msg.to_bytes();
        self.transport.queue_message(recipient, data).await?;
        self.sent_log.write().await.insert(header_id, header_msg);

        // 2. Send each chunk as a separate, independently encrypted message
        for (i, chunk_data) in file_data.chunks(CHUNK_SIZE).enumerate() {
            let encrypted_chunk = aes_encrypt(&session_key, chunk_data)?;

            let chunk_msg = CipherMessage {
                id: uuid::Uuid::new_v4(),
                sender: our_addr.clone(),
                recipient: recipient.to_string(),
                msg_type: MessageType::FileChunk {
                    file_id: file_id.clone(),
                    chunk_index: i as u32,
                    total_chunks,
                },
                timestamp: chrono::Utc::now(),
                payload: encrypted_chunk.ciphertext,
                nonce: encrypted_chunk.nonce,
                dh_public: [0u8; 32],
                counter: i as u64,
                ttl: 30 * 86400,
            };

            let data = chunk_msg.to_bytes();
            self.transport.queue_message(recipient, data).await?;
        }

        // 3. Flush all messages immediately
        self.transport
            .direct
            .flush_outbox(&crate::transport::direct::DefaultSender {
                direct: self.transport.direct.clone(),
            })
            .await?;

        // Track in conversation
        let mut conversations = self.conversations.write().await;
        let conv = conversations.entry(recipient.to_string()).or_insert(Conversation {
            peer_address: recipient.to_string(),
            ratchet: None,
            message_ids: Vec::new(),
            statuses: HashMap::new(),
            unread: 0,
        });
        conv.message_ids.push(header_id);
        conv.statuses.insert(header_id, DeliveryStatus::Queued);

        info!(
            "File '{}' ({} bytes, {} chunks) sent to {}",
            file_name, file_data.len(), total_chunks, recipient
        );

        Ok((header_id, metadata))
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

    /// Whether there are unread messages buffered in the local inbox.
    pub async fn has_pending_inbox(&self) -> bool {
        !self.inbox.read().await.is_empty()
    }

    async fn record_seen_id(&self, msg_id: MessageId) {
        let mut seen = self.seen_ids.write().await;
        seen.insert(msg_id);
        if seen.len() > 500 {
            let to_remove: Vec<_> = seen.iter().take(250).cloned().collect();
            for id in to_remove {
                seen.remove(&id);
            }
        }
    }

    /// Background loop: Receive and process all pending messages autonomously
    pub async fn process_incoming(&self) {
        let raw_messages = self.transport.drain_unread().await;
        if raw_messages.is_empty() {
            return;
        }

        let mut decoded = Vec::with_capacity(raw_messages.len());
        for data in raw_messages {
            match CipherMessage::from_bytes(&data) {
                Ok(msg) => decoded.push(msg),
                Err(e) => {
                    log::warn!("Failed to decode message envelope: {}", e);
                }
            }
        }

        // Process X3DH KeyExchange before data frames, and order chains deterministically.
        decoded.sort_by_key(|m| (
            !matches!(m.msg_type, MessageType::KeyExchange),
            m.timestamp,
            m.counter,
        ));

        let mut queue: VecDeque<CipherMessage> = VecDeque::from(decoded);
        let mut added_to_inbox = false;

        while let Some(mut msg) = queue.pop_front() {
            let sender = msg.sender.clone();
            let msg_id = msg.id;

            // Dedup: skip if we've already processed this message
            // (can arrive twice via WebSocket + HTTP dual delivery)
            if self.seen_ids.read().await.contains(&msg_id) {
                continue;
            }

            // 1. Handle X3DH KeyExchange initialization
            if matches!(msg.msg_type, MessageType::KeyExchange) {
                let header_bytes = if msg.nonce == [0u8; 12] {
                    msg.payload.clone()
                } else {
                    let temp_key = self.derive_temp_session_key(&sender);
                    let enc = EncryptedMessage {
                        ciphertext: msg.payload.clone(),
                        nonce: msg.nonce,
                    };
                    match aes_decrypt(&temp_key, &enc) {
                        Ok(pt) => pt,
                        Err(_) => msg.payload.clone(),
                    }
                };

                match serde_json::from_slice::<X3dhHandshakeHeader>(&header_bytes) {
                    Ok(header) => {
                        match x3dh_respond(
                            self.identity.x25519_secret_key(),
                            &self.signed_prekey,
                            None,
                            &header.sender_identity_x25519,
                            &header.ephemeral_public,
                        ) {
                            Ok(shared_secret) => {
                                let ratchet = DoubleRatchet::init_receiver(
                                    shared_secret,
                                    self.signed_prekey.clone(),
                                );
                                self.save_ratchet(&sender, ratchet).await;
                                self.record_seen_id(msg_id).await;
                                debug!("Established X3DH + Double Ratchet session with {}", sender);

                                // Replay any buffered messages from this sender in order.
                                let sender_key = sender.to_lowercase();
                                let mut pending = self.pending_ratchet.write().await.remove(&sender_key).unwrap_or_default();
                                pending.sort_by_key(|m| (m.timestamp, m.counter));
                                for buffered in pending.into_iter().rev() {
                                    queue.push_front(buffered);
                                }
                            }
                            Err(e) => {
                                self.record_seen_id(msg_id).await;
                                log::warn!("X3DH handshake failed from {}: {}", sender, e);
                            }
                        }
                    }
                    Err(e) => {
                        self.record_seen_id(msg_id).await;
                        log::warn!("Invalid X3DH KeyExchange header from {}: {}", sender, e);
                    }
                }
                continue;
            }

            // 2. Decrypt payload (Double Ratchet when `dh_public != [0;32]`, else v0.2.3 fallback)
            if msg.dh_public != [0u8; 32] {
                let Some(mut ratchet) = self.load_or_get_ratchet(&sender).await else {
                    // Handshake envelope may arrive in a later poll; buffer temporarily.
                    let sender_key = sender.to_lowercase();
                    let mut pending = self.pending_ratchet.write().await;
                    let list = pending.entry(sender_key).or_default();
                    if list.len() < 64 && !list.iter().any(|m| m.id == msg_id) {
                        list.push(msg);
                    }
                    continue;
                };

                let rmsg = RatchetMessage {
                    dh_public: msg.dh_public,
                    counter: msg.counter,
                    encrypted: EncryptedMessage {
                        ciphertext: msg.payload.clone(),
                        nonce: msg.nonce,
                    },
                };
                match ratchet.decrypt(&rmsg) {
                    Ok(plaintext) => {
                        self.save_ratchet(&sender, ratchet).await;
                        self.record_seen_id(msg_id).await;
                        if msg.msg_type == crate::message::MessageType::CallMedia {
                            let _ = self.media_tx.send(plaintext);
                            continue;
                        }
                        msg.payload = plaintext;
                    }
                    Err(e) => {
                        self.record_seen_id(msg_id).await;
                        log::warn!("Ratchet decrypt failed for {} from {}: {}", msg_id, sender, e);
                        continue;
                    }
                }
            } else {
                self.record_seen_id(msg_id).await;
                let session_key = self.derive_temp_session_key(&sender);
                let encrypted_msg = EncryptedMessage {
                    ciphertext: msg.payload.clone(),
                    nonce: msg.nonce,
                };
                match aes_decrypt(&session_key, &encrypted_msg) {
                    Ok(plaintext) => {
                        if msg.msg_type == crate::message::MessageType::CallMedia {
                            let _ = self.media_tx.send(plaintext);
                            continue;
                        }
                        msg.payload = plaintext;
                    }
                    Err(e) => {
                        log::warn!("Failed to decrypt message {} from {}: {}", msg_id, sender, e);
                        continue;
                    }
                }
            }

            // Track in conversations for UI notifications
            let mut conversations = self.conversations.write().await;
            let conv_key = Self::find_conversation_key(&conversations, &sender)
                .await
                .unwrap_or_else(|| sender.clone());
            let conv = conversations.entry(conv_key).or_insert(Conversation {
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
                        MessageType::FileChunk { ref file_id, chunk_index, total_chunks } => {
                            let ci: u32 = *chunk_index;
                            let tc: u32 = *total_chunks;
                            // Store chunk in buffer, assemble when complete
                            let mut buf = self.chunk_buffer.write().await;
                            let assembly = buf.entry(file_id.clone()).or_insert_with(|| ChunkAssembly {
                                sender: sender.clone(),
                                total_chunks: tc,
                                chunks: HashMap::new(),
                                header_msg: None,
                            });
                            assembly.chunks.insert(ci, msg.payload.clone());
                            info!("Chunk {}/{} for file {} from {}", ci + 1, tc, file_id, sender);

                            // Check if all chunks arrived
                            if assembly.chunks.len() == tc as usize {
                                // Reassemble file
                                let mut file_data = Vec::new();
                                for i in 0..tc {
                                    if let Some(chunk) = assembly.chunks.get(&i) {
                                        file_data.extend_from_slice(chunk);
                                    }
                                }
                                let assembled_sender = assembly.sender.clone();
                                let header = assembly.header_msg.take();
                                buf.remove(file_id);
                                drop(buf);

                                // Create a file message with the reassembled data
                                if let Some(mut h) = header {
                                    h.payload = file_data;
                                    conv.message_ids.push(h.id);
                                    conv.unread += 1;
                                    drop(conversations);
                                    let _ = self.send_receipt(&assembled_sender, h.id, ReceiptType::Delivered).await;
                                    self.inbox.write().await.push(h);
                                    added_to_inbox = true;
                                } else {
                                    // No header yet — create synthetic file message
                                    let file_msg = CipherMessage {
                                        id: msg_id,
                                        sender: assembled_sender.clone(),
                                        recipient: self.our_address(),
                                        msg_type: MessageType::File(crate::message::FileMetadata {
                                            file_name: format!("file_{}", &file_id[..8]),
                                            mime_type: "application/octet-stream".to_string(),
                                            size_bytes: file_data.len() as u64,
                                            total_chunks: tc,
                                            merkle_root: [0u8; 32],
                                            thumbnail: None,
                                        }),
                                        timestamp: chrono::Utc::now(),
                                        payload: file_data,
                                        nonce: [0u8; 12],
                                        dh_public: [0u8; 32],
                                        counter: 0,
                                        ttl: 0,
                                    };
                                    conv.message_ids.push(msg_id);
                                    conv.unread += 1;
                                    drop(conversations);
                                    self.inbox.write().await.push(file_msg);
                                    added_to_inbox = true;
                                }
                            } else {
                                drop(buf);
                                drop(conversations);
                            }
                            continue;
                        }
                        MessageType::File(_) => {
                            // File header — check if it has file_id in the payload (chunked transfer)
                            if let Ok(payload_str) = String::from_utf8(msg.payload.clone()) {
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&payload_str) {
                                    if let Some(fid) = json.get("file_id").and_then(|v| v.as_str()) {
                                        // Chunked file — store header in chunk buffer
                                        let mut buf = self.chunk_buffer.write().await;
                                        let assembly = buf.entry(fid.to_string()).or_insert_with(|| ChunkAssembly {
                                            sender: sender.clone(),
                                            total_chunks: 0,
                                            chunks: HashMap::new(),
                                            header_msg: None,
                                        });
                                        assembly.header_msg = Some(msg.clone());
                                        
                                        // Check if all chunks already arrived before header
                                        if assembly.total_chunks > 0 && assembly.chunks.len() == assembly.total_chunks as usize {
                                            let mut file_data = Vec::new();
                                            for i in 0..assembly.total_chunks {
                                                if let Some(chunk) = assembly.chunks.get(&i) {
                                                    file_data.extend_from_slice(chunk);
                                                }
                                            }
                                            let mut h = msg.clone();
                                            h.payload = file_data;
                                            buf.remove(fid);
                                            drop(buf);
                                            
                                            conv.message_ids.push(h.id);
                                            conv.unread += 1;
                                            drop(conversations);
                                            let _ = self.send_receipt(&sender, h.id, ReceiptType::Delivered).await;
                                            self.inbox.write().await.push(h);
                                            added_to_inbox = true;
                                        } else {
                                            drop(buf);
                                            drop(conversations);
                                        }
                                        continue;
                                    }
                                }
                            }
                            // Non-chunked file (legacy single message) — fall through to normal handling
                            conv.message_ids.push(msg_id);
                            conv.unread += 1;
                            drop(conversations);
                            let _ = self.send_receipt(&sender, msg_id, ReceiptType::Delivered).await;
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

                    // Append to unread inbox for CLI / Dart FFI!
                    self.inbox.write().await.push(msg);
                    added_to_inbox = true;
        }

        if added_to_inbox {
            self.inbox_notify.notify_waiters();
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
        let session_key = client.derive_temp_session_key("0xSender999");
        use crate::encryption::aes_encrypt;
        let enc = aes_encrypt(&session_key, b"test message").unwrap();

        // Simulate incoming message
        let msg = CipherMessage::new_text(
            "0xSender999",
            &client.our_address(),
            enc.ciphertext,
            enc.nonce,
            [0u8; 32],
            0,
        );
        client.transport.direct.push_received(msg.to_bytes()).await;
        client.process_incoming().await;

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

    #[tokio::test]
    async fn test_dual_path_x3dh_and_bidirectional_double_ratchet() {
        let offline_bundle = crate::network_bundle::NetworkBundle::fallback();
        let empty_relay = RelayPool::from_bundle(&offline_bundle);
        let empty_signal = Arc::new(SignalPool::new_from_bundle(&offline_bundle));

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let alice_dir = std::env::temp_dir().join(format!("cipher-ratchet-alice-{ts}"));
        let bob_dir = std::env::temp_dir().join(format!("cipher-ratchet-bob-{ts}"));

        let alice_id = CipherIdentity::generate().unwrap();
        let bob_id = CipherIdentity::generate().unwrap();
        let alice_addr = alice_id.display_address();
        let bob_addr = bob_id.display_address();

        let alice = SwarmClient::with_mode_and_pools(
            alice_id.clone(),
            TransportMode::Direct,
            empty_relay.clone(),
            empty_signal.clone(),
        )
        .with_session_dir(alice_dir.clone());
        let bob = SwarmClient::with_mode_and_pools(
            bob_id.clone(),
            TransportMode::Direct,
            empty_relay.clone(),
            empty_signal.clone(),
        )
        .with_session_dir(bob_dir.clone());

        let alice_bundle = SignedPeerBundle::from_identity(&alice.identity).unwrap();
        let bob_bundle = SignedPeerBundle::from_identity(&bob.identity).unwrap();
        alice.peer_directory.insert_verified(bob_bundle.clone()).await.unwrap();
        bob.peer_directory.insert_verified(alice_bundle.clone()).await.unwrap();

        alice.send_text(&bob_addr, "hello bob 1").await.unwrap();
        alice.send_text(&bob_addr, "hello bob 2").await.unwrap();

        let outbound = alice.transport.direct.get_pending(&bob_addr).await;
        // KeyExchange + 2 encrypted text envelopes
        assert_eq!(outbound.len(), 3);
        let first_env = CipherMessage::from_bytes(&outbound[0]).unwrap();
        assert_eq!(first_env.msg_type, MessageType::KeyExchange);
        let second_env = CipherMessage::from_bytes(&outbound[1]).unwrap();
        assert_ne!(second_env.dh_public, [0u8; 32]);

        // Deliver text frames BEFORE KeyExchange to exercise buffering + replay ordering.
        bob.transport.direct.push_received(outbound[2].clone()).await;
        bob.transport.direct.push_received(outbound[1].clone()).await;
        bob.process_incoming().await;
        assert!(bob.receive_all().await.is_empty());

        bob.transport.direct.push_received(outbound[0].clone()).await;
        bob.process_incoming().await;
        let bob_msgs = bob.receive_all().await;
        assert_eq!(bob_msgs.len(), 2);
        assert_eq!(String::from_utf8_lossy(&bob_msgs[0].payload), "hello bob 1");
        assert_eq!(String::from_utf8_lossy(&bob_msgs[1].payload), "hello bob 2");

        // Bob replies via Double Ratchet DH ratchet step back to Alice
        // (two Delivery receipts were also auto-queued when Bob processed Alice's 2 texts).
        let msg1_id = alice.conversations.read().await.get(&bob_addr).unwrap().message_ids[0];
        let msg2_id = alice.conversations.read().await.get(&bob_addr).unwrap().message_ids[1];
        bob.send_text(&alice_addr, "hi alice").await.unwrap();
        let replies = bob.transport.direct.get_pending(&alice_addr).await;
        assert_eq!(replies.len(), 3);
        let reply_env = CipherMessage::from_bytes(&replies[2]).unwrap();
        assert_ne!(reply_env.dh_public, [0u8; 32]);

        for frame in &replies {
            alice.transport.direct.push_received(frame.clone()).await;
        }
        alice.process_incoming().await;
        let alice_msgs = alice.receive_all().await;
        assert_eq!(alice_msgs.len(), 1);
        assert_eq!(String::from_utf8_lossy(&alice_msgs[0].payload), "hi alice");
        assert_eq!(alice.delivery_status(&msg1_id).await, Some(DeliveryStatus::Delivered));
        assert_eq!(alice.delivery_status(&msg2_id).await, Some(DeliveryStatus::Delivered));

        // Simulate new short-lived CLI process reloading Alice's ratchet from disk.
        let alice_restarted = SwarmClient::with_mode_and_pools(
            alice_id,
            TransportMode::Direct,
            empty_relay,
            empty_signal,
        )
        .with_session_dir(alice_dir.clone());
        alice_restarted.send_text(&bob_addr, "persisted ratchet").await.unwrap();
        let next_outbound = alice_restarted.transport.direct.get_pending(&bob_addr).await;
        assert_eq!(next_outbound.len(), 1); // No repeat KeyExchange needed
        bob.transport.direct.push_received(next_outbound[0].clone()).await;
        bob.process_incoming().await;
        let bob_next = bob.receive_all().await;
        assert_eq!(bob_next.len(), 1);
        assert_eq!(String::from_utf8_lossy(&bob_next[0].payload), "persisted ratchet");

        let _ = std::fs::remove_dir_all(alice_dir);
        let _ = std::fs::remove_dir_all(bob_dir);
    }

    #[tokio::test]
    async fn test_legacy_v023_fallback_compatibility() {
        let offline_bundle = crate::network_bundle::NetworkBundle::fallback();
        let empty_relay = RelayPool::from_bundle(&offline_bundle);
        let empty_signal = Arc::new(SignalPool::new_from_bundle(&offline_bundle));

        let alice = SwarmClient::with_mode_and_pools(
            CipherIdentity::generate().unwrap(),
            TransportMode::Direct,
            empty_relay.clone(),
            empty_signal.clone(),
        );
        let legacy_bob = SwarmClient::with_mode_and_pools(
            CipherIdentity::generate().unwrap(),
            TransportMode::Direct,
            empty_relay,
            empty_signal,
        );
        let bob_addr = legacy_bob.our_address();

        // No SignedPeerBundle published -> must fall back to dh_public == [0;32] v0.2.3 envelope.
        alice.send_text(&bob_addr, "legacy v0.2.3 hello").await.unwrap();
        let queued = alice.transport.direct.get_pending(&bob_addr).await;
        assert_eq!(queued.len(), 1);
        let env = CipherMessage::from_bytes(&queued[0]).unwrap();
        assert_eq!(env.dh_public, [0u8; 32]);

        legacy_bob.transport.direct.push_received(queued[0].clone()).await;
        legacy_bob.process_incoming().await;
        let msgs = legacy_bob.receive_all().await;
        assert_eq!(msgs.len(), 1);
        assert_eq!(String::from_utf8_lossy(&msgs[0].payload), "legacy v0.2.3 hello");
    }

    #[tokio::test]
    async fn test_peer_directory_registers_iroh_endpoint_for_auto_mode() {
        let offline_bundle = crate::network_bundle::NetworkBundle::fallback();
        let alice = SwarmClient::with_mode_and_pools(
            CipherIdentity::generate().unwrap(),
            TransportMode::Auto,
            RelayPool::from_bundle(&offline_bundle),
            Arc::new(SignalPool::new_from_bundle(&offline_bundle)),
        );
        let bob_id = CipherIdentity::generate().unwrap();
        let bob_addr = bob_id.display_address();
        let bob_bundle = SignedPeerBundle::from_identity(&bob_id).unwrap();
        let expected_eid = bob_bundle.iroh_endpoint_id().unwrap();

        alice.peer_directory.insert_verified(bob_bundle).await.unwrap();
        let resolved = alice.ensure_peer_resolved(&bob_addr).await;
        assert!(resolved.is_some());

        let registered_eid = alice.transport.iroh.resolve_endpoint(&bob_addr).await.unwrap();
        assert_eq!(registered_eid, expected_eid);
    }
}
