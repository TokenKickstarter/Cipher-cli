//! # Iroh P2P Transport (QUIC + Magicsock Hole-Punching)
//!
//! Direct, encrypted, NAT-traversing P2P transport powered by Iroh.
//! - Uses QUIC over UDP for high-performance direct connections.
//! - Magicsock performs automatic STUN / ICE UDP hole-punching through firewalls.
//! - Transparently falls back to decentralized TKS/Iroh relays when hole punching fails.
//! - Identifies endpoints by their Ed25519 `EndpointId` (NodeId).

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Notify, RwLock};
use log::{info, warn, error, debug};
use async_trait::async_trait;

use crate::error::CipherError;
use super::Transport;

pub const CIPHER_ALPN: &[u8] = b"tks-cipher/iroh/v1";

/// Status of the Iroh P2P transport.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IrohState {
    Uninitialized,
    Starting,
    Ready { node_id: String },
    Connected { node_id: String, peers_count: usize },
    Error(String),
}

/// Iroh P2P transport managing direct QUIC tunnels.
pub struct IrohTransport {
    /// Our EVM address
    our_address: String,
    /// Our 32-byte Ed25519 seed or secret key
    secret_key_bytes: [u8; 32],
    /// Current state
    state: Arc<RwLock<IrohState>>,
    /// Active endpoint
    endpoint: Arc<RwLock<Option<iroh::endpoint::Endpoint>>>,
    /// Warm QUIC connections keyed by remote EndpointId (avoids re-handshaking every message)
    connections: Arc<RwLock<HashMap<iroh::EndpointId, iroh::endpoint::Connection>>>,
    /// Verified EVM `0x...` address -> Iroh `EndpointId` cache populated from PeerDirectory
    peer_endpoints: Arc<RwLock<HashMap<String, iroh::EndpointId>>>,
    /// Incoming message receiver
    incoming_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<(String, Vec<u8>)>>>,
    /// Incoming message sender
    incoming_tx: mpsc::Sender<(String, Vec<u8>)>,
    /// Shared wake notifier whenever QUIC delivers an incoming packet
    incoming_notify: Arc<Notify>,
}

impl IrohTransport {
    pub fn new(our_address: String, secret_key_bytes: [u8; 32]) -> Self {
        Self::new_with_notify(our_address, secret_key_bytes, Arc::new(Notify::new()))
    }

    pub fn new_with_notify(
        our_address: String,
        secret_key_bytes: [u8; 32],
        incoming_notify: Arc<Notify>,
    ) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(1024);
        Self {
            our_address,
            secret_key_bytes,
            state: Arc::new(RwLock::new(IrohState::Uninitialized)),
            endpoint: Arc::new(RwLock::new(None)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            peer_endpoints: Arc::new(RwLock::new(HashMap::new())),
            incoming_rx: Arc::new(tokio::sync::Mutex::new(incoming_rx)),
            incoming_tx,
            incoming_notify,
        }
    }

    /// Map a peer identifier (e.g. lowercase `0x...` EVM address) to its verified Iroh EndpointId.
    pub async fn register_peer_endpoint(&self, peer_addr: &str, endpoint_id: iroh::EndpointId) {
        self.peer_endpoints
            .write()
            .await
            .insert(peer_addr.trim().to_lowercase(), endpoint_id);
    }

    /// Resolve a peer identifier (`0x...` address or raw NodeId string) to an Iroh EndpointId.
    pub async fn resolve_endpoint(&self, recipient: &str) -> Result<iroh::EndpointId, CipherError> {
        let key = recipient.trim().to_lowercase();
        if let Some(id) = self.peer_endpoints.read().await.get(&key).copied() {
            return Ok(id);
        }
        recipient.trim().parse::<iroh::EndpointId>().map_err(|e| {
            CipherError::Identity(format!("No Iroh EndpointId known for '{recipient}': {e}"))
        })
    }

    pub async fn is_ready(&self) -> bool {
        matches!(
            &*self.state.read().await,
            IrohState::Ready { .. } | IrohState::Connected { .. }
        )
    }

    /// Initialize the Iroh endpoint with our Ed25519 secret key.
    pub async fn init(&self) -> Result<String, CipherError> {
        if let Some(existing) = self.node_id().await {
            return Ok(existing);
        }
        info!("[Iroh] Initializing Iroh QUIC endpoint for {}", self.our_address);
        *self.state.write().await = IrohState::Starting;

        let secret_key = iroh::SecretKey::from_bytes(&self.secret_key_bytes);
        let node_id = secret_key.public();
        let node_id_str = node_id.to_string();

        let endpoint = iroh::endpoint::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(secret_key)
            .alpns(vec![CIPHER_ALPN.to_vec()])
            .bind()
            .await
            .map_err(|e| CipherError::Network(format!("Failed to bind Iroh endpoint: {e}")))?;

        let endpoint_clone = endpoint.clone();
        let incoming_tx = self.incoming_tx.clone();
        let incoming_notify = self.incoming_notify.clone();
        let node_id_copy = node_id_str.clone();

        // Spawn background connection accept loop
        tokio::spawn(async move {
            info!("[Iroh] Listening for incoming QUIC connections on NodeId: {}", node_id_copy);
            while let Some(incoming) = endpoint_clone.accept().await {
                let tx = incoming_tx.clone();
                let notify = incoming_notify.clone();
                tokio::spawn(async move {
                    if let Ok(connecting) = incoming.accept() {
                        if let Ok(connection) = connecting.await {
                            let remote_node_id = connection.remote_id().to_string();
                            debug!("[Iroh] Accepted QUIC connection from {}", remote_node_id);

                            // Handle incoming uni-directional streams
                            while let Ok(mut recv_stream) = connection.accept_uni().await {
                                // Read up to 10MB payload (matches large file chunk or text message)
                                if let Ok(buf) = recv_stream.read_to_end(10 * 1024 * 1024).await {
                                    if !buf.is_empty() {
                                        let _ = tx.send((remote_node_id.clone(), buf)).await;
                                        notify.notify_waiters();
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });

        *self.endpoint.write().await = Some(endpoint);
        *self.state.write().await = IrohState::Ready { node_id: node_id_str.clone() };

        info!("[Iroh] Ready! NodeId: {}", node_id_str);
        Ok(node_id_str)
    }

    async fn get_or_connect(
        &self,
        endpoint: &iroh::endpoint::Endpoint,
        remote_node_id: iroh::EndpointId,
    ) -> Result<iroh::endpoint::Connection, CipherError> {
        if let Some(conn) = self.connections.read().await.get(&remote_node_id).cloned() {
            if conn.close_reason().is_none() {
                return Ok(conn);
            }
        }
        let connection = endpoint
            .connect(remote_node_id, CIPHER_ALPN)
            .await
            .map_err(|e| CipherError::Network(format!("Failed to connect to NodeId '{remote_node_id}': {e}")))?;
        self.connections
            .write()
            .await
            .insert(remote_node_id, connection.clone());
        Ok(connection)
    }

    /// Connect and send raw data to a peer address (`0x...` resolved via PeerDirectory) or raw NodeId.
    pub async fn send_to_node(&self, recipient_or_id: &str, data: &[u8]) -> Result<(), CipherError> {
        let ep_guard = self.endpoint.read().await;
        let endpoint = ep_guard
            .as_ref()
            .ok_or_else(|| CipherError::Network("Iroh endpoint not initialized".to_string()))?
            .clone();
        drop(ep_guard);

        let remote_node_id = self.resolve_endpoint(recipient_or_id).await?;
        let mut connection = self.get_or_connect(&endpoint, remote_node_id).await?;

        let mut send_stream = match connection.open_uni().await {
            Ok(s) => s,
            Err(_) => {
                // Evict stale pooled connection and reconnect once cleanly.
                self.connections.write().await.remove(&remote_node_id);
                connection = self.get_or_connect(&endpoint, remote_node_id).await?;
                connection
                    .open_uni()
                    .await
                    .map_err(|e| CipherError::Network(format!("Failed to open uni stream: {e}")))?
            }
        };

        send_stream
            .write_all(data)
            .await
            .map_err(|e| CipherError::Network(format!("Failed to write data to stream: {e}")))?;

        let _ = send_stream.finish();
        // Flush check ensures QUIC peer finishes reading before short-lived processes exit.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), send_stream.stopped()).await;

        Ok(())
    }

    /// Drain all pending received messages from Iroh QUIC streams.
    pub async fn drain_incoming(&self) -> Vec<Vec<u8>> {
        let mut rx = self.incoming_rx.lock().await;
        let mut messages = Vec::new();
        while let Ok((_sender, bytes)) = rx.try_recv() {
            messages.push(bytes);
        }
        messages
    }

    /// Return our NodeId string if ready.
    pub async fn node_id(&self) -> Option<String> {
        match &*self.state.read().await {
            IrohState::Ready { node_id } | IrohState::Connected { node_id, .. } => Some(node_id.clone()),
            _ => None,
        }
    }

    /// Get current state.
    pub async fn state(&self) -> IrohState {
        self.state.read().await.clone()
    }
}

#[async_trait]
impl Transport for IrohTransport {
    async fn send(&self, peer_id: &str, data: Vec<u8>) -> Result<(), CipherError> {
        self.send_to_node(peer_id, &data).await
    }

    async fn recv(&self) -> Result<(String, Vec<u8>), CipherError> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await.ok_or_else(|| {
            CipherError::Network("Iroh incoming channel closed".to_string())
        })
    }

    fn our_address(&self) -> String {
        self.our_address.clone()
    }

    fn is_available(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "Iroh (QUIC + Magicsock P2P)"
    }
}
