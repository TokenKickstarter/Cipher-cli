//! # WebSocket Real-Time Signal Transport
//!
//! Maintains a persistent WebSocket connection to the Cloudflare Signal Relay
//! for instant delivery of call signaling messages (Offer/Answer/ICE/Hangup).
//!
//! PRIVACY: Uses sealed sender — the relay only sees a hashed mailbox ID,
//! not the real EVM address. The sender's identity is inside the encrypted payload.

use crate::error::CipherError;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// The default Cloudflare Signal Relay WebSocket URL.
pub const DEFAULT_SIGNAL_WS_URL: &str = "wss://signal.tokenkickstarter.com/ws";

/// PRIVACY: Derive a sealed mailbox ID from an address.
/// The relay only sees this hash, never the real address.
pub fn sealed_mailbox(address: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cipher-sealed-v1:");
    hasher.update(address.to_lowercase().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// WebSocket connection state.
#[derive(Debug, Clone, PartialEq)]
pub enum WsState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

/// Outgoing signal envelope (sent TO Cloudflare).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsOutgoing {
    to: String,
    payload: String, // Base64-encoded encrypted signal
}

/// Incoming signal envelope (received FROM Cloudflare).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsIncoming {
    from: String,
    payload: String, // Base64-encoded encrypted signal
    ts: u64,
}

/// Ack from Cloudflare after sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsAck {
    ack: Option<bool>,
    delivered: Option<bool>,
    queued: Option<bool>,
    error: Option<String>,
}

/// Real-time WebSocket signal transport.
pub struct WebSocketSignal {
    /// Our EVM address (lowercase)
    our_address: String,
    /// WebSocket URL  
    ws_url: String,
    /// Connection state
    state: Arc<RwLock<WsState>>,
    /// Channel to send outgoing messages to the WebSocket writer task
    outgoing_tx: mpsc::Sender<String>,
    /// Channel that receives incoming signal payloads (raw ciphertext bytes)
    incoming_tx: mpsc::Sender<Vec<u8>>,
    /// Incoming receiver exposed to the transport layer
    incoming_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl WebSocketSignal {
    /// Create a new WebSocket signal transport.
    pub fn new(our_address: String) -> Self {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(500);
        let (incoming_tx, incoming_rx) = mpsc::channel(500);

        // PRIVACY: Use sealed mailbox ID instead of real address for relay registration
        let sealed_addr = sealed_mailbox(&our_address);

        let ws = Self {
            our_address: our_address.to_lowercase(),
            ws_url: DEFAULT_SIGNAL_WS_URL.to_string(),
            state: Arc::new(RwLock::new(WsState::Disconnected)),
            outgoing_tx,
            incoming_tx,
            incoming_rx: Arc::new(tokio::sync::Mutex::new(incoming_rx)),
        };

        // Spawn the background connection manager
        let state = ws.state.clone();
        let addr = sealed_addr; // Use sealed mailbox, NOT real address
        let url = ws.ws_url.clone();
        let tx = ws.incoming_tx.clone();

        // Store the outgoing_rx in an Arc<Mutex> so the background task can use it
        let outgoing_rx = Arc::new(tokio::sync::Mutex::new(outgoing_rx));

        crate::ffi::runtime().spawn(async move {
            Self::connection_loop(state, addr, url, tx, outgoing_rx).await;
        });

        ws
    }

    /// Background connection loop with auto-reconnect.
    async fn connection_loop(
        state: Arc<RwLock<WsState>>,
        addr: String,
        base_url: String,
        incoming_tx: mpsc::Sender<Vec<u8>>,
        outgoing_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<String>>>,
    ) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::connect_async;
        use tokio_tungstenite::tungstenite::Message;

        let mut backoff_ms: u64 = 1000;
        let max_backoff_ms: u64 = 30000;

        loop {
            let ws_url = format!("{}?addr={}", base_url, addr);
            info!("[WS] Connecting to {}...", ws_url);
            *state.write().await = WsState::Connecting;

            match connect_async(&ws_url).await {
                Ok((ws_stream, _response)) => {
                    info!("[WS] ✅ Connected to signal relay as {}", addr);
                    *state.write().await = WsState::Connected;
                    backoff_ms = 1000; // Reset backoff on successful connect

                    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

                    // Spawn a task to forward outgoing messages and send periodic pings
                    let outgoing_handle = {
                        let outgoing_rx = outgoing_rx.clone();
                        tokio::spawn(async move {
                            let mut rx = outgoing_rx.lock().await;
                            let mut ping_interval =
                                tokio::time::interval(tokio::time::Duration::from_secs(30));
                            // Skip the first immediate tick
                            ping_interval.tick().await;

                            loop {
                                tokio::select! {
                                    _ = ping_interval.tick() => {
                                        // Send an application-level Ping to keep the Cloudflare WebSocket alive
                                        // Raw Ping frames are sometimes rejected by Cloudflare edge proxies.
                                        let ping_msg = r#"{"type":"ping","to":"ping","payload":"ping"}"#.to_string();
                                        if let Err(e) = ws_sender.send(Message::Text(ping_msg)).await {
                                            warn!("[WS] Ping send error: {}", e);
                                            break;
                                        }
                                        debug!("[WS] Sent app-level keep-alive ping");
                                    }
                                    msg_opt = rx.recv() => {
                                        match msg_opt {
                                            Some(msg) => {
                                                if let Err(e) = ws_sender.send(Message::Text(msg)).await {
                                                    warn!("[WS] Send error: {}", e);
                                                    break;
                                                }
                                            }
                                            None => {
                                                // Channel closed
                                                let _ = ws_sender.send(Message::Close(None)).await;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        })
                    };

                    // Read incoming messages
                    while let Some(result) = ws_receiver.next().await {
                        match result {
                            Ok(Message::Text(text)) => {
                                // Parse as generic JSON first to check the type
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                    let msg_type = json.get("type").and_then(|t| t.as_str()).unwrap_or("");

                                    match msg_type {
                                        // Relay v2: instant message push via WebSocket
                                        "message" => {
                                            if let Some(data_b64) = json.get("data").and_then(|d| d.as_str()) {
                                                match base64_decode(data_b64) {
                                                    Ok(bytes) => {
                                                        info!("[WS] ⚡ Instant message received via WebSocket push!");
                                                        let _ = incoming_tx.send(bytes).await;
                                                        crate::ffi::notify_dart();

                                                        // ACK the message so relay removes it from queue
                                                        if let Some(mid) = json.get("message_id").and_then(|m| m.as_str()) {
                                                            let ack_body = serde_json::json!({
                                                                "recipient_id": addr,
                                                                "message_ids": [mid],
                                                            }).to_string();
                                                            let ack_url = format!("{}/ack", "https://signal.tokenkickstarter.com");
                                                            let _ = tokio::task::spawn_blocking(move || {
                                                                ureq::post(&ack_url)
                                                                    .set("Content-Type", "application/json")
                                                                    .timeout(std::time::Duration::from_secs(5))
                                                                    .send_string(&ack_body)
                                                            }).await;
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("[WS] Failed to decode WS push data: {}", e);
                                                    }
                                                }
                                            }
                                        }

                                        // Call signaling messages
                                        "signal" => {
                                            if let Some(payload) = json.get("payload").and_then(|p| p.as_str()) {
                                                debug!("[WS] 📬 Incoming signal");
                                                match base64_decode(payload) {
                                                    Ok(bytes) => {
                                                        let _ = incoming_tx.send(bytes).await;
                                                        crate::ffi::notify_dart();
                                                    }
                                                    Err(e) => {
                                                        warn!("[WS] Failed to decode signal payload: {}", e);
                                                    }
                                                }
                                            }
                                        }

                                        // ACK responses
                                        _ => {
                                            if let Ok(ack) = serde_json::from_str::<WsAck>(&text) {
                                                if let Some(err) = ack.error {
                                                    warn!("[WS] Server error: {}", err);
                                                } else {
                                                    debug!(
                                                        "[WS] ACK: delivered={:?} queued={:?}",
                                                        ack.delivered, ack.queued
                                                    );
                                                }
                                            }
                                            // Also try legacy WsIncoming format (no type field)
                                            else if let Ok(incoming) = serde_json::from_str::<WsIncoming>(&text) {
                                                debug!("[WS] 📬 Incoming signal from {}", incoming.from);
                                                match base64_decode(&incoming.payload) {
                                                    Ok(bytes) => {
                                                        let _ = incoming_tx.send(bytes).await;
                                                        crate::ffi::notify_dart();
                                                    }
                                                    Err(e) => {
                                                        warn!("[WS] Failed to decode incoming payload: {}", e);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Message::Ping(data)) => {
                                debug!("[WS] Ping received, pong handled automatically");
                                let _ = data; // tungstenite auto-responds to pings
                            }
                            Ok(Message::Close(_)) => {
                                info!("[WS] Server closed connection");
                                break;
                            }
                            Err(e) => {
                                warn!("[WS] Read error: {}", e);
                                break;
                            }
                            _ => {}
                        }
                    }

                    // Connection lost — abort outgoing task
                    outgoing_handle.abort();
                    *state.write().await = WsState::Reconnecting;
                }
                Err(e) => {
                    error!("[WS] Connection failed: {}", e);
                    *state.write().await = WsState::Reconnecting;
                }
            }

            // Exponential backoff before reconnecting
            info!("[WS] Reconnecting in {}ms...", backoff_ms);
            tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
        }
    }

    /// Send a call signal via the WebSocket (instant delivery).
    pub async fn send_signal(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        let state = self.state.read().await;
        if *state != WsState::Connected {
            return Err(CipherError::Network(
                "WebSocket not connected, signal will use HTTP fallback".to_string(),
            ));
        }
        drop(state);

        let payload = base64_encode(&data);
        let envelope = WsOutgoing {
            // PRIVACY: Use sealed mailbox hash, not real address
            to: sealed_mailbox(recipient),
            payload,
        };

        let json =
            serde_json::to_string(&envelope).map_err(|e| CipherError::Encryption(e.to_string()))?;

        self.outgoing_tx
            .send(json)
            .await
            .map_err(|e| CipherError::Network(format!("WebSocket send channel closed: {}", e)))?;

        debug!("[WS] 📤 Signal queued for {}", recipient);
        Ok(())
    }

    /// Drain any incoming signals received via WebSocket push.
    pub async fn drain_incoming(&self) -> Vec<Vec<u8>> {
        let mut rx = self.incoming_rx.lock().await;
        let mut messages = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            messages.push(msg);
        }
        messages
    }

    /// Get current connection state.
    pub async fn connection_state(&self) -> WsState {
        self.state.read().await.clone()
    }

    /// Check if connected.
    pub async fn is_connected(&self) -> bool {
        *self.state.read().await == WsState::Connected
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| e.to_string())
}
