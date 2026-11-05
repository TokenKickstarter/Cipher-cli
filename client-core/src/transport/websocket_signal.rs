//! # WebSocket Real-Time Signal Transport
//!
//! Maintains a persistent WebSocket connection to federated signal relays
//! for instant delivery of messages and call signaling.
//!
//! PRIVACY: Uses sealed sender — the relay only sees a hashed mailbox ID,
//! not the real EVM address. The sender's identity is inside the encrypted payload.

use crate::error::CipherError;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Legacy export — federated clients use [`crate::network_bundle::SignalPool`] instead.
pub const DEFAULT_SIGNAL_WS_URL: &str = "";

/// PRIVACY: Derive a sealed mailbox ID from an address.
pub fn sealed_mailbox(address: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"cipher-sealed-v1:");
    hasher.update(address.to_lowercase().as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, PartialEq)]
pub enum WsState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsOutgoing {
    to: String,
    payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsIncoming {
    from: String,
    payload: String,
    ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WsAck {
    ack: Option<bool>,
    delivered: Option<bool>,
    queued: Option<bool>,
    error: Option<String>,
}

pub struct WebSocketSignal {
    our_address: String,
    signal_pool: Arc<crate::network_bundle::SignalPool>,
    relay_pool: Arc<crate::network_bundle::RelayPool>,
    ws_index: Arc<RwLock<usize>>,
    state: Arc<RwLock<WsState>>,
    outgoing_tx: mpsc::Sender<String>,
    incoming_tx: mpsc::Sender<Vec<u8>>,
    incoming_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl WebSocketSignal {
    pub fn new(
        our_address: String,
        signal_pool: Arc<crate::network_bundle::SignalPool>,
        relay_pool: Arc<crate::network_bundle::RelayPool>,
    ) -> Self {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(500);
        let (incoming_tx, incoming_rx) = mpsc::channel(500);

        let sealed_addr = sealed_mailbox(&our_address);

        let ws = Self {
            our_address: our_address.to_lowercase(),
            signal_pool: signal_pool.clone(),
            relay_pool: relay_pool.clone(),
            ws_index: Arc::new(RwLock::new(0)),
            state: Arc::new(RwLock::new(WsState::Disconnected)),
            outgoing_tx,
            incoming_tx,
            incoming_rx: Arc::new(tokio::sync::Mutex::new(incoming_rx)),
        };

        let state = ws.state.clone();
        let addr = sealed_addr;
        let pool = ws.signal_pool.clone();
        let relay_pool_spawn = ws.relay_pool.clone();
        let ws_index = ws.ws_index.clone();
        let tx = ws.incoming_tx.clone();
        let outgoing_rx = Arc::new(tokio::sync::Mutex::new(outgoing_rx));

        crate::ffi::runtime().spawn(async move {
            Self::connection_loop(
                state,
                addr,
                pool,
                relay_pool_spawn,
                ws_index,
                tx,
                outgoing_rx,
            )
            .await;
        });

        ws
    }

    async fn connection_loop(
        state: Arc<RwLock<WsState>>,
        addr: String,
        signal_pool: Arc<crate::network_bundle::SignalPool>,
        relay_pool: Arc<crate::network_bundle::RelayPool>,
        ws_index: Arc<RwLock<usize>>,
        incoming_tx: mpsc::Sender<Vec<u8>>,
        outgoing_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<String>>>,
    ) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::connect_async_with_config;
        use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
        use tokio_tungstenite::tungstenite::Message;

        let mut backoff_ms: u64 = 1000;
        let max_backoff_ms: u64 = 30000;

        loop {
            let ws_urls = signal_pool.ordered_urls().await;
            if ws_urls.is_empty() {
                warn!("[WS] No signal endpoints yet — waiting for federated discovery…");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                continue;
            }

            let idx = *ws_index.read().await;
            let base_url = ws_urls[idx % ws_urls.len()].clone();
            let ws_url = format!("{base_url}?addr={addr}");
            info!("[WS] Connecting to {ws_url}...");
            *state.write().await = WsState::Connecting;

            let ws_config = WebSocketConfig {
                max_message_size: Some(256 * 1024 * 1024),
                max_frame_size: Some(64 * 1024 * 1024),
                ..Default::default()
            };

            match connect_async_with_config(&ws_url, Some(ws_config), false).await {
                Ok((ws_stream, _response)) => {
                    info!("[WS] ✅ Connected to signal relay as {addr}");
                    *state.write().await = WsState::Connected;
                    backoff_ms = 1000;

                    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

                    let outgoing_handle = {
                        let outgoing_rx = outgoing_rx.clone();
                        tokio::spawn(async move {
                            let mut rx = outgoing_rx.lock().await;
                            let mut ping_interval =
                                tokio::time::interval(tokio::time::Duration::from_secs(30));
                            ping_interval.tick().await;

                            loop {
                                tokio::select! {
                                    _ = ping_interval.tick() => {
                                        let ping_msg = r#"{"type":"ping","to":"ping","payload":"ping"}"#.to_string();
                                        if ws_sender.send(Message::Text(ping_msg)).await.is_err() {
                                            break;
                                        }
                                        debug!("[WS] Sent app-level keep-alive ping");
                                    }
                                    msg_opt = rx.recv() => {
                                        match msg_opt {
                                            Some(msg) => {
                                                if ws_sender.send(Message::Text(msg)).await.is_err() {
                                                    break;
                                                }
                                            }
                                            None => {
                                                let _ = ws_sender.send(Message::Close(None)).await;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        })
                    };

                    while let Some(result) = ws_receiver.next().await {
                        match result {
                            Ok(Message::Text(text)) => {
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                                    let msg_type =
                                        json.get("type").and_then(|t| t.as_str()).unwrap_or("");

                                    match msg_type {
                                        "message" => {
                                            if let Some(data_b64) =
                                                json.get("data").and_then(|d| d.as_str())
                                            {
                                                match base64_decode(data_b64) {
                                                    Ok(bytes) => {
                                                        info!("[WS] ⚡ Instant message via WebSocket push");
                                                        let _ = incoming_tx.send(bytes).await;
                                                        crate::ffi::notify_dart();

                                                        if let Some(mid) = json
                                                            .get("message_id")
                                                            .and_then(|m| m.as_str())
                                                        {
                                                            let ack_body = serde_json::json!({
                                                                "recipient_id": addr,
                                                                "message_ids": [mid],
                                                            })
                                                            .to_string();
                                                            let pool = relay_pool.clone();
                                                            tokio::spawn(async move {
                                                                let _ = pool
                                                                    .post_json_failover("/ack", ack_body, 5)
                                                                    .await;
                                                            });
                                                        }
                                                    }
                                                    Err(e) => {
                                                        warn!("[WS] Failed to decode WS push data: {e}");
                                                    }
                                                }
                                            }
                                        }
                                        "signal" => {
                                            if let Some(payload) =
                                                json.get("payload").and_then(|p| p.as_str())
                                            {
                                                match base64_decode(payload) {
                                                    Ok(bytes) => {
                                                        let _ = incoming_tx.send(bytes).await;
                                                        crate::ffi::notify_dart();
                                                    }
                                                    Err(e) => {
                                                        warn!("[WS] Failed to decode signal payload: {e}");
                                                    }
                                                }
                                            }
                                        }
                                        _ => {
                                            if let Ok(ack) = serde_json::from_str::<WsAck>(&text) {
                                                if let Some(err) = ack.error {
                                                    warn!("[WS] Server error: {err}");
                                                } else {
                                                    debug!(
                                                        "[WS] ACK: delivered={:?} queued={:?}",
                                                        ack.delivered, ack.queued
                                                    );
                                                }
                                            } else if let Ok(incoming) =
                                                serde_json::from_str::<WsIncoming>(&text)
                                            {
                                                match base64_decode(&incoming.payload) {
                                                    Ok(bytes) => {
                                                        let _ = incoming_tx.send(bytes).await;
                                                        crate::ffi::notify_dart();
                                                    }
                                                    Err(e) => {
                                                        warn!("[WS] Failed to decode incoming payload: {e}");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Ok(Message::Close(_)) => {
                                info!("[WS] Server closed connection");
                                break;
                            }
                            Err(e) => {
                                warn!("[WS] Read error: {e}");
                                break;
                            }
                            _ => {}
                        }
                    }

                    outgoing_handle.abort();
                    *state.write().await = WsState::Reconnecting;
                }
                Err(e) => {
                    error!("[WS] Connection failed: {e}");
                    *state.write().await = WsState::Reconnecting;
                }
            }

            if ws_urls.len() > 1 {
                let mut idx = ws_index.write().await;
                *idx = (*idx + 1) % ws_urls.len();
                info!(
                    "[WS] Trying next signal relay ({}/{})",
                    *idx + 1,
                    ws_urls.len()
                );
            }

            info!("[WS] Reconnecting in {backoff_ms}ms...");
            tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
            backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
        }
    }

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
            to: sealed_mailbox(recipient),
            payload,
        };

        let json =
            serde_json::to_string(&envelope).map_err(|e| CipherError::Encryption(e.to_string()))?;

        self.outgoing_tx
            .send(json)
            .await
            .map_err(|e| CipherError::Network(format!("WebSocket send channel closed: {e}")))?;

        debug!("[WS] 📤 Signal queued for {recipient}");
        Ok(())
    }

    pub async fn drain_incoming(&self) -> Vec<Vec<u8>> {
        let mut rx = self.incoming_rx.lock().await;
        let mut messages = Vec::new();
        while let Ok(msg) = rx.try_recv() {
            messages.push(msg);
        }
        messages
    }

    pub async fn connection_state(&self) -> WsState {
        self.state.read().await.clone()
    }

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
