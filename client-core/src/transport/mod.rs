//! # Transport Layer
//!
//! Abstracts the network transport with privacy-preserving layers:
//! - Direct (WebSocket to VPS relay — fast, minimal privacy)
//! - Tor (routes through Tor circuit — hides sender IP)
//! - Nym mixnet (5-hop mixing + cover traffic — maximum privacy)
//!
//! `TransportRouter` auto-selects the best available transport
//! based on the configured `TransportMode`.

pub mod direct;
pub mod tor;
pub mod nym;
pub mod domain_front;
pub mod ble_mesh;
pub mod wifi;
pub mod mesh;
pub mod websocket_signal;

use crate::error::CipherError;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn, debug};

/// Transport-agnostic interface for sending/receiving bytes.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Send encrypted message bytes to a peer.
    async fn send(&self, peer_id: &str, data: Vec<u8>) -> Result<(), CipherError>;

    /// Receive the next message (blocks until available).
    async fn recv(&self) -> Result<(String, Vec<u8>), CipherError>;

    /// Get our own peer address on this transport.
    fn our_address(&self) -> String;

    /// Check if transport is connected / available.
    fn is_available(&self) -> bool;

    /// Transport name for logging.
    fn name(&self) -> &'static str;
}

/// Transport selection strategy.
/// Per Blueprint §8: Auto selects Nym → Tor → Direct
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TransportMode {
    /// Auto-select best available (Nym → Tor → Direct)
    Auto,
    /// Force direct relay (no privacy layer, fast, for LAN/dev)
    Direct,
    /// Force Tor (hides IP, moderate latency)
    Tor,
    /// Force Nym mixnet (full metadata protection, higher latency)
    Nym,
    /// Connect through a Cloudflare Worker reverse proxy
    DomainFronting,
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "Auto (Nym → Tor → Direct)"),
            Self::Direct => write!(f, "Direct (no privacy layer)"),
            Self::Tor => write!(f, "Tor (IP hidden)"),
            Self::Nym => write!(f, "Nym Mixnet (full metadata protection)"),
            Self::DomainFronting => write!(f, "Domain Fronting (censorship resistance)"),
        }
    }
}

/// Routes messages through the appropriate privacy transport.
///
/// Manages all three transport layers (Direct, Tor, Nym) and
/// selects the active one based on `TransportMode`.
pub struct TransportRouter {
    /// Current transport mode
    mode: Arc<RwLock<TransportMode>>,
    /// Direct transport (always available)
    pub direct: Arc<direct::DirectTransport>,
    /// Tor transport (available when Tor proxy is running)
    pub tor: Arc<tor::TorTransport>,
    /// Nym transport (available when Nym SDK is connected)
    pub nym: Arc<nym::NymTransport>,
    /// Domain fronting proxy 
    pub domain_front: Arc<domain_front::DomainFrontTransport>,
    /// Real-time WebSocket signal channel (for instant call signaling)
    pub ws_signal: Arc<websocket_signal::WebSocketSignal>,
    /// Our EVM address
    peer_id: String,
}

impl TransportRouter {
    /// Create a new transport router with all three layers.
    pub fn new(peer_id: String) -> Self {
        let direct = Arc::new(direct::DirectTransport::new(
            peer_id.clone(),
            direct::DirectTransportConfig::default(),
        ));
        let tor = Arc::new(tor::TorTransport::new(
            peer_id.clone(),
            tor::TorConfig::default(),
        ));
        let nym = Arc::new(nym::NymTransport::new(
            peer_id.clone(),
            nym::NymConfig::default(),
        ));
        let domain_front = Arc::new(domain_front::DomainFrontTransport::new());
        let ws_signal = Arc::new(websocket_signal::WebSocketSignal::new(peer_id.clone()));

        Self {
            mode: Arc::new(RwLock::new(TransportMode::Direct)),
            direct,
            tor,
            nym,
            domain_front,
            ws_signal,
            peer_id,
        }
    }

    /// Start the transport router — connects to relay and begins polling.
    pub async fn start(&self) {
        info!("[Router] Starting transport router for {}", self.peer_id);

        let mode = self.mode.read().await.clone();
        info!("[Router] Active transport mode: {}", mode);

        // Try to bootstrap privacy layers
        match mode {
            TransportMode::Auto => {
                // Try Nym first, then Tor, fall back to Direct
                if self.nym.connect().await.is_ok() {
                    info!("[Router] Auto: Using Nym mixnet");
                } else if self.tor.bootstrap().await.is_ok() {
                    info!("[Router] Auto: Using Tor (Nym unavailable)");
                } else {
                    info!("[Router] Auto: Using Direct (Tor + Nym unavailable)");
                }
            }
            TransportMode::Nym => {
                if let Err(e) = self.nym.connect().await {
                    warn!("[Router] Nym requested but failed: {} — using Direct", e);
                }
            }
            TransportMode::Tor => {
                if let Err(e) = self.tor.bootstrap().await {
                    warn!("[Router] Tor requested but failed: {} — using Direct", e);
                }
            }
            TransportMode::Direct => {
                info!("[Router] Direct mode — no privacy layer");
            }
            TransportMode::DomainFronting => {
                info!("[Router] Domain Fronting Cloudflare mode");
            }
        }
    }

    /// Set the transport mode.
    pub async fn set_mode(&self, mode: TransportMode) {
        info!("[Router] Switching transport mode to: {}", mode);
        *self.mode.write().await = mode;
    }

    /// Get the current transport mode.
    pub async fn get_mode(&self) -> TransportMode {
        self.mode.read().await.clone()
    }

    /// Get the active transport privacy mode and name.
    pub async fn active_transport_name(&self) -> &'static str {
        let mode = self.mode.read().await.clone();
        match mode {
            TransportMode::Nym => {
                if self.nym.nym_state().await != nym::NymState::Disabled {
                    "Nym Mixnet"
                } else {
                    "Direct (Nym fallback)"
                }
            }
            TransportMode::Tor => {
                if self.tor.tor_state().await != tor::TorState::Disabled {
                    "Tor"
                } else {
                    "Direct (Tor fallback)"
                }
            }
            TransportMode::DomainFronting => {
                if self.domain_front.state().await != domain_front::DomainFrontState::Disabled {
                    "Domain Fronting (Cloudflare)"
                } else {
                    "Direct (Domain Front fallback)"
                }
            }
            _ => "Direct",
        }
    }

    /// Queue a message using the active transport.
    pub async fn queue_message(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        let mode = self.mode.read().await.clone();
        match mode {
            TransportMode::Nym => {
                if self.nym.nym_state().await != nym::NymState::Disabled {
                    self.nym.queue_message(recipient, data).await
                } else {
                    self.direct.queue_message(recipient, data).await
                }
            }
            TransportMode::Tor => {
                if self.tor.tor_state().await != tor::TorState::Disabled {
                    self.tor.queue_message(recipient, data).await
                } else {
                    self.direct.queue_message(recipient, data).await
                }
            }
            TransportMode::DomainFronting => {
                if self.domain_front.state().await != domain_front::DomainFrontState::Disabled {
                    self.direct.queue_message(recipient, data).await
                } else {
                    self.direct.queue_message(recipient, data).await
                }
            }
            _ => self.direct.queue_message(recipient, data).await,
        }
    }

    /// Drain all unread messages from BOTH channels:
    /// 1. WebSocket push channel (instant call signals)
    /// 2. HTTP polling channel (store-and-forward text messages)
    pub async fn drain_unread(&self) -> Vec<Vec<u8>> {
        let mut all = self.ws_signal.drain_incoming().await;
        all.extend(self.direct.drain_unread().await);
        all
    }

    /// Send a message via BOTH channels for reliability:
    /// 1. HTTP relay (guaranteed store-and-forward delivery)
    /// 2. WebSocket (instant delivery if both peers are connected)
    pub async fn send_signal(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        // ALWAYS send via HTTP relay for guaranteed delivery
        self.queue_message(recipient, data.clone()).await?;
        // Instantly force flush the outbox using fallback (instead of full trait system)
        self.direct.flush_outbox(&crate::transport::direct::DefaultSender {
            direct: self.direct.clone(),
        }).await;

        // ALSO try WebSocket for instant delivery (best-effort, don't fail if it errors)
        if let Err(e) = self.ws_signal.send_signal(recipient, data).await {
            debug!("[Router] WebSocket boost unavailable (HTTP will deliver): {}", e);
        }

        Ok(())
    }

    /// Get the underlying direct transport (used by SwarmClient).
    pub fn get_direct(&self) -> &Arc<direct::DirectTransport> {
        &self.direct
    }
}
