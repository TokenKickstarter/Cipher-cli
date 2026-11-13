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
pub mod iroh_p2p;

use crate::error::CipherError;
use crate::network_bundle::{NetworkBundle, RelayPool, SignalPool};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{Notify, RwLock};
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
/// Per Blueprint §8: Auto selects Iroh P2P → Nym → Tor → Direct
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TransportMode {
    /// Auto-select best available (Iroh P2P → Nym → Tor → Direct)
    Auto,
    /// Direct P2P via Iroh (QUIC + Magicsock hole-punching)
    Iroh,
    /// Force direct relay (no privacy layer, fast, for LAN/dev)
    Direct,
    /// Force Tor (hides IP, moderate latency)
    Tor,
    /// Force Nym mixnet (full metadata protection, higher latency)
    Nym,
    /// Connect through a Cloudflare Worker reverse proxy
    DomainFronting,
}

impl TransportMode {
    /// Parse persisted or CLI transport mode string (defaults to `Direct` for unknown values).
    pub fn from_config_str(raw: &str) -> Self {
        match raw.trim().to_lowercase().as_str() {
            "auto" => Self::Auto,
            "iroh" => Self::Iroh,
            "tor" => Self::Tor,
            "nym" => Self::Nym,
            "front" | "domain-fronting" | "domain_fronting" => Self::DomainFronting,
            _ => Self::Direct,
        }
    }

    pub fn config_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Iroh => "iroh",
            Self::Direct => "direct",
            Self::Tor => "tor",
            Self::Nym => "nym",
            Self::DomainFronting => "domain-fronting",
        }
    }
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "Auto (Iroh → Nym → Tor → Direct)"),
            Self::Iroh => write!(f, "Iroh (Direct QUIC + Magicsock P2P)"),
            Self::Direct => write!(f, "Direct (no privacy layer)"),
            Self::Tor => write!(f, "Tor (IP hidden)"),
            Self::Nym => write!(f, "Nym Mixnet (full metadata protection)"),
            Self::DomainFronting => write!(f, "Domain Fronting (censorship resistance)"),
        }
    }
}

/// Resolve persisted transport mode from `CIPHER_TRANSPORT_MODE` or `$CIPHER_DIR/config.json` / `~/.cipher/config.json`.
pub fn load_persisted_mode() -> TransportMode {
    if let Ok(env_mode) = std::env::var("CIPHER_TRANSPORT_MODE") {
        if !env_mode.trim().is_empty() {
            return TransportMode::from_config_str(&env_mode);
        }
    }
    let dir = std::env::var_os("CIPHER_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|h| std::path::PathBuf::from(h).join(".cipher"))
        });
    if let Some(cfg_path) = dir.map(|d| d.join("config.json")) {
        if let Ok(text) = std::fs::read_to_string(&cfg_path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(m) = v.get("transport_mode").and_then(|s| s.as_str()) {
                    return TransportMode::from_config_str(m);
                }
            }
        }
    }
    TransportMode::Direct
}

/// Routes messages through the appropriate privacy transport.
///
/// Manages transport layers (Iroh, Direct, Tor, Nym) and
/// selects the active one based on `TransportMode`.
pub struct TransportRouter {
    /// Current transport mode
    mode: Arc<RwLock<TransportMode>>,
    /// Direct transport (always available)
    pub direct: Arc<direct::DirectTransport>,
    /// Iroh P2P transport (QUIC + Magicsock)
    pub iroh: Arc<iroh_p2p::IrohTransport>,
    /// Tor transport (available when Tor proxy is running)
    pub tor: Arc<tor::TorTransport>,
    /// Nym transport (available when Nym SDK is connected)
    pub nym: Arc<nym::NymTransport>,
    /// Domain fronting proxy 
    pub domain_front: Arc<domain_front::DomainFrontTransport>,
    /// Real-time WebSocket signal channel (for instant call signaling)
    pub ws_signal: Arc<websocket_signal::WebSocketSignal>,
    /// Unified notifier woken whenever Direct, WebSocket, or Iroh receives incoming bytes
    pub incoming_notify: Arc<Notify>,
    /// Our EVM address
    peer_id: String,
}

impl TransportRouter {
    /// Create a new transport router with default derived key.
    pub fn new(peer_id: String) -> Self {
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(peer_id.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        Self::new_with_secret(peer_id, key)
    }

    /// Create a new transport router honoring the persisted CLI/config mode.
    pub fn new_with_secret(peer_id: String, secret_key: [u8; 32]) -> Self {
        Self::new_with_mode(peer_id, secret_key, load_persisted_mode())
    }

    /// Create a new transport router with explicit Ed25519 secret key and transport mode.
    pub fn new_with_mode(peer_id: String, secret_key: [u8; 32], initial_mode: TransportMode) -> Self {
        Self::new_with_mode_and_pools(
            peer_id,
            secret_key,
            initial_mode,
            RelayPool::global(),
            SignalPool::global(),
        )
    }

    /// Create a transport router with explicit pools (useful for isolated tests or local relays).
    pub fn new_with_mode_and_pools(
        peer_id: String,
        secret_key: [u8; 32],
        initial_mode: TransportMode,
        relay_pool: Arc<RelayPool>,
        signal_pool: Arc<SignalPool>,
    ) -> Self {
        let incoming_notify = Arc::new(Notify::new());

        let direct = Arc::new(direct::DirectTransport::new_with_notify(
            peer_id.clone(),
            direct::DirectTransportConfig::default(),
            relay_pool.clone(),
            incoming_notify.clone(),
        ));
        let iroh = Arc::new(iroh_p2p::IrohTransport::new_with_notify(
            peer_id.clone(),
            secret_key,
            incoming_notify.clone(),
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
        let ws_signal = Arc::new(websocket_signal::WebSocketSignal::new_with_notify(
            peer_id.clone(),
            signal_pool,
            relay_pool.clone(),
            incoming_notify.clone(),
        ));

        Self {
            mode: Arc::new(RwLock::new(initial_mode)),
            direct,
            iroh,
            tor,
            nym,
            domain_front,
            ws_signal,
            incoming_notify,
            peer_id,
        }
    }

    /// Start the transport router — connects to relay and begins polling.
    pub async fn start(&self) {
        info!("[Router] Starting transport router for {}", self.peer_id);

        let pool = self.direct.relay_pool().clone();
        let rpcs = NetworkBundle::global().rpc_http.clone();
        let stats = pool.refresh_network(&rpcs).await;
        info!(
            "[Router] Federated pool: {} HTTP relay(s) (+{} chain, +{} discovery), {} signal WS (+{} signal)",
            stats.pool_size,
            stats.chain_hints,
            stats.discovery_hints,
            stats.signal_pool_size,
            stats.signal_hints
        );
        pool.spawn_periodic_refresh(rpcs);

        let mode = self.mode.read().await.clone();
        info!("[Router] Active transport mode: {}", mode);

        // Try to bootstrap privacy / P2P layers
        match mode {
            TransportMode::Auto => {
                // Prefer direct Iroh QUIC P2P; probe Tor SOCKS5 only if locally running, fallback Direct.
                if let Ok(node_id) = self.iroh.init().await {
                    info!("[Router] Auto: Iroh P2P active with NodeId: {}", node_id);
                } else if self.tor.bootstrap().await.is_ok() {
                    info!("[Router] Auto: Using Tor fallback");
                } else {
                    info!("[Router] Auto: Using Direct relay store-and-forward + WS push");
                }
            }
            TransportMode::Iroh => {
                if let Err(e) = self.iroh.init().await {
                    warn!("[Router] Iroh requested but failed: {} — using Direct", e);
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
            TransportMode::Auto => {
                if self.iroh.is_ready().await {
                    "Auto (Iroh P2P + Relay Fallback)"
                } else if self.tor.tor_state().await == tor::TorState::Connected {
                    "Auto (Tor)"
                } else {
                    "Auto (Direct Relay + WS)"
                }
            }
            TransportMode::Iroh => "Iroh (QUIC + Magicsock P2P)",
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
            TransportMode::Direct => "Direct",
        }
    }

    /// Queue a message using the active transport.
    pub async fn queue_message(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        let mode = self.mode.read().await.clone();
        match mode {
            TransportMode::Auto => {
                if self.iroh.is_ready().await && self.iroh.resolve_endpoint(recipient).await.is_ok() {
                    if let Err(e) = self.iroh.send_to_node(recipient, &data).await {
                        debug!("[Router] Auto Iroh QUIC send failed ({e}) — falling back cleanly");
                    } else {
                        return Ok(());
                    }
                }
                if self.tor.tor_state().await == tor::TorState::Connected {
                    return self.tor.queue_message(recipient, data).await;
                }
                self.direct.queue_message(recipient, data).await
            }
            TransportMode::Iroh => {
                if !self.iroh.is_ready().await {
                    let _ = self.iroh.init().await;
                }
                if let Err(e) = self.iroh.send_to_node(recipient, &data).await {
                    debug!("[Router] Direct Iroh QUIC send failed: {e} — falling back to relay store-and-forward");
                    self.direct.queue_message(recipient, data).await
                } else {
                    Ok(())
                }
            }
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
            TransportMode::Direct => self.direct.queue_message(recipient, data).await,
        }
    }

    /// Drain all unread messages from ALL channels:
    /// 1. WebSocket push channel (instant call signals)
    /// 2. HTTP polling channel (store-and-forward text messages)
    /// 3. Direct Iroh QUIC stream channel
    pub async fn drain_unread(&self) -> Vec<Vec<u8>> {
        let mut all = self.ws_signal.drain_incoming().await;
        all.extend(self.direct.drain_unread().await);
        all.extend(self.iroh.drain_incoming().await);
        all
    }

    /// Send via multiple paths: federated HTTP relays, Iroh QUIC (when active), WebSocket signal.
    pub async fn send_signal(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        self.queue_message(recipient, data.clone()).await?;
        // Instantly force flush the outbox using fallback (instead of full trait system)
        let _ = self
            .direct
            .flush_outbox(&crate::transport::direct::DefaultSender {
                direct: self.direct.clone(),
            })
            .await;

        // Try direct Iroh QUIC P2P delivery when active & peer EndpointId is known
        if self.iroh.is_ready().await && self.iroh.resolve_endpoint(recipient).await.is_ok() {
            let _ = self.iroh.send_to_node(recipient, &data).await;
        }

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
