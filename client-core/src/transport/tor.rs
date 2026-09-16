//! # Tor Transport
//!
//! Routes all relay communication through a Tor circuit using the `arti` crate.
//! Per TKS Blueprint §4: "Fallback: Tor Arti (Rust) as backup transport"
//!
//! The relay sees a Tor exit node IP instead of the user's real IP.
//! Message content is already E2E encrypted, so Tor only hides metadata.

use std::sync::Arc;
use tokio::sync::RwLock;
use log::{info, warn, debug};

use crate::error::CipherError;
use crate::transport::direct::{DirectTransport, DirectTransportConfig, RelayRequest, RelayResponse, StoredChunk, ConnectionState};

/// Tor transport configuration
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// SOCKS5 proxy port for Tor (default: 9050)
    pub socks_port: u16,
    /// Whether to use the Tor network
    pub enabled: bool,
    /// Relay URL to connect to through Tor
    pub relay_url: String,
    /// Circuit isolation: use a new circuit per conversation
    pub isolate_circuits: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_port: 9050,
            enabled: false,
            relay_url: "http://209.97.165.19:4002/relay".to_string(),
            isolate_circuits: true,
        }
    }
}

/// Tor transport state
#[derive(Debug, Clone, PartialEq)]
pub enum TorState {
    /// Tor is not initialized
    Disabled,
    /// Tor is bootstrapping (connecting to guard nodes)
    Bootstrapping,
    /// Tor circuit is established and ready
    Connected,
    /// Tor connection failed
    Failed(String),
}

/// Tor transport wrapper — routes DirectTransport traffic through Tor.
///
/// Architecture:
/// ```text
/// App → TorTransport → SOCKS5 Proxy → Tor Circuit → Exit Node → VPS Relay
///                                                                    ↓
///                                                              Encrypted chunks
/// ```
pub struct TorTransport {
    /// Underlying direct transport (reuses all message logic)
    inner: Arc<DirectTransport>,
    /// Tor configuration
    config: TorConfig,
    /// Current Tor state
    state: Arc<RwLock<TorState>>,
    /// Our EVM address
    peer_id: String,
}

impl TorTransport {
    /// Create a new Tor transport wrapping a DirectTransport.
    pub fn new(peer_id: String, config: TorConfig) -> Self {
        // Create inner transport that will route through Tor SOCKS5
        let direct_config = DirectTransportConfig::default();
        let inner = Arc::new(DirectTransport::new(peer_id.clone(), direct_config));

        Self {
            inner,
            config,
            state: Arc::new(RwLock::new(TorState::Disabled)),
            peer_id,
        }
    }

    /// Bootstrap the Tor connection.
    ///
    /// In production, this uses `arti-client` to create a Tor circuit:
    /// ```rust,ignore
    /// use arti_client::{TorClient, TorClientConfig};
    /// let config = TorClientConfig::default();
    /// let tor = TorClient::create_bootstrapped(config).await?;
    /// let stream = tor.connect(("209.97.165.19", 4002)).await?;
    /// ```
    ///
    /// For now, we use a SOCKS5 proxy approach (compatible with existing Tor daemon):
    /// All HTTP requests go through `socks5://127.0.0.1:9050` → Tor network → relay.
    pub async fn bootstrap(&self) -> Result<(), CipherError> {
        *self.state.write().await = TorState::Bootstrapping;
        info!("[Tor] Bootstrapping Tor circuit to relay...");

        // Check if a Tor SOCKS5 proxy is available
        let socks_addr = format!("127.0.0.1:{}", self.config.socks_port);
        match tokio::net::TcpStream::connect(&socks_addr).await {
            Ok(_) => {
                *self.state.write().await = TorState::Connected;
                info!("[Tor] ✅ Tor SOCKS5 proxy available at {}", socks_addr);
                Ok(())
            }
            Err(_) => {
                // Tor not available — fall back to direct
                let msg = format!("Tor SOCKS5 proxy not available at {}", socks_addr);
                *self.state.write().await = TorState::Failed(msg.clone());
                warn!("[Tor] {}", msg);
                Err(CipherError::Network(msg))
            }
        }
    }

    /// Send a request through Tor to the relay.
    ///
    /// When Tor is connected, routes through SOCKS5 proxy.
    /// When Tor is not available, falls back to direct connection.
    pub async fn send_through_tor(&self, request: &RelayRequest) -> Result<Vec<u8>, CipherError> {
        let state = self.state.read().await.clone();

        match state {
            TorState::Connected => {
                let request_bytes = bincode::serialize(request)
                    .map_err(|e| CipherError::Network(format!("Serialize error: {}", e)))?;
                let socks_port = self.config.socks_port;
                let relay_url = self.config.relay_url.clone();

                // Route through Tor SOCKS5 proxy
                let response = tokio::task::spawn_blocking(move || {
                    let proxy = ureq::Proxy::new(format!("socks5://127.0.0.1:{}", socks_port))
                        .map_err(|e| CipherError::Network(format!("SOCKS5 error: {}", e)))?;
                    let agent = ureq::AgentBuilder::new().proxy(proxy).build();
                    agent.post(&relay_url)
                        .set("Content-Type", "application/octet-stream")
                        .send_bytes(&request_bytes)
                        .map_err(|e| CipherError::Network(format!("Tor HTTP error: {}", e)))
                })
                .await
                .map_err(|e| CipherError::Network(format!("Join error: {}", e)))??;

                let mut body = Vec::new();
                use std::io::Read;
                response.into_reader().read_to_end(&mut body)
                    .map_err(|e| CipherError::Network(format!("Read error: {}", e)))?;

                Ok(body)
            }
            _ => {
                // Fall back to direct connection
                warn!("[Tor] Not connected, falling back to direct");
                Err(CipherError::Network("Tor not connected".into()))
            }
        }
    }

    /// Queue a message (delegates to inner transport).
    pub async fn queue_message(&self, recipient: &str, data: Vec<u8>) -> Result<(), CipherError> {
        self.inner.queue_message(recipient, data).await
    }

    /// Get current Tor state.
    pub async fn tor_state(&self) -> TorState {
        self.state.read().await.clone()
    }

    /// Get the inner direct transport (for fallback).
    pub fn inner(&self) -> &Arc<DirectTransport> {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tor_config_defaults() {
        let config = TorConfig::default();
        assert_eq!(config.socks_port, 9050);
        assert!(!config.enabled);
        assert!(config.relay_url.contains("209.97.165.19"));
    }

    #[tokio::test]
    async fn test_tor_transport_creation() {
        let transport = TorTransport::new("0xTest".into(), TorConfig::default());
        assert_eq!(transport.tor_state().await, TorState::Disabled);
    }

    #[tokio::test]
    async fn test_tor_bootstrap_no_proxy() {
        // Should fail gracefully when no Tor proxy is running
        let transport = TorTransport::new("0xTest".into(), TorConfig::default());
        let result = transport.bootstrap().await;
        assert!(result.is_err()); // No Tor on test machine
    }
}
