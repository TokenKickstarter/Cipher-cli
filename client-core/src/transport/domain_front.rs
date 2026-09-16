//! # Domain Fronting Transport
//!
//! Routes traffic through a Cloudflare Worker (or other CDN) to hide the VPS IP
//! from the user's ISP. This provides robust censorship resistance.
//! All traffic looks like standard HTTPS to Cloudflare's edge.

use log::{debug, error, info};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::direct::{RelayRequest, RelayResponse, StoredChunk};
use crate::error::CipherError;
use crate::transport::websocket_signal::sealed_mailbox;

#[derive(Debug, Clone, PartialEq)]
pub enum DomainFrontState {
    Disabled,
    Active { url: String },
}

pub struct DomainFrontTransport {
    state: Arc<RwLock<DomainFrontState>>,
    http_client: reqwest::Client,
}

impl DomainFrontTransport {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // Traffic appears as standard HTTPS to Cloudflare's CDN edge.
            // ISPs/firewalls see connections to Cloudflare IPs — not the VPS.
            .build()
            .expect("Failed to build HTTP client for domain fronting");

        Self {
            // PRIVACY: Auto-activate domain fronting via Cloudflare proxy worker
            state: Arc::new(RwLock::new(DomainFrontState::Active {
                url: "https://cipher-relay-proxy.admin-5f1.workers.dev".to_string(),
            })),
            http_client: client,
        }
    }

    /// Update the Cloudflare worker URL.
    pub async fn set_url(&self, url: &str) {
        if url.is_empty() {
            *self.state.write().await = DomainFrontState::Disabled;
            info!("[DomainFront] Domain fronting disabled");
        } else {
            *self.state.write().await = DomainFrontState::Active {
                url: url.to_string(),
            };
            info!("[DomainFront] Domain fronting ACTIVE via {}", url);
        }
    }

    /// Get current state.
    pub async fn state(&self) -> DomainFrontState {
        self.state.read().await.clone()
    }

    /// Send a request to the relay via the Domain Front worker.
    pub async fn send_through_front(&self, req: &RelayRequest) -> Result<Vec<u8>, CipherError> {
        let state = self.state().await;

        let url = match state {
            DomainFrontState::Disabled => {
                return Err(CipherError::Network(
                    "Domain fronting is disabled".to_string(),
                ));
            }
            DomainFrontState::Active { url } => url,
        };

        debug!("[DomainFront] Forwarding request via Worker");

        let body = bincode::serialize(req)
            .map_err(|e| CipherError::Encryption(format!("Serialization failed: {}", e)))?;

        // Forward to the /relay endpoint on the worker
        let relay_url = format!("{}/relay", url.trim_end_matches('/'));

        let resp = self
            .http_client
            .post(&relay_url)
            .header("Content-Type", "application/octet-stream")
            .body(body)
            .send()
            .await
            .map_err(|e| CipherError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let error_text = resp.text().await.unwrap_or_default();
            error!("[DomainFront] Worker proxy returned error: {}", error_text);
            return Err(CipherError::Network(format!(
                "Worker error: {}",
                error_text
            )));
        }

        let resp_bytes = resp
            .bytes()
            .await
            .map_err(|e: reqwest::Error| CipherError::Network(e.to_string()))?;

        info!("[DomainFront] ✓ Successfully proxied request via Cloudflare Worker");
        Ok(resp_bytes.to_vec())
    }
}
