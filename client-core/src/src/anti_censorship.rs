//! # Anti-Censorship Module
//!
//! Pluggable transports and censorship circumvention:
//! - Domain fronting (looks like HTTPS to google.com / cloudflare)
//! - obfs4 (randomized obfuscation — indistinguishable from random)
//! - Snowflake (WebRTC-based, uses volunteer browser proxies)
//! - meek (HTTP-based, domain fronts through CDNs)
//! - Nym mixnet wrapper
//!
//! Auto-probes for censorship and selects the best bypass.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CipherError;

// ─────────────────────────────────────────────────────────
// Pluggable Transport Definitions
// ─────────────────────────────────────────────────────────

/// Available pluggable transports for censorship circumvention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Hash, Eq)]
pub enum PluggableTransport {
    /// Direct connection (no pluggable transport)
    Direct,
    /// obfs4 — randomized look, indistinguishable from noise
    Obfs4,
    /// Snowflake — WebRTC via volunteer browser proxies
    Snowflake,
    /// meek — HTTP-based domain fronting via CDN
    Meek,
    /// Domain fronting — outer TLS points to CDN, inner routes to Cipher
    DomainFronting,
    /// Nym mixnet — full metadata protection
    NymMixnet,
}

impl PluggableTransport {
    pub fn description(&self) -> &'static str {
        match self {
            Self::Direct => "Direct connection (no obfuscation)",
            Self::Obfs4 => "Randomized obfuscation — looks like random noise",
            Self::Snowflake => "WebRTC via volunteer browser proxies",
            Self::Meek => "HTTP domain fronting via CDN (Akamai/Azure)",
            Self::DomainFronting => "TLS wrapping — appears as traffic to google.com",
            Self::NymMixnet => "Full mixnet — metadata-resistant",
        }
    }

    /// How detectable is this transport? Lower = harder to detect.
    pub fn detectability_score(&self) -> u8 {
        match self {
            Self::NymMixnet => 1,       // Virtually undetectable
            Self::Obfs4 => 2,           // Looks like random
            Self::Snowflake => 3,       // Looks like WebRTC
            Self::DomainFronting => 3,  // Looks like Google/CDN
            Self::Meek => 4,            // HTTP, but patterns possible
            Self::Direct => 10,         // Easily fingerprinted
        }
    }

    /// Speed penalty (1 = no penalty, 10 = very slow).
    pub fn speed_penalty(&self) -> u8 {
        match self {
            Self::Direct => 1,
            Self::Obfs4 => 2,
            Self::DomainFronting => 3,
            Self::Snowflake => 4,
            Self::Meek => 5,
            Self::NymMixnet => 7,  // Mixnet adds latency
        }
    }
}

// ─────────────────────────────────────────────────────────
// Bridge Configuration
// ─────────────────────────────────────────────────────────

/// A bridge relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bridge {
    pub transport: PluggableTransport,
    pub address: String,
    pub fingerprint: Option<String>,
    pub params: HashMap<String, String>,
    pub last_tested: Option<DateTime<Utc>>,
    pub is_reachable: bool,
    pub latency_ms: Option<u32>,
}

/// Domain fronting configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFrontConfig {
    /// The outer domain (SNI) — what censors see (e.g., "www.google.com")
    pub front_domain: String,
    /// The inner host header — where traffic actually goes
    pub real_host: String,
    /// CDN provider
    pub cdn: CdnProvider,
    /// Path on the CDN
    pub path: String,
}

/// CDN providers usable for domain fronting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CdnProvider {
    Cloudflare,
    Fastly,
    AzureCdn,
    GoogleCloud,
}

// ─────────────────────────────────────────────────────────
// Censorship Probing
// ─────────────────────────────────────────────────────────

/// Result of a censorship probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub transport: PluggableTransport,
    pub reachable: bool,
    pub latency_ms: Option<u32>,
    pub tested_at: DateTime<Utc>,
}

/// Censorship detection results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensorshipStatus {
    /// Is direct connection blocked?
    pub direct_blocked: bool,
    /// Is Tor blocked?
    pub tor_blocked: bool,
    /// Detected censorship method
    pub method: Option<CensorshipMethod>,
    /// Probe results for each transport
    pub probes: Vec<ProbeResult>,
    /// Recommended transport
    pub recommended: PluggableTransport,
    /// Last check timestamp
    pub last_checked: DateTime<Utc>,
}

/// Known censorship methods.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CensorshipMethod {
    /// IP blocking
    IpBlock,
    /// DNS poisoning
    DnsPoisoning,
    /// Deep Packet Inspection
    Dpi,
    /// TLS fingerprinting
    TlsFingerprinting,
    /// Protocol blocking (e.g., WebRTC, specific ports)
    ProtocolBlock,
    /// Complete internet shutdown
    InternetShutdown,
}

// ─────────────────────────────────────────────────────────
// Anti-Censorship Manager
// ─────────────────────────────────────────────────────────

/// Manages censorship circumvention.
pub struct AntiCensorshipManager {
    /// Current censorship status
    pub status: Arc<RwLock<Option<CensorshipStatus>>>,
    /// Available bridges
    pub bridges: Arc<RwLock<Vec<Bridge>>>,
    /// Domain fronting configs
    pub fronts: Arc<RwLock<Vec<DomainFrontConfig>>>,
    /// Currently active transport
    pub active_transport: Arc<RwLock<PluggableTransport>>,
}

impl AntiCensorshipManager {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(None)),
            bridges: Arc::new(RwLock::new(Vec::new())),
            fronts: Arc::new(RwLock::new(Vec::new())),
            active_transport: Arc::new(RwLock::new(PluggableTransport::Direct)),
        }
    }

    /// Add a bridge configuration.
    pub async fn add_bridge(&self, bridge: Bridge) {
        self.bridges.write().await.push(bridge);
    }

    /// Add a domain fronting configuration.
    pub async fn add_front(&self, config: DomainFrontConfig) {
        self.fronts.write().await.push(config);
    }

    /// Probe for censorship — tests each transport and recommends the best.
    pub async fn probe_censorship(&self) -> CensorshipStatus {
        let transports = vec![
            PluggableTransport::Direct,
            PluggableTransport::Obfs4,
            PluggableTransport::Snowflake,
            PluggableTransport::DomainFronting,
            PluggableTransport::Meek,
            PluggableTransport::NymMixnet,
        ];

        let mut probes = Vec::new();
        let mut direct_blocked = false;

        for transport in &transports {
            // Simulate probing (real: async TCP/HTTP/WebRTC tests)
            let (reachable, latency) = self.test_transport(transport).await;

            if *transport == PluggableTransport::Direct && !reachable {
                direct_blocked = true;
            }

            probes.push(ProbeResult {
                transport: transport.clone(),
                reachable,
                latency_ms: latency,
                tested_at: Utc::now(),
            });
        }

        // Select best: reachable, lowest detectability, acceptable speed
        let recommended = probes
            .iter()
            .filter(|p| p.reachable)
            .min_by_key(|p| p.transport.detectability_score() * 10 + p.transport.speed_penalty())
            .map(|p| p.transport.clone())
            .unwrap_or(PluggableTransport::Direct);

        let method = if direct_blocked {
            Some(CensorshipMethod::Dpi) // Assume DPI if direct blocked
        } else {
            None
        };

        let status = CensorshipStatus {
            direct_blocked,
            tor_blocked: false,
            method,
            probes,
            recommended: recommended.clone(),
            last_checked: Utc::now(),
        };

        *self.status.write().await = Some(status.clone());
        *self.active_transport.write().await = recommended;

        status
    }

    /// Test a specific transport (mock — real impl connects to bridges).
    async fn test_transport(&self, transport: &PluggableTransport) -> (bool, Option<u32>) {
        // In production: actually try to connect
        // For now: simulate all reachable with varying latency
        match transport {
            PluggableTransport::Direct => (true, Some(20)),
            PluggableTransport::Obfs4 => {
                let bridges = self.bridges.read().await;
                let has_bridge = bridges.iter().any(|b| b.transport == PluggableTransport::Obfs4);
                (has_bridge, if has_bridge { Some(80) } else { None })
            }
            PluggableTransport::Snowflake => (true, Some(150)),
            PluggableTransport::DomainFronting => {
                let has_front = !self.fronts.read().await.is_empty();
                (has_front, if has_front { Some(100) } else { None })
            }
            PluggableTransport::Meek => (true, Some(200)),
            PluggableTransport::NymMixnet => (true, Some(500)),
        }
    }

    /// Get the currently active transport.
    pub async fn active(&self) -> PluggableTransport {
        self.active_transport.read().await.clone()
    }

    /// Force a specific transport.
    pub async fn force_transport(&self, transport: PluggableTransport) {
        *self.active_transport.write().await = transport;
    }

    /// Get reachable bridges for a transport type.
    pub async fn reachable_bridges(&self, transport: &PluggableTransport) -> Vec<Bridge> {
        self.bridges
            .read()
            .await
            .iter()
            .filter(|b| b.transport == *transport && b.is_reachable)
            .cloned()
            .collect()
    }

    /// Get the last censorship status.
    pub async fn last_status(&self) -> Option<CensorshipStatus> {
        self.status.read().await.clone()
    }

    /// Get default domain fronting configs for well-known CDNs.
    pub fn default_fronts() -> Vec<DomainFrontConfig> {
        vec![
            DomainFrontConfig {
                front_domain: "www.google.com".into(),
                real_host: "cipher-relay.appspot.com".into(),
                cdn: CdnProvider::GoogleCloud,
                path: "/api/v1/relay".into(),
            },
            DomainFrontConfig {
                front_domain: "cdn.cloudflare.com".into(),
                real_host: "cipher-bridge.workers.dev".into(),
                cdn: CdnProvider::Cloudflare,
                path: "/relay".into(),
            },
            DomainFrontConfig {
                front_domain: "ajax.aspnetcdn.com".into(),
                real_host: "cipher-meek.azurewebsites.net".into(),
                cdn: CdnProvider::AzureCdn,
                path: "/v1/send".into(),
            },
        ]
    }
}

impl Default for AntiCensorshipManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_probe_censorship() {
        let mgr = AntiCensorshipManager::new();

        let status = mgr.probe_censorship().await;
        assert!(!status.direct_blocked);
        assert!(!status.probes.is_empty());
        // Selection prefers lowest detectability — Nym wins even when uncensored
        // (privacy-first design)
        assert_eq!(status.recommended, PluggableTransport::NymMixnet);
    }

    #[tokio::test]
    async fn test_with_bridges() {
        let mgr = AntiCensorshipManager::new();

        mgr.add_bridge(Bridge {
            transport: PluggableTransport::Obfs4,
            address: "192.168.1.1:9001".into(),
            fingerprint: Some("ABC123".into()),
            params: HashMap::new(),
            last_tested: None,
            is_reachable: true,
            latency_ms: Some(80),
        }).await;

        mgr.add_front(DomainFrontConfig {
            front_domain: "www.google.com".into(),
            real_host: "cipher-relay.example.com".into(),
            cdn: CdnProvider::GoogleCloud,
            path: "/relay".into(),
        }).await;

        let status = mgr.probe_censorship().await;
        // With obfs4 bridge + domain fronting available, 
        // should recommend lowest detectability
        let reachable: Vec<_> = status.probes.iter()
            .filter(|p| p.reachable)
            .map(|p| p.transport.clone())
            .collect();
        assert!(reachable.contains(&PluggableTransport::Obfs4));
        assert!(reachable.contains(&PluggableTransport::DomainFronting));
    }

    #[tokio::test]
    async fn test_force_transport() {
        let mgr = AntiCensorshipManager::new();

        mgr.force_transport(PluggableTransport::NymMixnet).await;
        assert_eq!(mgr.active().await, PluggableTransport::NymMixnet);
    }

    #[tokio::test]
    async fn test_transport_properties() {
        // Nym should be hardest to detect
        assert!(
            PluggableTransport::NymMixnet.detectability_score()
                < PluggableTransport::Direct.detectability_score()
        );
        // Direct should be fastest
        assert!(
            PluggableTransport::Direct.speed_penalty()
                < PluggableTransport::NymMixnet.speed_penalty()
        );
    }

    #[test]
    fn test_default_fronts() {
        let fronts = AntiCensorshipManager::default_fronts();
        assert_eq!(fronts.len(), 3);
        assert_eq!(fronts[0].cdn, CdnProvider::GoogleCloud);
        assert!(fronts[0].front_domain.contains("google"));
    }
}
