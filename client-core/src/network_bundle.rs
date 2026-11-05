//! Federated network bootstrap — no single relay or RPC hostname in code paths.
//!
//! Override with `CIPHER_NETWORK_BUNDLE=/path/to/bundle.json`.
//! v1 bundles are unsigned; operators should ship multiple `http_relays` entries.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use log::{debug, info, warn};
use tokio::sync::Mutex;

use crate::error::CipherError;

static GLOBAL: OnceLock<Arc<NetworkBundle>> = OnceLock::new();
static GLOBAL_POOL: OnceLock<Arc<RelayPool>> = OnceLock::new();
static GLOBAL_SIGNAL_POOL: OnceLock<Arc<SignalPool>> = OnceLock::new();

/// Counts from the latest `refresh_network` (hints merged, not necessarily unique hosts).
#[derive(Debug, Clone, Default)]
pub struct NetworkRefreshStats {
    pub chain_hints: usize,
    pub discovery_hints: usize,
    pub pool_size: usize,
    pub signal_hints: usize,
    pub signal_pool_size: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkBundle {
    pub version: u32,
    pub bundle_id: String,
    #[serde(default)]
    pub http_relays: Vec<String>,
    #[serde(default)]
    pub signal_ws: Vec<String>,
    #[serde(default, rename = "rpc_http")]
    pub rpc_http: Vec<String>,
    #[serde(default)]
    pub iroh_relays: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ChainSwarmValidator {
    endpoint: String,
    #[serde(default)]
    active: bool,
}

impl NetworkBundle {
    pub fn load() -> Arc<Self> {
        if let Ok(path) = std::env::var("CIPHER_NETWORK_BUNDLE") {
            match Self::load_from_path(&path) {
                Ok(b) => {
                    info!("[Network] Loaded bundle from {path} ({})", b.bundle_id);
                    return Arc::new(b);
                }
                Err(e) => warn!("[Network] CIPHER_NETWORK_BUNDLE invalid: {e} — using embedded default"),
            }
        }
        match serde_json::from_str(include_str!("../network_bundle.default.json")) {
            Ok(b) => Arc::new(b),
            Err(e) => {
                warn!("[Network] Embedded bundle parse error: {e}");
                Arc::new(Self::fallback())
            }
        }
    }

    pub fn global() -> Arc<Self> {
        GLOBAL.get_or_init(Self::load).clone()
    }

    fn fallback() -> Self {
        Self {
            version: 1,
            bundle_id: "cipher-network-fallback-v1".into(),
            http_relays: vec![],
            signal_ws: vec![],
            rpc_http: vec!["http://127.0.0.1:9944".into()],
            iroh_relays: vec![],
            notes: Some("Federated-only: merge relays from chain + /discovery".into()),
        }
    }

    fn load_from_path(path: &str) -> Result<Self, CipherError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CipherError::Network(format!("read bundle {path}: {e}")))?;
        serde_json::from_str(&text)
            .map_err(|e| CipherError::Network(format!("parse bundle {path}: {e}")))
    }

    pub fn normalize_http_bases(urls: Vec<String>) -> Vec<String> {
        let mut out = Vec::new();
        for u in urls {
            let t = u.trim().trim_end_matches('/').to_string();
            if t.is_empty() || out.iter().any(|x| x == &t) {
                continue;
            }
            out.push(t);
        }
        out
    }

    pub fn primary_rpc(&self) -> String {
        self.rpc_http
            .first()
            .cloned()
            .unwrap_or_else(|| "http://127.0.0.1:9944".into())
    }
}

/// Derive federated signal WebSocket URL from HTTP relay base (same-host `/ws` pattern).
/// Shard ingest vhosts (e.g. `shard.example.com`, `:4010`) are not cipher mailboxes.
pub fn endpoint_is_mailbox_http(http: &str) -> bool {
    let h = http.trim().to_lowercase();
    if h.is_empty() {
        return false;
    }
    !(h.contains("shard.") || h.contains(":4010"))
}

/// POST `/fetch` response from a real cipher-relay (includes `Chunks`, even when empty).
pub fn fetch_response_is_mailbox_api(body: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    if v.get("Chunks").is_some() {
        return true;
    }
    if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
        return !err.eq_ignore_ascii_case("not found");
    }
    false
}

fn probe_mailbox_base_sync(base: &str) -> bool {
    if !endpoint_is_mailbox_http(base) {
        return false;
    }
    let url = format!("{}/fetch", base.trim_end_matches('/'));
    let body = r#"{"recipient_id":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
    match ureq::post(&url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_secs(3))
        .send_string(body)
    {
        Ok(resp) => fetch_response_is_mailbox_api(&resp.into_string().unwrap_or_default()),
        Err(_) => false,
    }
}

pub fn http_base_to_signal_ws(http: &str) -> Option<String> {
    let http = http.trim().trim_end_matches('/');
    if http.is_empty() {
        return None;
    }
    if let Some(rest) = http.strip_prefix("https://") {
        return Some(format!("wss://{rest}/ws"));
    }
    if let Some(rest) = http.strip_prefix("http://") {
        return Some(format!("ws://{rest}/ws"));
    }
    None
}

fn normalize_ws_urls(urls: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for u in urls {
        let t = u.trim().trim_end_matches('/').to_string();
        if t.is_empty() || out.iter().any(|x| x == &t) {
            continue;
        }
        out.push(t);
    }
    out
}

fn signal_ws_to_health_probe(ws: &str) -> Option<String> {
    let ws = ws.trim().trim_end_matches('/');
    if let Some(rest) = ws.strip_prefix("wss://") {
        let host = rest.strip_suffix("/ws").unwrap_or(rest);
        return Some(format!("https://{host}/health"));
    }
    if let Some(rest) = ws.strip_prefix("ws://") {
        let host = rest.strip_suffix("/ws").unwrap_or(rest);
        return Some(format!("http://{host}/health"));
    }
    None
}

/// Federated WebSocket signal endpoints (RTT-ranked for ~100ms delivery).
pub struct SignalPool {
    urls: tokio::sync::RwLock<Vec<String>>,
    ranked: tokio::sync::RwLock<Vec<String>>,
    last_rank: tokio::sync::RwLock<Option<Instant>>,
}

impl SignalPool {
    const RANK_INTERVAL: Duration = Duration::from_secs(120);

    fn new_from_bundle(bundle: &NetworkBundle) -> Self {
        let urls = normalize_ws_urls(bundle.signal_ws.clone());
        if !urls.is_empty() {
            info!("[SignalPool] {} bootstrap WebSocket(s)", urls.len());
        }
        Self {
            urls: tokio::sync::RwLock::new(urls),
            ranked: tokio::sync::RwLock::new(Vec::new()),
            last_rank: tokio::sync::RwLock::new(None),
        }
    }

    pub fn global() -> Arc<Self> {
        GLOBAL_SIGNAL_POOL
            .get_or_init(|| Arc::new(Self::new_from_bundle(&NetworkBundle::global())))
            .clone()
    }

    pub async fn merge_urls(&self, extra: Vec<String>) -> usize {
        let mut urls = self.urls.write().await;
        let mut added = 0usize;
        for u in normalize_ws_urls(extra) {
            if !urls.iter().any(|x| x == &u) {
                debug!("[SignalPool] +signal {}", u);
                urls.push(u);
                added += 1;
            }
        }
        added
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.urls.read().await.clone()
    }

    pub async fn len(&self) -> usize {
        self.urls.read().await.len()
    }

    /// Merge signal URLs from bundle, chain-derived HTTP bases, and GET /discovery.
    pub async fn refresh_from_network(&self, relay_pool: &RelayPool, rpc_http: &[String]) {
        let bundle = NetworkBundle::global();
        self.merge_urls(bundle.signal_ws.clone()).await;

        for http in relay_pool.snapshot().await {
            if !endpoint_is_mailbox_http(&http) {
                continue;
            }
            if let Some(ws) = http_base_to_signal_ws(&http) {
                self.merge_urls(vec![ws]).await;
            }
        }

        let mut from_disc = Vec::new();
        for (_base, body) in relay_pool.get_json_all("/discovery", 8).await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(ws) = v.get("self_signal_ws").and_then(|s| s.as_str()) {
                    if !ws.is_empty() {
                        from_disc.push(ws.to_string());
                    }
                }
                if let Some(arr) = v.get("relays").and_then(|r| r.as_array()) {
                    for item in arr {
                        if let Some(ws) = item.get("signal_ws").and_then(|s| s.as_str()) {
                            if !ws.is_empty() {
                                from_disc.push(ws.to_string());
                            }
                        }
                        if let Some(http) = item.get("http_base").and_then(|h| h.as_str()) {
                            if let Some(ws) = http_base_to_signal_ws(http) {
                                from_disc.push(ws);
                            }
                        }
                    }
                }
            }
        }

        let n = self.merge_urls(from_disc).await;
        if n > 0 {
            info!("[SignalPool] Discovery merged {n} signal hint(s)");
        }

        let _ = rpc_http;
        self.ensure_ranked().await;
    }

    async fn ensure_ranked(&self) {
        let stale = {
            let last = self.last_rank.read().await;
            last.map(|t| t.elapsed() > Self::RANK_INTERVAL)
                .unwrap_or(true)
        };
        if !stale {
            return;
        }
        let urls = self.urls.read().await.clone();
        if urls.is_empty() {
            return;
        }

        let mut scored: Vec<(u64, String)> = Vec::new();
        for url in urls {
            let probe = signal_ws_to_health_probe(&url);
            let ms = if let Some(health) = probe {
                let health = health.clone();
                let start = Instant::now();
                let ok = tokio::task::spawn_blocking(move || {
                    ureq::get(&health)
                        .timeout(Duration::from_secs(2))
                        .call()
                        .is_ok()
                })
                .await
                .unwrap_or(false);
                if ok {
                    start.elapsed().as_millis() as u64
                } else {
                    u64::MAX / 2
                }
            } else {
                u64::MAX / 2
            };
            scored.push((ms, url));
        }
        scored.sort_by_key(|(ms, _)| *ms);
        let ordered: Vec<String> = scored.into_iter().map(|(_, u)| u).collect();
        *self.ranked.write().await = ordered;
        *self.last_rank.write().await = Some(Instant::now());
    }

    /// RTT-ranked WebSocket bases (lowest latency first).
    pub async fn ordered_urls(&self) -> Vec<String> {
        self.ensure_ranked().await;
        let ranked = self.ranked.read().await.clone();
        if !ranked.is_empty() {
            return ranked;
        }
        self.urls.read().await.clone()
    }
}

/// Mutable pool of HTTP relay bases (store/fetch/ack + discovery).
pub struct RelayPool {
    bases: tokio::sync::RwLock<Vec<String>>,
    last_refresh: tokio::sync::RwLock<Option<Instant>>,
    refresh_lock: Mutex<()>,
}

impl RelayPool {
    const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

    fn new_from_bundle(bundle: &NetworkBundle) -> Self {
        let bases = NetworkBundle::normalize_http_bases(bundle.http_relays.clone());
        if bases.is_empty() {
            warn!("[RelayPool] Bundle has zero http_relays — messaging will fail until discovery runs");
        } else {
            info!(
                "[RelayPool] {} bootstrap HTTP relay(s): {}",
                bases.len(),
                bases.join(", ")
            );
        }
        Self {
            bases: tokio::sync::RwLock::new(bases),
            last_refresh: tokio::sync::RwLock::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    /// Process-wide relay pool (bundle bootstrap + merged discovery).
    pub fn global() -> Arc<Self> {
        GLOBAL_POOL
            .get_or_init(|| Arc::new(Self::new_from_bundle(&NetworkBundle::global())))
            .clone()
    }

    /// Independent pool (tests / custom bundles).
    pub fn from_bundle(bundle: &NetworkBundle) -> Arc<Self> {
        Arc::new(Self::new_from_bundle(bundle))
    }

    /// Refresh if never refreshed or older than [`Self::REFRESH_INTERVAL`].
    pub async fn ensure_fresh(&self, rpc_http: &[String]) {
        let stale = {
            let last = self.last_refresh.read().await;
            last.map(|t| t.elapsed() > Self::REFRESH_INTERVAL)
                .unwrap_or(true)
        };
        if !stale {
            return;
        }
        let _guard = self.refresh_lock.lock().await;
        let still_stale = {
            let last = self.last_refresh.read().await;
            last.map(|t| t.elapsed() > Self::REFRESH_INTERVAL)
                .unwrap_or(true)
        };
        if still_stale {
            self.refresh_network_unlocked(rpc_http).await;
        }
    }

    /// Background refresh every 5 minutes (call once from transport startup).
    pub fn spawn_periodic_refresh(self: &Arc<Self>, rpc_http: Vec<String>) {
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Self::REFRESH_INTERVAL);
            tick.tick().await;
            loop {
                tick.tick().await;
                info!("[RelayPool] Periodic federated refresh");
                pool.refresh_network(&rpc_http).await;
            }
        });
    }

    pub async fn merge_bases(&self, extra: Vec<String>) -> usize {
        let mut bases = self.bases.write().await;
        let mut added = 0usize;
        for u in NetworkBundle::normalize_http_bases(extra) {
            if !endpoint_is_mailbox_http(&u) {
                debug!("[RelayPool] skip shard/non-mailbox {}", u);
                continue;
            }
            if !bases.iter().any(|x| x == &u) {
                debug!("[RelayPool] +relay {}", u);
                bases.push(u);
                added += 1;
            }
        }
        added
    }

    pub async fn snapshot(&self) -> Vec<String> {
        self.bases.read().await.clone()
    }

    pub async fn len(&self) -> usize {
        self.bases.read().await.len()
    }

    pub async fn post_to_base(
        base: &str,
        path: &str,
        body: String,
        timeout_secs: u64,
    ) -> Option<String> {
        let url = format!("{}{path}", base.trim_end_matches('/'));
        let result = tokio::task::spawn_blocking(move || {
            ureq::post(&url)
                .set("Content-Type", "application/json")
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .send_string(&body)
        })
        .await;

        match result {
            Ok(Ok(resp)) => resp.into_string().ok(),
            _ => None,
        }
    }

    /// POST JSON to `{base}{path}`; try each base until one succeeds.
    pub async fn post_json_failover(
        &self,
        path: &str,
        body: String,
        timeout_secs: u64,
    ) -> Option<(String, String)> {
        let rpcs = NetworkBundle::global().rpc_http.clone();
        self.ensure_fresh(&rpcs).await;
        let bases = self.ranked_mailbox_bases().await;
        for base in bases {
            let url = format!("{base}{path}");
            let body_clone = body.clone();
            let post_url = url.clone();
            let result = tokio::task::spawn_blocking(move || {
                ureq::post(&post_url)
                    .set("Content-Type", "application/json")
                    .timeout(std::time::Duration::from_secs(timeout_secs))
                    .send_string(&body_clone)
            })
            .await;

            match result {
                Ok(Ok(resp)) => {
                    let text = resp.into_string().unwrap_or_default();
                    return Some((base, text));
                }
                Ok(Err(e)) => {
                    debug!("[RelayPool] POST {url} failed: {e}");
                }
                Err(e) => {
                    debug!("[RelayPool] POST task error for {url}: {e}");
                }
            }
        }
        None
    }

    /// GET `{base}{path}` from each relay; returns all successful bodies.
    pub async fn get_json_all(&self, path: &str, timeout_secs: u64) -> Vec<(String, String)> {
        let bases = self.bases.read().await.clone();
        let mut out = Vec::new();
        for base in bases {
            let url = format!("{base}{path}");
            let result = tokio::task::spawn_blocking(move || {
                ureq::get(&url)
                    .timeout(std::time::Duration::from_secs(timeout_secs))
                    .call()
            })
            .await;

            if let Ok(Ok(resp)) = result {
                if let Ok(text) = resp.into_string() {
                    out.push((base, text));
                }
            }
        }
        out
    }

    /// Map on-chain `endpoint` (HTTPS URL or libp2p multiaddr) to Cipher HTTP relay base.
    pub fn endpoint_to_http_relay(endpoint: &str) -> Option<String> {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            return None;
        }
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            return Some(endpoint.trim_end_matches('/').to_string());
        }
        // /ip4/1.2.3.4/tcp/4002 → http://1.2.3.4:4002 (cipher-relay default port)
        let parts: Vec<&str> = endpoint.split('/').filter(|s| !s.is_empty()).collect();
        let mut ip = None;
        let mut port = "4002";
        let mut i = 0;
        while i < parts.len() {
            match parts[i] {
                "ip4" | "ip6" if i + 1 < parts.len() => {
                    ip = Some(parts[i + 1]);
                    i += 2;
                }
                "tcp" if i + 1 < parts.len() => {
                    port = parts[i + 1];
                    i += 2;
                }
                _ => i += 1,
            }
        }
        ip.map(|host| format!("http://{host}:{port}"))
    }

    /// Merge relay bases from `tks_listSwarmValidators` on any reachable TKS RPC.
    async fn refresh_from_chain(&self, rpc_http: &[String]) -> usize {
        let mut found = Vec::new();
        for rpc in rpc_http {
            let rpc = rpc.trim().trim_end_matches('/');
            if rpc.is_empty() {
                continue;
            }
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "tks_listSwarmValidators",
                "params": [],
                "id": 1
            })
            .to_string();
            let rpc_owned = rpc.to_string();
            let result = tokio::task::spawn_blocking(move || {
                ureq::post(&rpc_owned)
                    .set("Content-Type", "application/json")
                    .timeout(std::time::Duration::from_secs(12))
                    .send_string(&body)
            })
            .await;

            let Ok(Ok(resp)) = result else {
                debug!("[RelayPool] tks_listSwarmValidators failed on {rpc}");
                continue;
            };
            let Ok(text) = resp.into_string() else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            let Some(arr) = v.get("result").and_then(|r| r.as_array()) else {
                continue;
            };
            for item in arr {
                let Ok(val) = serde_json::from_value::<ChainSwarmValidator>(item.clone()) else {
                    continue;
                };
                if !val.active {
                    continue;
                }
                if let Some(http) = Self::endpoint_to_http_relay(&val.endpoint) {
                    if endpoint_is_mailbox_http(&http) {
                        found.push(http);
                    }
                }
            }
        }
        let n = found.len();
        if !found.is_empty() {
            info!(
                "[RelayPool] On-chain registry merged {} relay hint(s)",
                n
            );
            self.merge_bases(found).await;
        }
        n
    }

    /// Chain registry + HTTP `/discovery` on all known relays.
    pub async fn refresh_network(&self, rpc_http: &[String]) -> NetworkRefreshStats {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_network_unlocked(rpc_http).await
    }

    async fn refresh_network_unlocked(&self, rpc_http: &[String]) -> NetworkRefreshStats {
        let chain_hints = self.refresh_from_chain(rpc_http).await;
        let discovery_hints = self.refresh_from_discovery().await;
        *self.last_refresh.write().await = Some(Instant::now());
        let pool_size = self.len().await;

        let signal_pool = SignalPool::global();
        let before = signal_pool.len().await;
        signal_pool.refresh_from_network(self, rpc_http).await;
        let signal_pool_size = signal_pool.len().await;
        let signal_hints = signal_pool_size.saturating_sub(before);

        NetworkRefreshStats {
            chain_hints,
            discovery_hints,
            pool_size,
            signal_hints,
            signal_pool_size,
        }
    }

    /// Mailbox-capable relay bases (excludes shard ingest), RTT-ranked via fast `/fetch` probe.
    pub async fn ranked_mailbox_bases(&self) -> Vec<String> {
        let bases: Vec<String> = self
            .snapshot()
            .await
            .into_iter()
            .filter(|b| endpoint_is_mailbox_http(b))
            .collect();
        if bases.is_empty() {
            return bases;
        }
        if bases.len() == 1 {
            return bases;
        }
        let mut scored: Vec<(u64, String)> = Vec::new();
        for base in bases {
            let b = base.clone();
            let start = Instant::now();
            let ok = tokio::task::spawn_blocking(move || probe_mailbox_base_sync(&b))
                .await
                .unwrap_or(false);
            let ms = if ok {
                start.elapsed().as_millis() as u64
            } else {
                u64::MAX / 2
            };
            scored.push((ms, base));
        }
        scored.sort_by_key(|(ms, _)| *ms);
        scored.into_iter().map(|(_, b)| b).collect()
    }

    /// Parallel POST `/fetch` on all mailbox relays (3s each); returns successful responses.
    pub async fn post_fetch_parallel(
        &self,
        body: String,
        timeout_secs: u64,
    ) -> Vec<(String, String)> {
        let rpcs = NetworkBundle::global().rpc_http.clone();
        self.ensure_fresh(&rpcs).await;
        let bases = self.ranked_mailbox_bases().await;
        let mut handles = Vec::new();
        for base in bases {
            let body = body.clone();
            handles.push(tokio::spawn(async move {
                let text = Self::post_to_base(&base, "/fetch", body, timeout_secs).await?;
                if fetch_response_is_mailbox_api(&text) {
                    Some((base, text))
                } else {
                    None
                }
            }));
        }
        let mut out = Vec::new();
        for h in handles {
            if let Ok(Some(pair)) = h.await {
                out.push(pair);
            }
        }
        out
    }

    /// Pull extra relay URLs from `GET /discovery` on known peers (TKS cipher-relay format).
    async fn refresh_from_discovery(&self) -> usize {
        let responses = self.get_json_all("/discovery", 12).await;
        let mut found = Vec::new();
        for (_base, body) in responses {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(arr) = v.get("relays").and_then(|r| r.as_array()) {
                    for item in arr {
                        if let Some(http) = item.get("http_base").and_then(|h| h.as_str()) {
                            if http.is_empty() {
                                continue;
                            }
                            let mailbox = item
                                .get("message_relay")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(true);
                            if mailbox && endpoint_is_mailbox_http(http) {
                                found.push(http.to_string());
                            }
                        }
                    }
                }
            }
        }
        let n = found.len();
        if !found.is_empty() {
            info!(
                "[RelayPool] Discovery merged {} relay hint(s)",
                n
            );
            self.merge_bases(found).await;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::RelayPool;

    #[test]
    fn fetch_response_detects_mailbox_vs_shard() {
        assert!(super::fetch_response_is_mailbox_api(r#"{"Chunks":[]}"#));
        assert!(!super::fetch_response_is_mailbox_api(r#"{"error":"not found"}"#));
    }

    #[test]
    fn endpoint_is_mailbox_http_excludes_shard_hosts() {
        assert!(!super::endpoint_is_mailbox_http("https://shard.tokenkickstarter.com"));
        assert!(super::endpoint_is_mailbox_http("https://relay.tokenkickstarter.com"));
    }

    #[test]
    fn endpoint_to_http_relay_parses_https_and_multiaddr() {
        assert_eq!(
            RelayPool::endpoint_to_http_relay("https://relay.example.com/"),
            Some("https://relay.example.com".into())
        );
        assert_eq!(
            RelayPool::endpoint_to_http_relay("/ip4/203.0.113.10/tcp/4002"),
            Some("http://203.0.113.10:4002".into())
        );
        assert!(RelayPool::endpoint_to_http_relay("").is_none());
    }
}
