//! `cipher-cli network` — federated relays (auto-refreshed from chain + discovery).

use colored::Colorize;
use client_core::network_bundle::{NetworkBundle, NetworkRefreshStats, RelayPool, SignalPool};
use indicatif::{ProgressBar, ProgressStyle};

use crate::ui;

pub async fn run(bundle_only: bool) -> Result<(), String> {
    let bundle = NetworkBundle::global();
    let pool = RelayPool::global();

    let stats = if bundle_only {
        NetworkRefreshStats::default()
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("  {spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Refreshing relays (TKS registry + /discovery)…");
        pb.enable_steady_tick(std::time::Duration::from_millis(80));

        let rpcs = bundle.rpc_http.clone();
        let s = pool.refresh_network(&rpcs).await;

        pb.finish_and_clear();
        s
    };

    let relays = pool.snapshot().await;
    let signals = SignalPool::global().ordered_urls().await;

    ui::title("Network");
    ui::section("Configuration");
    ui::kv("Bundle", &bundle.bundle_id);
    ui::kv("Bootstrap", format!("{} relay(s)", bundle.http_relays.len()));
    ui::kv("RPC endpoints", format!("{} URL(s)", bundle.rpc_http.len()));
    for rpc in &bundle.rpc_http {
        ui::bullet(rpc);
    }

    if !bundle_only {
        ui::blank();
        ui::section("Last refresh");
        ui::kv_ok("On-chain", format!("+{} from tks_listSwarmValidators", stats.chain_hints));
        ui::kv_ok("Discovery", format!("+{} from GET /discovery", stats.discovery_hints));
        ui::kv("Pool size", format!("{} relay(s), {} signal WS", stats.pool_size, stats.signal_pool_size));
    } else {
        ui::hint("Bundle-only mode — run without --bundle-only for live discovery");
    }

    ui::blank();
    ui::section("HTTP relay pool");
    if relays.is_empty() {
        ui::kv_warn("Relays", "(empty — check RPC and bundle)");
    } else {
        for (i, r) in relays.iter().enumerate() {
            ui::numbered(i + 1, r.cyan());
        }
    }

    ui::blank();
    ui::section("Signal WebSocket pool (RTT-ranked)");
    if signals.is_empty() {
        ui::kv_warn("Signal WS", "(empty — run a TKS node with relay + signal, or set bundle signal_ws)");
    } else {
        for (i, s) in signals.iter().enumerate() {
            ui::numbered(i + 1, s.cyan());
        }
    }

    ui::blank();
    Ok(())
}

/// After `start_sync_daemon`, wait for federated relay discovery and print an honest status line.
pub async fn print_connect_status(client: &std::sync::Arc<client_core::swarm_client::SwarmClient>) {
    let _ = client;
    let _stats = client_core::network_bundle::ensure_federated_pools().await;
    let pool = RelayPool::global();
    let relays = pool.snapshot().await;
    if relays.is_empty() {
        println!(
            "  {} No relay in pool — set {} or ensure RPC reaches mainnet",
            "!".yellow(),
            "CIPHER_NETWORK_BUNDLE".cyan()
        );
    } else {
        println!(
            "  {} Ready ({} HTTP relay(s); WS push optional)",
            "✓".green(),
            relays.len()
        );
    }
}
