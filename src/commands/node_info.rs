//! `cipher-cli node-info` — Query TKS blockchain node status

use client_core::tks_rpc::TksRpcClient;
use colored::Colorize;

use crate::ui;

pub async fn run() -> Result<(), String> {
    let rpc = TksRpcClient::default();
    let endpoint = client_core::tks_rpc::local_rpc_http();
    let connected = rpc.is_connected();

    ui::title("TKS node");
    ui::section("RPC");
    ui::kv("Endpoint", &endpoint);
    if connected {
        ui::kv_ok("Connected", "yes");
    } else {
        ui::kv_err("Connected", "no");
        ui::blank();
        ui::section("Troubleshooting");
        ui::bullet("Node not running or still syncing");
        ui::bullet("Firewall blocking RPC port");
        ui::hint(format!("curl {endpoint}"));
        ui::blank();
        return Ok(());
    }

    ui::blank();
    ui::section("Chain");
    match rpc.chain_name() {
        Ok(name) => ui::kv("Name", name.cyan().to_string()),
        Err(e) => ui::kv_err("Name", e.to_string()),
    }
    match rpc.runtime_version() {
        Ok(v) => {
            ui::kv("Spec", format!("{} v{}", v.spec_name, v.spec_version));
            ui::kv("Tx version", v.transaction_version.to_string());
        }
        Err(e) => ui::kv_err("Runtime", e.to_string()),
    }
    match rpc.genesis_hash() {
        Ok(hash) => ui::kv_hint("Genesis", format!("0x{}", hex::encode(&hash))),
        Err(e) => ui::kv_err("Genesis", e.to_string()),
    }
    match rpc.best_block_number() {
        Ok(block) => ui::kv_ok("Best block", format!("#{block}")),
        Err(e) => ui::kv_err("Best block", e.to_string()),
    }

    ui::blank();
    ui::section("Name registry");
    match rpc.name_registry_pallet_index() {
        Ok(idx) => {
            ui::kv("Pallet index", idx.to_string());
            match rpc.total_registered_names() {
                Ok(total) => ui::kv("Registered names", total.to_string()),
                Err(_) => ui::kv_hint("Registered names", "n/a"),
            }
        }
        Err(_) => ui::kv_warn("Status", "pallet not in runtime"),
    }

    ui::blank();
    ui::section("Seed DNS");
    for (dns, region) in [
        ("seed.tokenkickstarter.com", "US"),
        ("seed.tkstoken.com", "EU"),
        ("seed.tksscan.com", "Asia"),
    ] {
        ui::bullet(format!("{dns} ({region})"));
    }
    ui::blank();
    Ok(())
}
