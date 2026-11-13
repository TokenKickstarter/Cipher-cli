//! `cipher-cli status` — identity, transport, and federated network snapshot.

use client_core::network_bundle::{NetworkBundle, RelayPool};
use colored::Colorize;
use std::sync::Arc;

use crate::identity_store;
use crate::ui;

pub async fn run() -> Result<(), String> {
    let identity = identity_store::get_identity()?;
    let our_addr = identity.evm_address();

    let client = Arc::new(crate::commands::mode::create_swarm_client(identity));
    let bundle = NetworkBundle::global();
    let pool = RelayPool::global();
    pool.ensure_fresh(&bundle.rpc_http).await;
    let relays = pool.snapshot().await;

    let transport_name = client.transport.active_transport_name().await;
    let mode = client.transport.get_mode().await;
    let total_unread = client.total_unread().await;
    let contacts = client.conversation_list().await;

    ui::title("Status");

    ui::section("Identity");
    ui::kv("Address", our_addr.cyan().to_string());
    ui::kv_hint("Keystore", identity_store::identity_path().display().to_string());

    ui::blank();
    ui::section("Transport");
    ui::kv("Mode", format!("{mode}"));
    ui::kv_ok("Active", transport_name);
    ui::kv("Encryption", "AES-256-GCM · Double Ratchet".to_string());

    ui::blank();
    ui::section("Network");
    ui::kv("Bundle", &bundle.bundle_id);
    ui::kv("Relays", format!("{} in pool", relays.len()));
    if relays.len() <= 4 {
        for (i, r) in relays.iter().enumerate() {
            ui::numbered(i + 1, r);
        }
    } else {
        for r in relays.iter().take(3) {
            ui::bullet(r);
        }
        ui::hint(format!("… and {} more — `cipher-cli network`", relays.len() - 3));
    }
    ui::kv_hint("RPC", bundle.primary_rpc());

    ui::blank();
    ui::section("Inbox");
    ui::kv("Contacts", contacts.len().to_string());
    if total_unread > 0 {
        ui::kv_warn("Unread", total_unread.to_string());
    } else {
        ui::kv("Unread", "0");
    }

    ui::blank();
    Ok(())
}
