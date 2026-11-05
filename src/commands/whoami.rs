//! `cipher-cli whoami` — Display your identity information

use crate::identity_store;
use crate::ui;
use colored::Colorize;

pub async fn run() -> Result<(), String> {
    let identity = identity_store::get_identity()?;
    let pub_id = identity.public_identity();

    ui::title("Identity");
    ui::section("Addresses");
    ui::kv("EVM", pub_id.evm_address.white().bold().to_string());
    ui::kv("Substrate", pub_id.substrate_address);
    ui::kv_ok("Chat ID", pub_id.display_address);

    ui::blank();
    ui::section("Public keys");
    ui::kv_hint("Ed25519", hex::encode(&pub_id.ed25519_public));
    ui::kv_hint("X25519", hex::encode(&pub_id.x25519_public));
    ui::kv_hint("Sr25519", hex::encode(&pub_id.sr25519_public));
    ui::kv_hint("secp256k1", hex::encode(&pub_id.secp256k1_public));

    ui::blank();
    ui::hint(format!(
        "Share your {} to receive messages",
        "Chat ID".cyan()
    ));
    ui::blank();
    Ok(())
}
