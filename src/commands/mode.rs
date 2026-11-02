//! `cipher-cli mode` — View or set privacy transport mode (Direct, Tor, Nym)

use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub transport_mode: String,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            transport_mode: "direct".to_string(),
        }
    }
}

pub fn config_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".cipher").join("config.json")
}

pub fn load_config() -> CliConfig {
    let path = config_path();
    if let Ok(data) = fs::read_to_string(&path) {
        if let Ok(cfg) = serde_json::from_str::<CliConfig>(&data) {
            return cfg;
        }
    }
    CliConfig::default()
}

pub fn save_config(cfg: &CliConfig) -> Result<(), String> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let data = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    fs::write(&path, data).map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

pub async fn run(mode_arg: Option<&str>) -> Result<(), String> {
    let mut config = load_config();

    if let Some(new_mode) = mode_arg {
        let normalized = new_mode.to_lowercase().trim().to_string();
        match normalized.as_str() {
            "direct" | "iroh" | "tor" | "nym" | "front" | "domain-fronting" | "auto" => {
                config.transport_mode = match normalized.as_str() {
                    "front" => "domain-fronting".to_string(),
                    other => other.to_string(),
                };
                save_config(&config)?;
                println!();
                println!("  {} Privacy transport mode set to: {}", "✓".green(), config.transport_mode.cyan().bold());
                println!();
            }
            _ => {
                return Err("Invalid mode. Choose: direct, iroh, tor, nym, front, or auto".to_string());
            }
        }
    } else {
        println!();
        println!("{}", "══════════════════════════════════════════════════".cyan());
        println!("  {} {}", "🛡️".bold(), "CIPHER PRIVACY TRANSPORT STATUS".cyan().bold());
        println!("{}", "══════════════════════════════════════════════════".cyan());
        println!("  {} {}", "Current Mode:".dimmed(), config.transport_mode.cyan().bold());
        println!();
        println!("  {}", "Available Privacy Modes:".white().bold());
        println!("    {}    — Direct QUIC + Magicsock P2P (UDP hole punching, zero relay)", "• iroh  ".white().bold());
        println!("    {}  — Fast, direct connection to Storage Swarm (default)", "• direct".white().bold());
        println!("    {}     — Routes traffic through 3-hop onion circuit (IP hidden)", "• tor   ".white().bold());
        println!("    {}     — 5-hop decentralized mixnet with cover traffic (Metadata immune)", "• nym   ".white().bold());
        println!("    {}   — Circumvents firewalls via Cloudflare Workers", "• front ".white().bold());
        println!("    {}    — Automatically selects Iroh P2P → Nym → Tor → Direct fallback", "• auto  ".white().bold());
        println!();
        println!("  {} Run `cipher-cli mode <mode>` or `/mode <mode>` to switch", "💡".yellow());
        println!();
    }

    Ok(())
}

