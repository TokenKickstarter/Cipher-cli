//! `cipher-cli node-info` — Query TKS blockchain node status

use colored::Colorize;
use client_core::tks_rpc::TksRpcClient;

pub async fn run() -> Result<(), String> {
    println!();
    println!("{}", "Connecting to TKS blockchain node...".yellow());

    let rpc = TksRpcClient::default();
    let endpoint = client_core::tks_rpc::LOCAL_RPC_HTTP;

    // Check connectivity
    let connected = rpc.is_connected();

    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".cyan().bold());
    println!("{}", "║           TKS Blockchain Node Info               ║".cyan().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".cyan().bold());
    println!();

    println!("  {} {}", "RPC Endpoint:".dimmed(), endpoint.white());
    println!("  {} {}", "Connected:   ".dimmed(), if connected { "✅ Yes".green().to_string() } else { "❌ No".red().to_string() });
    println!();

    if !connected {
        println!("  {} TKS node is not reachable. It may be:", "⚠️ ".yellow());
        println!("    {} Not running on the VPS", "•".dimmed());
        println!("    {} Firewall blocking port 9944", "•".dimmed());
        println!("    {} Node syncing — try again later", "•".dimmed());
        println!();
        println!("  {} Check with: {}", "💡".green(), "curl https://rpc.tokenkickstarter.com".dimmed());
        println!();
        return Ok(());
    }

    // Chain name
    match rpc.chain_name() {
        Ok(name) => println!("  {} {}", "Chain:       ".dimmed(), name.cyan().bold()),
        Err(e) => println!("  {} {}", "Chain:       ".dimmed(), format!("Error: {}", e).red()),
    }

    // Runtime version
    match rpc.runtime_version() {
        Ok(version) => {
            println!("  {} {}", "Spec Name:   ".dimmed(), version.spec_name.white());
            println!("  {} {}", "Spec Version:".dimmed(), version.spec_version.to_string().white());
            println!("  {} {}", "Tx Version:  ".dimmed(), version.transaction_version.to_string().white());
        }
        Err(e) => println!("  {} {}", "Runtime:     ".dimmed(), format!("Error: {}", e).red()),
    }

    // Genesis hash
    match rpc.genesis_hash() {
        Ok(hash) => {
            let hash_hex = format!("0x{}", hex::encode(&hash));
            println!("  {} {}", "Genesis Hash:".dimmed(), hash_hex.dimmed());
        }
        Err(e) => println!("  {} {}", "Genesis:     ".dimmed(), format!("Error: {}", e).red()),
    }

    // Best block
    match rpc.best_block_number() {
        Ok(block) => println!("  {} #{}", "Best Block:  ".dimmed(), block.to_string().green().bold()),
        Err(e) => println!("  {} {}", "Best Block:  ".dimmed(), format!("Error: {}", e).red()),
    }

    // NameRegistry pallet
    println!();
    println!("{}", "  NameRegistry Pallet:".green().bold());
    match rpc.name_registry_pallet_index() {
        Ok(idx) => {
            println!("  {} {}", "Pallet Index:".dimmed(), idx.to_string().white());
            // Total registered names
            match rpc.total_registered_names() {
                Ok(total) => println!("  {} {}", "Total Names: ".dimmed(), total.to_string().cyan().bold()),
                Err(_) => println!("  {} {}", "Total Names: ".dimmed(), "N/A".dimmed()),
            }
        }
        Err(_) => {
            println!("  {} {}", "Status:      ".dimmed(), "Not found in runtime".yellow());
        }
    }

    println!();

    // DNS Seed Nodes
    println!("{}", "  Seed Nodes:".green().bold());
    let seeds = [
        ("seed.tokenkickstarter.com", "US"),
        ("seed.tkstoken.com", "EU"),
        ("seed.tksscan.com", "Asia"),
    ];
    for (dns, region) in &seeds {
        println!("  {} {} ({})", "•".dimmed(), dns.white(), region.dimmed());
    }
    println!();

    Ok(())
}
