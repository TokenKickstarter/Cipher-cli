//! `cipher-cli send-file` — Send an encrypted file to a recipient

use colored::Colorize;
use std::path::Path;
use std::sync::Arc;
use client_core::swarm_client::SwarmClient;
use crate::identity_store;

/// MIME type detection from file extension
fn guess_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        // Images
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "ico" => "image/x-icon",
        // Video
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        // Audio
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "aac" => "audio/aac",
        "m4a" => "audio/mp4",
        // Documents
        "pdf" => "application/pdf",
        "doc" | "docx" => "application/msword",
        "xls" | "xlsx" => "application/vnd.ms-excel",
        "ppt" | "pptx" => "application/vnd.ms-powerpoint",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "csv" => "text/csv",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        // Archives
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" | "tgz" => "application/gzip",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/x-rar-compressed",
        // Code
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" => "text/javascript",
        "ts" => "text/typescript",
        "dart" => "text/x-dart",
        "sol" => "text/x-solidity",
        // Default
        _ => "application/octet-stream",
    }
}

/// Format file size for display
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub async fn run(recipient: &str, file_path: &str) -> Result<(), String> {
    // Resolve @username → 0x address via TKS blockchain
    let recipient = super::resolve::resolve_recipient(recipient)?;

    let path = Path::new(file_path);

    // Validate file exists
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }
    if !path.is_file() {
        return Err(format!("Not a file: {}", file_path));
    }

    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let mime_type = guess_mime(path);
    let file_data = std::fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = file_data.len() as u64;

    // Show file info
    println!();
    println!("{}", "Preparing file transfer...".yellow());
    println!("  {} {}", "File:    ".dimmed(), file_name.white().bold());
    println!("  {} {}", "Size:    ".dimmed(), format_size(file_size).cyan());
    println!("  {} {}", "Type:    ".dimmed(), mime_type.white());
    println!("  {} {}", "Chunks:  ".dimmed(), format!("{} × 2MB", (file_size + 2_097_151) / 2_097_152).white());
    println!("  {} {}", "Encrypt: ".dimmed(), "AES-256-GCM per chunk ✓".green());
    println!();

    let identity = identity_store::get_identity()?;

    let our_addr = identity.evm_address();
    println!("{}", format!("Sending as {}...", our_addr).dimmed());

    let client = Arc::new(SwarmClient::new(identity));
    let client_clone = client.clone();
    client_clone.start_sync_daemon();

    // Wait for transport
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Send the file
    println!("{}", format!("Encrypting & sending '{}' to {}...", file_name, recipient).yellow());

    let (msg_id, metadata) = client
        .send_file(&recipient, &file_data, file_name, mime_type)
        .await
        .map_err(|e| format!("File send failed: {e}"))?;

    // Wait for relay flush
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!();
    println!("{}", "╔══════════════════════════════════════════════════╗".green().bold());
    println!("{}", "║          ✅ File Sent!                           ║".green().bold());
    println!("{}", "╚══════════════════════════════════════════════════╝".green().bold());
    println!();
    println!("  {} {}", "To:        ".dimmed(), recipient.cyan());
    println!("  {} {}", "File:      ".dimmed(), metadata.file_name.white().bold());
    println!("  {} {}", "Size:      ".dimmed(), format_size(metadata.size_bytes).white());
    println!("  {} {}", "MIME:      ".dimmed(), metadata.mime_type.white());
    println!("  {} {}", "Chunks:    ".dimmed(), format!("{}", metadata.total_chunks).white());
    println!("  {} {}", "Merkle:    ".dimmed(), hex::encode(&metadata.merkle_root[..8]).dimmed());
    println!("  {} {}", "Message ID:".dimmed(), msg_id.to_string().dimmed());
    println!("  {} {}", "Encrypted: ".dimmed(), "AES-256-GCM per chunk ✓".green());
    println!();

    Ok(())
}

/// Send a file using an existing SwarmClient (used by interactive shell).
pub async fn run_with_client(client: &Arc<SwarmClient>, recipient: &str, file_path: &str) -> Result<(), String> {
    use colored::Colorize;

    let path = std::path::Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {}", file_path));
    }

    let file_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let mime_type = guess_mime(path);
    let file_data = std::fs::read(path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = file_data.len() as u64;

    println!("  {} {} ({}, {})", "📎".yellow(), file_name.white().bold(), format_size(file_size).dimmed(), mime_type.dimmed());

    let (msg_id, metadata) = client
        .send_file(recipient, &file_data, file_name, mime_type)
        .await
        .map_err(|e| format!("File send failed: {e}"))?;

    // Wait for relay flush
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let time = chrono::Utc::now().format("%H:%M:%S");
    println!(
        "  {} {} 📎 {} {} {}",
        format!("[{}]", time).dimmed(),
        "▶".green().bold(),
        file_name.yellow(),
        format!("({})", format_size(metadata.size_bytes)).dimmed(),
        "✓".green(),
    );

    Ok(())
}
