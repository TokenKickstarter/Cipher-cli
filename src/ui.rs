//! Shared terminal layout for cipher-cli commands.

use colored::Colorize;
use std::fmt::Display;

pub const INNER: usize = 50;

pub fn blank() {
    println!();
}

/// Top-of-command title bar (no outer banner — main.rs prints session header).
pub fn title(text: &str) {
    blank();
    let line = format!(" {text} ");
    let pad = INNER.saturating_sub(line.len());
    println!(
        "  {}{}{}",
        "─".repeat(1),
        line.cyan().bold(),
        "─".repeat(pad)
    );
}

pub fn section(name: &str) {
    println!("  {}", name.green().bold());
}

pub fn kv(label: &str, value: impl Display) {
    println!("    {:<16} {}", label.dimmed(), value);
}

pub fn kv_hint(label: &str, value: impl Display) {
    println!("    {:<16} {}", label.dimmed(), value.to_string().dimmed());
}

pub fn kv_ok(label: &str, value: impl Display) {
    println!("    {:<16} {}", label.dimmed(), value.to_string().green());
}

pub fn kv_warn(label: &str, value: impl Display) {
    println!("    {:<16} {}", label.dimmed(), value.to_string().yellow());
}

pub fn kv_err(label: &str, value: impl Display) {
    println!("    {:<16} {}", label.dimmed(), value.to_string().red());
}

pub fn bullet(text: impl Display) {
    println!("    {} {}", "•".dimmed(), text);
}

pub fn numbered(i: usize, text: impl Display) {
    println!("    {:>2}. {}", i, text);
}

pub fn hint(text: impl Display) {
    println!("  {} {}", "→".cyan(), text.to_string().dimmed());
}

/// Sanitize a sender-supplied attachment filename to stay strictly inside the downloads folder.
pub fn sanitize_attachment_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c == '\0' || c.is_control() || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.');
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "cipher-attachment.bin".to_string();
    }
    trimmed.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::sanitize_attachment_filename;

    #[test]
    fn sanitizes_traversal_dotfiles_and_control_chars() {
        assert_eq!(
            sanitize_attachment_filename("../../../../.ssh/authorized_keys"),
            "authorized_keys"
        );
        assert_eq!(sanitize_attachment_filename(".."), "cipher-attachment.bin");
        assert_eq!(sanitize_attachment_filename("."), "cipher-attachment.bin");
        assert_eq!(sanitize_attachment_filename(".bashrc"), "bashrc");
        assert_eq!(sanitize_attachment_filename("a\0b\nc.txt"), "a_b_c.txt");
        assert_eq!(
            sanitize_attachment_filename(r"C:\evil\payload.exe"),
            "payload.exe"
        );
        assert_eq!(sanitize_attachment_filename("report.pdf"), "report.pdf");
    }
}
