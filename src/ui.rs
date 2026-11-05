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
