//! # Identity Store
//!
//! Persists Cipher identity to disk with password-based encryption.
//! Stored at `~/.cipher/identity.json` as AES-256-GCM encrypted data.

use colored::Colorize;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use client_core::identity::CipherIdentity;

/// Encrypted identity file format
#[derive(Serialize, Deserialize)]
struct EncryptedIdentity {
    /// AES-256-GCM encrypted seed phrase
    ciphertext: Vec<u8>,
    /// Nonce used for encryption
    nonce: [u8; 12],
    /// Salt for password key derivation
    salt: [u8; 32],
    /// Version marker for future migration
    version: u32,
}

/// Get the identity file path (~/.cipher/identity.json)
pub fn identity_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".cipher").join("identity.json")
}

/// Check if an identity file already exists
pub fn identity_exists() -> bool {
    identity_path().exists()
}

/// Derive a 32-byte encryption key from a password + salt using SHA-256
/// (lightweight; for a CLI tool this is acceptable — production would use Argon2/scrypt)
fn derive_key(password: &str, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hasher.update(b"cipher-cli-identity-v1");
    // Multiple rounds for basic stretching
    let mut key = hasher.finalize();
    for _ in 0..10_000 {
        let mut h = Sha256::new();
        h.update(&key);
        h.update(salt);
        key = h.finalize();
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&key);
    result
}

/// Save a CipherIdentity to disk, encrypted with the given password.
pub fn save_identity(identity: &CipherIdentity, password: &str) -> Result<(), String> {
    let path = identity_path();

    // Create directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create ~/.cipher directory: {e}"))?;
    }

    // Generate random salt
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive encryption key from password
    let key = derive_key(password, &salt);

    // Encrypt the seed phrase
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES init failed: {e}"))?;
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce_bytes, identity.mnemonic().as_bytes())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let encrypted = EncryptedIdentity {
        ciphertext,
        nonce,
        salt,
        version: 1,
    };

    let json = serde_json::to_string_pretty(&encrypted)
        .map_err(|e| format!("Serialization failed: {e}"))?;

    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write identity file: {e}"))?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set file permissions: {e}"))?;
    }

    Ok(())
}

/// Load a CipherIdentity from disk, decrypting with the given password.
pub fn load_identity(password: &str) -> Result<CipherIdentity, String> {
    let path = identity_path();

    if !path.exists() {
        return Err("No identity found. Run `cipher-cli init` first.".to_string());
    }

    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read identity file: {e}"))?;

    let encrypted: EncryptedIdentity = serde_json::from_str(&data)
        .map_err(|e| format!("Invalid identity file format: {e}"))?;

    // Derive key from password + stored salt
    let key = derive_key(password, &encrypted.salt);

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES init failed: {e}"))?;
    let nonce = Nonce::from_slice(&encrypted.nonce);
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| "Wrong password or corrupted identity file.".to_string())?;

    let mnemonic = String::from_utf8(plaintext)
        .map_err(|_| "Decrypted data is not valid UTF-8".to_string())?;

    CipherIdentity::from_mnemonic(&mnemonic)
        .map_err(|e| format!("Failed to restore identity: {e}"))
}

/// Prompt for a password from stdin (hides input)
pub fn prompt_password(prompt: &str) -> String {
    rpassword::prompt_password_stderr(prompt).unwrap_or_default()
}

/// Prompt for a new password with confirmation
pub fn prompt_new_password() -> Result<String, String> {
    let p1 = prompt_password("🔑 Set a password to encrypt your identity: ");
    if p1.is_empty() {
        return Err("Password cannot be empty.".to_string());
    }
    let p2 = prompt_password("🔑 Confirm password: ");
    if p1 != p2 {
        return Err("Passwords do not match.".to_string());
    }
    Ok(p1)
}

/// Smart identity loader: tries session first, falls back to password prompt.
/// This is the primary entry point for all commands that need an identity.
pub fn get_identity() -> Result<CipherIdentity, String> {
    // 1. Try loading from active session
    if crate::session::is_session_active() {
        match crate::session::load_from_session() {
            Ok(identity) => return Ok(identity),
            Err(_) => {
                // Session corrupted, fall through to password
            }
        }
    }

    // 2. No session — prompt for password
    let password = prompt_password("🔑 Password: ");
    let identity = load_identity(&password)?;

    // 3. Auto-create session so they don't need password again
    if let Err(e) = crate::session::create_session(&identity) {
        eprintln!("  {} {}", "⚠".yellow(), format!("Could not create session: {e}").dimmed());
    }

    Ok(identity)
}

