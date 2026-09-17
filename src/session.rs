//! # Session Manager
//!
//! Provides `cipher-cli login` / `cipher-cli logout` for session-based auth.
//! After login, the decrypted identity is cached (encrypted with an ephemeral
//! key) in `~/.cipher/session` so subsequent commands don't need a password.
//!
//! Session expires after 4 hours by default.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use client_core::identity::CipherIdentity;

/// Session TTL: 4 hours in seconds
const SESSION_TTL_SECS: u64 = 4 * 60 * 60;

/// Session file stored alongside the identity
#[derive(Serialize, Deserialize)]
struct SessionFile {
    /// AES-256-GCM encrypted mnemonic
    ciphertext: Vec<u8>,
    /// Nonce for decryption
    nonce: [u8; 12],
    /// Ephemeral key (stored in the file — security is from file permissions, not secrecy)
    /// This is acceptable because:
    ///   1. The session file has 0600 permissions (owner-only)
    ///   2. It auto-expires after 4 hours
    ///   3. `cipher-cli logout` destroys it immediately
    ephemeral_key: [u8; 32],
    /// Unix timestamp when the session was created
    created_at: u64,
    /// EVM address (for display without decryption)
    address: String,
}

/// Path to the session file
fn session_path() -> PathBuf {
    let home = dirs::home_dir().expect("Could not determine home directory");
    home.join(".cipher").join("session")
}

/// Create a new session from a CipherIdentity.
/// The mnemonic is encrypted with an ephemeral key and stored in `~/.cipher/session`.
pub fn create_session(identity: &CipherIdentity) -> Result<(), String> {
    let path = session_path();

    // Generate ephemeral key
    let mut ephemeral_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_key);

    // Encrypt mnemonic
    let cipher = Aes256Gcm::new_from_slice(&ephemeral_key)
        .map_err(|e| format!("AES init failed: {e}"))?;
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce_bytes, identity.mnemonic().as_bytes())
        .map_err(|e| format!("Encryption failed: {e}"))?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let session = SessionFile {
        ciphertext,
        nonce,
        ephemeral_key,
        created_at: now,
        address: identity.evm_address(),
    };

    let json = serde_json::to_string_pretty(&session)
        .map_err(|e| format!("Serialization failed: {e}"))?;

    std::fs::write(&path, json)
        .map_err(|e| format!("Failed to write session: {e}"))?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set session permissions: {e}"))?;
    }

    Ok(())
}

/// Load identity from an active session (if one exists and hasn't expired).
pub fn load_from_session() -> Result<CipherIdentity, String> {
    let path = session_path();

    if !path.exists() {
        return Err("No active session. Run `cipher-cli login` first.".to_string());
    }

    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read session: {e}"))?;

    let session: SessionFile = serde_json::from_str(&data)
        .map_err(|e| format!("Invalid session file: {e}"))?;

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now - session.created_at > SESSION_TTL_SECS {
        // Session expired — clean up
        let _ = std::fs::remove_file(&path);
        return Err("Session expired. Run `cipher-cli login` to re-authenticate.".to_string());
    }

    // Decrypt mnemonic
    let cipher = Aes256Gcm::new_from_slice(&session.ephemeral_key)
        .map_err(|e| format!("AES init failed: {e}"))?;
    let nonce = Nonce::from_slice(&session.nonce);
    let plaintext = cipher
        .decrypt(nonce, session.ciphertext.as_ref())
        .map_err(|_| "Session corrupted. Run `cipher-cli login` again.".to_string())?;

    let mnemonic = String::from_utf8(plaintext)
        .map_err(|_| "Session data corrupted.".to_string())?;

    CipherIdentity::from_mnemonic(&mnemonic)
        .map_err(|e| format!("Failed to restore identity: {e}"))
}

/// Destroy the active session.
pub fn destroy_session() -> Result<(), String> {
    let path = session_path();
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to remove session: {e}"))?;
    }
    Ok(())
}

/// Check if a valid (non-expired) session exists.
pub fn is_session_active() -> bool {
    let path = session_path();
    if !path.exists() {
        return false;
    }

    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(session) = serde_json::from_str::<SessionFile>(&data) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            return now - session.created_at <= SESSION_TTL_SECS;
        }
    }

    false
}

/// Get the session address without decrypting (for display purposes).
pub fn session_address() -> Option<String> {
    let path = session_path();
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(session) = serde_json::from_str::<SessionFile>(&data) {
            return Some(session.address);
        }
    }
    None
}

/// How many seconds remain in the current session.
pub fn session_remaining_secs() -> Option<u64> {
    let path = session_path();
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(session) = serde_json::from_str::<SessionFile>(&data) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let elapsed = now - session.created_at;
            if elapsed < SESSION_TTL_SECS {
                return Some(SESSION_TTL_SECS - elapsed);
            }
        }
    }
    None
}
