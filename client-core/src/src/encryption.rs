//! # Encryption Module
//!
//! End-to-end encryption for Cipher messages:
//! - X3DH handshake (initial key agreement)
//! - Double Ratchet (per-message forward secrecy)
//! - AES-256-GCM (authenticated symmetric encryption)
//! - HKDF-SHA-256 (key derivation)

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::Zeroize;

use crate::error::CipherError;

type HmacSha256 = Hmac<Sha256>;

// ─────────────────────────────────────────────────────────
// AES-256-GCM Symmetric Encryption
// ─────────────────────────────────────────────────────────

/// Encrypted message with nonce for AES-256-GCM decryption.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

/// Encrypt plaintext with AES-256-GCM.
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedMessage, CipherError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CipherError::Encryption(format!("AES key init failed: {e}")))?;

    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce_bytes, plaintext)
        .map_err(|e| CipherError::Encryption(format!("AES encrypt failed: {e}")))?;

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_bytes);

    Ok(EncryptedMessage { ciphertext, nonce })
}

/// Decrypt ciphertext with AES-256-GCM.
pub fn aes_decrypt(key: &[u8; 32], msg: &EncryptedMessage) -> Result<Vec<u8>, CipherError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CipherError::Encryption(format!("AES key init failed: {e}")))?;

    let nonce = Nonce::from_slice(&msg.nonce);
    cipher
        .decrypt(nonce, msg.ciphertext.as_ref())
        .map_err(|e| CipherError::Encryption(format!("AES decrypt failed: {e}")))
}

// ─────────────────────────────────────────────────────────
// HKDF Key Derivation
// ─────────────────────────────────────────────────────────

/// Derive a 32-byte key using HKDF-SHA-256.
pub fn hkdf_derive(input: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 32], CipherError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), input);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|e| CipherError::Encryption(format!("HKDF expand failed: {e}")))?;
    Ok(okm)
}

// ─────────────────────────────────────────────────────────
// X3DH Key Agreement
// ─────────────────────────────────────────────────────────

/// Prekey bundle published by a user (stored on swarm for offline handshakes).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrekeyBundle {
    /// Identity key (long-term X25519 public)
    pub identity_key: [u8; 32],
    /// Signed prekey (medium-term, rotated periodically)
    pub signed_prekey: [u8; 32],
    /// One-time prekey (single use, consumed on handshake)
    pub one_time_prekey: Option<[u8; 32]>,
    /// Signature over signed_prekey by Ed25519 identity
    pub signature: Vec<u8>,
}

/// Result of an X3DH key agreement — shared secret for Double Ratchet init.
pub struct X3DHResult {
    /// Shared secret (32 bytes) — input to Double Ratchet
    pub shared_secret: [u8; 32],
    /// Ephemeral public key (sent to recipient)
    pub ephemeral_public: [u8; 32],
}

impl Drop for X3DHResult {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

/// Perform X3DH as the initiator (Alice).
///
/// Combines 3 (or 4) Diffie-Hellman exchanges into one shared secret.
pub fn x3dh_initiate(
    our_identity: &X25519Secret,
    their_bundle: &PrekeyBundle,
) -> Result<X3DHResult, CipherError> {
    // Generate ephemeral keypair
    let ephemeral_secret = X25519Secret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);

    let their_identity = X25519PublicKey::from(their_bundle.identity_key);
    let their_signed = X25519PublicKey::from(their_bundle.signed_prekey);

    // DH1: our_identity × their_signed_prekey
    let dh1 = our_identity.diffie_hellman(&their_signed);

    // DH2: our_ephemeral × their_identity
    let dh2 = ephemeral_secret.diffie_hellman(&their_identity);

    // DH3: our_ephemeral × their_signed_prekey
    let dh3 = ephemeral_secret.diffie_hellman(&their_signed);

    // Combine all DH outputs
    let mut combined = Vec::with_capacity(96 + 32);
    combined.extend_from_slice(dh1.as_bytes());
    combined.extend_from_slice(dh2.as_bytes());
    combined.extend_from_slice(dh3.as_bytes());

    // DH4 (optional): our_ephemeral × their_one_time_prekey
    if let Some(otpk) = their_bundle.one_time_prekey {
        let their_otpk = X25519PublicKey::from(otpk);
        let dh4 = ephemeral_secret.diffie_hellman(&their_otpk);
        combined.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret with HKDF
    let shared_secret = hkdf_derive(&combined, b"CipherX3DH", b"x3dh-shared-secret")?;

    // Zeroize intermediate values
    combined.zeroize();

    Ok(X3DHResult {
        shared_secret,
        ephemeral_public: *ephemeral_public.as_bytes(),
    })
}

// ─────────────────────────────────────────────────────────
// Double Ratchet
// ─────────────────────────────────────────────────────────

/// Double Ratchet session state.
///
/// Provides per-message forward secrecy: compromising one message key
/// doesn't compromise past or future messages.
#[derive(Clone)]
pub struct DoubleRatchet {
    /// Root key (ratcheted with each DH exchange)
    root_key: [u8; 32],
    /// Sending chain key
    chain_key_send: [u8; 32],
    /// Receiving chain key
    chain_key_recv: [u8; 32],
    /// Our current DH ratchet keypair
    dh_secret: X25519Secret,
    /// Their current DH ratchet public key
    their_dh_public: X25519PublicKey,
    /// Send message counter
    send_counter: u64,
    /// Receive message counter
    recv_counter: u64,
}

/// A ratcheted message ready for transport.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RatchetMessage {
    /// Our current DH public key
    pub dh_public: [u8; 32],
    /// Message counter
    pub counter: u64,
    /// Encrypted payload
    pub encrypted: EncryptedMessage,
}

impl DoubleRatchet {
    /// Initialize a Double Ratchet session from X3DH shared secret.
    pub fn init_sender(shared_secret: [u8; 32], their_dh_public: X25519PublicKey) -> Self {
        let dh_secret = X25519Secret::random_from_rng(OsRng);
        let dh_output = dh_secret.diffie_hellman(&their_dh_public);

        // First root key ratchet
        let root_key =
            hkdf_derive(dh_output.as_bytes(), &shared_secret, b"ratchet-root").unwrap();

        let chain_key_send =
            hkdf_derive(&root_key, b"cipher-chain", b"ratchet-send-chain").unwrap();
        let chain_key_recv =
            hkdf_derive(&root_key, b"cipher-chain", b"ratchet-recv-chain").unwrap();

        Self {
            root_key,
            chain_key_send,
            chain_key_recv,
            dh_secret,
            their_dh_public,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Initialize a Double Ratchet session as receiver.
    pub fn init_receiver(shared_secret: [u8; 32], our_dh_secret: X25519Secret) -> Self {
        let their_dh_public = X25519PublicKey::from([0u8; 32]); // Set on first message

        Self {
            root_key: shared_secret,
            chain_key_send: [0u8; 32],
            chain_key_recv: [0u8; 32],
            dh_secret: our_dh_secret,
            their_dh_public,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Encrypt a message using the sending chain.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, CipherError> {
        // Derive message key from chain key
        let message_key = self.advance_chain_send()?;

        // Encrypt with AES-256-GCM
        let encrypted = aes_encrypt(&message_key, plaintext)?;

        let dh_public = *x25519_dalek::PublicKey::from(&self.dh_secret).as_bytes();
        let counter = self.send_counter;
        self.send_counter += 1;

        Ok(RatchetMessage {
            dh_public,
            counter,
            encrypted,
        })
    }

    /// Decrypt a received ratcheted message.
    pub fn decrypt(&mut self, msg: &RatchetMessage) -> Result<Vec<u8>, CipherError> {
        // Check if DH ratchet step is needed
        let new_dh_public = X25519PublicKey::from(msg.dh_public);
        if msg.dh_public != *self.their_dh_public.as_bytes() {
            self.dh_ratchet_step(new_dh_public)?;
        }

        // Derive message key from receiving chain
        let message_key = self.advance_chain_recv()?;
        self.recv_counter += 1;

        aes_decrypt(&message_key, &msg.encrypted)
    }

    /// Perform a DH ratchet step (when we receive a new DH public key).
    fn dh_ratchet_step(&mut self, new_their_public: X25519PublicKey) -> Result<(), CipherError> {
        self.their_dh_public = new_their_public;

        // DH with their new public key using our current secret
        let dh_output = self.dh_secret.diffie_hellman(&self.their_dh_public);

        // Derive new root key and receiving chain
        // This mirrors the sender's init: they did DH(their_secret, our_public)
        // We do DH(our_secret, their_public) → same shared secret
        let new_root =
            hkdf_derive(dh_output.as_bytes(), &self.root_key, b"ratchet-root").unwrap();

        // Receiving chain = sender's sending chain (they used the same root)
        self.chain_key_recv =
            hkdf_derive(&new_root, b"cipher-chain", b"ratchet-send-chain").unwrap();

        // Generate new DH keypair for our sending
        self.dh_secret = X25519Secret::random_from_rng(OsRng);
        let dh_output_new = self.dh_secret.diffie_hellman(&self.their_dh_public);

        // Derive sending chain from the next root key ratchet
        self.root_key =
            hkdf_derive(dh_output_new.as_bytes(), &new_root, b"ratchet-root").unwrap();
        self.chain_key_send =
            hkdf_derive(&self.root_key, b"cipher-chain", b"ratchet-send-chain").unwrap();

        self.send_counter = 0;
        self.recv_counter = 0;

        Ok(())
    }

    /// Advance the sending chain and return a message key.
    fn advance_chain_send(&mut self) -> Result<[u8; 32], CipherError> {
        let message_key_bytes = {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key_send)
                .map_err(|e| CipherError::Encryption(format!("HMAC init failed: {e}")))?;
            mac.update(&[0x01]);
            mac.finalize().into_bytes()
        };

        let new_chain = {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key_send)
                .map_err(|e| CipherError::Encryption(format!("HMAC init failed: {e}")))?;
            mac.update(&[0x02]);
            mac.finalize().into_bytes()
        };

        self.chain_key_send.copy_from_slice(&new_chain);

        let mut key = [0u8; 32];
        key.copy_from_slice(&message_key_bytes);
        Ok(key)
    }

    /// Advance the receiving chain and return a message key.
    fn advance_chain_recv(&mut self) -> Result<[u8; 32], CipherError> {
        let message_key_bytes = {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key_recv)
                .map_err(|e| CipherError::Encryption(format!("HMAC init failed: {e}")))?;
            mac.update(&[0x01]);
            mac.finalize().into_bytes()
        };

        let new_chain = {
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.chain_key_recv)
                .map_err(|e| CipherError::Encryption(format!("HMAC init failed: {e}")))?;
            mac.update(&[0x02]);
            mac.finalize().into_bytes()
        };

        self.chain_key_recv.copy_from_slice(&new_chain);

        let mut key = [0u8; 32];
        key.copy_from_slice(&message_key_bytes);
        Ok(key)
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.chain_key_send.zeroize();
        self.chain_key_recv.zeroize();
    }
}

// ─────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = [42u8; 32];
        let plaintext = b"Hello, Cipher!";

        let encrypted = aes_encrypt(&key, plaintext).unwrap();
        let decrypted = aes_decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_wrong_key_fails() {
        let key = [42u8; 32];
        let wrong_key = [99u8; 32];
        let plaintext = b"secret message";

        let encrypted = aes_encrypt(&key, plaintext).unwrap();
        let result = aes_decrypt(&wrong_key, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_double_ratchet_session() {
        // Simulate X3DH producing a shared secret
        let shared_secret = [7u8; 32];

        // Bob's initial DH keypair
        let bob_dh_secret = X25519Secret::random_from_rng(OsRng);
        let bob_dh_public = x25519_dalek::PublicKey::from(&bob_dh_secret);

        // Alice initializes as sender
        let mut alice = DoubleRatchet::init_sender(shared_secret, bob_dh_public);

        // Bob initializes as receiver
        let mut bob = DoubleRatchet::init_receiver(shared_secret, bob_dh_secret);

        // Alice sends a message
        let msg1 = alice.encrypt(b"Hello Bob!").unwrap();

        // Bob decrypts
        let plaintext1 = bob.decrypt(&msg1).unwrap();
        assert_eq!(plaintext1, b"Hello Bob!");

        // Alice sends another message
        let msg2 = alice.encrypt(b"Second message").unwrap();
        let plaintext2 = bob.decrypt(&msg2).unwrap();
        assert_eq!(plaintext2, b"Second message");
    }

    #[test]
    fn test_hkdf_derive() {
        let key1 = hkdf_derive(b"input1", b"salt", b"info").unwrap();
        let key2 = hkdf_derive(b"input1", b"salt", b"info").unwrap();
        let key3 = hkdf_derive(b"input2", b"salt", b"info").unwrap();

        assert_eq!(key1, key2); // Deterministic
        assert_ne!(key1, key3); // Different inputs → different keys
    }
}
