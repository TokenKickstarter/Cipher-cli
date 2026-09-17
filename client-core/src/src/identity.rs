//! # Identity Module
//!
//! Generates and manages Cipher identities from a single BIP-39 seed phrase.
//!
//! One seed phrase → three keypairs:
//! - Ed25519: Chat signing + encryption (X3DH / Double Ratchet)
//! - Sr25519: TKS Substrate account (staking, @username)
//! - secp256k1: EVM wallet (0x address, tokens, NFTs)

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use k256::ecdsa::{SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey};
use schnorrkel::{
    keys::MiniSecretKey as Sr25519MiniSecret,
    Keypair as Sr25519Keypair,
    PublicKey as Sr25519PublicKey,
};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{StaticSecret as X25519Secret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

use crate::error::CipherError;

// ─────────────────────────────────────────────────────────
// BIP-44 derivation paths (conceptual — used for seed splitting)
// m/44'/7331'/0'/0/0 — TKS chain ID 7331
// ─────────────────────────────────────────────────────────

/// A complete Cipher identity derived from a single seed phrase.
#[derive(Clone)]
pub struct CipherIdentity {
    /// The BIP-39 mnemonic (12 or 24 words) — SENSITIVE
    mnemonic: String,

    /// Ed25519 signing key — for chat signatures + X3DH identity
    ed25519_signing: Ed25519SigningKey,

    /// X25519 static secret — for Diffie-Hellman key exchange
    x25519_secret: X25519Secret,

    /// Sr25519 keypair — for TKS Substrate transactions
    sr25519_keypair: Sr25519Keypair,

    /// secp256k1 signing key — for EVM transactions
    secp256k1_signing: K256SigningKey,
}

/// Public identity — safe to share
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicIdentity {
    /// Ed25519 public key (32 bytes hex) — chat identity
    pub ed25519_public: Vec<u8>,

    /// X25519 public key (32 bytes) — for key exchange
    pub x25519_public: Vec<u8>,

    /// Sr25519 public key (32 bytes) — Substrate account
    pub sr25519_public: Vec<u8>,

    /// secp256k1 public key (33 bytes compressed) — EVM
    pub secp256k1_public: Vec<u8>,

    /// Substrate SS58 address (e.g., 5GrwvaEF...)
    pub substrate_address: String,

    /// EVM address (0x...)
    pub evm_address: String,

    /// Display address (primary identifier for chat)
    pub display_address: String,
}

impl CipherIdentity {
    /// Generate a brand new identity with a fresh 12-word seed phrase.
    pub fn generate() -> Result<Self, CipherError> {
        Self::generate_with_word_count(12)
    }

    /// Generate a new identity with a specified word count (12 or 24).
    pub fn generate_with_word_count(word_count: usize) -> Result<Self, CipherError> {
        let mnemonic = match word_count {
            12 => bip39::Mnemonic::generate(12)
                .map_err(|e| CipherError::Identity(format!("Mnemonic generation failed: {e}")))?,
            24 => bip39::Mnemonic::generate(24)
                .map_err(|e| CipherError::Identity(format!("Mnemonic generation failed: {e}")))?,
            _ => {
                return Err(CipherError::Identity(
                    "Word count must be 12 or 24".to_string(),
                ))
            }
        };

        let phrase = mnemonic.to_string();
        Self::from_mnemonic(&phrase)
    }

    /// Restore an identity from an existing seed phrase.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, CipherError> {
        // Validate the mnemonic
        let mnemonic = bip39::Mnemonic::parse(phrase)
            .map_err(|e| CipherError::Identity(format!("Invalid mnemonic: {e}")))?;

        // Derive master seed (64 bytes) — this is where PBKDF2 runs
        let seed = mnemonic.to_seed("");

        Self::from_seed_bytes(&seed, &mnemonic.to_string())
    }

    /// Create identity from raw 64-byte seed, bypassing PBKDF2.
    /// Use this in tests with a pre-computed seed to avoid the slow PBKDF2 call.
    pub fn from_seed_bytes(seed: &[u8; 64], mnemonic_str: &str) -> Result<Self, CipherError> {
        // Derive Ed25519 key from seed[0..32]
        let ed25519_bytes: [u8; 32] = {
            let hash = Sha256::digest(&seed[0..32]);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash);
            arr
        };
        let ed25519_signing = Ed25519SigningKey::from_bytes(&ed25519_bytes);

        // Derive X25519 key from Ed25519 (standard conversion)
        let x25519_bytes: [u8; 32] = {
            let hash = Sha512::digest(ed25519_signing.as_bytes());
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&hash[0..32]);
            // Clamp for X25519
            arr[0] &= 248;
            arr[31] &= 127;
            arr[31] |= 64;
            arr
        };
        let x25519_secret = X25519Secret::from(x25519_bytes);

        // Derive Sr25519 key from seed[0..32]
        let sr25519_mini = Sr25519MiniSecret::from_bytes(&seed[0..32])
            .map_err(|e| CipherError::Identity(format!("Sr25519 key derivation failed: {e}")))?;
        let sr25519_keypair = sr25519_mini.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);

        // Derive secp256k1 key from seed using standard BIP44 Ethereum path: m/44'/60'/0'/0/0
        let secp256k1_signing = {
            use bip32::{DerivationPath, XPrv};
            let path: DerivationPath = "m/44'/60'/0'/0/0".parse()
                .map_err(|e| CipherError::Identity(format!("Invalid derivation path: {e}")))?;
            let child_xprv = XPrv::derive_from_path(seed, &path)
                .map_err(|e| CipherError::Identity(format!("BIP44 derivation failed: {e}")))?;
            
            K256SigningKey::from_bytes((&child_xprv.private_key().to_bytes()).into())
                .map_err(|e| CipherError::Identity(format!("secp256k1 key derivation failed: {e}")))?
        };

        Ok(Self {
            mnemonic: mnemonic_str.to_string(),
            ed25519_signing,
            x25519_secret,
            sr25519_keypair,
            secp256k1_signing,
        })
    }

    /// Get the seed phrase (SENSITIVE — only show during backup).
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    /// Get the Ed25519 signing key reference.
    pub fn ed25519_signing_key(&self) -> &Ed25519SigningKey {
        &self.ed25519_signing
    }

    /// Get the Ed25519 verifying (public) key.
    pub fn ed25519_public_key(&self) -> Ed25519VerifyingKey {
        self.ed25519_signing.verifying_key()
    }

    /// Get the X25519 public key for key exchange.
    pub fn x25519_public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.x25519_secret)
    }

    /// Get the X25519 secret for Diffie-Hellman.
    pub fn x25519_secret_key(&self) -> &X25519Secret {
        &self.x25519_secret
    }

    /// Get the Sr25519 keypair for Substrate.
    pub fn sr25519_keypair(&self) -> &Sr25519Keypair {
        &self.sr25519_keypair
    }

    /// Get the Sr25519 public key.
    pub fn sr25519_public_key(&self) -> Sr25519PublicKey {
        self.sr25519_keypair.public
    }

    /// Get the secp256k1 signing key for EVM.
    pub fn secp256k1_signing_key(&self) -> &K256SigningKey {
        &self.secp256k1_signing
    }

    /// Get the secp256k1 verifying (public) key.
    pub fn secp256k1_public_key(&self) -> K256VerifyingKey {
        *self.secp256k1_signing.verifying_key()
    }

    /// Compute the EVM address (0x...) from secp256k1 public key.
    /// EVM address = last 20 bytes of Keccak-256 of uncompressed public key.
    pub fn evm_address(&self) -> String {
        use sha3::{Digest as Sha3Digest, Keccak256};

        let pubkey = self.secp256k1_public_key();
        let point = pubkey.to_encoded_point(false);
        // Skip the 0x04 prefix byte, hash the 64-byte x||y
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    /// Compute the Substrate SS58 address from Sr25519 public key.
    /// Uses SS58 prefix 42 (generic Substrate).
    /// NOTE: TKS Network uses H160 (EVM) addresses, not SS58. Use `tks_h160_address()` for TKS.
    pub fn substrate_address(&self) -> String {
        ss58_encode(self.sr25519_public_key().as_ref(), 42)
    }

    /// TKS Network address — same as Ethereum H160 (20-byte Keccak).
    /// TKS is an EVM-compatible Substrate chain, so it uses 0x... addresses.
    pub fn tks_h160_address(&self) -> String {
        self.evm_address()
    }

    /// Get the primary display address (used as chat ID).
    /// This is the EVM address for simplicity and cross-chain compatibility.
    pub fn display_address(&self) -> String {
        self.evm_address()
    }

    /// Export the full public identity (safe to share).
    pub fn public_identity(&self) -> PublicIdentity {
        PublicIdentity {
            ed25519_public: self.ed25519_public_key().as_bytes().to_vec(),
            x25519_public: self.x25519_public_key().as_bytes().to_vec(),
            sr25519_public: self.sr25519_public_key().as_ref().to_vec(),
            secp256k1_public: self
                .secp256k1_public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
            substrate_address: self.substrate_address(),
            evm_address: self.evm_address(),
            display_address: self.display_address(),
        }
    }
}

impl Drop for CipherIdentity {
    fn drop(&mut self) {
        // Securely zero the mnemonic from memory
        self.mnemonic.zeroize();
    }
}

// ─────────────────────────────────────────────────────────
// SS58 encoding (minimal implementation)
// ─────────────────────────────────────────────────────────

fn ss58_encode(pubkey: &[u8], prefix: u8) -> String {
    use blake2::{Blake2b512, Digest as Blake2Digest};

    let mut payload = vec![prefix];
    payload.extend_from_slice(pubkey);

    // SS58 checksum = first 2 bytes of Blake2b("SS58PRE" || prefix || pubkey)
    let mut hasher = Blake2b512::new();
    hasher.update(b"SS58PRE");
    hasher.update(&payload);
    let hash = hasher.finalize();

    payload.push(hash[0]);
    payload.push(hash[1]);

    bs58::encode(payload).into_string()
}

// ─────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = CipherIdentity::generate().unwrap();
        let words: Vec<&str> = id.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 12);

        let pub_id = id.public_identity();
        assert_eq!(pub_id.ed25519_public.len(), 32);
        assert_eq!(pub_id.x25519_public.len(), 32);
        assert_eq!(pub_id.sr25519_public.len(), 32);
        assert!(pub_id.evm_address.starts_with("0x"));
        assert_eq!(pub_id.evm_address.len(), 42); // 0x + 40 hex chars
        assert!(!pub_id.substrate_address.is_empty());

        println!("Mnemonic:  {}", id.mnemonic());
        println!("EVM addr:  {}", pub_id.evm_address);
        println!("SS58 addr: {}", pub_id.substrate_address);
        println!("Chat ID:   {}", pub_id.display_address);
    }

    #[test]
    fn test_import_identity_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let id1 = CipherIdentity::from_mnemonic(phrase).unwrap();
        let id2 = CipherIdentity::from_mnemonic(phrase).unwrap();

        // Same seed → same keys
        assert_eq!(
            id1.public_identity().evm_address,
            id2.public_identity().evm_address
        );
        assert_eq!(
            id1.public_identity().substrate_address,
            id2.public_identity().substrate_address
        );
        assert_eq!(
            id1.public_identity().ed25519_public,
            id2.public_identity().ed25519_public
        );
    }

    #[test]
    fn test_24_word_mnemonic() {
        let id = CipherIdentity::generate_with_word_count(24).unwrap();
        let words: Vec<&str> = id.mnemonic().split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = CipherIdentity::from_mnemonic("invalid words here");
        assert!(result.is_err());
    }
}
