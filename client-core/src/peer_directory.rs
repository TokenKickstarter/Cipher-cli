//! # Authenticated Peer Directory & Dual-Path Discovery
//!
//! Binds a user's EVM address (`0x...`) to their:
//! - Ed25519 public key (= Iroh `EndpointId` for direct QUIC P2P), and
//! - X3DH `PrekeyBundle` (X25519 identity + signed prekey for Double Ratchet).
//!
//! Each `SignedPeerBundle` is co-signed with BOTH secp256k1 (proving `0x...`) and
//! Ed25519 (proving the Iroh/chat keypair) and stored via live relay `/store` &
//! `/fetch` mailboxes under a deterministic directory key so peers discover and
//! verify one another immediately with zero centralized directory or L1 fork.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature as EdSignature, Signer, Verifier, VerifyingKey as EdVerifyingKey};
use k256::ecdsa::{
    signature::{Signer as _, Verifier as _},
    Signature as K256Signature, VerifyingKey as K256VerifyingKey,
};
use log::{debug, info};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

use crate::encryption::{hkdf_derive, PrekeyBundle};
use crate::error::CipherError;
use crate::identity::CipherIdentity;
use crate::network_bundle::RelayPool;

const PEER_DIR_CACHE_TTL: Duration = Duration::from_secs(300);
const PEER_BUNDLE_TTL_SECS: u64 = 7 * 86400;

/// Derive a deterministic medium-term X25519 signed prekey secret from `identity`
/// so single-shot CLI invocations (`send`/`recv`) and persistent daemons compute the
/// same X3DH responder key without needing extra manual key provisioning.
pub fn derive_signed_prekey(identity: &CipherIdentity) -> X25519Secret {
    let raw = hkdf_derive(
        identity.x25519_secret_key().as_bytes(),
        b"CipherSignedPrekeyV1",
        b"epoch-0",
    )
    .expect("32-byte HKDF output always succeeds");
    X25519Secret::from(raw)
}

/// Deterministic relay storage key for publishing/fetching a peer's `SignedPeerBundle`.
pub fn peer_directory_mailbox(evm_address: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"cipher-peer-dir-v1:");
    h.update(evm_address.trim().to_lowercase().as_bytes());
    format!("peer-dir-v1:{}", hex::encode(h.finalize()))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPeerBundle {
    pub version: u8,
    pub evm_address: String,
    pub ed25519_public: [u8; 32],
    pub x25519_identity: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub prekey_signature: Vec<u8>,
    pub secp256k1_pubkey: Vec<u8>,
    pub secp256k1_signature: Vec<u8>,
    pub ed25519_signature: Vec<u8>,
    pub timestamp_ms: u64,
}

impl SignedPeerBundle {
    fn canonical_payload(
        version: u8,
        evm_address: &str,
        ed25519_public: &[u8; 32],
        x25519_identity: &[u8; 32],
        signed_prekey: &[u8; 32],
        timestamp_ms: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"CipherSignedPeerBundleV1");
        out.push(version);
        out.extend_from_slice(evm_address.to_lowercase().as_bytes());
        out.extend_from_slice(ed25519_public);
        out.extend_from_slice(x25519_identity);
        out.extend_from_slice(signed_prekey);
        out.extend_from_slice(&timestamp_ms.to_be_bytes());
        out
    }

    pub fn from_identity(identity: &CipherIdentity) -> Result<Self, CipherError> {
        let signed_prekey_secret = derive_signed_prekey(identity);
        let signed_prekey = *X25519PublicKey::from(&signed_prekey_secret).as_bytes();
        let prekey = PrekeyBundle::create_signed(identity, signed_prekey, None);

        let evm_address = identity.evm_address().to_lowercase();
        let ed25519_public = *identity.ed25519_public_key().as_bytes();
        let x25519_identity = *identity.x25519_public_key().as_bytes();
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let payload = Self::canonical_payload(
            1,
            &evm_address,
            &ed25519_public,
            &x25519_identity,
            &signed_prekey,
            timestamp_ms,
        );

        let ed25519_signature = identity
            .ed25519_signing_key()
            .sign(&payload)
            .to_bytes()
            .to_vec();
        let secp256k1_pubkey = identity
            .secp256k1_public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let sig_k256: K256Signature = identity.secp256k1_signing_key().sign(&payload);
        let secp256k1_signature = sig_k256.to_bytes().to_vec();

        Ok(Self {
            version: 1,
            evm_address,
            ed25519_public,
            x25519_identity,
            signed_prekey,
            prekey_signature: prekey.signature,
            secp256k1_pubkey,
            secp256k1_signature,
            ed25519_signature,
            timestamp_ms,
        })
    }

    pub fn prekey_bundle(&self) -> PrekeyBundle {
        PrekeyBundle {
            identity_key: self.x25519_identity,
            signed_prekey: self.signed_prekey,
            one_time_prekey: None,
            signature: self.prekey_signature.clone(),
        }
    }

    pub fn iroh_endpoint_id(&self) -> Result<iroh::EndpointId, CipherError> {
        iroh::EndpointId::from_bytes(&self.ed25519_public)
            .map_err(|e| CipherError::Identity(format!("Invalid Iroh EndpointId bytes: {e}")))
    }

    pub fn verify(&self) -> Result<(), CipherError> {
        if self.version != 1 {
            return Err(CipherError::Identity(format!(
                "Unsupported peer bundle version {}",
                self.version
            )));
        }

        // 1. Verify secp256k1 public key hashes to evm_address.
        let vk_secp = K256VerifyingKey::from_sec1_bytes(&self.secp256k1_pubkey)
            .map_err(|e| CipherError::Identity(format!("Invalid secp256k1 pubkey: {e}")))?;
        let uncompressed = vk_secp.to_encoded_point(false);
        let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let derived_evm = format!("0x{}", hex::encode(&hash[12..]));
        if derived_evm != self.evm_address.to_lowercase() {
            return Err(CipherError::Identity(format!(
                "Peer bundle secp256k1 key {} does not match EVM address {}",
                derived_evm, self.evm_address
            )));
        }

        // 2. Verify signatures over canonical payload.
        let payload = Self::canonical_payload(
            self.version,
            &self.evm_address,
            &self.ed25519_public,
            &self.x25519_identity,
            &self.signed_prekey,
            self.timestamp_ms,
        );

        let secp_sig = K256Signature::from_slice(&self.secp256k1_signature)
            .map_err(|e| CipherError::Identity(format!("Invalid secp256k1 signature: {e}")))?;
        vk_secp
            .verify(&payload, &secp_sig)
            .map_err(|e| CipherError::Identity(format!("secp256k1 signature verification failed: {e}")))?;

        let vk_ed = EdVerifyingKey::from_bytes(&self.ed25519_public)
            .map_err(|e| CipherError::Identity(format!("Invalid Ed25519 pubkey: {e}")))?;
        let ed_sig = EdSignature::from_slice(&self.ed25519_signature)
            .map_err(|e| CipherError::Identity(format!("Invalid Ed25519 signature: {e}")))?;
        vk_ed
            .verify(&payload, &ed_sig)
            .map_err(|e| CipherError::Identity(format!("Ed25519 signature verification failed: {e}")))?;

        // 3. Verify X3DH signed prekey signature.
        self.prekey_bundle().verify(&self.ed25519_public)?;
        Ok(())
    }
}

struct CachedPeer {
    bundle: Option<SignedPeerBundle>,
    fetched_at: Instant,
}

/// Thread-safe cache and relay publisher/resolver for `SignedPeerBundle`.
pub struct PeerDirectory {
    cache: RwLock<HashMap<String, CachedPeer>>,
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn insert_verified(&self, bundle: SignedPeerBundle) -> Result<(), CipherError> {
        bundle.verify()?;
        let key = bundle.evm_address.to_lowercase();
        let mut cache = self.cache.write().await;
        if let Some(existing) = cache.get(&key).and_then(|c| c.bundle.as_ref()) {
            if existing.timestamp_ms > bundle.timestamp_ms {
                return Ok(());
            }
        }
        cache.insert(
            key,
            CachedPeer {
                bundle: Some(bundle),
                fetched_at: Instant::now(),
            },
        );
        Ok(())
    }

    pub async fn get_cached(&self, evm_address: &str) -> Option<SignedPeerBundle> {
        let key = evm_address.to_lowercase();
        let cache = self.cache.read().await;
        cache.get(&key).and_then(|c| {
            if c.fetched_at.elapsed() <= PEER_DIR_CACHE_TTL {
                c.bundle.clone()
            } else {
                None
            }
        })
    }

    /// Publish our own `SignedPeerBundle` to reachable relays so peers can discover our
    /// Iroh `EndpointId` and X3DH `PrekeyBundle`.
    pub async fn publish(&self, pool: &Arc<RelayPool>, identity: &CipherIdentity) -> Result<(), CipherError> {
        let bundle = SignedPeerBundle::from_identity(identity)?;
        self.insert_verified(bundle.clone()).await?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let raw = serde_json::to_vec(&bundle)
            .map_err(|e| CipherError::Network(format!("Serialize peer bundle: {e}")))?;

        let chunk = serde_json::json!({
            "recipient_id": peer_directory_mailbox(&bundle.evm_address),
            "message_id": format!("peer-bundle-{}", bundle.evm_address),
            "ciphertext": raw,
            "stored_at": now,
            "expires_at": now + PEER_BUNDLE_TTL_SECS,
        })
        .to_string();

        if let Some((base, _)) = pool.post_json_failover("/store", chunk, 5).await {
            info!(
                "[PeerDir] Published verified EndpointId + PrekeyBundle to {}",
                base
            );
            Ok(())
        } else {
            Err(CipherError::Network(
                "Could not publish peer bundle to any relay".into(),
            ))
        }
    }

    /// Resolve a peer's verified `SignedPeerBundle` (cache first, then relay directory lookup).
    /// Note: directory bundles are NEVER `/ack`-ed on fetch so they stay readable to all peers.
    pub async fn resolve(
        &self,
        pool: &Arc<RelayPool>,
        evm_address: &str,
    ) -> Option<SignedPeerBundle> {
        let key = evm_address.trim().to_lowercase();
        if !key.starts_with("0x") {
            return None;
        }
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&key) {
                let ttl = if entry.bundle.is_some() {
                    PEER_DIR_CACHE_TTL
                } else {
                    Duration::from_secs(20)
                };
                if entry.fetched_at.elapsed() <= ttl {
                    return entry.bundle.clone();
                }
            }
        }

        let mailbox = peer_directory_mailbox(&key);
        let body = serde_json::json!({ "recipient_id": mailbox }).to_string();
        let responses = pool.post_fetch_parallel(body, 2).await;

        let mut newest: Option<SignedPeerBundle> = None;
        for (_base, resp_text) in responses {
            let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_text) else {
                continue;
            };
            let Some(chunks) = parsed.get("Chunks").and_then(|c| c.as_array()) else {
                continue;
            };
            for chunk in chunks {
                let Some(arr) = chunk.get("ciphertext").and_then(|c| c.as_array()) else {
                    continue;
                };
                let raw: Vec<u8> = arr
                    .iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u8))
                    .collect();
                let Ok(candidate) = serde_json::from_slice::<SignedPeerBundle>(&raw) else {
                    continue;
                };
                if candidate.evm_address.to_lowercase() != key {
                    continue;
                }
                if candidate.verify().is_err() {
                    debug!("[PeerDir] Ignoring invalid signature on peer bundle for {key}");
                    continue;
                }
                if newest
                    .as_ref()
                    .map(|cur| candidate.timestamp_ms > cur.timestamp_ms)
                    .unwrap_or(true)
                {
                    newest = Some(candidate);
                }
            }
        }

        self.cache.write().await.insert(
            key,
            CachedPeer {
                bundle: newest.clone(),
                fetched_at: Instant::now(),
            },
        );
        newest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_peer_bundle_roundtrip_and_tamper_rejection() {
        let id = CipherIdentity::generate().unwrap();
        let mut bundle = SignedPeerBundle::from_identity(&id).unwrap();
        bundle.verify().expect("authentic bundle must verify");
        assert!(bundle.iroh_endpoint_id().is_ok());

        // Tampering with ed25519_public or evm_address fails cryptographic check.
        let mut tampered = bundle.clone();
        tampered.ed25519_public[0] ^= 0xff;
        assert!(tampered.verify().is_err());

        bundle.evm_address = "0x0000000000000000000000000000000000000001".to_string();
        assert!(bundle.verify().is_err());
    }
}

