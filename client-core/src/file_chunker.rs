//! # File Chunker Module
//!
//! Splits files into **512 KiB** encrypted chunks (HyperSwarm-safe; see
//! `tks-substrate-node/network/CIPHER-CLIENT-CHUNKING-SPEC.md`).
//! Files NEVER touch the blockchain — stored temporarily on swarm nodes.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};

use crate::error::CipherError;

/// Plaintext bytes per piece (before AES-GCM). See CIPHER-CLIENT-CHUNKING-SPEC.md.
pub const CHUNK_SIZE: usize = 512 * 1024;

/// Relay + libp2p JSON request-response limit (~1 MiB); reject larger wire blobs.
pub const MAX_RELAY_CIPHERTEXT: usize = 900_000;

/// Wire format version inside relay `EncryptedChunk.ciphertext`.
pub const RELAY_WIRE_VERSION: u8 = 1;

/// Bincode payload stored in relay `EncryptedChunk.ciphertext` (spec v1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayWireChunk {
    pub version: u8,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub nonce: [u8; 12],
    pub chunk_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub aes_ciphertext: Vec<u8>,
}

/// Relay `message_id` for a file piece: `{file_id}#c{index:05}`.
pub fn relay_message_id(file_id: &str, chunk_index: u32) -> String {
    format!("{file_id}#c{chunk_index:05}")
}

/// Relay `message_id` for encrypted `FileMetadata` header.
pub fn relay_header_message_id(file_id: &str) -> String {
    format!("{file_id}#header")
}

/// Parse piece id; returns `(file_id, chunk_index)` or None for `#header`.
pub fn parse_relay_message_id(message_id: &str) -> Option<(String, Option<u32>)> {
    if message_id.ends_with("#header") {
        return Some((message_id.trim_end_matches("#header").to_string(), None));
    }
    let (file_id, idx) = message_id.rsplit_once("#c")?;
    let index: u32 = idx.parse().ok()?;
    Some((file_id.to_string(), Some(index)))
}

impl EncryptedChunk {
    /// Encode for `POST /store` → field `ciphertext`.
    pub fn to_relay_wire_bytes(&self) -> Result<Vec<u8>, CipherError> {
        let wire = RelayWireChunk {
            version: RELAY_WIRE_VERSION,
            chunk_index: self.chunk_index,
            total_chunks: self.total_chunks,
            nonce: self.nonce,
            chunk_hash: self.chunk_hash,
            merkle_root: self.merkle_root,
            aes_ciphertext: self.ciphertext.clone(),
        };
        let bytes = bincode::serialize(&wire)
            .map_err(|e| CipherError::File(format!("wire encode: {e}")))?;
        if bytes.len() > MAX_RELAY_CIPHERTEXT {
            return Err(CipherError::File(format!(
                "relay wire {} bytes exceeds MAX_RELAY_CIPHERTEXT {}",
                bytes.len(),
                MAX_RELAY_CIPHERTEXT
            )));
        }
        Ok(bytes)
    }

    /// Decode relay `EncryptedChunk.ciphertext` bytes.
    pub fn from_relay_wire_bytes(data: &[u8]) -> Result<Self, CipherError> {
        let wire: RelayWireChunk = bincode::deserialize(data)
            .map_err(|e| CipherError::File(format!("wire decode: {e}")))?;
        if wire.version != RELAY_WIRE_VERSION {
            return Err(CipherError::File(format!(
                "unsupported relay wire version {}",
                wire.version
            )));
        }
        Ok(EncryptedChunk {
            chunk_index: wire.chunk_index,
            total_chunks: wire.total_chunks,
            ciphertext: wire.aes_ciphertext,
            nonce: wire.nonce,
            chunk_hash: wire.chunk_hash,
            merkle_root: wire.merkle_root,
            expires_at: 0,
        })
    }
}

/// An encrypted chunk of a file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedChunk {
    /// Index of this chunk (0-based)
    pub chunk_index: u32,
    /// Total number of chunks
    pub total_chunks: u32,
    /// AES-256-GCM encrypted data
    pub ciphertext: Vec<u8>,
    /// AES-GCM nonce (12 bytes)
    pub nonce: [u8; 12],
    /// SHA-256 hash of the plaintext chunk (for Merkle tree)
    pub chunk_hash: [u8; 32],
    /// Merkle root of all chunk hashes (for integrity verification)
    pub merkle_root: [u8; 32],
    /// Expiry timestamp (Unix seconds) — nodes auto-delete after this
    pub expires_at: u64,
}

/// Result of chunking a file — contains all encrypted chunks + metadata.
#[derive(Debug, Clone)]
pub struct ChunkedFile {
    /// All encrypted chunks
    pub chunks: Vec<EncryptedChunk>,
    /// Merkle root hash (verify file integrity)
    pub merkle_root: [u8; 32],
    /// Original file size in bytes
    pub original_size: u64,
    /// Original file name (optional)
    pub file_name: Option<String>,
    /// MIME type (optional)
    pub mime_type: Option<String>,
}

/// Encrypt and chunk a file for transmission.
///
/// - Splits into 512 KiB plaintext chunks
/// - AES-256-GCM encrypts each chunk
/// - Computes Merkle root for integrity
pub fn encrypt_and_chunk(
    file_data: &[u8],
    session_key: &[u8; 32],
    ttl_days: u64,
) -> Result<ChunkedFile, CipherError> {
    let total_chunks = (file_data.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + (ttl_days * 86400);

    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|e| CipherError::File(format!("AES key init failed: {e}")))?;

    // First pass: encrypt chunks and compute hashes
    let mut chunks = Vec::with_capacity(total_chunks);
    let mut chunk_hashes = Vec::with_capacity(total_chunks);

    for (i, raw_chunk) in file_data.chunks(CHUNK_SIZE).enumerate() {
        // Hash the plaintext chunk
        let chunk_hash: [u8; 32] = Sha256::digest(raw_chunk).into();
        chunk_hashes.push(chunk_hash);

        // Encrypt with AES-256-GCM
        let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce_bytes, raw_chunk)
            .map_err(|e| CipherError::File(format!("Chunk encryption failed: {e}")))?;

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);

        let piece = EncryptedChunk {
            chunk_index: i as u32,
            total_chunks: total_chunks as u32,
            ciphertext,
            nonce,
            chunk_hash,
            merkle_root: [0u8; 32], // Filled in second pass
            expires_at,
        };
        piece.to_relay_wire_bytes()?;
        chunks.push(piece);
    }

    // Compute Merkle root
    let merkle_root = compute_merkle_root(&chunk_hashes);

    // Fill in Merkle root for all chunks
    for chunk in &mut chunks {
        chunk.merkle_root = merkle_root;
    }

    Ok(ChunkedFile {
        chunks,
        merkle_root,
        original_size: file_data.len() as u64,
        file_name: None,
        mime_type: None,
    })
}

/// Decrypt and reassemble chunks back into the original file.
pub fn decrypt_and_reassemble(
    chunks: &mut [EncryptedChunk],
    session_key: &[u8; 32],
) -> Result<Vec<u8>, CipherError> {
    // Sort by chunk index
    chunks.sort_by_key(|c| c.chunk_index);

    // Verify all chunks present
    let total = chunks[0].total_chunks as usize;
    if chunks.len() != total {
        return Err(CipherError::File(format!(
            "Missing chunks: got {}, expected {}",
            chunks.len(),
            total
        )));
    }

    // Verify Merkle root consistency
    let expected_root = chunks[0].merkle_root;
    let chunk_hashes: Vec<[u8; 32]> = chunks.iter().map(|c| c.chunk_hash).collect();
    let computed_root = compute_merkle_root(&chunk_hashes);

    if computed_root != expected_root {
        return Err(CipherError::File(
            "Merkle root mismatch — file integrity compromised".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|e| CipherError::File(format!("AES key init failed: {e}")))?;

    let mut file_data = Vec::new();

    for chunk in chunks.iter() {
        let nonce = Nonce::from_slice(&chunk.nonce);
        let plaintext = cipher
            .decrypt(nonce, chunk.ciphertext.as_ref())
            .map_err(|e| CipherError::File(format!("Chunk decryption failed: {e}")))?;

        // Verify chunk hash
        let hash: [u8; 32] = Sha256::digest(&plaintext).into();
        if hash != chunk.chunk_hash {
            return Err(CipherError::File(format!(
                "Chunk {} hash mismatch — tampered",
                chunk.chunk_index
            )));
        }

        file_data.extend_from_slice(&plaintext);
    }

    Ok(file_data)
}

/// Compute a Merkle root from chunk hashes.
fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut level: Vec<[u8; 32]> = hashes.to_vec();

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity((level.len() + 1) / 2);

        for pair in level.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            if pair.len() > 1 {
                hasher.update(pair[1]);
            } else {
                hasher.update(pair[0]); // Duplicate odd leaf
            }
            next_level.push(hasher.finalize().into());
        }

        level = next_level;
    }

    level[0]
}

// ─────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_and_reassemble_small() {
        let key = [42u8; 32];
        let data = b"Hello, Cipher file transfer!";

        let chunked = encrypt_and_chunk(data, &key, 30).unwrap();
        assert_eq!(chunked.chunks.len(), 1); // Small file = 1 chunk
        assert_eq!(chunked.original_size, data.len() as u64);

        let mut chunks = chunked.chunks;
        let reassembled = decrypt_and_reassemble(&mut chunks, &key).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_chunk_and_reassemble_multi_chunk() {
        let key = [42u8; 32];
        // 5 MiB → ceil(5M / 512K) = 10 chunks
        let data: Vec<u8> = (0..5_000_000).map(|i| (i % 256) as u8).collect();

        let chunked = encrypt_and_chunk(&data, &key, 30).unwrap();
        assert_eq!(chunked.chunks.len(), 10);

        let mut chunks = chunked.chunks;
        let reassembled = decrypt_and_reassemble(&mut chunks, &key).unwrap();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_tampered_chunk_detected() {
        let key = [42u8; 32];
        let data = b"Sensitive file contents";

        let chunked = encrypt_and_chunk(data, &key, 30).unwrap();
        let mut chunks = chunked.chunks;

        // Tamper with Merkle root
        chunks[0].merkle_root = [0u8; 32];

        let result = decrypt_and_reassemble(&mut chunks, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_message_id_parse() {
        let id = relay_message_id("550e8400-e29b-41d4-a716-446655440000", 3);
        assert_eq!(id, "550e8400-e29b-41d4-a716-446655440000#c00003");
        let (fid, idx) = parse_relay_message_id(&id).unwrap();
        assert_eq!(fid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(idx, Some(3));
    }

    #[test]
    fn test_relay_wire_roundtrip() {
        let key = [1u8; 32];
        let data = vec![0u8; 600_000];
        let chunked = encrypt_and_chunk(&data, &key, 7).unwrap();
        let wire = chunked.chunks[0].to_relay_wire_bytes().unwrap();
        assert!(wire.len() <= MAX_RELAY_CIPHERTEXT);
        let back = EncryptedChunk::from_relay_wire_bytes(&wire).unwrap();
        assert_eq!(back.chunk_index, chunked.chunks[0].chunk_index);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }
}
