//! # Message Protocol
//!
//! Wire protocol for Cipher messages — what gets encrypted and sent over the network.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Unique message identifier.
pub type MessageId = Uuid;

/// A Cipher message envelope (encrypted before transmission).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherMessage {
    /// Unique message ID
    pub id: MessageId,
    /// Sender's public identity key (Ed25519, 32 bytes hex)
    pub sender: String,
    /// Recipient's address (EVM 0x... or @username)
    pub recipient: String,
    /// Message type
    pub msg_type: MessageType,
    /// Timestamp (UTC)
    pub timestamp: DateTime<Utc>,
    /// Encrypted payload (AES-256-GCM ciphertext)
    pub payload: Vec<u8>,
    /// Nonce for AES-256-GCM
    pub nonce: [u8; 12],
    /// Double Ratchet DH public key (for ratchet step)
    pub dh_public: [u8; 32],
    /// Ratchet message counter
    pub counter: u64,
    /// TTL in seconds (nodes auto-delete after expiry)
    pub ttl: u64,
}

/// Types of messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    /// Text message
    Text,
    /// File/media (payload = chunk metadata, actual chunks sent separately)
    File(FileMetadata),
    /// Voice message
    Voice,
    /// Payment request
    PaymentRequest(PaymentInfo),
    /// Payment sent confirmation
    PaymentSent(PaymentInfo),
    /// Key exchange (X3DH initial message)
    KeyExchange,
    /// Prekey bundle publication
    PrekeyBundle,
    /// Delivery receipt (sent → delivered → read)
    Receipt(ReceiptType),
    /// Call signaling (SDP/ICE)
    CallSignal(CallSignalType),
    /// Raw WebRTC UDP Media Frame (Phase 2 Tunneling)
    CallMedia,
    /// Typing indicator
    Typing(bool),
    /// File chunk (proper chunked transfer)
    FileChunk {
        /// ID linking chunks to their header
        file_id: String,
        /// Chunk index (0-based)
        chunk_index: u32,
        /// Total number of chunks
        total_chunks: u32,
    },
    /// Group management
    GroupAction(GroupAction),
    /// Online/offline presence broadcast
    Presence(PresenceInfo),
}

/// Presence heartbeat payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PresenceInfo {
    /// Whether the user is currently online
    pub is_online: bool,
    /// UTC timestamp of the status change
    pub last_seen: DateTime<Utc>,
}

/// File metadata sent with file messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileMetadata {
    pub file_name: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub total_chunks: u32,
    pub merkle_root: [u8; 32],
    pub thumbnail: Option<Vec<u8>>,
}

/// Payment information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PaymentInfo {
    pub amount: String,
    pub currency: String,
    pub tx_hash: Option<String>,
    pub note: Option<String>,
}

/// Delivery receipt types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReceiptType {
    Delivered,
    Read,
}

/// Call signaling types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallSignalType {
    Offer { call_id: String, sdp: String, is_video: bool },
    Answer { call_id: String, sdp: String },
    IceCandidate { call_id: String, candidate: String },
    Hangup { call_id: String },
    /// Call declined by recipient (distinct from hangup — stops ringing immediately)
    Decline { call_id: String },
    /// Group call: invite participants to a room
    GroupCallInvite { room_id: String, participants: Vec<String>, is_video: bool },
    /// Group call: participant joined the room
    GroupCallJoin { room_id: String },
    /// Group call: participant left the room
    GroupCallLeave { room_id: String },
}

/// Group management actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GroupAction {
    Create { name: String, members: Vec<String> },
    AddMember(String),
    RemoveMember(String),
    Leave,
    UpdateName(String),
}

impl CipherMessage {
    /// Create a new call signaling message.
    pub fn new_signal(sender: &str, recipient: &str, signal: CallSignalType, encrypted_payload: Vec<u8>, nonce: [u8; 12], dh_public: [u8; 32], counter: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            msg_type: MessageType::CallSignal(signal),
            timestamp: Utc::now(),
            payload: encrypted_payload,
            nonce,
            dh_public,
            counter,
            ttl: 300, // Short TTL for call signals: 5 mins
        }
    }

    /// Create a new call media routing frame.
    pub fn new_media(sender: &str, recipient: &str, encrypted_payload: Vec<u8>, nonce: [u8; 12], dh_public: [u8; 32], counter: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            msg_type: MessageType::CallMedia,
            timestamp: Utc::now(),
            payload: encrypted_payload,
            nonce,
            dh_public,
            counter,
            ttl: 60, // Short TTL for ephemeral UDP packets
        }
    }

    /// Create a new text message.
    pub fn new_text(sender: &str, recipient: &str, encrypted_payload: Vec<u8>, nonce: [u8; 12], dh_public: [u8; 32], counter: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            msg_type: MessageType::Text,
            timestamp: Utc::now(),
            payload: encrypted_payload,
            nonce,
            dh_public,
            counter,
            ttl: 30 * 86400, // 30 days default
        }
    }

    /// Create a delivery/read receipt message.
    pub fn new_receipt(sender: &str, recipient: &str, receipt_type: ReceiptType, _msg_id_ref: MessageId, encrypted_payload: Vec<u8>, nonce: [u8; 12], dh_public: [u8; 32], counter: u64) -> Self {
        Self {
            id: Uuid::new_v4(), // MUST be unique to pass through `seen_ids` deduplication
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            msg_type: MessageType::Receipt(receipt_type),
            timestamp: Utc::now(),
            payload: encrypted_payload,
            nonce,
            dh_public,
            counter,
            ttl: 7 * 86400, // 7 days TTL for receipts
        }
    }

    /// Create a presence heartbeat message.
    pub fn new_presence(sender: &str, recipient: &str, info: PresenceInfo, encrypted_payload: Vec<u8>, nonce: [u8; 12], dh_public: [u8; 32], counter: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            sender: sender.to_string(),
            recipient: recipient.to_string(),
            msg_type: MessageType::Presence(info),
            timestamp: Utc::now(),
            payload: encrypted_payload,
            nonce,
            dh_public,
            counter,
            ttl: 300, // 5 min TTL — ephemeral presence
        }
    }

    /// Serialize to bytes for transmission.
    /// PRIVACY: Padded to the next 1KB boundary to prevent traffic analysis.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = bincode::serialize(self).expect("Message serialization failed");
        // Pad to next 1KB boundary (minimum 1KB)
        let pad_size = 1024;
        let target_len = ((data.len() / pad_size) + 1) * pad_size;
        let padding_needed = target_len - data.len();
        // Use PKCS7-style padding: pad bytes = padding length (mod 256)
        let pad_byte = (padding_needed % 256) as u8;
        data.extend(std::iter::repeat(pad_byte).take(padding_needed));
        data
    }

    /// Deserialize from bytes (with padding removal).
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        // Try direct deserialization first (handles both padded and unpadded)
        if let Ok(msg) = bincode::deserialize::<CipherMessage>(data) {
            return Ok(msg);
        }
        // If it fails, the data might have trailing padding — bincode is length-prefixed
        // so it should still work. Return the error.
        bincode::deserialize(data).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_roundtrip() {
        let msg = CipherMessage::new_text(
            "0xabc123",
            "0xdef456",
            vec![1, 2, 3, 4, 5],
            [0u8; 12],
            [7u8; 32],
            0,
        );

        let bytes = msg.to_bytes();
        let decoded = CipherMessage::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.sender, "0xabc123");
        assert_eq!(decoded.recipient, "0xdef456");
        assert_eq!(decoded.payload, vec![1, 2, 3, 4, 5]);
    }
}
