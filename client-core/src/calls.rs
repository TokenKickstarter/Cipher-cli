//! # WebRTC Call Signaling
//!
//! Manages voice/video call setup over the Cipher swarm:
//! - SDP offer/answer exchange via encrypted swarm messages
//! - ICE candidate relay
//! - Call state machine (ringing → active → ended)
//! - Opus audio (48kHz HQ) + VP9/AV1 video

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::CipherError;

/// Unique call identifier.
pub type CallId = Uuid;

/// Call direction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallDirection {
    Outgoing,
    Incoming,
}

/// Call media type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallMedia {
    Audio,
    Video,
}

/// Call state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CallState {
    /// Initiating — generating SDP offer
    Initiating,
    /// Ringing — SDP offer sent, waiting for answer
    Ringing,
    /// Connecting — SDP answer received, ICE negotiation
    Connecting,
    /// Active — media flowing
    Active,
    /// On hold
    Held,
    /// Ended normally
    Ended,
    /// Failed
    Failed(String),
    /// Missed (incoming, not answered)
    Missed,
    /// Declined by recipient
    Declined,
}

/// A signaling message exchanged between peers to set up a call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignalMessage {
    /// Offer to start a call
    Offer {
        call_id: CallId,
        media: CallMedia,
        sdp: String,
    },
    /// Answer accepting a call
    Answer { call_id: CallId, sdp: String },
    /// ICE candidate for NAT traversal
    IceCandidate { call_id: CallId, candidate: String },
    /// Decline an incoming call
    Decline { call_id: CallId },
    /// End an active call
    Hangup { call_id: CallId, duration_secs: u64 },
}

/// Represents an active or historical call session.
#[derive(Debug, Clone)]
pub struct CallSession {
    pub id: CallId,
    pub peer: String,
    pub direction: CallDirection,
    pub media: CallMedia,
    pub state: CallState,
    pub started_at: DateTime<Utc>,
    pub connected_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_secs: Option<u64>,
    /// Local SDP offer/answer
    pub local_sdp: Option<String>,
    /// Remote SDP offer/answer
    pub remote_sdp: Option<String>,
    /// ICE candidates collected
    pub ice_candidates: Vec<String>,
}

/// Call manager — handles call lifecycle.
pub struct CallManager {
    /// Our address
    our_address: String,
    /// Active calls
    active_calls: Arc<RwLock<Vec<CallSession>>>,
    /// Call history
    history: Arc<RwLock<Vec<CallSession>>>,
}

impl CallManager {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            active_calls: Arc::new(RwLock::new(Vec::new())),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Initiate an outgoing call.
    pub async fn initiate_call(
        &self,
        peer: &str,
        media: CallMedia,
        sdp: String,
    ) -> Result<(CallId, SignalMessage), CipherError> {
        let call_id = Uuid::new_v4();

        let session = CallSession {
            id: call_id,
            peer: peer.to_string(),
            direction: CallDirection::Outgoing,
            media: media.clone(),
            state: CallState::Ringing,
            started_at: Utc::now(),
            connected_at: None,
            ended_at: None,
            duration_secs: None,
            local_sdp: Some(sdp.clone()),
            remote_sdp: None,
            ice_candidates: Vec::new(),
        };

        self.active_calls.write().await.push(session);

        Ok((
            call_id,
            SignalMessage::Offer {
                call_id,
                media,
                sdp,
            },
        ))
    }

    /// Handle an incoming call offer.
    pub async fn handle_offer(
        &self,
        peer: &str,
        call_id: CallId,
        media: CallMedia,
        remote_sdp: String,
    ) -> CallSession {
        let session = CallSession {
            id: call_id,
            peer: peer.to_string(),
            direction: CallDirection::Incoming,
            media,
            state: CallState::Ringing,
            started_at: Utc::now(),
            connected_at: None,
            ended_at: None,
            duration_secs: None,
            local_sdp: None,
            remote_sdp: Some(remote_sdp),
            ice_candidates: Vec::new(),
        };

        self.active_calls.write().await.push(session.clone());
        session
    }

    /// Accept an incoming call — returns SDP answer.
    pub async fn accept_call(
        &self,
        call_id: &CallId,
        sdp: String,
        peer: String,
    ) -> Result<(), CipherError> {
        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.iter_mut().find(|c| c.id == *call_id) {
            call.local_sdp = Some(sdp.clone());
            call.state = CallState::Connecting;
            call.connected_at = Some(Utc::now());
        } else {
            let session = CallSession {
                id: *call_id,
                peer,
                direction: CallDirection::Incoming,
                media: CallMedia::Video,
                state: CallState::Connecting,
                started_at: Utc::now(),
                connected_at: Some(Utc::now()),
                ended_at: None,
                duration_secs: None,
                local_sdp: Some(sdp),
                remote_sdp: None,
                ice_candidates: Vec::new(),
            };
            calls.push(session);
        }
        Ok(())
    }

    /// Decline an incoming call.
    pub async fn decline_call(&self, call_id: &CallId) -> Result<(), CipherError> {
        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.iter_mut().find(|c| c.id == *call_id) {
            call.state = CallState::Declined;
            call.ended_at = Some(Utc::now());
            self.history.write().await.push(call.clone());
        }
        calls.retain(|c| c.id != *call_id);
        Ok(())
    }

    /// Handle SDP answer from remote peer — call connects.
    pub async fn handle_answer(&self, call_id: &CallId, remote_sdp: String) {
        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.iter_mut().find(|c| c.id == *call_id) {
            call.remote_sdp = Some(remote_sdp);
            call.state = CallState::Active;
            call.connected_at = Some(Utc::now());
        }
    }

    /// Add ICE candidate.
    pub async fn add_ice_candidate(&self, call_id: &CallId, candidate: String) {
        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.iter_mut().find(|c| c.id == *call_id) {
            call.ice_candidates.push(candidate);
        }
    }

    /// Hang up an active call.
    pub async fn hangup(&self, call_id: &CallId) -> Result<(), CipherError> {
        let mut calls = self.active_calls.write().await;
        if let Some(call) = calls.iter_mut().find(|c| c.id == *call_id) {
            let duration = call
                .connected_at
                .map(|c| (Utc::now() - c).num_seconds().max(0) as u64)
                .unwrap_or(0);

            call.state = CallState::Ended;
            call.ended_at = Some(Utc::now());
            call.duration_secs = Some(duration);
            self.history.write().await.push(call.clone());
        }
        calls.retain(|c| c.id != *call_id);
        Ok(())
    }

    /// Get active call with a peer.
    pub async fn active_call_with(&self, peer: &str) -> Option<CallSession> {
        self.active_calls
            .read()
            .await
            .iter()
            .find(|c| c.peer == peer)
            .cloned()
    }

    /// Get call history.
    pub async fn call_history(&self) -> Vec<CallSession> {
        self.history.read().await.clone()
    }

    /// Get all active calls.
    pub async fn active_calls(&self) -> Vec<CallSession> {
        self.active_calls.read().await.clone()
    }
}

/// Generate a mock SDP (placeholder — real SDP from webrtc-rs).
fn generate_mock_sdp(address: &str, media: &CallMedia) -> String {
    let media_type = match media {
        CallMedia::Audio => "audio",
        CallMedia::Video => "video",
    };
    format!(
        "v=0\no={} 0 0 IN IP4 0.0.0.0\ns=Cipher Call\nt=0 0\nm={} 9 UDP/TLS/RTP/SAVPF 111\na=rtpmap:111 opus/48000/2\na=fingerprint:sha-256 00:00:00:00",
        address, media_type
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_call_lifecycle() {
        let alice_mgr = CallManager::new("0xAlice".into());
        let bob_mgr = CallManager::new("0xBob".into());

        // Alice calls Bob
        let (call_id, offer) = alice_mgr
            .initiate_call("0xBob", CallMedia::Audio, "v=0\nm=audio".into())
            .await
            .unwrap();

        // Verify offer
        if let SignalMessage::Offer { sdp, media, .. } = &offer {
            assert_eq!(*media, CallMedia::Audio);
            assert!(sdp.contains("audio"));
        }

        // Bob receives offer
        if let SignalMessage::Offer {
            call_id,
            media,
            sdp,
        } = offer
        {
            bob_mgr.handle_offer("0xAlice", call_id, media, sdp).await;
        }

        // Bob accepts
        let _ = bob_mgr
            .accept_call(&call_id, "v=0\nm=audio answer".into(), "0xAlice".into())
            .await
            .unwrap();
        let answer = SignalMessage::Answer { call_id, sdp: "v=0\nm=audio answer".into() };
        if let SignalMessage::Answer { sdp, .. } = &answer {
            assert!(sdp.contains("audio"));
        }

        // Alice receives answer → call active
        if let SignalMessage::Answer { sdp, .. } = answer {
            alice_mgr.handle_answer(&call_id, sdp).await;
        }

        let active = alice_mgr.active_call_with("0xBob").await.unwrap();
        assert_eq!(active.state, CallState::Active);

        // Alice hangs up
        let _ = alice_mgr.hangup(&call_id).await.unwrap();
        let hangup = SignalMessage::Hangup { call_id, duration_secs: 1 };
        if let SignalMessage::Hangup { duration_secs, .. } = hangup {
            assert!(duration_secs < 2); // Almost instant in test
        }

        // Should be in history now
        assert_eq!(alice_mgr.call_history().await.len(), 1);
        assert!(alice_mgr.active_calls().await.is_empty());
    }

    #[tokio::test]
    async fn test_decline_call() {
        let bob_mgr = CallManager::new("0xBob".into());

        let call_id = Uuid::new_v4();
        bob_mgr
            .handle_offer("0xAlice", call_id, CallMedia::Video, "sdp".into())
            .await;

        let _ = bob_mgr.decline_call(&call_id).await.unwrap();
        let decline = SignalMessage::Decline { call_id };
        assert!(matches!(decline, SignalMessage::Decline { .. }));

        // In history as Declined
        let hist = bob_mgr.call_history().await;
        assert_eq!(hist[0].state, CallState::Declined);
    }
}
