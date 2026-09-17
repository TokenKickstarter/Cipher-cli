//! # Channels Module
//!
//! Telegram-style broadcast channels:
//! - Public/private channels with unlimited subscribers
//! - Only admins can post, subscribers read
//! - Channel discovery via swarm DHT
//! - Pinned messages, media, file sharing
//! - Channel-level encryption key for subscriber access

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;

/// Unique channel identifier.
pub type ChannelId = uuid::Uuid;

/// Channel visibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelVisibility {
    /// Anyone can find and join
    Public,
    /// Invite-only, hidden from search
    Private,
}

/// Role within a channel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChannelRole {
    Owner,
    Admin,
    Subscriber,
}

/// A channel subscriber.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelSubscriber {
    pub address: String,
    pub username: Option<String>,
    pub role: ChannelRole,
    pub joined_at: DateTime<Utc>,
    pub is_muted: bool,
}

/// A channel post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPost {
    pub id: uuid::Uuid,
    pub author: String,
    pub content: PostContent,
    pub timestamp: DateTime<Utc>,
    pub views: u64,
    pub reactions: HashMap<String, u32>,
    pub is_pinned: bool,
    pub reply_to: Option<uuid::Uuid>,
}

/// Content of a channel post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PostContent {
    Text(String),
    Media {
        caption: Option<String>,
        file_hash: String,
        mime_type: String,
    },
    Poll {
        question: String,
        options: Vec<String>,
        votes: HashMap<usize, u32>,
    },
    File {
        name: String,
        size: u64,
        hash: String,
    },
}

/// Channel metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: ChannelId,
    pub name: String,
    pub handle: Option<String>, // @channel_handle
    pub description: Option<String>,
    pub avatar_hash: Option<String>,
    pub visibility: ChannelVisibility,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub subscribers: Vec<ChannelSubscriber>,
    pub posts: Vec<ChannelPost>,
    pub channel_key: [u8; 32], // Symmetric key for content encryption
    pub subscriber_count: u64,
    pub allow_comments: bool,
}

/// Channel manager.
pub struct ChannelManager {
    our_address: String,
    channels: Arc<RwLock<HashMap<ChannelId, Channel>>>,
}

impl ChannelManager {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new channel.
    pub async fn create_channel(
        &self,
        name: &str,
        visibility: ChannelVisibility,
    ) -> Result<Channel, CipherError> {
        let channel_key = {
            let mut key = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut key);
            key
        };

        let channel = Channel {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            handle: None,
            description: None,
            avatar_hash: None,
            visibility,
            created_at: Utc::now(),
            created_by: self.our_address.clone(),
            subscribers: vec![ChannelSubscriber {
                address: self.our_address.clone(),
                username: None,
                role: ChannelRole::Owner,
                joined_at: Utc::now(),
                is_muted: false,
            }],
            posts: Vec::new(),
            channel_key,
            subscriber_count: 1,
            allow_comments: false,
        };

        self.channels
            .write()
            .await
            .insert(channel.id, channel.clone());
        Ok(channel)
    }

    /// Set channel handle (@name).
    pub async fn set_handle(
        &self,
        channel_id: &ChannelId,
        handle: &str,
    ) -> Result<(), CipherError> {
        let mut channels = self.channels.write().await;
        let ch = channels
            .get_mut(channel_id)
            .ok_or(CipherError::Network("Channel not found".into()))?;
        self.check_channel_admin(ch)?;
        ch.handle = Some(handle.to_string());
        Ok(())
    }

    /// Subscribe to a channel.
    pub async fn subscribe(&self, channel_id: &ChannelId) -> Result<(), CipherError> {
        let mut channels = self.channels.write().await;
        let ch = channels
            .get_mut(channel_id)
            .ok_or(CipherError::Network("Channel not found".into()))?;

        if ch.subscribers.iter().any(|s| s.address == self.our_address) {
            return Err(CipherError::Network("Already subscribed".into()));
        }

        ch.subscribers.push(ChannelSubscriber {
            address: self.our_address.clone(),
            username: None,
            role: ChannelRole::Subscriber,
            joined_at: Utc::now(),
            is_muted: false,
        });
        ch.subscriber_count += 1;
        Ok(())
    }

    /// Unsubscribe from a channel.
    pub async fn unsubscribe(&self, channel_id: &ChannelId) -> Result<(), CipherError> {
        let mut channels = self.channels.write().await;
        let ch = channels
            .get_mut(channel_id)
            .ok_or(CipherError::Network("Channel not found".into()))?;

        // Owner can't unsub
        if ch
            .subscribers
            .iter()
            .any(|s| s.address == self.our_address && s.role == ChannelRole::Owner)
        {
            return Err(CipherError::Network("Owner cannot unsubscribe".into()));
        }

        ch.subscribers.retain(|s| s.address != self.our_address);
        ch.subscriber_count = ch.subscriber_count.saturating_sub(1);
        Ok(())
    }

    /// Post to a channel (admin/owner only).
    pub async fn publish_post(
        &self,
        channel_id: &ChannelId,
        content: PostContent,
    ) -> Result<uuid::Uuid, CipherError> {
        let mut channels = self.channels.write().await;
        let ch = channels
            .get_mut(channel_id)
            .ok_or(CipherError::Network("Channel not found".into()))?;

        self.check_channel_admin(ch)?;

        let post = ChannelPost {
            id: uuid::Uuid::new_v4(),
            author: self.our_address.clone(),
            content,
            timestamp: Utc::now(),
            views: 0,
            reactions: HashMap::new(),
            is_pinned: false,
            reply_to: None,
        };

        let post_id = post.id;
        ch.posts.push(post);
        Ok(post_id)
    }

    /// Pin a post.
    pub async fn pin_post(
        &self,
        channel_id: &ChannelId,
        post_id: &uuid::Uuid,
    ) -> Result<(), CipherError> {
        let mut channels = self.channels.write().await;
        let ch = channels
            .get_mut(channel_id)
            .ok_or(CipherError::Network("Channel not found".into()))?;
        self.check_channel_admin(ch)?;

        if let Some(post) = ch.posts.iter_mut().find(|p| p.id == *post_id) {
            post.is_pinned = true;
        }
        Ok(())
    }

    /// Get channel info.
    pub async fn get_channel(&self, id: &ChannelId) -> Option<Channel> {
        self.channels.read().await.get(id).cloned()
    }

    /// List owned/subscribed channels.
    pub async fn list_channels(&self) -> Vec<Channel> {
        self.channels.read().await.values().cloned().collect()
    }

    fn check_channel_admin(&self, ch: &Channel) -> Result<(), CipherError> {
        let role = ch
            .subscribers
            .iter()
            .find(|s| s.address == self.our_address)
            .map(|s| &s.role);
        match role {
            Some(ChannelRole::Owner) | Some(ChannelRole::Admin) => Ok(()),
            _ => Err(CipherError::Network("Not an admin".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_channel() {
        let mgr = ChannelManager::new("0xOwner".into());
        let ch = mgr
            .create_channel("News", ChannelVisibility::Public)
            .await
            .unwrap();
        assert_eq!(ch.name, "News");
        assert_eq!(ch.subscriber_count, 1);
        assert_eq!(ch.subscribers[0].role, ChannelRole::Owner);
    }

    #[tokio::test]
    async fn test_subscribe_and_post() {
        let owner_mgr = ChannelManager::new("0xOwner".into());
        let ch = owner_mgr
            .create_channel("Tech", ChannelVisibility::Public)
            .await
            .unwrap();
        let cid = ch.id;

        // Post
        let post_id = owner_mgr
            .publish_post(&cid, PostContent::Text("Hello subscribers!".into()))
            .await
            .unwrap();

        // Pin
        owner_mgr.pin_post(&cid, &post_id).await.unwrap();
        let ch = owner_mgr.get_channel(&cid).await.unwrap();
        assert!(ch.posts[0].is_pinned);
    }

    #[tokio::test]
    async fn test_channel_handle() {
        let mgr = ChannelManager::new("0xOwner".into());
        let ch = mgr
            .create_channel("Cipher News", ChannelVisibility::Public)
            .await
            .unwrap();
        mgr.set_handle(&ch.id, "cipher_news").await.unwrap();
        let ch = mgr.get_channel(&ch.id).await.unwrap();
        assert_eq!(ch.handle, Some("cipher_news".into()));
    }
}
