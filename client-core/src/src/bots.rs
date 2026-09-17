//! # Bots Module
//!
//! Telegram-style bot platform for Cipher:
//! - Bots have their own identity (seed phrase → keys)
//! - Command handlers (/start, /help, custom commands)
//! - Inline queries (search and respond inline)
//! - Webhook/polling message handlers
//! - Bot API for external services
//! - Bot permissions and rate limiting

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;

/// Unique bot identifier.
pub type BotId = uuid::Uuid;

/// Bot type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BotType {
    /// Standard bot — responds to commands
    Standard,
    /// AI bot — powered by language model
    Ai,
    /// Service bot — automated notifications/actions
    Service,
    /// Custom bot
    Custom(String),
}

/// Bot permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotPermissions {
    pub can_read_messages: bool,
    pub can_send_messages: bool,
    pub can_send_media: bool,
    pub can_manage_groups: bool,
    pub can_access_files: bool,
    pub can_make_payments: bool,
    pub rate_limit_per_minute: u32,
}

impl Default for BotPermissions {
    fn default() -> Self {
        Self {
            can_read_messages: true,
            can_send_messages: true,
            can_send_media: true,
            can_manage_groups: false,
            can_access_files: false,
            can_make_payments: false,
            rate_limit_per_minute: 60,
        }
    }
}

/// A registered bot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bot {
    pub id: BotId,
    pub name: String,
    pub username: String,
    pub description: String,
    pub bot_type: BotType,
    pub owner: String,
    pub address: String, // Bot's own Cipher address
    pub created_at: DateTime<Utc>,
    pub permissions: BotPermissions,
    pub commands: Vec<BotCommand>,
    pub is_active: bool,
    pub message_count: u64,
}

/// A bot command definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotCommand {
    pub command: String, // e.g., "start", "help", "price"
    pub description: String,
    pub usage: Option<String>, // e.g., "/price BTC"
}

/// An incoming bot update (message, command, callback).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BotUpdate {
    /// Text message received
    Message {
        from: String,
        chat_id: String,
        text: String,
        timestamp: DateTime<Utc>,
    },
    /// Command received (e.g., /start)
    Command {
        from: String,
        chat_id: String,
        command: String,
        args: Vec<String>,
        timestamp: DateTime<Utc>,
    },
    /// Inline query
    InlineQuery {
        from: String,
        query: String,
        offset: String,
    },
    /// Callback from inline keyboard button
    Callback {
        from: String,
        chat_id: String,
        data: String,
    },
}

/// Bot response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BotResponse {
    /// Send text reply
    Text(String),
    /// Send text with inline keyboard
    TextWithButtons {
        text: String,
        buttons: Vec<Vec<InlineButton>>,
    },
    /// Send media
    Media {
        caption: Option<String>,
        file_hash: String,
        mime_type: String,
    },
    /// No response
    None,
}

/// Inline keyboard button.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InlineButton {
    pub text: String,
    pub callback_data: Option<String>,
    pub url: Option<String>,
}

/// Bot manager — creates and manages bots.
pub struct BotManager {
    our_address: String,
    bots: Arc<RwLock<HashMap<BotId, Bot>>>,
    /// Pending updates for each bot
    updates: Arc<RwLock<HashMap<BotId, Vec<BotUpdate>>>>,
    /// Command handlers registered by bots
    handlers: Arc<RwLock<HashMap<String, BotId>>>,
}

impl BotManager {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            bots: Arc::new(RwLock::new(HashMap::new())),
            updates: Arc::new(RwLock::new(HashMap::new())),
            handlers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create and register a new bot.
    pub async fn create_bot(
        &self,
        name: &str,
        username: &str,
        bot_type: BotType,
        commands: Vec<BotCommand>,
    ) -> Result<Bot, CipherError> {
        let bot = Bot {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            username: username.to_string(),
            description: String::new(),
            bot_type,
            owner: self.our_address.clone(),
            address: format!("bot_{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            created_at: Utc::now(),
            permissions: BotPermissions::default(),
            commands: commands.clone(),
            is_active: true,
            message_count: 0,
        };

        // Register command handlers
        let mut handlers = self.handlers.write().await;
        for cmd in &commands {
            handlers.insert(format!("/{}", cmd.command), bot.id);
        }

        self.bots.write().await.insert(bot.id, bot.clone());
        self.updates.write().await.insert(bot.id, Vec::new());
        Ok(bot)
    }

    /// Push an update to a bot.
    pub async fn push_update(&self, bot_id: &BotId, update: BotUpdate) -> Result<(), CipherError> {
        let mut updates = self.updates.write().await;
        updates
            .get_mut(bot_id)
            .ok_or(CipherError::Network("Bot not found".into()))?
            .push(update);
        Ok(())
    }

    /// Get pending updates for a bot (polling).
    pub async fn get_updates(&self, bot_id: &BotId) -> Vec<BotUpdate> {
        let mut updates = self.updates.write().await;
        updates
            .get_mut(bot_id)
            .map(|u| std::mem::take(u))
            .unwrap_or_default()
    }

    /// Route incoming message to appropriate bot.
    pub async fn route_message(&self, from: &str, chat_id: &str, text: &str) -> Option<BotId> {
        if text.starts_with('/') {
            let command = text.split_whitespace().next().unwrap_or("");
            let handlers = self.handlers.read().await;
            if let Some(bot_id) = handlers.get(command) {
                let args: Vec<String> = text
                    .split_whitespace()
                    .skip(1)
                    .map(|s| s.to_string())
                    .collect();

                let update = BotUpdate::Command {
                    from: from.to_string(),
                    chat_id: chat_id.to_string(),
                    command: command.to_string(),
                    args,
                    timestamp: Utc::now(),
                };

                let _ = self.push_update(bot_id, update).await;
                return Some(*bot_id);
            }
        }
        None
    }

    /// Get bot info.
    pub async fn get_bot(&self, bot_id: &BotId) -> Option<Bot> {
        self.bots.read().await.get(bot_id).cloned()
    }

    /// List all bots owned by us.
    pub async fn list_bots(&self) -> Vec<Bot> {
        self.bots
            .read()
            .await
            .values()
            .filter(|b| b.owner == self.our_address)
            .cloned()
            .collect()
    }

    /// Deactivate a bot.
    pub async fn deactivate_bot(&self, bot_id: &BotId) -> Result<(), CipherError> {
        let mut bots = self.bots.write().await;
        let bot = bots
            .get_mut(bot_id)
            .ok_or(CipherError::Network("Bot not found".into()))?;
        bot.is_active = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_bot() {
        let mgr = BotManager::new("0xOwner".into());
        let bot = mgr
            .create_bot(
                "Price Bot",
                "price_bot",
                BotType::Service,
                vec![
                    BotCommand {
                        command: "price".into(),
                        description: "Get crypto price".into(),
                        usage: Some("/price BTC".into()),
                    },
                    BotCommand {
                        command: "help".into(),
                        description: "Show help".into(),
                        usage: None,
                    },
                ],
            )
            .await
            .unwrap();

        assert_eq!(bot.name, "Price Bot");
        assert!(bot.is_active);
        assert_eq!(bot.commands.len(), 2);
    }

    #[tokio::test]
    async fn test_route_command() {
        let mgr = BotManager::new("0xOwner".into());
        let bot = mgr
            .create_bot(
                "Test Bot",
                "test_bot",
                BotType::Standard,
                vec![BotCommand {
                    command: "start".into(),
                    description: "Start".into(),
                    usage: None,
                }],
            )
            .await
            .unwrap();

        // Route a command
        let routed = mgr
            .route_message("0xUser", "chat-1", "/start hello world")
            .await;
        assert_eq!(routed, Some(bot.id));

        // Bot should have the update
        let updates = mgr.get_updates(&bot.id).await;
        assert_eq!(updates.len(), 1);
        if let BotUpdate::Command { command, args, .. } = &updates[0] {
            assert_eq!(command, "/start");
            assert_eq!(args, &vec!["hello".to_string(), "world".to_string()]);
        }
    }

    #[tokio::test]
    async fn test_bot_updates() {
        let mgr = BotManager::new("0xOwner".into());
        let bot = mgr
            .create_bot("Bot", "bot", BotType::Standard, vec![])
            .await
            .unwrap();

        mgr.push_update(
            &bot.id,
            BotUpdate::Message {
                from: "0xUser".into(),
                chat_id: "chat-1".into(),
                text: "Hello bot".into(),
                timestamp: Utc::now(),
            },
        )
        .await
        .unwrap();

        let updates = mgr.get_updates(&bot.id).await;
        assert_eq!(updates.len(), 1);

        // After polling, updates are drained
        let empty = mgr.get_updates(&bot.id).await;
        assert!(empty.is_empty());
    }
}
