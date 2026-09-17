//! # AI Integration Module
//!
//! Enables AI agents to communicate within Cipher:
//! - AI ↔ Human conversations
//! - AI ↔ AI inter-agent communication
//! - OpenClaw integration (local AI assistant)
//! - Custom model providers (OpenAI, Anthropic, local models)
//! - AI agent identity (separate seed phrase / bot account)
//! - Context-aware conversations with persistent memory

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;

// ─────────────────────────────────────────────────────────
// AI Provider Configuration
// ─────────────────────────────────────────────────────────

/// AI model providers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AiProvider {
    /// OpenClaw — local, privacy-first AI assistant
    OpenClaw,
    /// OpenAI (GPT-4, etc.)
    OpenAi,
    /// Anthropic (Claude)
    Anthropic,
    /// Local model (Ollama, llama.cpp, etc.)
    Local(String),
    /// Custom HTTP endpoint
    Custom { name: String, endpoint: String },
}

/// Configuration for an AI provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderConfig {
    pub provider: AiProvider,
    pub api_endpoint: String,
    pub api_key: Option<String>,
    pub model: String,
    pub max_tokens: u32,
    pub temperature: f32,
    pub system_prompt: Option<String>,
}

impl AiProviderConfig {
    /// Default OpenClaw config (runs locally).
    pub fn openclaw() -> Self {
        Self {
            provider: AiProvider::OpenClaw,
            api_endpoint: "http://localhost:3000/api/v1".to_string(),
            api_key: None, // Local, no key needed
            model: "openclaw-default".to_string(),
            max_tokens: 4096,
            temperature: 0.7,
            system_prompt: Some(
                "You are a Cipher AI assistant. You communicate via the Cipher \
                 decentralized messenger. Be helpful, concise, and respect user privacy."
                    .to_string(),
            ),
        }
    }

    /// Default for local models (Ollama).
    pub fn local_model(model_name: &str) -> Self {
        Self {
            provider: AiProvider::Local(model_name.to_string()),
            api_endpoint: "http://localhost:11434/api".to_string(),
            api_key: None,
            model: model_name.to_string(),
            max_tokens: 4096,
            temperature: 0.7,
            system_prompt: None,
        }
    }
}

// ─────────────────────────────────────────────────────────
// AI Agent
// ─────────────────────────────────────────────────────────

/// An AI agent registered on the Cipher network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAgent {
    pub id: uuid::Uuid,
    pub name: String,
    pub address: String, // Agent's Cipher address
    pub owner: String,   // Human owner's address
    pub provider: AiProvider,
    pub model: String,
    pub capabilities: Vec<AiCapability>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub conversations_count: u64,
    pub messages_processed: u64,
}

/// What an AI agent can do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AiCapability {
    /// Natural language chat
    Chat,
    /// Code generation / analysis
    Code,
    /// Image generation
    ImageGeneration,
    /// Image analysis / vision
    Vision,
    /// Web browsing (via OpenClaw)
    WebBrowsing,
    /// File processing
    FileProcessing,
    /// System commands (via OpenClaw)
    SystemAccess,
    /// Payment handling (crypto)
    Payments,
    /// Custom skill
    Custom(String),
}

// ─────────────────────────────────────────────────────────
// AI Conversation
// ─────────────────────────────────────────────────────────

/// Role in an AI conversation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConversationRole {
    System,
    Human,
    Ai,
}

/// A message in an AI conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiMessage {
    pub role: ConversationRole,
    pub content: String,
    pub sender: String,
    pub timestamp: DateTime<Utc>,
    pub tokens_used: Option<u32>,
    pub model: Option<String>,
}

/// Persistent memory entry for an AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    pub key: String,
    pub value: String,
    pub context: String,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}

/// An AI conversation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConversation {
    pub id: uuid::Uuid,
    pub agent_id: uuid::Uuid,
    pub participants: Vec<String>, // Cipher addresses (humans + AIs)
    pub messages: Vec<AiMessage>,
    pub memory: Vec<MemoryEntry>,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
}

// ─────────────────────────────────────────────────────────
// OpenClaw Integration
// ─────────────────────────────────────────────────────────

/// OpenClaw-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenClawConfig {
    /// OpenClaw server endpoint (local)
    pub endpoint: String,
    /// Enabled skills/plugins
    pub skills: Vec<String>,
    /// Persistent memory enabled
    pub memory_enabled: bool,
    /// Browser control enabled
    pub browser_enabled: bool,
    /// System access level
    pub system_access: OpenClawAccess,
}

/// OpenClaw system access levels.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OpenClawAccess {
    Sandboxed,
    ReadOnly,
    Full,
}

impl Default for OpenClawConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:3000".to_string(),
            skills: vec!["web-search".into(), "calculator".into()],
            memory_enabled: true,
            browser_enabled: false,
            system_access: OpenClawAccess::Sandboxed,
        }
    }
}

// ─────────────────────────────────────────────────────────
// AI Manager
// ─────────────────────────────────────────────────────────

/// Manages AI agents and their conversations.
pub struct AiManager {
    our_address: String,
    agents: Arc<RwLock<HashMap<uuid::Uuid, AiAgent>>>,
    providers: Arc<RwLock<HashMap<String, AiProviderConfig>>>,
    conversations: Arc<RwLock<HashMap<uuid::Uuid, AiConversation>>>,
    openclaw: Arc<RwLock<Option<OpenClawConfig>>>,
}

impl AiManager {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            agents: Arc::new(RwLock::new(HashMap::new())),
            providers: Arc::new(RwLock::new(HashMap::new())),
            conversations: Arc::new(RwLock::new(HashMap::new())),
            openclaw: Arc::new(RwLock::new(None)),
        }
    }

    /// Register an AI provider.
    pub async fn register_provider(&self, name: &str, config: AiProviderConfig) {
        self.providers
            .write()
            .await
            .insert(name.to_string(), config);
    }

    /// Configure OpenClaw integration.
    pub async fn setup_openclaw(&self, config: OpenClawConfig) {
        *self.openclaw.write().await = Some(config);
        // Auto-register as a provider
        self.register_provider("openclaw", AiProviderConfig::openclaw())
            .await;
    }

    /// Create a new AI agent.
    pub async fn create_agent(
        &self,
        name: &str,
        provider: AiProvider,
        model: &str,
        capabilities: Vec<AiCapability>,
    ) -> Result<AiAgent, CipherError> {
        let agent = AiAgent {
            id: uuid::Uuid::new_v4(),
            name: name.to_string(),
            address: format!("ai_{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
            owner: self.our_address.clone(),
            provider,
            model: model.to_string(),
            capabilities,
            created_at: Utc::now(),
            is_active: true,
            conversations_count: 0,
            messages_processed: 0,
        };

        self.agents.write().await.insert(agent.id, agent.clone());
        Ok(agent)
    }

    /// Start a conversation with an AI agent.
    pub async fn start_conversation(
        &self,
        agent_id: &uuid::Uuid,
        participants: Vec<String>,
    ) -> Result<AiConversation, CipherError> {
        let agents = self.agents.read().await;
        let agent = agents
            .get(agent_id)
            .ok_or(CipherError::Network("Agent not found".into()))?;

        let mut all_participants = participants;
        if !all_participants.contains(&agent.address) {
            all_participants.push(agent.address.clone());
        }

        let conv = AiConversation {
            id: uuid::Uuid::new_v4(),
            agent_id: *agent_id,
            participants: all_participants,
            messages: Vec::new(),
            memory: Vec::new(),
            created_at: Utc::now(),
            last_active: Utc::now(),
        };

        self.conversations
            .write()
            .await
            .insert(conv.id, conv.clone());
        Ok(conv)
    }

    /// Send a message in an AI conversation.
    pub async fn send_message(
        &self,
        conversation_id: &uuid::Uuid,
        sender: &str,
        content: &str,
    ) -> Result<AiMessage, CipherError> {
        let mut convs = self.conversations.write().await;
        let conv = convs
            .get_mut(conversation_id)
            .ok_or(CipherError::Network("Conversation not found".into()))?;

        let role = {
            let agents = self.agents.read().await;
            if agents.values().any(|a| a.address == sender) {
                ConversationRole::Ai
            } else {
                ConversationRole::Human
            }
        };

        let msg = AiMessage {
            role,
            content: content.to_string(),
            sender: sender.to_string(),
            timestamp: Utc::now(),
            tokens_used: None,
            model: None,
        };

        conv.messages.push(msg.clone());
        conv.last_active = Utc::now();

        // Update agent stats
        let mut agents = self.agents.write().await;
        if let Some(agent) = agents.get_mut(&conv.agent_id) {
            agent.messages_processed += 1;
        }

        Ok(msg)
    }

    /// Generate an AI response (mock — real: call provider API).
    pub async fn generate_response(
        &self,
        conversation_id: &uuid::Uuid,
    ) -> Result<AiMessage, CipherError> {
        let convs = self.conversations.read().await;
        let conv = convs
            .get(conversation_id)
            .ok_or(CipherError::Network("Conversation not found".into()))?;

        let agents = self.agents.read().await;
        let agent = agents
            .get(&conv.agent_id)
            .ok_or(CipherError::Network("Agent not found".into()))?;

        // Mock response (real: HTTP call to provider)
        let last_msg = conv
            .messages
            .last()
            .map(|m| m.content.as_str())
            .unwrap_or("");

        let response_text = format!(
            "[{}] Processed: \"{}\" (model: {})",
            agent.name, last_msg, agent.model
        );

        drop(agents);
        drop(convs);

        let response = AiMessage {
            role: ConversationRole::Ai,
            content: response_text,
            sender: {
                let agents = self.agents.read().await;
                agents
                    .get(&{
                        let convs = self.conversations.read().await;
                        convs.get(conversation_id).unwrap().agent_id
                    })
                    .unwrap()
                    .address
                    .clone()
            },
            timestamp: Utc::now(),
            tokens_used: Some(42),
            model: Some({
                let agents = self.agents.read().await;
                let convs = self.conversations.read().await;
                agents
                    .get(&convs.get(conversation_id).unwrap().agent_id)
                    .unwrap()
                    .model
                    .clone()
            }),
        };

        let mut convs = self.conversations.write().await;
        let conv = convs.get_mut(conversation_id).unwrap();
        conv.messages.push(response.clone());

        Ok(response)
    }

    /// Add memory entry for an agent.
    pub async fn add_memory(
        &self,
        conversation_id: &uuid::Uuid,
        key: &str,
        value: &str,
        context: &str,
    ) -> Result<(), CipherError> {
        let mut convs = self.conversations.write().await;
        let conv = convs
            .get_mut(conversation_id)
            .ok_or(CipherError::Network("Conversation not found".into()))?;

        conv.memory.push(MemoryEntry {
            key: key.to_string(),
            value: value.to_string(),
            context: context.to_string(),
            created_at: Utc::now(),
            last_accessed: Utc::now(),
        });

        Ok(())
    }

    /// Get agent info.
    pub async fn get_agent(&self, id: &uuid::Uuid) -> Option<AiAgent> {
        self.agents.read().await.get(id).cloned()
    }

    /// List all agents.
    pub async fn list_agents(&self) -> Vec<AiAgent> {
        self.agents.read().await.values().cloned().collect()
    }

    /// Check if OpenClaw is configured.
    pub async fn has_openclaw(&self) -> bool {
        self.openclaw.read().await.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_ai_agent() {
        let mgr = AiManager::new("0xHuman".into());
        let agent = mgr
            .create_agent(
                "Assistant",
                AiProvider::OpenClaw,
                "openclaw-default",
                vec![AiCapability::Chat, AiCapability::Code],
            )
            .await
            .unwrap();

        assert_eq!(agent.name, "Assistant");
        assert!(agent.address.starts_with("ai_"));
        assert!(agent.is_active);
    }

    #[tokio::test]
    async fn test_ai_conversation() {
        let mgr = AiManager::new("0xHuman".into());
        let agent = mgr
            .create_agent(
                "Helper",
                AiProvider::Local("llama3".into()),
                "llama3",
                vec![AiCapability::Chat],
            )
            .await
            .unwrap();

        // Start conversation
        let conv = mgr
            .start_conversation(&agent.id, vec!["0xHuman".into()])
            .await
            .unwrap();

        // Human sends message
        let msg = mgr
            .send_message(&conv.id, "0xHuman", "Hello AI!")
            .await
            .unwrap();
        assert_eq!(msg.role, ConversationRole::Human);

        // AI generates response
        let resp = mgr.generate_response(&conv.id).await.unwrap();
        assert_eq!(resp.role, ConversationRole::Ai);
        assert!(resp.content.contains("Hello AI!"));
        assert!(resp.tokens_used.is_some());
    }

    #[tokio::test]
    async fn test_openclaw_setup() {
        let mgr = AiManager::new("0xHuman".into());
        assert!(!mgr.has_openclaw().await);

        mgr.setup_openclaw(OpenClawConfig::default()).await;
        assert!(mgr.has_openclaw().await);
    }

    #[tokio::test]
    async fn test_ai_to_ai_communication() {
        let mgr = AiManager::new("0xHuman".into());

        let agent1 = mgr
            .create_agent(
                "Researcher",
                AiProvider::OpenClaw,
                "openclaw",
                vec![AiCapability::Chat, AiCapability::WebBrowsing],
            )
            .await
            .unwrap();

        let agent2 = mgr
            .create_agent(
                "Coder",
                AiProvider::Local("codellama".into()),
                "codellama",
                vec![AiCapability::Chat, AiCapability::Code],
            )
            .await
            .unwrap();

        // AI-to-AI conversation
        let conv = mgr
            .start_conversation(
                &agent1.id,
                vec![agent1.address.clone(), agent2.address.clone()],
            )
            .await
            .unwrap();

        // Agent1 sends to Agent2
        let msg = mgr
            .send_message(&conv.id, &agent1.address, "Research this topic")
            .await
            .unwrap();
        assert_eq!(msg.role, ConversationRole::Ai);

        // Both are AI participants
        assert_eq!(conv.participants.len(), 2);
    }

    #[tokio::test]
    async fn test_persistent_memory() {
        let mgr = AiManager::new("0xHuman".into());
        let agent = mgr
            .create_agent(
                "MemBot",
                AiProvider::OpenClaw,
                "openclaw",
                vec![AiCapability::Chat],
            )
            .await
            .unwrap();

        let conv = mgr
            .start_conversation(&agent.id, vec!["0xHuman".into()])
            .await
            .unwrap();

        mgr.add_memory(&conv.id, "user_name", "Alice", "User introduced herself")
            .await
            .unwrap();

        let convs = mgr.conversations.read().await;
        let c = convs.get(&conv.id).unwrap();
        assert_eq!(c.memory.len(), 1);
        assert_eq!(c.memory[0].key, "user_name");
        assert_eq!(c.memory[0].value, "Alice");
    }
}
