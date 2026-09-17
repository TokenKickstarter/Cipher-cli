//! # Group Chat Module
//!
//! Group management and messaging using MLS-inspired key management:
//! - Create groups with multiple members
//! - Add/remove members with key rotation
//! - Group message broadcast
//! - Admin controls

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::CipherError;

/// Unique group identifier.
pub type GroupId = Uuid;

/// Role within a group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GroupRole {
    /// Creator / owner — can add/remove admins, edit anything
    Owner,
    /// Admin — can add/remove members, change settings
    Admin,
    /// Moderator — can delete messages, ban members, but cannot touch settings
    Moderator,
    /// Regular member
    Member,
    /// Restricted member — customized permissions (e.g. read only)
    Restricted,
}

/// Granular permissions for a member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPermissions {
    pub can_send_messages: bool,
    pub can_send_media: bool,
    pub can_add_members: bool,
    pub can_change_info: bool,
    pub can_delete_messages: bool,
    pub can_ban_users: bool,
    pub can_pin_messages: bool,
}

impl GroupPermissions {
    pub fn default_for(role: &GroupRole) -> Self {
        match role {
            GroupRole::Owner | GroupRole::Admin => Self {
                can_send_messages: true,
                can_send_media: true,
                can_add_members: true,
                can_change_info: true,
                can_delete_messages: true,
                can_ban_users: true,
                can_pin_messages: true,
            },
            GroupRole::Moderator => Self {
                can_send_messages: true,
                can_send_media: true,
                can_add_members: false,
                can_change_info: false,
                can_delete_messages: true,
                can_ban_users: true,
                can_pin_messages: true,
            },
            GroupRole::Member => Self {
                can_send_messages: true,
                can_send_media: true,
                can_add_members: false,
                can_change_info: false,
                can_delete_messages: false,
                can_ban_users: false,
                can_pin_messages: false,
            },
            GroupRole::Restricted => Self {
                can_send_messages: false,
                can_send_media: false,
                can_add_members: false,
                can_change_info: false,
                can_delete_messages: false,
                can_ban_users: false,
                can_pin_messages: false,
            },
        }
    }
}

/// A member of a group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's address (EVM 0x...)
    pub address: String,
    /// Optional @username
    pub username: Option<String>,
    pub role: GroupRole,
    /// Specific toggles
    pub permissions: GroupPermissions,
    /// When they joined
    pub joined_at: DateTime<Utc>,
}

/// Group metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub id: GroupId,
    pub name: String,
    pub description: Option<String>,
    pub avatar_hash: Option<String>,
    pub pinned_message_id: Option<String>,
    pub slow_mode_delay_seconds: u32,
    pub join_link_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub members: Vec<GroupMember>,
    /// Current group epoch (incremented on member change)
    pub epoch: u64,
    /// Group key (rotated each epoch) — 32 bytes
    pub group_key: [u8; 32],
    /// Group's on-chain identity seed (12-word mnemonic)
    pub group_seed: Option<String>,
    /// Whether the group owns an @username on the TKS blockchain
    pub is_registered_on_chain: bool,
}

/// Group manager.
pub struct GroupManager {
    our_address: String,
    groups: Arc<RwLock<HashMap<GroupId, GroupInfo>>>,
}

impl GroupManager {
    pub fn new(our_address: String) -> Self {
        Self {
            our_address,
            groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new group.
    pub async fn create_group(
        &self,
        name: &str,
        member_addresses: Vec<String>,
    ) -> Result<GroupInfo, CipherError> {
        let group_id = Uuid::new_v4();

        // Generate initial group key
        let group_key = generate_group_key();

        // Generate a blockchain identity for the group
        let identity = crate::identity::CipherIdentity::generate()?;
        let group_seed = Some(identity.mnemonic().to_string());

        let mut members = vec![GroupMember {
            address: self.our_address.clone(),
            username: None,
            role: GroupRole::Owner,
            permissions: GroupPermissions::default_for(&GroupRole::Owner),
            joined_at: Utc::now(),
        }];

        for addr in &member_addresses {
            members.push(GroupMember {
                address: addr.clone(),
                username: None,
                role: GroupRole::Member,
                permissions: GroupPermissions::default_for(&GroupRole::Member),
                joined_at: Utc::now(),
            });
        }

        let group = GroupInfo {
            id: group_id,
            name: name.to_string(),
            description: None,
            avatar_hash: None,
            pinned_message_id: None,
            slow_mode_delay_seconds: 0,
            join_link_hash: None,
            created_at: Utc::now(),
            created_by: self.our_address.clone(),
            members,
            epoch: 0,
            group_key,
            group_seed,
            is_registered_on_chain: false,
        };

        self.groups.write().await.insert(group_id, group.clone());
        Ok(group)
    }

    /// Add a member to a group (requires Admin/Owner role).
    pub async fn add_member(
        &self,
        group_id: &GroupId,
        new_member: &str,
    ) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        // Check permissions
        self.check_admin(group)?;

        // Check not already a member
        if group.members.iter().any(|m| m.address == new_member) {
            return Err(CipherError::Network("Already a member".into()));
        }

        group.members.push(GroupMember {
            address: new_member.to_string(),
            username: None,
            role: GroupRole::Member,
            permissions: GroupPermissions::default_for(&GroupRole::Member),
            joined_at: Utc::now(),
        });

        // Rotate group key (forward secrecy)
        group.epoch += 1;
        group.group_key = generate_group_key();

        Ok(())
    }

    /// Remove a member from a group (requires Admin/Owner role).
    pub async fn remove_member(&self, group_id: &GroupId, member: &str) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        self.check_admin(group)?;

        // Can't remove the owner
        if group
            .members
            .iter()
            .any(|m| m.address == member && m.role == GroupRole::Owner)
        {
            return Err(CipherError::Network("Cannot remove group owner".into()));
        }

        group.members.retain(|m| m.address != member);

        // Rotate group key (post-compromise security)
        group.epoch += 1;
        group.group_key = generate_group_key();

        Ok(())
    }

    /// Leave a group.
    pub async fn leave_group(&self, group_id: &GroupId) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        // Owner can't leave (must transfer or delete)
        if group
            .members
            .iter()
            .any(|m| m.address == self.our_address && m.role == GroupRole::Owner)
        {
            return Err(CipherError::Network(
                "Owner must transfer ownership before leaving".into(),
            ));
        }

        group.members.retain(|m| m.address != self.our_address);

        Ok(())
    }

    /// Get group info.
    pub async fn get_group(&self, group_id: &GroupId) -> Option<GroupInfo> {
        self.groups.read().await.get(group_id).cloned()
    }

    /// List all groups we're in.
    pub async fn list_groups(&self) -> Vec<GroupInfo> {
        self.groups.read().await.values().cloned().collect()
    }

    /// Get group member count.
    pub async fn member_count(&self, group_id: &GroupId) -> usize {
        self.groups
            .read()
            .await
            .get(group_id)
            .map(|g| g.members.len())
            .unwrap_or(0)
    }

    /// Update group name (requires Admin/Owner).
    pub async fn update_name(&self, group_id: &GroupId, name: &str) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        self.check_admin(group)?;
        group.name = name.to_string();
        Ok(())
    }

    /// Update member role and permissions (requires Admin/Owner).
    pub async fn update_member_permissions(
        &self,
        group_id: &GroupId,
        member_addr: &str,
        role: GroupRole,
        permissions: GroupPermissions,
    ) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        self.check_admin(group)?;

        let target_member = group
            .members
            .iter_mut()
            .find(|m| m.address == member_addr)
            .ok_or(CipherError::Network("Member not found".into()))?;

        if target_member.role == GroupRole::Owner {
            return Err(CipherError::Network("Cannot modify Owner".into()));
        }

        target_member.role = role;
        target_member.permissions = permissions;
        Ok(())
    }

    /// Pin a message.
    pub async fn pin_message(
        &self,
        group_id: &GroupId,
        message_id: Option<String>,
    ) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        self.check_can_pin(group)?;
        group.pinned_message_id = message_id;
        Ok(())
    }

    /// Set slow mode delay in seconds.
    pub async fn set_slow_mode(
        &self,
        group_id: &GroupId,
        delay_seconds: u32,
    ) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        self.check_admin(group)?;
        group.slow_mode_delay_seconds = delay_seconds;
        Ok(())
    }

    /// Generate an invite link for the group.
    pub async fn generate_join_link(&self, group_id: &GroupId) -> Result<String, CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        self.check_admin_or_invite(group)?;

        let link_hash = Uuid::new_v4().to_string();
        group.join_link_hash = Some(link_hash.clone());

        Ok(format!("cipher://join/{}", link_hash))
    }

    fn check_can_pin(&self, group: &GroupInfo) -> Result<(), CipherError> {
        let m = group.members.iter().find(|m| m.address == self.our_address);
        match m {
            Some(member) if member.permissions.can_pin_messages => Ok(()),
            _ => Err(CipherError::Network(
                "Insufficient permissions to pin messages".into(),
            )),
        }
    }

    fn check_admin_or_invite(&self, group: &GroupInfo) -> Result<(), CipherError> {
        let m = group.members.iter().find(|m| m.address == self.our_address);
        match m {
            Some(member) if member.permissions.can_add_members => Ok(()),
            _ => Err(CipherError::Network(
                "Insufficient permissions to create links".into(),
            )),
        }
    }

    fn check_admin(&self, group: &GroupInfo) -> Result<(), CipherError> {
        let our_role = group
            .members
            .iter()
            .find(|m| m.address == self.our_address)
            .map(|m| &m.role);

        match our_role {
            Some(GroupRole::Owner) | Some(GroupRole::Admin) => Ok(()),
            _ => Err(CipherError::Network("Insufficient permissions".into())),
        }
    }

    /// Register a username for the group on the TKS blockchain.
    pub async fn register_group_username(
        &self,
        group_id: &GroupId,
        username: &str,
    ) -> Result<(), CipherError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or(CipherError::Network("Group not found".into()))?;

        // Must be admin to register a username
        self.check_admin(group)?;

        let seed = group.group_seed.clone().ok_or(CipherError::Network(
            "Group does not have a blockchain seed".into(),
        ))?;

        let identity = crate::identity::CipherIdentity::from_mnemonic(&seed)
            .map_err(|e| CipherError::Network(format!("Invalid group seed: {}", e)))?;

        let registry = crate::username_registry::UsernameRegistry::with_identity(
            identity.display_address(),
            Some(identity),
            crate::username_registry::RegistryBackend::TksNode,
        );

        registry.register(username).await?;
        group.is_registered_on_chain = true;

        Ok(())
    }
}

/// Generate a random 32-byte group key.
fn generate_group_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_group() {
        let mgr = GroupManager::new("0xOwner".into());
        let group = mgr
            .create_group("Test Group", vec!["0xAlice".into(), "0xBob".into()])
            .await
            .unwrap();

        assert_eq!(group.name, "Test Group");
        assert_eq!(group.members.len(), 3); // Owner + 2
        assert_eq!(group.members[0].role, GroupRole::Owner);
        assert_eq!(group.epoch, 0);
    }

    #[tokio::test]
    async fn test_add_remove_member() {
        let mgr = GroupManager::new("0xOwner".into());
        let group = mgr
            .create_group("Chat", vec!["0xAlice".into()])
            .await
            .unwrap();
        let gid = group.id;

        // Add Bob
        mgr.add_member(&gid, "0xBob").await.unwrap();
        assert_eq!(mgr.member_count(&gid).await, 3);

        // Key should have rotated
        let g = mgr.get_group(&gid).await.unwrap();
        assert_eq!(g.epoch, 1);

        // Remove Alice
        mgr.remove_member(&gid, "0xAlice").await.unwrap();
        assert_eq!(mgr.member_count(&gid).await, 2);
        assert_eq!(mgr.get_group(&gid).await.unwrap().epoch, 2);

        // Can't remove owner
        assert!(mgr.remove_member(&gid, "0xOwner").await.is_err());
    }

    #[tokio::test]
    async fn test_group_permissions() {
        let member_mgr = GroupManager::new("0xMember".into());
        // Member creates a group where they're owner
        let group = member_mgr.create_group("My Group", vec![]).await.unwrap();

        // Now simulate a different user trying to modify
        let outsider = GroupManager::new("0xOutsider".into());
        // Outsider can't add to a group they don't own
        // (they don't even have the group in their state)
        assert!(outsider.get_group(&group.id).await.is_none());
    }
}
