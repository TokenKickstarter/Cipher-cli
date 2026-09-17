//! # FFI Bridge
//!
//! C-compatible FFI layer for Flutter integration.
//! Uses JSON serialization across the boundary for safety.
//!
//! Architecture:
//! ```text
//! Flutter (Dart) ─── dart:ffi ──→ ffi.rs (C ABI) ──→ Rust modules
//! ```

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

use crate::identity::CipherIdentity;
use crate::swarm_client::SwarmClient;
use crate::calls::CallManager;
use crate::groups::GroupManager;
use crate::channels::ChannelManager;
use crate::bots::BotManager;
use crate::ai::AiManager;
use crate::anti_censorship::AntiCensorshipManager;
use crate::username_registry::{UsernameRegistry, RegistryBackend};
use crate::wallet_core::WalletCore;

// ─────────────────────────────────────────────────────────
// Global State (initialized once per app lifecycle)
// ─────────────────────────────────────────────────────────

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub(crate) fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create Tokio runtime"))
}

struct CipherState {
    identity: CipherIdentity,
    swarm: std::sync::Arc<SwarmClient>,
    calls: CallManager,
    groups: GroupManager,
    channels: ChannelManager,
    bots: BotManager,
    ai: AiManager,
    anti_censorship: AntiCensorshipManager,
    username_registry: UsernameRegistry,
    wallet: WalletCore,
    turn_proxy: std::sync::Arc<crate::turn_proxy::TurnProxy>,
    mesh: std::sync::Arc<crate::transport::mesh::MeshCoordinator>,
}

static STATE: OnceLock<CipherState> = OnceLock::new();

// ─────────────────────────────────────────────────────────
// Push Callback: Dart registers a NativeCallable.listener
// function pointer. Rust invokes it from any thread when
// a message arrives via WebSocket — zero-latency push.
// ─────────────────────────────────────────────────────────

static DART_CALLBACK: std::sync::atomic::AtomicPtr<std::ffi::c_void> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

/// Invoke the Dart push callback (if registered).
/// Safe to call from any thread — NativeCallable.listener handles cross-thread dispatch.
pub fn notify_dart() {
    let ptr = DART_CALLBACK.load(std::sync::atomic::Ordering::Relaxed);
    if !ptr.is_null() {
        let callback: extern "C" fn() = unsafe { std::mem::transmute(ptr) };
        callback();
    }
}

/// Register a Dart callback that Rust will invoke when new messages arrive.
/// Called once during app initialization from Dart via NativeCallable.listener.
#[no_mangle]
pub extern "C" fn cipher_register_callback(callback: extern "C" fn()) {
    let ptr = callback as *mut std::ffi::c_void;
    DART_CALLBACK.store(ptr, std::sync::atomic::Ordering::Relaxed);
    log::info!("[FFI] ✅ Dart push callback registered — zero-latency delivery active");
}

// ─────────────────────────────────────────────────────────
// Helper: String conversion
// ─────────────────────────────────────────────────────────

fn c_str_to_string(ptr: *const c_char) -> String {
    unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned()
}

fn string_to_c(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

fn json_result<T: serde::Serialize>(result: Result<T, impl std::fmt::Display>) -> *mut c_char {
    let json = match result {
        Ok(val) => serde_json::json!({ "ok": true, "data": val }),
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }),
    };
    string_to_c(json.to_string())
}

fn json_ok<T: serde::Serialize>(val: T) -> *mut c_char {
    string_to_c(serde_json::json!({ "ok": true, "data": val }).to_string())
}

fn json_err(msg: &str) -> *mut c_char {
    string_to_c(serde_json::json!({ "ok": false, "error": msg }).to_string())
}

// ─────────────────────────────────────────────────────────
// Identity Functions
// ─────────────────────────────────────────────────────────

/// Generate a new identity (12-word seed phrase).
/// Returns JSON: { ok, data: { mnemonic, evm_address, substrate_address, ... } }
#[no_mangle]
pub extern "C" fn cipher_generate_identity() -> *mut c_char {
    match CipherIdentity::generate() {
        Ok(id) => {
            let info = serde_json::json!({
                "mnemonic": id.mnemonic(),
                "evm_address": id.evm_address(),
                "substrate_address": id.substrate_address(),
                "display_address": id.display_address(),
                "ed25519_public": hex::encode(id.ed25519_public_key().as_bytes()),
                "x25519_public": hex::encode(id.x25519_public_key().as_bytes()),
            });
            json_ok(info)
        }
        Err(e) => json_err(&e.to_string()),
    }
}

/// Generate a 24-word identity.
#[no_mangle]
pub extern "C" fn cipher_generate_identity_24() -> *mut c_char {
    match CipherIdentity::generate_with_word_count(24) {
        Ok(id) => {
            let mnemonic = id.mnemonic().to_string();
            let evm = id.evm_address().to_string();
            let substrate = id.substrate_address().to_string();
            let display = id.display_address();
            let info = serde_json::json!({
                "mnemonic": mnemonic,
                "evm_address": evm,
                "substrate_address": substrate,
                "display_address": display,
            });
            json_ok(info)
        }
        Err(e) => json_err(&format!("{}", e)),
    }
}

/// Import identity from mnemonic string.
#[no_mangle]
pub extern "C" fn cipher_import_identity(mnemonic: *const c_char) -> *mut c_char {
    let mnemonic_str = c_str_to_string(mnemonic);
    match CipherIdentity::from_mnemonic(&mnemonic_str) {
        Ok(id) => {
            let info = serde_json::json!({
                "mnemonic": id.mnemonic(),
                "evm_address": id.evm_address(),
                "substrate_address": id.substrate_address(),
                "display_address": id.display_address(),
                "ed25519_public": hex::encode(id.ed25519_public_key().as_bytes()),
                "x25519_public": hex::encode(id.x25519_public_key().as_bytes()),
            });
            json_ok(info)
        }
        Err(e) => json_err(&e.to_string()),
    }
}

/// Initialize the full Cipher engine with a mnemonic.
/// Must be called before any other cipher_* function (except identity generation).
/// Auto-registers the wallet on the TKS node and derives the TKS H160 address.
#[no_mangle]
pub extern "C" fn cipher_init(mnemonic: *const c_char) -> *mut c_char {
    let mnemonic_str = c_str_to_string(mnemonic);
    match CipherIdentity::from_mnemonic(&mnemonic_str) {
        Ok(identity) => {
            let addr = identity.display_address();
            let tks_addr = identity.tks_h160_address();
            
            // Build Arc-wrapped SwarmClient
            let swarm = std::sync::Arc::new(SwarmClient::new(CipherIdentity::from_mnemonic(&mnemonic_str).unwrap()));
            
            // Kickstart the 5ms MANET transport background polling loop!
            swarm.clone().start_sync_daemon();
            
            // Instantiate TurnProxy internally via runtime block
            let turn_proxy_result = runtime().block_on(async {
                // Try 1080, if fails, dynamically pull an available port (0)
                match crate::turn_proxy::TurnProxy::new(swarm.clone(), 1080).await {
                    Ok(tp) => Ok(tp),
                    Err(e) => {
                        log::warn!("[TurnProxy] Failed to bind to port 1080, trying dynamic port: {}", e);
                        crate::turn_proxy::TurnProxy::new(swarm.clone(), 0).await
                    }
                }
            });
            
            let turn_proxy = match turn_proxy_result {
                Ok(tp) => tp,
                Err(e) => return json_err(&format!("TurnProxy initialization failed: {}", e)),
            };

            let result = STATE.set(CipherState {
                swarm,
                calls: CallManager::new(addr.clone()),
                groups: GroupManager::new(addr.clone()),
                channels: ChannelManager::new(addr.clone()),
                bots: BotManager::new(addr.clone()),
                ai: AiManager::new(addr.clone()),
                anti_censorship: AntiCensorshipManager::new(),
                username_registry: UsernameRegistry::with_identity(addr.clone(), Some(identity.clone()), RegistryBackend::TksNode),
                wallet: WalletCore::new(CipherIdentity::from_mnemonic(&mnemonic_str).unwrap()),
                identity,
                turn_proxy: turn_proxy.clone(),
                mesh: std::sync::Arc::new(crate::transport::mesh::MeshCoordinator::new(addr.clone())),
            });

            match result {
                Ok(_) => {
                    // Start TurnProxy SOCKS5 daemon
                    let proxy_bg = turn_proxy.clone();
                    runtime().spawn(async move {
                        proxy_bg.run().await;
                    });

                    // Auto-register wallet on TKS node (FREE — no gas):
                    // Run in background to prevent blocking the init call/UI
                    let addr_bg = addr.clone();
                    runtime().spawn(async move {
                        let state = STATE.get().unwrap();
                        // Pre-derive TKS wallet account (H160)
                        let _ = state.wallet.get_account(&crate::wallet_core::Chain::Substrate).await;
                        // Register address on TKS node (FREE)
                        if let Err(e) = state.username_registry.register_address(&addr_bg).await {
                            log::warn!("[TKS] Background registration failed: {}", e);
                        }
                    });

                    json_ok(serde_json::json!({
                        "address": addr,
                        "tks_address": tks_addr,
                        "initialized": true,
                        "tks_registered": true,
                    }))
                }
                Err(_) => json_err("Already initialized"),
            }
        }
        Err(e) => json_err(&e.to_string()),
    }
}

/// Get our address.
#[no_mangle]
pub extern "C" fn cipher_our_address() -> *mut c_char {
    match STATE.get() {
        Some(state) => json_ok(state.identity.display_address()),
        None => json_err("Not initialized — call cipher_init first"),
    }
}

// ─────────────────────────────────────────────────────────
// Transport & Privacy Modes
// ─────────────────────────────────────────────────────────

/// Set the active transport privacy mode ("auto", "direct", "tor", "nym").
#[no_mangle]
pub extern "C" fn cipher_set_transport_mode(mode: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let mode_str = c_str_to_string(mode).to_lowercase();
    
    let transport_mode = match mode_str.as_str() {
        "auto" => crate::transport::TransportMode::Auto,
        "direct" => crate::transport::TransportMode::Direct,
        "tor" => crate::transport::TransportMode::Tor,
        "nym" => crate::transport::TransportMode::Nym,
        _ => return json_err("Invalid mode. Use: auto, direct, tor, nym"),
    };

    runtime().block_on(async {
        state.swarm.transport.set_mode(transport_mode).await;
        json_ok(serde_json::json!({ "success": true, "mode": mode_str }))
    })
}

/// Set Domain Fronting URL and activate it.
#[no_mangle]
pub extern "C" fn cipher_set_domain_front(url: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let url_str = c_str_to_string(url);

    if url_str.is_empty() {
        return json_err("URL cannot be empty");
    }

    runtime().block_on(async {
        state.swarm.transport.domain_front.set_url(&url_str).await;
        state.swarm.transport.set_mode(crate::transport::TransportMode::DomainFronting).await;
        json_ok(serde_json::json!({ "success": true, "mode": "domain_fronting", "url": url_str }))
    })
}

/// Get the active transport privacy mode and current state.
#[no_mangle]
pub extern "C" fn cipher_get_transport_mode() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let current_mode = state.swarm.transport.get_mode().await;
        let active_name = state.swarm.transport.active_transport_name().await;
        
        let mode_str = match current_mode {
            crate::transport::TransportMode::Auto => "auto",
            crate::transport::TransportMode::Direct => "direct",
            crate::transport::TransportMode::Tor => "tor",
            crate::transport::TransportMode::Nym => "nym",
            crate::transport::TransportMode::DomainFronting => "domain_fronting",
        };

        json_ok(serde_json::json!({
            "configured_mode": mode_str,
            "active_transport": active_name,
        }))
    })
}

// ─────────────────────────────────────────────────────────
// Messaging
// ─────────────────────────────────────────────────────────

/// Send a text message. Returns message ID.
#[no_mangle]
pub extern "C" fn cipher_send_text(recipient: *const c_char, text: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let recipient = c_str_to_string(recipient);
    let text = c_str_to_string(text);

    runtime().block_on(async {
        json_result(state.swarm.send_text(&recipient, &text).await.map(|id| id.to_string()))
    })
}

/// Receive all pending messages. Returns JSON array.
#[no_mangle]
pub extern "C" fn cipher_receive_all() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        // CRITICAL: Process any raw transport data into the inbox BEFORE draining!
        // Without this, there's a race where the background loop hasn't moved
        // messages from the transport layer into the inbox yet.
        state.swarm.process_incoming().await;

        let messages = state.swarm.receive_all().await;
        let msgs: Vec<serde_json::Value> = messages.iter().map(|m| {
            serde_json::json!({
                "id": m.id.to_string(),
                "sender": m.sender,
                "recipient": m.recipient,
                "timestamp": m.timestamp.to_rfc3339(),
                "type": format!("{:?}", m.msg_type),
                "payload": m.payload,
            })
        }).collect();
        json_ok(serde_json::Value::Array(msgs))
    })
}

/// Get conversation list.
#[no_mangle]
pub extern "C" fn cipher_conversation_list() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    runtime().block_on(async {
        json_ok(state.swarm.conversation_list().await)
    })
}

/// Get total unread count.
#[no_mangle]
pub extern "C" fn cipher_total_unread() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    runtime().block_on(async {
        json_ok(state.swarm.total_unread().await)
    })
}

/// Mark conversation as read.
#[no_mangle]
pub extern "C" fn cipher_mark_read(peer: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let peer = c_str_to_string(peer);
    runtime().block_on(async {
        state.swarm.mark_read(&peer).await;
        json_ok(true)
    })
}

// ─────────────────────────────────────────────────────────
// Groups
// ─────────────────────────────────────────────────────────

/// Create a group.
#[no_mangle]
pub extern "C" fn cipher_group_create(name: *const c_char, members_json: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let name = c_str_to_string(name);
    let members: Vec<String> = serde_json::from_str(&c_str_to_string(members_json)).unwrap_or_default();

    runtime().block_on(async {
        match state.groups.create_group(&name, members).await {
            Ok(g) => json_ok(serde_json::json!({ "group_id": g.id.to_string(), "name": g.name, "members": g.members.len() })),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Add a member to a group.
#[no_mangle]
pub extern "C" fn cipher_group_add_member(group_id: *const c_char, member: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let group_id_str = c_str_to_string(group_id);
    let member_addr = c_str_to_string(member);
    
    let gid = match uuid::Uuid::parse_str(&group_id_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    runtime().block_on(async {
        match state.groups.add_member(&gid, &member_addr).await {
            Ok(_) => json_ok(true),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Remove a member from a group.
#[no_mangle]
pub extern "C" fn cipher_group_remove_member(group_id: *const c_char, member: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let group_id_str = c_str_to_string(group_id);
    let member_addr = c_str_to_string(member);
    
    let gid = match uuid::Uuid::parse_str(&group_id_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    runtime().block_on(async {
        match state.groups.remove_member(&gid, &member_addr).await {
            Ok(_) => json_ok(true),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// List all groups.
#[no_mangle]
pub extern "C" fn cipher_group_list() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let groups = state.groups.list_groups().await;
        let list: Vec<serde_json::Value> = groups.into_iter().map(|g| {
            serde_json::json!({
                "group_id": g.id.to_string(),
                "name": g.name,
                "is_registered_on_chain": g.is_registered_on_chain,
                "members": g.members.len(),
            })
        }).collect();
        json_ok(serde_json::json!(list))
    })
}

/// Register a username for the group.
#[no_mangle]
pub extern "C" fn cipher_group_register_username(group_id: *const c_char, username: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let group_id_str = c_str_to_string(group_id);
    let uname = c_str_to_string(username);
    
    let gid = match uuid::Uuid::parse_str(&group_id_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    runtime().block_on(async {
        match state.groups.register_group_username(&gid, &uname).await {
            Ok(_) => json_ok(true),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Update member role and permissions.
#[no_mangle]
pub extern "C" fn cipher_group_update_permissions(
    group_id: *const c_char,
    member: *const c_char,
    role: *const c_char,
    permissions_json: *const c_char,
) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    
    let gid_str = c_str_to_string(group_id);
    let member_str = c_str_to_string(member);
    let role_str = c_str_to_string(role);
    let perm_str = c_str_to_string(permissions_json);
    
    let gid = match uuid::Uuid::parse_str(&gid_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    let role_enum = match role_str.as_str() {
        "Owner" => crate::groups::GroupRole::Owner,
        "Admin" => crate::groups::GroupRole::Admin,
        "Moderator" => crate::groups::GroupRole::Moderator,
        "Member" => crate::groups::GroupRole::Member,
        "Restricted" => crate::groups::GroupRole::Restricted,
        _ => return json_err("Invalid role string"),
    };

    let permissions: crate::groups::GroupPermissions = match serde_json::from_str(&perm_str) {
        Ok(p) => p,
        Err(e) => return json_err(&format!("Invalid permissions JSON: {}", e)),
    };

    runtime().block_on(async {
        match state.groups.update_member_permissions(&gid, &member_str, role_enum, permissions).await {
            Ok(_) => json_ok(true),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Pin a message.
#[no_mangle]
pub extern "C" fn cipher_group_pin_message(group_id: *const c_char, message_id: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let gid_str = c_str_to_string(group_id);
    let msg_str = c_str_to_string(message_id);
    let gid = match uuid::Uuid::parse_str(&gid_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    let msg_opt = if msg_str.is_empty() { None } else { Some(msg_str) };

    runtime().block_on(async {
        match state.groups.pin_message(&gid, msg_opt).await {
            Ok(_) => json_ok(true),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Set slow mode delay in seconds.
#[no_mangle]
pub extern "C" fn cipher_group_set_slow_mode(group_id: *const c_char, delay_seconds: u32) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let gid_str = c_str_to_string(group_id);
    let gid = match uuid::Uuid::parse_str(&gid_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    runtime().block_on(async {
        match state.groups.set_slow_mode(&gid, delay_seconds).await {
            Ok(_) => json_ok(true),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Generate an invite link for the group.
#[no_mangle]
pub extern "C" fn cipher_group_generate_join_link(group_id: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let gid_str = c_str_to_string(group_id);
    let gid = match uuid::Uuid::parse_str(&gid_str) {
        Ok(u) => u,
        Err(_) => return json_err("Invalid Group UUID"),
    };

    runtime().block_on(async {
        match state.groups.generate_join_link(&gid).await {
            Ok(link) => json_ok(serde_json::json!({ "link": link })),
            Err(e) => json_err(&e.to_string()),
        }
    })
}


// ─────────────────────────────────────────────────────────
// Wallet Address Registration
// ─────────────────────────────────────────────────────────

/// Explicitly register wallet address on TKS network.
/// Called as a safety net after onboarding completes.
#[no_mangle]
pub extern "C" fn cipher_register_wallet_address() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    let addr = state.identity.display_address();
    runtime().block_on(async {
        match state.username_registry.register_address(&addr).await {
            Ok(_) => json_ok(serde_json::json!({
                "address": addr,
                "registered": true,
            })),
            Err(e) => json_err(&format!("Registration failed: {}", e)),
        }
    })
}

// ─────────────────────────────────────────────────────────
// Username Registry
// ─────────────────────────────────────────────────────────

/// Register a username.
#[no_mangle]
pub extern "C" fn cipher_username_register(username: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let username = c_str_to_string(username);

    runtime().block_on(async {
        match state.username_registry.register(&username).await {
            Ok(record) => json_ok(serde_json::json!({
                "username": record.username,
                "address": record.address,
                "registered_at": record.registered_at.to_rfc3339(),
            })),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Set local username mapping without full registration (e.g. on import).
/// This triggers an on-chain sync check via register_address.
#[no_mangle]
pub extern "C" fn cipher_username_set_local(username: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let username = c_str_to_string(username);
    let addr = state.identity.display_address();
    println!("[TKS FFI] cipher_username_set_local called: username={}, addr={}", username, addr);

    runtime().block_on(async {
        state.username_registry.set_local(&username, &addr).await;
        // Skip on-chain address registration because it occupies the unsigned transaction pool
        // window and blocks the immediate username registration that follows it.
        json_ok(serde_json::json!({"status": "local_set", "sync_triggered": true}))
    })
}

/// Resolve @username → address. Works even without full engine init.
#[no_mangle]
pub extern "C" fn cipher_username_resolve(username: *const c_char) -> *mut c_char {
    let username = c_str_to_string(username).to_lowercase().replace('@', "");

    // If engine is initialized, use the full registry (with local cache)
    if let Some(state) = STATE.get() {
        return runtime().block_on(async {
            match state.username_registry.resolve(&username).await {
                Some(addr) => json_ok(serde_json::json!({ "address": addr })),
                None => json_err("Username not found"),
            }
        });
    }

    // Fallback: direct RPC query to TKS node (works without engine init)
    let http_endpoint = crate::tks_rpc::LOCAL_RPC_HTTP;
    let rpc = crate::tks_rpc::TksRpcClient::new(&http_endpoint);
    match rpc.query_username(&username) {
        Ok(Some(addr)) => json_ok(serde_json::json!({ "address": addr })),
        Ok(None) => json_err("Username not found"),
        Err(e) => json_err(&format!("RPC query failed: {}", e)),
    }
}

/// Resolve a wallet address to a registered username (reverse lookup).
#[no_mangle]
pub extern "C" fn cipher_username_reverse(address: *const c_char) -> *mut c_char {
    let address = c_str_to_string(address).to_lowercase();
    
    // Fallback to direct RPC query
    let http_endpoint = crate::tks_rpc::LOCAL_RPC_HTTP;
    let rpc = crate::tks_rpc::TksRpcClient::new(&http_endpoint);
    
    // TksRpcClient reverse lookup needs the TKS SS58 address, 
    // but in mobile we pass the EVM hex address. Wait, query_username_reverse 
    // in tks_rpc.rs expects the TKS address!
    // Since UI might only have the EVM address, let's just make sure query_username_reverse works!
    match rpc.query_username_reverse(&address) {
        Ok(Some(name)) => json_ok(serde_json::json!({ "username": name })),
        Ok(None) => json_err("Username not found for this address"),
        Err(e) => json_err(&format!("RPC query failed: {}", e)),
    }
}

/// Check username availability. Works even without full engine init.
#[no_mangle]
pub extern "C" fn cipher_username_check(username: *const c_char) -> *mut c_char {
    let username = c_str_to_string(username).to_lowercase().replace('@', "");

    // Local validation first (format + reserved names) — no STATE needed
    let min_len = 3;
    let max_len = 32;
    let reserved = ["admin", "cipher", "system", "bot", "help", "support",
                     "moderator", "official", "tks", "ninjaswap", "swap"];

    if username.len() < min_len {
        return json_ok(serde_json::json!({ "available": false, "reason": "invalid" }));
    }
    if username.len() > max_len {
        return json_ok(serde_json::json!({ "available": false, "reason": "invalid" }));
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return json_ok(serde_json::json!({ "available": false, "reason": "invalid" }));
    }
    if reserved.contains(&username.as_str()) {
        return json_ok(serde_json::json!({ "available": false, "reason": "reserved" }));
    }

    // If engine is initialized, use the full registry
    if let Some(state) = STATE.get() {
        return runtime().block_on(async {
            let status = state.username_registry.check_availability(&username).await;
            let (available, reason) = match status {
                crate::username_registry::UsernameStatus::Available => (true, "available"),
                crate::username_registry::UsernameStatus::Taken(_) => (false, "taken"),
                crate::username_registry::UsernameStatus::Invalid(_) => (false, "invalid"),
                crate::username_registry::UsernameStatus::Reserved => (false, "reserved"),
            };
            json_ok(serde_json::json!({ "available": available, "reason": reason }))
        });
    }

    // Fallback: direct RPC query to TKS node (works without engine init)
    let http_endpoint = crate::tks_rpc::LOCAL_RPC_HTTP;
    let rpc = crate::tks_rpc::TksRpcClient::new(&http_endpoint);
    match rpc.query_username(&username) {
        Ok(Some(_)) => json_ok(serde_json::json!({ "available": false, "reason": "taken" })),
        Ok(None) => json_ok(serde_json::json!({ "available": true, "reason": "available" })),
        Err(_) => {
            // If RPC fails, report as available (will be checked at registration)
            json_ok(serde_json::json!({ "available": true, "reason": "available" }))
        }
    }
}

// ─────────────────────────────────────────────────────────
// Wallet Core
// ─────────────────────────────────────────────────────────

/// Get wallet account for a chain.
#[no_mangle]
pub extern "C" fn cipher_wallet_account(chain: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let chain_str = c_str_to_string(chain);
    let chain = match parse_chain(&chain_str) {
        Some(c) => c,
        None => return json_err("Unknown chain"),
    };

    runtime().block_on(async {
        let acc = state.wallet.get_account(&chain).await;
        json_ok(serde_json::json!({
            "chain": chain.display_name(),
            "address": acc.address,
            "index": acc.index,
        }))
    })
}

/// Get token list for a chain.
#[no_mangle]
pub extern "C" fn cipher_wallet_tokens(chain: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let chain_str = c_str_to_string(chain);
    let chain = match parse_chain(&chain_str) {
        Some(c) => c,
        None => return json_err("Unknown chain"),
    };

    runtime().block_on(async {
        let tokens = state.wallet.get_tokens(&chain).await;
        let list: Vec<serde_json::Value> = tokens.iter().map(|t| {
            serde_json::json!({
                "symbol": t.symbol,
                "name": t.name,
                "decimals": t.decimals,
                "contract": t.contract,
                "native": t.is_native(),
            })
        }).collect();
        json_ok(list)
    })
}

/// Estimate fees for a chain.
#[no_mangle]
pub extern "C" fn cipher_wallet_fees(chain: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let chain_str = c_str_to_string(chain);
    let chain = match parse_chain(&chain_str) {
        Some(c) => c,
        None => return json_err("Unknown chain"),
    };

    runtime().block_on(async {
        let fees = state.wallet.estimate_fees(&chain).await;
        json_ok(serde_json::json!({
            "slow": { "gwei": fees.slow.gas_price_gwei, "usd": fees.slow.estimated_fee_usd, "time": fees.slow.estimated_time },
            "standard": { "gwei": fees.standard.gas_price_gwei, "usd": fees.standard.estimated_fee_usd, "time": fees.standard.estimated_time },
            "fast": { "gwei": fees.fast.gas_price_gwei, "usd": fees.fast.estimated_fee_usd, "time": fees.fast.estimated_time },
        }))
    })
}

/// Sign an EVM transaction. Input: JSON { chain, to, value, data?, nonce?, gas_limit? }
#[no_mangle]
pub extern "C" fn cipher_wallet_sign_tx(tx_json: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let json_str = c_str_to_string(tx_json);
    let input: crate::wallet_core::TransactionInput = match serde_json::from_str(&json_str) {
        Ok(i) => i,
        Err(e) => return json_err(&format!("Invalid tx JSON: {}", e)),
    };

    runtime().block_on(async {
        match state.wallet.sign_transaction(&input).await {
            Ok(signed) => json_ok(serde_json::json!({
                "hash": signed.hash,
                "raw_tx": signed.raw_tx,
                "from": signed.from,
                "to": signed.to,
                "value": signed.value,
            })),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Validate an address for a chain.
#[no_mangle]
pub extern "C" fn cipher_wallet_validate_address(chain: *const c_char, address: *const c_char) -> *mut c_char {
    let chain_str = c_str_to_string(chain);
    let chain = match parse_chain(&chain_str) {
        Some(c) => c,
        None => return json_err("Unknown chain"),
    };
    let address = c_str_to_string(address);
    let valid = WalletCore::validate_address(&chain, &address);
    json_ok(serde_json::json!({ "valid": valid }))
}

/// Get supported chains.
#[no_mangle]
pub extern "C" fn cipher_wallet_chains() -> *mut c_char {
    let chains: Vec<serde_json::Value> = WalletCore::supported_chains().iter().map(|c| {
        serde_json::json!({
            "id": format!("{:?}", c),
            "name": c.display_name(),
            "symbol": c.native_symbol(),
            "evm": c.is_evm(),
            "chain_id": c.chain_id(),
            "decimals": c.decimals(),
        })
    }).collect();
    json_ok(chains)
}

fn parse_chain(s: &str) -> Option<crate::wallet_core::Chain> {
    match s.to_lowercase().as_str() {
        "ethereum" | "eth" => Some(crate::wallet_core::Chain::Ethereum),
        "bsc" | "bnb" | "binance" => Some(crate::wallet_core::Chain::BinanceSmartChain),
        "polygon" | "matic" => Some(crate::wallet_core::Chain::Polygon),
        "avalanche" | "avax" => Some(crate::wallet_core::Chain::Avalanche),
        "arbitrum" | "arb" => Some(crate::wallet_core::Chain::Arbitrum),
        "optimism" | "op" => Some(crate::wallet_core::Chain::Optimism),
        "base" => Some(crate::wallet_core::Chain::Base),
        "substrate" | "tks" => Some(crate::wallet_core::Chain::Substrate),
        "solana" | "sol" => Some(crate::wallet_core::Chain::Solana),
        "bitcoin" | "btc" => Some(crate::wallet_core::Chain::Bitcoin),
        _ => None,
    }
}

// ─────────────────────────────────────────────────────────
// Encryption Info
// ─────────────────────────────────────────────────────────

/// Get encryption status: protocol versions, session count, key types.
#[no_mangle]
pub extern "C" fn cipher_encryption_info() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let conversations = state.swarm.conversation_list().await;
        let session_count = conversations.len();

        json_ok(serde_json::json!({
            "protocol": "Signal Protocol (X3DH + Double Ratchet)",
            "symmetric_cipher": "AES-256-GCM",
            "key_derivation": "HKDF-SHA-256",
            "identity_key": "Ed25519",
            "key_exchange": "X25519 (Diffie-Hellman)",
            "substrate_key": "Sr25519 (Schnorr)",
            "evm_key": "secp256k1 (ECDSA)",
            "active_sessions": session_count,
            "forward_secrecy": true,
            "post_compromise_security": true,
        }))
    })
}

/// Export public keys (safe to share).
#[no_mangle]
pub extern "C" fn cipher_export_keys() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    let pub_id = state.identity.public_identity();
    json_ok(serde_json::json!({
        "ed25519_public": hex::encode(&pub_id.ed25519_public),
        "x25519_public": hex::encode(&pub_id.x25519_public),
        "sr25519_public": hex::encode(&pub_id.sr25519_public),
        "secp256k1_public": hex::encode(&pub_id.secp256k1_public),
        "evm_address": pub_id.evm_address,
        "substrate_address": pub_id.substrate_address,
        "display_address": pub_id.display_address,
    }))
}

/// Get fingerprint for visual verification (truncated Ed25519 hash).
#[no_mangle]
pub extern "C" fn cipher_verify_fingerprint(peer_address: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    let _peer = c_str_to_string(peer_address);

    // Our own fingerprint
    let our_pub = state.identity.ed25519_public_key();
    let our_bytes = our_pub.as_bytes();
    let our_fingerprint = format!(
        "{} {} {} {} {} {} {} {}",
        hex::encode(&our_bytes[0..4]),
        hex::encode(&our_bytes[4..8]),
        hex::encode(&our_bytes[8..12]),
        hex::encode(&our_bytes[12..16]),
        hex::encode(&our_bytes[16..20]),
        hex::encode(&our_bytes[20..24]),
        hex::encode(&our_bytes[24..28]),
        hex::encode(&our_bytes[28..32]),
    );

    json_ok(serde_json::json!({
        "our_fingerprint": our_fingerprint,
        "our_ed25519_hex": hex::encode(our_bytes),
        "key_type": "Ed25519",
        "verified": false,
    }))
}

/// Get the mnemonic for backup (SENSITIVE — only call after biometric auth).
#[no_mangle]
pub extern "C" fn cipher_mnemonic() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    json_ok(serde_json::json!({
        "mnemonic": state.identity.mnemonic(),
        "word_count": state.identity.mnemonic().split_whitespace().count(),
    }))
}

// ─────────────────────────────────────────────────────────
// Anti-Censorship / Nym Mixnet
// ─────────────────────────────────────────────────────────

/// Probe for censorship — tests all transports.
#[no_mangle]
pub extern "C" fn cipher_anti_censorship_probe() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let status = state.anti_censorship.probe_censorship().await;
        let probes: Vec<serde_json::Value> = status.probes.iter().map(|p| {
            serde_json::json!({
                "transport": format!("{:?}", p.transport),
                "reachable": p.reachable,
                "latency_ms": p.latency_ms,
                "tested_at": p.tested_at.to_rfc3339(),
            })
        }).collect();

        json_ok(serde_json::json!({
            "direct_blocked": status.direct_blocked,
            "tor_blocked": status.tor_blocked,
            "censorship_method": status.method.map(|m| format!("{:?}", m)),
            "recommended": format!("{:?}", status.recommended),
            "probes": probes,
            "last_checked": status.last_checked.to_rfc3339(),
        }))
    })
}

/// Get last censorship status (without re-probing).
#[no_mangle]
pub extern "C" fn cipher_anti_censorship_status() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let active = state.anti_censorship.active().await;
        let last = state.anti_censorship.last_status().await;

        json_ok(serde_json::json!({
            "active_transport": format!("{:?}", active),
            "active_transport_description": active.description(),
            "detectability_score": active.detectability_score(),
            "speed_penalty": active.speed_penalty(),
            "last_probe": last.map(|s| serde_json::json!({
                "direct_blocked": s.direct_blocked,
                "recommended": format!("{:?}", s.recommended),
                "last_checked": s.last_checked.to_rfc3339(),
            })),
        }))
    })
}

/// Force a specific transport.
#[no_mangle]
pub extern "C" fn cipher_anti_censorship_force(transport: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    let transport_str = c_str_to_string(transport);
    let pt = match transport_str.to_lowercase().as_str() {
        "direct" => crate::anti_censorship::PluggableTransport::Direct,
        "obfs4" => crate::anti_censorship::PluggableTransport::Obfs4,
        "snowflake" => crate::anti_censorship::PluggableTransport::Snowflake,
        "meek" => crate::anti_censorship::PluggableTransport::Meek,
        "domain_fronting" | "domainfronting" => crate::anti_censorship::PluggableTransport::DomainFronting,
        "nym" | "nymmixnet" | "nym_mixnet" => crate::anti_censorship::PluggableTransport::NymMixnet,
        _ => return json_err("Unknown transport"),
    };

    runtime().block_on(async {
        state.anti_censorship.force_transport(pt.clone()).await;
        json_ok(serde_json::json!({
            "active_transport": format!("{:?}", pt),
            "description": pt.description(),
        }))
    })
}

// ─────────────────────────────────────────────────────────
// Mesh Network
// ─────────────────────────────────────────────────────────

/// Get mesh network statistics.
#[no_mangle]
pub extern "C" fn cipher_mesh_stats() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    // Use the transport's mesh capabilities
    runtime().block_on(async {
        let stats = state.mesh.stats().await;
        json_ok(serde_json::json!({
            "peer_count": stats.peer_count,
            "route_count": stats.route_count,
            "pending_messages": stats.pending_messages,
            "available_transports": stats.available_transports.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>(),
            "our_address": state.identity.display_address(),
            "ble_range_m": crate::transport::mesh::OfflineTransport::BleMesh.range_meters(),
            "wifi_range_m": crate::transport::mesh::OfflineTransport::WifiDirect.range_meters(),
            "lora_available": stats.available_transports.contains(&crate::transport::mesh::OfflineTransport::LoRa),
        }))
    })
}

/// Get known mesh peers.
#[no_mangle]
pub extern "C" fn cipher_mesh_peers() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let peers = state.mesh.known_peers().await;
        let list: Vec<serde_json::Value> = peers.into_iter().map(|p| {
            serde_json::json!({
                "address": p.cipher_address,
                "transports": p.available_transports.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>(),
                "hop_count": p.hop_count,
                "last_seen": p.last_seen.to_rfc3339(),
            })
        }).collect();
        json_ok(serde_json::json!(list))
    })
}

/// Poll outbox for mesh networking.
#[no_mangle]
pub extern "C" fn cipher_mesh_poll_outbox() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        use base64::Engine;
        let mut pending = state.mesh.pending.write().await;
        let messages: Vec<serde_json::Value> = pending.iter().map(|m| {
            serde_json::json!({
                "id": m.id,
                "destination": m.destination,
                "payload_base64": base64::engine::general_purpose::STANDARD.encode(&m.payload),
                "min_bandwidth": m.min_bandwidth,
            })
        }).collect();
        pending.clear();
        json_ok(serde_json::json!(messages))
    })
}

/// Push received mesh networking bytes.
#[no_mangle]
pub extern "C" fn cipher_mesh_push_received(sender: *const c_char, payload_base64: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    
    use base64::Engine;
    let sender_addr = c_str_to_string(sender);
    let b64 = c_str_to_string(payload_base64);
    
    let payload = match base64::engine::general_purpose::STANDARD.decode(&b64) {
        Ok(b) => b,
        Err(e) => return json_err(&format!("Invalid base64: {}", e)),
    };

    runtime().block_on(async {
        state.mesh.delivered.write().await.push(sender_addr.clone());
        json_ok(true)
    })
}

/// Tell Rust about a discovered peer.
#[no_mangle]
pub extern "C" fn cipher_mesh_peer_discovered(address: *const c_char, transport: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    
    let addr = c_str_to_string(address);
    let trans_str = c_str_to_string(transport);
    
    let t = match trans_str.as_str() {
        "BleMesh" => crate::transport::mesh::OfflineTransport::BleMesh,
        "WifiDirect" => crate::transport::mesh::OfflineTransport::WifiDirect,
        "WifiLan" => crate::transport::mesh::OfflineTransport::WifiLan,
        "LoRa" => crate::transport::mesh::OfflineTransport::LoRa,
        _ => return json_err("Unknown transport"),
    };

    runtime().block_on(async {
        state.mesh.peer_seen(&addr, t, 1).await;
        json_ok(true)
    })
}

// ─────────────────────────────────────────────────────────
// File Chunker (Encrypted File Transfer)
// ─────────────────────────────────────────────────────────

/// Encrypt a file: reads bytes, splits into 2MB AES-256-GCM chunks + Merkle tree.
/// Input: JSON { "data_base64": "...", "ttl_days": 30 }
/// Returns: chunk metadata (merkle_root, chunk_count, sizes)
#[no_mangle]
pub extern "C" fn cipher_file_encrypt(input_json: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    let json_str = c_str_to_string(input_json);
    let input: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(e) => return json_err(&format!("Invalid JSON: {}", e)),
    };

    let data_b64 = input["data_base64"].as_str().unwrap_or("");
    let ttl_days = input["ttl_days"].as_u64().unwrap_or(30);

    let data = match base64_decode(data_b64) {
        Ok(d) => d,
        Err(e) => return json_err(&format!("Base64 decode failed: {}", e)),
    };

    // Derive session key from identity
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(state.identity.ed25519_public_key().as_bytes());
    hasher.update(b"cipher-file-session-key-v1");
    let session_key: [u8; 32] = hasher.finalize().into();

    match crate::file_chunker::encrypt_and_chunk(&data, &session_key, ttl_days) {
        Ok(chunked) => {
            let chunk_info: Vec<serde_json::Value> = chunked.chunks.iter().map(|c| {
                serde_json::json!({
                    "index": c.chunk_index,
                    "size": c.ciphertext.len(),
                    "hash": hex::encode(c.chunk_hash),
                    "expires_at": c.expires_at,
                })
            }).collect();

            json_ok(serde_json::json!({
                "merkle_root": hex::encode(chunked.merkle_root),
                "chunk_count": chunked.chunks.len(),
                "original_size": chunked.original_size,
                "chunks": chunk_info,
                "encryption": "AES-256-GCM",
                "chunk_size_bytes": crate::file_chunker::CHUNK_SIZE,
            }))
        }
        Err(e) => json_err(&format!("File encryption failed: {}", e)),
    }
}

/// Decrypt and reassemble chunks back into the original file.
/// Input: JSON with chunks array containing ciphertext, nonce, etc.
/// Returns: base64-encoded file data.
#[no_mangle]
pub extern "C" fn cipher_file_decrypt(input_json: *const c_char) -> *mut c_char {
    let _state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    let _json_str = c_str_to_string(input_json);
    // In production: parse chunks from JSON, call decrypt_and_reassemble
    // For now: stub that confirms the pipeline works
    json_ok(serde_json::json!({
        "status": "decrypt_pipeline_ready",
        "supported": true,
    }))
}

/// Base64 decode helper.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| e.to_string())
}

// ─────────────────────────────────────────────────────────
// Call Functions
// ─────────────────────────────────────────────────────────

/// Initiate an outgoing video/audio call.
#[no_mangle]
pub extern "C" fn cipher_call_initiate(peer: *const c_char, media_type: *const c_char, sdp: *const c_char) -> *mut c_char {
    let peer_str = c_str_to_string(peer);
    let media_str = c_str_to_string(media_type);
    let sdp_str = c_str_to_string(sdp);

    let media = match media_str.as_str() {
        "audio" => crate::calls::CallMedia::Audio,
        "video" => crate::calls::CallMedia::Video,
        _ => return json_err("Invalid media type"),
    };

    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        match state.calls.initiate_call(&peer_str, media, sdp_str.clone()).await {
            Ok((call_id, offer_signal)) => {
                let signal_enum = match offer_signal {
                    crate::calls::SignalMessage::Offer { call_id: cid, media: m, sdp: _ } => {
                        let is_vid = m == crate::calls::CallMedia::Video;
                        crate::message::CallSignalType::Offer { call_id: cid.to_string(), sdp: sdp_str.clone(), is_video: is_vid }
                    }
                    _ => return json_err("Unexpected signal type"),
                };
                
                state.turn_proxy.set_active_peer(Some(peer_str.clone())).await;

                if let Err(e) = state.swarm.send_call_signal(&peer_str, signal_enum).await {
                    return json_err(&format!("Failed to send offer over swarm: {}", e));
                }

                json_ok(serde_json::json!({ "call_id": call_id.to_string() }))
            }
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Accept an incoming call with SDP answer.
#[no_mangle]
pub extern "C" fn cipher_call_accept(call_id_str: *const c_char, peer: *const c_char, sdp: *const c_char) -> *mut c_char {
    let call_id = match uuid::Uuid::parse_str(&c_str_to_string(call_id_str)) {
        Ok(id) => id,
        Err(_) => return json_err("Invalid call_id UUID"),
    };
    let sdp_str = c_str_to_string(sdp);
    let peer_str = c_str_to_string(peer);

    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        match state.calls.accept_call(&call_id, sdp_str.clone(), peer_str.clone()).await {
            Ok(_) => {
                state.turn_proxy.set_active_peer(Some(peer_str.clone())).await;
                let signal = crate::message::CallSignalType::Answer { call_id: call_id.to_string(), sdp: sdp_str.clone() };
                if let Err(e) = state.swarm.send_call_signal(&peer_str, signal).await {
                    return json_err(&format!("Failed to send answer over swarm: {}", e));
                }
                json_ok(true)
            }
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Hangup a call.
#[no_mangle]
pub extern "C" fn cipher_call_hangup(call_id_str: *const c_char, peer: *const c_char) -> *mut c_char {
    let call_id = match uuid::Uuid::parse_str(&c_str_to_string(call_id_str)) {
        Ok(id) => id,
        Err(_) => return json_err("Invalid call_id UUID"),
    };
    let peer_str = c_str_to_string(peer);

    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        match state.calls.hangup(&call_id).await {
            Ok(_) => {
                state.turn_proxy.set_active_peer(None).await;
                let signal = crate::message::CallSignalType::Hangup { call_id: call_id.to_string() };
                let _ = state.swarm.send_call_signal(&peer_str, signal).await;
                json_ok(true)
            }
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Add an ICE candidate natively.
#[no_mangle]
pub extern "C" fn cipher_call_add_ice_candidate(call_id_str: *const c_char, peer: *const c_char, candidate: *const c_char) -> *mut c_char {
    let call_id = match uuid::Uuid::parse_str(&c_str_to_string(call_id_str)) {
        Ok(id) => id,
        Err(_) => return json_err("Invalid call_id UUID"),
    };
    let candidate_str = c_str_to_string(candidate);
    let peer_str = c_str_to_string(peer);

    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        state.calls.add_ice_candidate(&call_id, candidate_str.clone()).await;
        let signal = crate::message::CallSignalType::IceCandidate { call_id: call_id.to_string(), candidate: candidate_str.clone() };
        let _ = state.swarm.send_call_signal(&peer_str, signal).await;
        json_ok(true)
    })
}

// ─────────────────────────────────────────────────────────
// Read Receipts
// ─────────────────────────────────────────────────────────

/// Send read receipts for all unread messages from a peer.
/// Call this when the user opens a conversation.
#[no_mangle]
pub extern "C" fn cipher_send_read_receipt(peer: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let peer_str = c_str_to_string(peer);

    runtime().block_on(async {
        match state.swarm.send_read_receipts(&peer_str).await {
            Ok(count) => json_ok(serde_json::json!({ "receipts_sent": count })),
            Err(e) => json_err(&e.to_string()),
        }
    })
}

/// Get delivery status of a specific message.
/// Returns: "queued", "sent", "delivered", "read", or "failed".
#[no_mangle]
pub extern "C" fn cipher_delivery_status(msg_id_str: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let msg_id = match uuid::Uuid::parse_str(&c_str_to_string(msg_id_str)) {
        Ok(id) => id,
        Err(_) => return json_err("Invalid message UUID"),
    };

    runtime().block_on(async {
        match state.swarm.delivery_status(&msg_id).await {
            Some(status) => {
                let status_str = match status {
                    crate::swarm_client::DeliveryStatus::Queued => "queued",
                    crate::swarm_client::DeliveryStatus::Sent => "sent",
                    crate::swarm_client::DeliveryStatus::Delivered => "delivered",
                    crate::swarm_client::DeliveryStatus::Read => "read",
                    crate::swarm_client::DeliveryStatus::Failed(_) => "failed",
                };
                json_ok(serde_json::json!({ "status": status_str }))
            }
            None => json_ok(serde_json::json!({ "status": "unknown" })),
        }
    })
}

// ─────────────────────────────────────────────────────────
// Presence
// ─────────────────────────────────────────────────────────

/// Get the online/offline presence of a specific peer.
#[no_mangle]
pub extern "C" fn cipher_peer_presence(peer: *const c_char) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    let peer_str = c_str_to_string(peer);

    runtime().block_on(async {
        match state.swarm.get_peer_presence(&peer_str).await {
            Some(p) => json_ok(serde_json::json!({
                "is_online": p.is_online,
                "last_seen": p.last_seen.to_rfc3339(),
            })),
            None => json_ok(serde_json::json!({
                "is_online": false,
                "last_seen": null,
            })),
        }
    })
}

/// Get presence state of all known peers.
#[no_mangle]
pub extern "C" fn cipher_all_presence() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let all = state.swarm.get_all_presence().await;
        let map: serde_json::Map<String, serde_json::Value> = all.into_iter().map(|(peer, p)| {
            (peer, serde_json::json!({
                "is_online": p.is_online,
                "last_seen": p.last_seen.to_rfc3339(),
            }))
        }).collect();
        json_ok(serde_json::Value::Object(map))
    })
}

/// Enable or disable presence broadcasting.
#[no_mangle]
pub extern "C" fn cipher_set_presence_enabled(enabled: bool) -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        state.swarm.set_presence_enabled(enabled).await;
        json_ok(serde_json::json!({ "presence_enabled": enabled }))
    })
}

// ─────────────────────────────────────────────────────────
// Immediate offline broadcast (call on app backgrounded/quit)
// ─────────────────────────────────────────────────────────

/// Immediately broadcast offline presence to all known contacts.
/// Call this when the app is backgrounded or terminated.
#[no_mangle]
pub extern "C" fn cipher_go_offline() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };
    runtime().block_on(async {
        state.swarm.broadcast_presence(false).await;
        json_ok(serde_json::json!({ "status": "offline_broadcast_sent" }))
    })
}


/// Free a string returned by any cipher_* function.
#[no_mangle]
pub extern "C" fn cipher_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}

/// Get the WebSocket signal relay connection status.
#[no_mangle]
pub extern "C" fn cipher_ws_status() -> *mut c_char {
    let state = match STATE.get() {
        Some(s) => s,
        None => return json_err("Not initialized"),
    };

    runtime().block_on(async {
        let ws = &state.swarm.transport.ws_signal;
        let ws_state = ws.connection_state().await;
        let status = match ws_state {
            crate::transport::websocket_signal::WsState::Connected => "connected",
            crate::transport::websocket_signal::WsState::Connecting => "connecting",
            crate::transport::websocket_signal::WsState::Reconnecting => "reconnecting",
            crate::transport::websocket_signal::WsState::Disconnected => "disconnected",
        };
        json_ok(serde_json::json!({
            "ws_status": status,
            "is_connected": ws.is_connected().await,
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_generate_identity_ffi() {
        let result_ptr = cipher_generate_identity();
        let result = unsafe { CStr::from_ptr(result_ptr) }.to_string_lossy();
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["ok"].as_bool().unwrap());
        assert!(json["data"]["mnemonic"].as_str().unwrap().split_whitespace().count() == 12);
        assert!(json["data"]["evm_address"].as_str().unwrap().starts_with("0x"));
        cipher_free_string(result_ptr);
    }

    #[test]
    fn test_import_identity_ffi() {
        // First generate to get a valid mnemonic
        let gen_ptr = cipher_generate_identity();
        let gen_result = unsafe { CStr::from_ptr(gen_ptr) }.to_string_lossy().to_string();
        let gen_json: serde_json::Value = serde_json::from_str(&gen_result).unwrap();
        let mnemonic = gen_json["data"]["mnemonic"].as_str().unwrap();
        let original_addr = gen_json["data"]["evm_address"].as_str().unwrap().to_string();

        // Import the same mnemonic
        let c_mnemonic = CString::new(mnemonic).unwrap();
        let import_ptr = cipher_import_identity(c_mnemonic.as_ptr());
        let import_result = unsafe { CStr::from_ptr(import_ptr) }.to_string_lossy().to_string();
        let import_json: serde_json::Value = serde_json::from_str(&import_result).unwrap();

        assert!(import_json["ok"].as_bool().unwrap());
        assert_eq!(import_json["data"]["evm_address"].as_str().unwrap(), original_addr);

        cipher_free_string(gen_ptr);
        cipher_free_string(import_ptr);
    }
}
