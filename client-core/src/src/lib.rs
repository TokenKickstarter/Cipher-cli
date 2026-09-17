//! # Cipher Client Core
//!
//! Shared Rust library for Cipher — the decentralized anonymous messenger.
//! One seed phrase → chat identity + wallet + everything.

pub mod ai;
pub mod anti_censorship;
pub mod bots;
pub mod calls;
pub mod channels;
pub mod encryption;
pub mod error;
pub mod ffi;
pub mod file_chunker;
pub mod groups;
pub mod identity;
pub mod message;
pub mod swarm_client;
pub mod tks_rpc;
pub mod transport;
pub mod turn_proxy;
pub mod username_registry;
pub mod wallet_core;
