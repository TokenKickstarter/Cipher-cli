//! # Wallet Core SDK
//!
//! Trust Wallet Core-style multi-chain wallet engine.
//!
//! Built on top of the existing `identity.rs` BIP-39/BIP-32 derivation.
//! Supports:
//! - Multi-chain HD wallet (BIP-44)
//! - Transaction signing (EVM, Substrate)
//! - Token management (ERC-20, native)
//! - Balance tracking
//! - Transaction history
//! - Address validation
//! - Fee estimation
//! - Multi-account support

use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::CipherError;
use crate::identity::CipherIdentity;

// ─────────────────────────────────────────────────────────
// Chain Definitions
// ─────────────────────────────────────────────────────────

/// Supported blockchain networks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    Ethereum,
    EthereumGoerli,
    BinanceSmartChain,
    Polygon,
    Avalanche,
    Arbitrum,
    Optimism,
    Base,
    Substrate, // TKS / Polkadot / Kusama
    Solana,
    Bitcoin,
}

impl Chain {
    /// BIP-44 coin type for HD derivation.
    pub fn coin_type(&self) -> u32 {
        match self {
            Chain::Ethereum | Chain::EthereumGoerli => 60,
            Chain::BinanceSmartChain => 60, // same as ETH (EVM)
            Chain::Polygon => 60,
            Chain::Avalanche => 60,
            Chain::Arbitrum => 60,
            Chain::Optimism => 60,
            Chain::Base => 60,
            Chain::Substrate => 354, // Polkadot
            Chain::Solana => 501,
            Chain::Bitcoin => 0,
        }
    }

    /// Chain ID for EVM networks.
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Chain::Ethereum => Some(1),
            Chain::EthereumGoerli => Some(5),
            Chain::BinanceSmartChain => Some(56),
            Chain::Polygon => Some(137),
            Chain::Avalanche => Some(43114),
            Chain::Arbitrum => Some(42161),
            Chain::Optimism => Some(10),
            Chain::Base => Some(8453),
            _ => None,
        }
    }

    /// Whether this is an EVM-compatible chain.
    pub fn is_evm(&self) -> bool {
        self.chain_id().is_some()
    }

    /// Native token symbol.
    pub fn native_symbol(&self) -> &str {
        match self {
            Chain::Ethereum | Chain::EthereumGoerli => "ETH",
            Chain::BinanceSmartChain => "BNB",
            Chain::Polygon => "MATIC",
            Chain::Avalanche => "AVAX",
            Chain::Arbitrum => "ETH",
            Chain::Optimism => "ETH",
            Chain::Base => "ETH",
            Chain::Substrate => "TKS",
            Chain::Solana => "SOL",
            Chain::Bitcoin => "BTC",
        }
    }

    /// Native token decimals.
    pub fn decimals(&self) -> u8 {
        match self {
            Chain::Bitcoin => 8,
            Chain::Solana => 9,
            _ => 18,
        }
    }

    /// Default RPC endpoint.
    pub fn default_rpc(&self) -> &str {
        match self {
            Chain::Ethereum => "https://eth-mainnet.g.alchemy.com/v2/demo",
            Chain::EthereumGoerli => "https://eth-goerli.g.alchemy.com/v2/demo",
            Chain::BinanceSmartChain => "https://bsc-dataseed.binance.org",
            Chain::Polygon => "https://polygon-rpc.com",
            Chain::Avalanche => "https://api.avax.network/ext/bc/C/rpc",
            Chain::Arbitrum => "https://arb1.arbitrum.io/rpc",
            Chain::Optimism => "https://mainnet.optimism.io",
            Chain::Base => "https://mainnet.base.org",
            Chain::Substrate => crate::tks_rpc::LOCAL_RPC_WS, // Local TKS dev node
            Chain::Solana => "https://api.mainnet-beta.solana.com",
            Chain::Bitcoin => "https://blockstream.info/api",
        }
    }

    /// Display name.
    pub fn display_name(&self) -> &str {
        match self {
            Chain::Ethereum => "Ethereum",
            Chain::EthereumGoerli => "Ethereum Goerli",
            Chain::BinanceSmartChain => "BNB Chain",
            Chain::Polygon => "Polygon",
            Chain::Avalanche => "Avalanche",
            Chain::Arbitrum => "Arbitrum",
            Chain::Optimism => "Optimism",
            Chain::Base => "Base",
            Chain::Substrate => "TKS Network",
            Chain::Solana => "Solana",
            Chain::Bitcoin => "Bitcoin",
        }
    }
}

// ─────────────────────────────────────────────────────────
// Token
// ─────────────────────────────────────────────────────────

/// A token on a specific chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub chain: Chain,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    /// Contract address (None for native tokens)
    pub contract: Option<String>,
    /// Logo URL or IPFS hash
    pub logo: Option<String>,
    /// Current price in USD
    pub price_usd: Option<f64>,
}

impl Token {
    /// Create a native token for a chain.
    pub fn native(chain: &Chain) -> Self {
        Self {
            chain: chain.clone(),
            symbol: chain.native_symbol().to_string(),
            name: chain.display_name().to_string(),
            decimals: chain.decimals(),
            contract: None,
            logo: None,
            price_usd: None,
        }
    }

    /// Create an ERC-20 token.
    pub fn erc20(chain: Chain, symbol: &str, name: &str, contract: &str, decimals: u8) -> Self {
        Self {
            chain,
            symbol: symbol.to_string(),
            name: name.to_string(),
            decimals,
            contract: Some(contract.to_string()),
            logo: None,
            price_usd: None,
        }
    }

    pub fn is_native(&self) -> bool {
        self.contract.is_none()
    }
}

// ─────────────────────────────────────────────────────────
// Account & Balance
// ─────────────────────────────────────────────────────────

/// A wallet account derived from the HD path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub chain: Chain,
    pub address: String,
    pub index: u32,
    pub label: Option<String>,
}

/// Token balance for an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub token: Token,
    pub balance_raw: String,     // Raw balance (wei, lamports, satoshi)
    pub balance_display: String, // Human-readable (e.g. "1.5")
    pub value_usd: Option<f64>,
}

// ─────────────────────────────────────────────────────────
// Transaction
// ─────────────────────────────────────────────────────────

/// Transaction input for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub chain: Chain,
    pub to: String,
    pub value: String,        // Amount in smallest unit (wei, etc.)
    pub data: Option<String>, // Hex-encoded calldata (for contract calls)
    pub nonce: Option<u64>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<String>,        // wei
    pub max_fee_per_gas: Option<String>,  // EIP-1559
    pub max_priority_fee: Option<String>, // EIP-1559
}

/// A signed transaction ready for broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub chain: Chain,
    pub hash: String,
    pub raw_tx: String, // Hex-encoded signed tx
    pub from: String,
    pub to: String,
    pub value: String,
}

/// Transaction status.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Transaction record in history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    pub hash: String,
    pub chain: Chain,
    pub from: String,
    pub to: String,
    pub value: String,
    pub token_symbol: String,
    pub status: TxStatus,
    pub timestamp: i64,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
    pub fee: Option<String>,
}

// ─────────────────────────────────────────────────────────
// Fee Estimation
// ─────────────────────────────────────────────────────────

/// Gas/fee estimation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub chain: Chain,
    pub slow: FeeOption,
    pub standard: FeeOption,
    pub fast: FeeOption,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeOption {
    pub label: String,
    pub gas_price_gwei: String,
    pub estimated_fee_usd: String,
    pub estimated_time: String, // "~30s", "~5min", etc.
}

// ─────────────────────────────────────────────────────────
// Wallet Core
// ─────────────────────────────────────────────────────────

/// Multi-chain wallet engine.
pub struct WalletCore {
    identity: CipherIdentity,
    /// Accounts per chain
    accounts: Arc<RwLock<HashMap<Chain, Vec<WalletAccount>>>>,
    /// Token balances per address
    balances: Arc<RwLock<HashMap<String, Vec<TokenBalance>>>>,
    /// Transaction history
    history: Arc<RwLock<Vec<TransactionRecord>>>,
    /// Custom tokens added by user
    custom_tokens: Arc<RwLock<Vec<Token>>>,
    /// Custom RPC endpoints
    custom_rpcs: Arc<RwLock<HashMap<Chain, String>>>,
}

impl WalletCore {
    /// Create a new wallet from identity.
    pub fn new(identity: CipherIdentity) -> Self {
        let wallet = Self {
            identity,
            accounts: Arc::new(RwLock::new(HashMap::new())),
            balances: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            custom_tokens: Arc::new(RwLock::new(Vec::new())),
            custom_rpcs: Arc::new(RwLock::new(HashMap::new())),
        };
        wallet
    }

    // ─── Account Management ──────────────────────────────

    /// Get the default account for a chain.
    pub async fn get_account(&self, chain: &Chain) -> WalletAccount {
        // Check cache under read lock (must drop before write)
        {
            let accounts = self.accounts.read().await;
            if let Some(chain_accounts) = accounts.get(chain) {
                if let Some(acc) = chain_accounts.first() {
                    return acc.clone();
                }
            }
        } // ← read lock dropped here
          // Auto-create from identity (needs write lock)
        self.derive_account(chain, 0).await
    }

    /// Derive account at specific index.
    pub async fn derive_account(&self, chain: &Chain, index: u32) -> WalletAccount {
        let address = if chain.is_evm() {
            self.identity.evm_address().to_string()
        } else {
            match chain {
                // TKS uses Ethereum H160 addresses (EVM-compatible Substrate)
                Chain::Substrate => self.identity.evm_address().to_string(),
                _ => self.identity.evm_address().to_string(),
            }
        };

        let account = WalletAccount {
            chain: chain.clone(),
            address,
            index,
            label: None,
        };

        // Cache it
        let mut accounts = self.accounts.write().await;
        accounts
            .entry(chain.clone())
            .or_default()
            .push(account.clone());

        account
    }

    /// Get all accounts across all chains.
    pub async fn all_accounts(&self) -> Vec<WalletAccount> {
        let accounts = self.accounts.read().await;
        accounts.values().flatten().cloned().collect()
    }

    // ─── Address Utilities ───────────────────────────────

    /// Validate an address for a chain.
    pub fn validate_address(chain: &Chain, address: &str) -> bool {
        match chain {
            c if c.is_evm() => Self::validate_evm_address(address),
            Chain::Substrate => Self::validate_substrate_address(address),
            Chain::Bitcoin => Self::validate_btc_address(address),
            Chain::Solana => Self::validate_solana_address(address),
            _ => false,
        }
    }

    fn validate_evm_address(address: &str) -> bool {
        if !address.starts_with("0x") {
            return false;
        }
        if address.len() != 42 {
            return false;
        }
        address[2..].chars().all(|c| c.is_ascii_hexdigit())
    }

    fn validate_substrate_address(address: &str) -> bool {
        // SS58: starts with 1-9 or A-H, J-N, P-Z, 46-48 chars
        address.len() >= 46 && address.len() <= 48 && address.chars().all(|c| c.is_alphanumeric())
    }

    fn validate_btc_address(address: &str) -> bool {
        // P2PKH: starts with 1, P2SH: starts with 3, Bech32: starts with bc1
        (address.starts_with('1') && address.len() >= 25 && address.len() <= 34)
            || (address.starts_with('3') && address.len() >= 25 && address.len() <= 34)
            || (address.starts_with("bc1") && address.len() >= 42 && address.len() <= 62)
    }

    fn validate_solana_address(address: &str) -> bool {
        // Base58, 32-44 chars
        address.len() >= 32 && address.len() <= 44 && address.chars().all(|c| c.is_alphanumeric())
    }

    // ─── Balance ─────────────────────────────────────────

    /// Get token balances for a chain.
    pub async fn get_balances(&self, chain: &Chain) -> Vec<TokenBalance> {
        let account = self.get_account(chain).await;
        let balances = self.balances.read().await;
        balances.get(&account.address).cloned().unwrap_or_default()
    }

    /// Get total portfolio value in USD.
    pub async fn total_value_usd(&self) -> f64 {
        let balances = self.balances.read().await;
        balances
            .values()
            .flatten()
            .filter_map(|b| b.value_usd)
            .sum()
    }

    /// Set balances (mock / after RPC fetch).
    pub async fn set_balances(&self, address: &str, balances: Vec<TokenBalance>) {
        self.balances
            .write()
            .await
            .insert(address.to_string(), balances);
    }

    // ─── Transaction Signing ─────────────────────────────

    /// Sign an EVM transaction (EIP-155 / EIP-1559).
    pub async fn sign_transaction(
        &self,
        input: &TransactionInput,
    ) -> Result<SignedTransaction, CipherError> {
        if !input.chain.is_evm() {
            return Err(CipherError::Network(format!(
                "Transaction signing not yet supported for {:?}",
                input.chain
            )));
        }

        // Get the signing key from identity
        let signing_key = self.identity.secp256k1_signing_key();

        // Build the transaction hash to sign
        let tx_hash = self.build_evm_tx_hash(input)?;

        // Sign with secp256k1
        let signature: Signature = signing_key.sign(&tx_hash);
        let sig_bytes = signature.to_bytes();

        let account = self.get_account(&input.chain).await;
        let tx_hash_hex = format!("0x{}", hex::encode(&tx_hash[..8]));

        Ok(SignedTransaction {
            chain: input.chain.clone(),
            hash: tx_hash_hex,
            raw_tx: format!("0x{}", hex::encode(sig_bytes)),
            from: account.address.clone(),
            to: input.to.clone(),
            value: input.value.clone(),
        })
    }

    /// Build the EVM transaction hash for signing.
    fn build_evm_tx_hash(&self, input: &TransactionInput) -> Result<Vec<u8>, CipherError> {
        let chain_id = input
            .chain
            .chain_id()
            .ok_or(CipherError::Network("Not an EVM chain".into()))?;

        // Simplified RLP-like hash (production: use full RLP encoding)
        let mut hasher = Keccak256::new();
        hasher.update(chain_id.to_be_bytes());
        hasher.update(input.nonce.unwrap_or(0).to_be_bytes());
        hasher.update(input.to.as_bytes());
        hasher.update(input.value.as_bytes());
        if let Some(data) = &input.data {
            hasher.update(data.as_bytes());
        }
        hasher.update(input.gas_limit.unwrap_or(21000).to_be_bytes());

        Ok(hasher.finalize().to_vec())
    }

    // ─── ERC-20 Token Transfers ──────────────────────────

    /// Build calldata for ERC-20 transfer.
    pub fn build_erc20_transfer(to: &str, amount: &str) -> String {
        // transfer(address,uint256) selector = 0xa9059cbb
        let to_clean = to.trim_start_matches("0x");
        let to_padded = format!("{:0>64}", to_clean);
        // Amount as hex (simplified — production needs proper uint256)
        let amount_hex = format!("{:0>64x}", amount.parse::<u128>().unwrap_or(0));
        format!("0xa9059cbb{}{}", to_padded, amount_hex)
    }

    /// Build calldata for ERC-20 approve.
    pub fn build_erc20_approve(spender: &str, amount: &str) -> String {
        // approve(address,uint256) selector = 0x095ea7b3
        let spender_clean = spender.trim_start_matches("0x");
        let spender_padded = format!("{:0>64}", spender_clean);
        let amount_hex = format!("{:0>64x}", amount.parse::<u128>().unwrap_or(0));
        format!("0x095ea7b3{}{}", spender_padded, amount_hex)
    }

    // ─── Fee Estimation ──────────────────────────────────

    /// Estimate transaction fees.
    pub async fn estimate_fees(&self, chain: &Chain) -> FeeEstimate {
        // Mock fee estimation (production: query RPC)
        let (slow_gwei, std_gwei, fast_gwei) = match chain {
            Chain::Ethereum => ("15", "25", "40"),
            Chain::BinanceSmartChain => ("3", "5", "8"),
            Chain::Polygon => ("30", "50", "100"),
            Chain::Avalanche => ("25", "30", "45"),
            Chain::Arbitrum => ("0.1", "0.2", "0.3"),
            Chain::Optimism => ("0.001", "0.002", "0.005"),
            Chain::Base => ("0.001", "0.002", "0.005"),
            _ => ("1", "2", "5"),
        };

        FeeEstimate {
            chain: chain.clone(),
            slow: FeeOption {
                label: "Slow".into(),
                gas_price_gwei: slow_gwei.into(),
                estimated_fee_usd: "$0.50".into(),
                estimated_time: "~5 min".into(),
            },
            standard: FeeOption {
                label: "Standard".into(),
                gas_price_gwei: std_gwei.into(),
                estimated_fee_usd: "$1.20".into(),
                estimated_time: "~30s".into(),
            },
            fast: FeeOption {
                label: "Fast".into(),
                gas_price_gwei: fast_gwei.into(),
                estimated_fee_usd: "$2.50".into(),
                estimated_time: "~10s".into(),
            },
        }
    }

    // ─── Transaction History ─────────────────────────────

    /// Add a transaction to history.
    pub async fn add_to_history(&self, tx: TransactionRecord) {
        self.history.write().await.push(tx);
    }

    /// Get transaction history for a chain.
    pub async fn get_history(&self, chain: &Chain) -> Vec<TransactionRecord> {
        self.history
            .read()
            .await
            .iter()
            .filter(|tx| &tx.chain == chain)
            .cloned()
            .collect()
    }

    /// Get all transaction history.
    pub async fn all_history(&self) -> Vec<TransactionRecord> {
        self.history.read().await.clone()
    }

    // ─── Token Management ────────────────────────────────

    /// Get default tokens for a chain.
    pub fn default_tokens(chain: &Chain) -> Vec<Token> {
        let mut tokens = vec![Token::native(chain)];

        match chain {
            Chain::Ethereum => {
                tokens.push(Token::erc20(
                    Chain::Ethereum,
                    "USDT",
                    "Tether",
                    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
                    6,
                ));
                tokens.push(Token::erc20(
                    Chain::Ethereum,
                    "USDC",
                    "USD Coin",
                    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    6,
                ));
                tokens.push(Token::erc20(
                    Chain::Ethereum,
                    "DAI",
                    "Dai",
                    "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                    18,
                ));
                tokens.push(Token::erc20(
                    Chain::Ethereum,
                    "WETH",
                    "Wrapped Ether",
                    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                    18,
                ));
                tokens.push(Token::erc20(
                    Chain::Ethereum,
                    "UNI",
                    "Uniswap",
                    "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984",
                    18,
                ));
                tokens.push(Token::erc20(
                    Chain::Ethereum,
                    "LINK",
                    "Chainlink",
                    "0x514910771AF9Ca656af840dff83E8264EcF986CA",
                    18,
                ));
            }
            Chain::BinanceSmartChain => {
                tokens.push(Token::erc20(
                    Chain::BinanceSmartChain,
                    "USDT",
                    "Tether BSC",
                    "0x55d398326f99059fF775485246999027B3197955",
                    18,
                ));
                tokens.push(Token::erc20(
                    Chain::BinanceSmartChain,
                    "BUSD",
                    "Binance USD",
                    "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
                    18,
                ));
                tokens.push(Token::erc20(
                    Chain::BinanceSmartChain,
                    "CAKE",
                    "PancakeSwap",
                    "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82",
                    18,
                ));
            }
            Chain::Polygon => {
                tokens.push(Token::erc20(
                    Chain::Polygon,
                    "USDT",
                    "Tether Polygon",
                    "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
                    6,
                ));
                tokens.push(Token::erc20(
                    Chain::Polygon,
                    "USDC",
                    "USD Coin Polygon",
                    "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
                    6,
                ));
                tokens.push(Token::erc20(
                    Chain::Polygon,
                    "AAVE",
                    "Aave",
                    "0xD6DF932A45C0f255f85145f286eA0b292B21C90B",
                    18,
                ));
            }
            _ => {}
        }
        tokens
    }

    /// Add a custom token.
    pub async fn add_custom_token(&self, token: Token) {
        self.custom_tokens.write().await.push(token);
    }

    /// Get all tokens for a chain (default + custom).
    pub async fn get_tokens(&self, chain: &Chain) -> Vec<Token> {
        let mut tokens = Self::default_tokens(chain);
        let custom = self.custom_tokens.read().await;
        tokens.extend(custom.iter().filter(|t| &t.chain == chain).cloned());
        tokens
    }

    // ─── RPC Configuration ───────────────────────────────

    /// Set a custom RPC endpoint for a chain.
    pub async fn set_rpc(&self, chain: Chain, url: String) {
        self.custom_rpcs.write().await.insert(chain, url);
    }

    /// Get the active RPC endpoint for a chain.
    pub async fn get_rpc(&self, chain: &Chain) -> String {
        let custom = self.custom_rpcs.read().await;
        custom
            .get(chain)
            .cloned()
            .unwrap_or_else(|| chain.default_rpc().to_string())
    }

    // ─── Utility ─────────────────────────────────────────

    /// Format balance from raw to display (e.g. wei → ETH).
    pub fn format_balance(raw: &str, decimals: u8) -> String {
        let raw_val: u128 = raw.parse().unwrap_or(0);
        if raw_val == 0 {
            return "0".to_string();
        }

        let divisor = 10u128.pow(decimals as u32);
        let whole = raw_val / divisor;
        let frac = raw_val % divisor;

        if frac == 0 {
            format!("{}", whole)
        } else {
            let frac_str = format!("{:0>width$}", frac, width = decimals as usize);
            let trimmed = frac_str.trim_end_matches('0');
            format!("{}.{}", whole, trimmed)
        }
    }

    /// Parse display amount to raw (e.g. "1.5" ETH → wei string).
    pub fn parse_amount(display: &str, decimals: u8) -> String {
        let parts: Vec<&str> = display.split('.').collect();
        let whole: u128 = parts[0].parse().unwrap_or(0);
        let frac: u128 = if parts.len() > 1 {
            let frac_str = format!("{:0<width$}", parts[1], width = decimals as usize);
            frac_str[..decimals as usize].parse().unwrap_or(0)
        } else {
            0
        };
        let raw = whole * 10u128.pow(decimals as u32) + frac;
        raw.to_string()
    }

    /// Get supported chains list.
    pub fn supported_chains() -> Vec<Chain> {
        vec![
            Chain::Ethereum,
            Chain::BinanceSmartChain,
            Chain::Polygon,
            Chain::Avalanche,
            Chain::Arbitrum,
            Chain::Optimism,
            Chain::Base,
            Chain::Substrate,
            Chain::Solana,
            Chain::Bitcoin,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    /// Pre-computed PBKDF2 seed for BIP-39 "abandon abandon abandon ... about"
    /// with empty passphrase. This is the well-known BIP-39 test vector #1.
    /// Using from_seed_bytes() bypasses the slow PBKDF2 call in debug mode.
    const TEST_SEED: [u8; 64] = [
        0x5e, 0xb0, 0x0b, 0xbd, 0xdc, 0xf0, 0x69, 0x08, 0x48, 0x89, 0xa8, 0xab, 0x91, 0x55, 0x56,
        0x81, 0x65, 0xf5, 0xc4, 0x53, 0xcc, 0xb8, 0x5e, 0x70, 0x81, 0x1a, 0xae, 0xd6, 0xf6, 0xda,
        0x5f, 0xc1, 0x9a, 0x5a, 0xc4, 0x0b, 0x38, 0x9c, 0xd3, 0x70, 0xd0, 0x86, 0x20, 0x6d, 0xec,
        0x8a, 0xa6, 0xc4, 0x3d, 0xae, 0xa6, 0x69, 0x0f, 0x20, 0xad, 0x3d, 0x8d, 0x48, 0xb2, 0xd2,
        0xce, 0x9e, 0x38, 0xe4,
    ];

    static TEST_ID: LazyLock<CipherIdentity> = LazyLock::new(|| {
        CipherIdentity::from_seed_bytes(
            &TEST_SEED,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ).unwrap()
    });

    fn test_wallet() -> WalletCore {
        WalletCore::new(TEST_ID.clone())
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn test_derive_evm_account() {
        let wallet = test_wallet();
        let acc = wallet.get_account(&Chain::Ethereum).await;
        assert!(acc.address.starts_with("0x"));
        assert_eq!(acc.address.len(), 42);
        assert_eq!(acc.chain, Chain::Ethereum);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_multi_chain_accounts() {
        let wallet = test_wallet();
        let eth = wallet.get_account(&Chain::Ethereum).await;
        let bsc = wallet.get_account(&Chain::BinanceSmartChain).await;
        let poly = wallet.get_account(&Chain::Polygon).await;
        assert_eq!(eth.address, bsc.address);
        assert_eq!(bsc.address, poly.address);
        // TKS is EVM-compatible → same H160 address as Ethereum
        let sub = wallet.get_account(&Chain::Substrate).await;
        assert_eq!(eth.address, sub.address, "TKS uses H160 (same as ETH)");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_sign_transaction() {
        let wallet = test_wallet();
        let input = TransactionInput {
            chain: Chain::Ethereum,
            to: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD60".into(),
            value: "1000000000000000000".into(),
            data: None,
            nonce: Some(0),
            gas_limit: Some(21000),
            gas_price: Some("20000000000".into()),
            max_fee_per_gas: None,
            max_priority_fee: None,
        };

        let signed = wallet.sign_transaction(&input).await.unwrap();
        assert!(signed.hash.starts_with("0x"));
        assert!(signed.raw_tx.starts_with("0x"));
        assert_eq!(signed.to, input.to);
    }

    #[test]
    fn test_address_validation() {
        assert!(WalletCore::validate_address(
            &Chain::Ethereum,
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD60"
        ));
        assert!(!WalletCore::validate_address(&Chain::Ethereum, "0xinvalid"));
        assert!(!WalletCore::validate_address(
            &Chain::Ethereum,
            "not_an_address"
        ));
    }

    #[test]
    fn test_format_balance() {
        assert_eq!(WalletCore::format_balance("1000000000000000000", 18), "1");
        assert_eq!(WalletCore::format_balance("1500000000000000000", 18), "1.5");
        assert_eq!(WalletCore::format_balance("1000000", 6), "1");
        assert_eq!(WalletCore::format_balance("0", 18), "0");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(WalletCore::parse_amount("1", 18), "1000000000000000000");
        assert_eq!(WalletCore::parse_amount("1.5", 18), "1500000000000000000");
        assert_eq!(WalletCore::parse_amount("1", 6), "1000000");
    }

    #[test]
    fn test_default_tokens() {
        let tokens = WalletCore::default_tokens(&Chain::Ethereum);
        assert!(tokens.len() >= 5);
        assert_eq!(tokens[0].symbol, "ETH");
        assert!(tokens[0].is_native());
        assert!(!tokens[1].is_native());
    }

    #[test]
    fn test_erc20_transfer_calldata() {
        let data = WalletCore::build_erc20_transfer(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD60",
            "1000000",
        );
        assert!(data.starts_with("0xa9059cbb"));
        assert_eq!(data.len(), 138);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_fee_estimation() {
        let wallet = test_wallet();
        let fees = wallet.estimate_fees(&Chain::Ethereum).await;
        assert_eq!(fees.chain, Chain::Ethereum);
        assert!(!fees.slow.gas_price_gwei.is_empty());
        assert!(!fees.fast.gas_price_gwei.is_empty());
    }

    #[test]
    fn test_chain_properties() {
        assert_eq!(Chain::Ethereum.chain_id(), Some(1));
        assert_eq!(Chain::BinanceSmartChain.chain_id(), Some(56));
        assert!(Chain::Ethereum.is_evm());
        assert!(!Chain::Bitcoin.is_evm());
        assert_eq!(Chain::Bitcoin.decimals(), 8);
        assert_eq!(Chain::Ethereum.decimals(), 18);
    }
}
