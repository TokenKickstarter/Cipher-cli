//! Cipher client-core error types.

#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Key exchange error: {0}")]
    KeyExchange(String),

    #[error("File error: {0}")]
    File(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
