use crate::crypto::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Missing _public_key in JSON")]
    MissingPublicKey,

    #[error("Invalid _public_key format (expected 64 hex chars)")]
    InvalidPublicKey,

    #[error("Private key not found for public key {0}")]
    PrivateKeyNotFound(String),

    #[error("Cannot use --write/-w without specifying --file/-f")]
    WriteWithoutFile,

    #[error("--write/-w is only supported for JSON output (use -o json)")]
    InvalidWriteForOutput,
}
