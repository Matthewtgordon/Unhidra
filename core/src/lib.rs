//! Unhidra Core Library
//!
//! Shared utilities and security primitives for the Unhidra platform.
//!
//! # Modules
//!
//! - [`crypto`] - End-to-end encryption with Double Ratchet protocol
//! - [`audit`] - Immutable audit logging (requires `postgres` feature)

pub mod crypto;

#[cfg(feature = "postgres")]
pub mod audit;

// Re-exports for convenience
pub use crypto::{E2eeError, EncryptedMessage, KeyPair, PreKeyBundle, Ratchet};

/// Core library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
