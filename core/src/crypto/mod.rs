//! Cryptographic primitives for Unhidra
//!
//! This module provides:
//! - E2EE (End-to-End Encryption) using the Noise Protocol with Double Ratchet
//! - Key management utilities
//! - Secure message serialization

pub mod e2ee;

pub use e2ee::{
    encrypt_for_device, E2eeError, EncryptedMessage, KeyPair, PreKeyBundle, Ratchet,
};
