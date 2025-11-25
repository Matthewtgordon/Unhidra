//! E2EE module for Unhidra Desktop
//!
//! Client-side encryption using the Noise Protocol (Double Ratchet).

use crate::AppState;
use base64::Engine;
use serde::{Deserialize, Serialize};
use snow::Builder;
use std::sync::{Arc, Mutex};
use thiserror::Error;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_MESSAGE_SIZE: usize = 65535;

#[derive(Error, Debug)]
pub enum E2eeError {
    #[error("Noise protocol error: {0}")]
    Noise(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Handshake not complete")]
    HandshakeNotComplete,

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Pre-key bundle for session establishment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: String,  // base64
    pub signed_prekey: String, // base64
    pub signature: String,     // base64
}

/// E2EE session ratchet
pub struct Ratchet {
    session: Arc<Mutex<Option<snow::TransportState>>>,
    pub public_key: Vec<u8>,
}

impl Ratchet {
    /// Create a new ratchet with fresh keys
    pub fn new() -> Result<Self, E2eeError> {
        let builder =
            Builder::new(NOISE_PATTERN.parse().map_err(|e| E2eeError::Noise(format!("{:?}", e)))?)
        ;
        let keypair = builder
            .generate_keypair()
            .map_err(|e| E2eeError::Noise(e.to_string()))?;

        Ok(Self {
            session: Arc::new(Mutex::new(None)),
            public_key: keypair.public.to_vec(),
        })
    }

    /// Generate pre-key bundle for sharing
    pub fn generate_prekey_bundle(&self) -> PreKeyBundle {
        PreKeyBundle {
            identity_key: base64::engine::general_purpose::STANDARD.encode(&self.public_key),
            signed_prekey: base64::engine::general_purpose::STANDARD.encode(&self.public_key),
            signature: base64::engine::general_purpose::STANDARD.encode(&[0u8; 64]), // Placeholder
        }
    }

    /// Initiate session with peer's pre-key bundle
    pub fn initiate(&self, remote_bundle: &PreKeyBundle) -> Result<String, E2eeError> {
        let remote_key =
            base64::engine::general_purpose::STANDARD.decode(&remote_bundle.identity_key)?;

        let builder =
            Builder::new(NOISE_PATTERN.parse().map_err(|e| E2eeError::Noise(format!("{:?}", e)))?)
        ;

        let keypair = builder
            .generate_keypair()
            .map_err(|e| E2eeError::Noise(e.to_string()))?;

        let mut handshake = builder
            .local_private_key(&keypair.private)
            .remote_public_key(&remote_key)
            .build_initiator()
            .map_err(|e| E2eeError::Noise(e.to_string()))?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let len = handshake
            .write_message(&[], &mut buf)
            .map_err(|e| E2eeError::Noise(e.to_string()))?;
        buf.truncate(len);

        // For simplicity, go straight to transport mode
        // In production, complete the full handshake
        let transport = handshake
            .into_transport_mode()
            .map_err(|e| E2eeError::Noise(e.to_string()))?;
        *self.session.lock().unwrap() = Some(transport);

        Ok(base64::engine::general_purpose::STANDARD.encode(&buf))
    }

    /// Encrypt plaintext
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, E2eeError> {
        let mut session_guard = self.session.lock().unwrap();
        let session = session_guard
            .as_mut()
            .ok_or(E2eeError::HandshakeNotComplete)?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let len = session
            .write_message(plaintext, &mut buf)
            .map_err(|e| E2eeError::Noise(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Decrypt ciphertext
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, E2eeError> {
        let mut session_guard = self.session.lock().unwrap();
        let session = session_guard
            .as_mut()
            .ok_or(E2eeError::HandshakeNotComplete)?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let len = session
            .read_message(ciphertext, &mut buf)
            .map_err(|e| E2eeError::Noise(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }
}

/// Initialize E2EE session with a peer
pub async fn init_session(
    state: &AppState,
    peer_id: &str,
    peer_prekey_bundle_json: &str,
) -> Result<String, E2eeError> {
    let bundle: PreKeyBundle = serde_json::from_str(peer_prekey_bundle_json)?;

    let ratchet = Ratchet::new()?;
    let handshake_msg = ratchet.initiate(&bundle)?;

    // Store session
    state
        .e2ee_sessions
        .write()
        .await
        .insert(peer_id.to_string(), ratchet);

    tracing::info!(peer_id = peer_id, "E2EE session initialized");
    Ok(handshake_msg)
}

/// Encrypt a message for a peer
pub async fn encrypt_for_peer(
    state: &AppState,
    peer_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let sessions = state.e2ee_sessions.read().await;
    let ratchet = sessions
        .get(peer_id)
        .ok_or_else(|| E2eeError::SessionNotFound(peer_id.to_string()))?;
    ratchet.encrypt(plaintext)
}

/// Decrypt a message from a peer
pub async fn decrypt_from_peer(
    state: &AppState,
    peer_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let sessions = state.e2ee_sessions.read().await;
    let ratchet = sessions
        .get(peer_id)
        .ok_or_else(|| E2eeError::SessionNotFound(peer_id.to_string()))?;
    ratchet.decrypt(ciphertext)
}
