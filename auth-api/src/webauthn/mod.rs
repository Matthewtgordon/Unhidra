//! WebAuthn/Passkeys Authentication
//!
//! Provides passwordless authentication using FIDO2/WebAuthn standard:
//! - Hardware security keys (YubiKey, etc.)
//! - Platform authenticators (Touch ID, Windows Hello, Android biometrics)
//! - Passkeys (synced across devices)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] WebauthnError),

    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    #[error("Credential not found")]
    CredentialNotFound,

    #[error("Registration state not found")]
    RegistrationStateNotFound,

    #[error("Authentication state not found")]
    AuthenticationStateNotFound,

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// WebAuthn configuration
#[derive(Clone, Debug)]
pub struct WebAuthnConfig {
    /// Relying Party ID (typically the domain)
    pub rp_id: String,
    /// Relying Party name (displayed to user)
    pub rp_name: String,
    /// Relying Party origin URL
    pub rp_origin: String,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "unhidra.example.com".to_string(),
            rp_name: "Unhidra Secure Chat".to_string(),
            rp_origin: "https://unhidra.example.com".to_string(),
        }
    }
}

/// Stored credential for a user
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: Vec<u8>,
    pub user_id: Uuid,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub device_name: Option<String>,
}

/// Registration challenge response to send to client
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationChallenge {
    pub challenge: CreationChallengeResponse,
    pub state_id: String,
}

/// Authentication challenge response to send to client
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationChallenge {
    pub challenge: RequestChallengeResponse,
    pub state_id: String,
}

/// WebAuthn service for managing passkey registration and authentication
pub struct WebAuthnService {
    webauthn: Webauthn,
    /// In-memory storage for registration states (use Redis in production)
    registration_states: Arc<RwLock<HashMap<String, PasskeyRegistration>>>,
    /// In-memory storage for authentication states (use Redis in production)
    authentication_states: Arc<RwLock<HashMap<String, PasskeyAuthentication>>>,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(config: WebAuthnConfig) -> Result<Self, WebAuthnError> {
        let rp_id = config.rp_id.clone();
        let rp_origin = Url::parse(&config.rp_origin)
            .map_err(|e| WebAuthnError::ConfigError(e.to_string()))?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| WebAuthnError::ConfigError(e.to_string()))?
            .rp_name(&config.rp_name);

        let webauthn = builder
            .build()
            .map_err(|e| WebAuthnError::ConfigError(e.to_string()))?;

        Ok(Self {
            webauthn,
            registration_states: Arc::new(RwLock::new(HashMap::new())),
            authentication_states: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Start passkey registration for a user
    ///
    /// Returns challenge to send to client
    pub async fn start_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
        existing_credentials: Vec<CredentialID>,
    ) -> Result<RegistrationChallenge, WebAuthnError> {
        let (challenge, reg_state) = self.webauthn.start_passkey_registration(
            user_id,
            username,
            display_name,
            Some(existing_credentials),
        )?;

        let state_id = Uuid::new_v4().to_string();

        // Store registration state
        self.registration_states
            .write()
            .await
            .insert(state_id.clone(), reg_state);

        Ok(RegistrationChallenge {
            challenge,
            state_id,
        })
    }

    /// Complete passkey registration
    ///
    /// Returns the credential to store
    pub async fn finish_registration(
        &self,
        state_id: &str,
        response: RegisterPublicKeyCredential,
    ) -> Result<Passkey, WebAuthnError> {
        let reg_state = self
            .registration_states
            .write()
            .await
            .remove(state_id)
            .ok_or(WebAuthnError::RegistrationStateNotFound)?;

        let passkey = self
            .webauthn
            .finish_passkey_registration(&response, &reg_state)?;

        Ok(passkey)
    }

    /// Start passkey authentication
    ///
    /// Returns challenge to send to client
    pub async fn start_authentication(
        &self,
        credentials: Vec<Passkey>,
    ) -> Result<AuthenticationChallenge, WebAuthnError> {
        let (challenge, auth_state) = self.webauthn.start_passkey_authentication(&credentials)?;

        let state_id = Uuid::new_v4().to_string();

        // Store authentication state
        self.authentication_states
            .write()
            .await
            .insert(state_id.clone(), auth_state);

        Ok(AuthenticationChallenge {
            challenge,
            state_id,
        })
    }

    /// Complete passkey authentication
    ///
    /// Returns the authenticated credential and updated auth result
    pub async fn finish_authentication(
        &self,
        state_id: &str,
        response: PublicKeyCredential,
        credentials: &mut [Passkey],
    ) -> Result<AuthenticationResult, WebAuthnError> {
        let auth_state = self
            .authentication_states
            .write()
            .await
            .remove(state_id)
            .ok_or(WebAuthnError::AuthenticationStateNotFound)?;

        let result = self
            .webauthn
            .finish_passkey_authentication(&response, &auth_state)?;

        // Update credential counter to prevent replay attacks
        for cred in credentials.iter_mut() {
            if cred.cred_id() == result.cred_id() {
                cred.update_credential(&result);
                break;
            }
        }

        Ok(result)
    }

    /// Clean up expired registration states (call periodically)
    pub async fn cleanup_expired_states(&self, max_age_secs: u64) {
        // In a real implementation, states would have timestamps
        // For now, we just limit the size
        let mut reg_states = self.registration_states.write().await;
        if reg_states.len() > 1000 {
            reg_states.clear();
        }

        let mut auth_states = self.authentication_states.write().await;
        if auth_states.len() > 1000 {
            auth_states.clear();
        }

        let _ = max_age_secs; // Would be used with timestamps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WebAuthnConfig::default();
        assert_eq!(config.rp_id, "unhidra.example.com");
        assert_eq!(config.rp_name, "Unhidra Secure Chat");
    }

    #[tokio::test]
    async fn test_service_creation() {
        let config = WebAuthnConfig {
            rp_id: "localhost".to_string(),
            rp_name: "Test".to_string(),
            rp_origin: "https://localhost".to_string(),
        };

        let service = WebAuthnService::new(config);
        assert!(service.is_ok());
    }
}
