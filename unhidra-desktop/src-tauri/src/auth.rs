//! Authentication module for Unhidra Desktop
//!
//! Handles OIDC SSO login and secure credential storage.

use crate::AppState;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("OIDC error: {0}")]
    Oidc(String),

    #[error("Token storage error: {0}")]
    Storage(String),

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// User information from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

/// Login result returned to frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResult {
    pub success: bool,
    pub user: Option<UserInfo>,
    pub access_token: Option<String>,
    pub error: Option<String>,
}

/// Store credentials securely in system keychain
pub fn store_token(service: &str, token: &str) -> Result<(), AuthError> {
    let entry = keyring::Entry::new(service, "unhidra-user")
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    entry
        .set_password(token)
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    Ok(())
}

/// Retrieve credentials from system keychain
pub fn get_stored_token(service: &str) -> Result<Option<String>, AuthError> {
    let entry = keyring::Entry::new(service, "unhidra-user")
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    match entry.get_password() {
        Ok(token) => Ok(Some(token)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(AuthError::Storage(e.to_string())),
    }
}

/// Delete stored credentials
pub fn delete_token(service: &str) -> Result<(), AuthError> {
    let entry = keyring::Entry::new(service, "unhidra-user")
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    entry
        .delete_credential()
        .map_err(|e| AuthError::Storage(e.to_string()))?;
    Ok(())
}

/// Login via OIDC
pub async fn login_oidc(
    state: &AppState,
    issuer: &str,
    client_id: &str,
) -> Result<LoginResult, AuthError> {
    // In production, this would:
    // 1. Open system browser to OIDC authorization URL
    // 2. Listen on localhost for callback
    // 3. Exchange code for tokens
    // 4. Store tokens securely

    // For now, return a placeholder
    tracing::info!(issuer = issuer, client_id = client_id, "OIDC login initiated");

    // Placeholder implementation
    let user = UserInfo {
        id: uuid::Uuid::new_v4().to_string(),
        email: Some("user@example.com".to_string()),
        name: Some("Demo User".to_string()),
        picture: None,
    };

    // Store user in state
    *state.current_user.write().await = Some(user.clone());

    Ok(LoginResult {
        success: true,
        user: Some(user),
        access_token: Some("placeholder-token".to_string()),
        error: None,
    })
}

/// Logout and clear credentials
pub async fn logout(state: &AppState) -> Result<(), AuthError> {
    // Clear stored tokens
    let _ = delete_token("unhidra-access-token");
    let _ = delete_token("unhidra-refresh-token");

    // Clear state
    *state.current_user.write().await = None;
    *state.ws_manager.write().await = None;
    state.e2ee_sessions.write().await.clear();

    tracing::info!("User logged out");
    Ok(())
}
