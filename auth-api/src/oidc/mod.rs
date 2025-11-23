//! OIDC (OpenID Connect) SSO Provider Integration
//!
//! Supports enterprise SSO via any OIDC-compliant identity provider:
//! - Okta, Auth0, Azure AD, Google Workspace, Keycloak, etc.

use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType, CoreUserInfoClaims},
    reqwest::async_http_client,
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum OidcError {
    #[error("OIDC configuration error: {0}")]
    ConfigError(String),

    #[error("OIDC provider error: {0}")]
    ProviderError(String),

    #[error("Token exchange failed: {0}")]
    TokenExchangeError(String),

    #[error("User info retrieval failed: {0}")]
    UserInfoError(String),

    #[error("Missing environment variable: {0}")]
    EnvVarError(String),
}

/// OIDC configuration loaded from environment
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
}

impl OidcConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, OidcError> {
        Ok(Self {
            client_id: env::var("OIDC_CLIENT_ID")
                .map_err(|_| OidcError::EnvVarError("OIDC_CLIENT_ID".to_string()))?,
            client_secret: env::var("OIDC_CLIENT_SECRET")
                .map_err(|_| OidcError::EnvVarError("OIDC_CLIENT_SECRET".to_string()))?,
            issuer_url: env::var("OIDC_ISSUER")
                .map_err(|_| OidcError::EnvVarError("OIDC_ISSUER".to_string()))?,
            redirect_url: env::var("OIDC_REDIRECT_URL").unwrap_or_else(|_| {
                "https://chat.yourdomain.com/auth/callback".to_string()
            }),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
        })
    }
}

/// User information retrieved from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUser {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
}

/// OIDC authentication state for session management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub csrf_token: String,
    pub nonce: String,
    pub pkce_verifier: Option<String>,
}

/// OIDC Provider client
pub struct OidcProvider {
    client: CoreClient,
    config: OidcConfig,
}

impl OidcProvider {
    /// Create a new OIDC provider from configuration
    pub async fn new(config: OidcConfig) -> Result<Self, OidcError> {
        let issuer_url = IssuerUrl::new(config.issuer_url.clone())
            .map_err(|e| OidcError::ConfigError(e.to_string()))?;

        // Discover provider metadata
        let provider_metadata =
            CoreProviderMetadata::discover_async(issuer_url, async_http_client)
                .await
                .map_err(|e| OidcError::ProviderError(e.to_string()))?;

        let redirect_url = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|e| OidcError::ConfigError(e.to_string()))?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
        )
        .set_redirect_uri(redirect_url);

        Ok(Self { client, config })
    }

    /// Generate the authorization URL for SSO login
    ///
    /// Returns (auth_url, auth_state) where auth_state should be stored in session
    pub fn authorization_url(&self) -> (String, AuthState) {
        let mut auth_request = self.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );

        // Add configured scopes
        for scope in &self.config.scopes {
            auth_request = auth_request.add_scope(Scope::new(scope.clone()));
        }

        let (auth_url, csrf_token, nonce) = auth_request.url();

        let state = AuthState {
            csrf_token: csrf_token.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: None,
        };

        (auth_url.to_string(), state)
    }

    /// Exchange authorization code for tokens and user info
    pub async fn exchange_code(
        &self,
        code: &str,
        _state: &AuthState,
    ) -> Result<(String, OidcUser), OidcError> {
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OidcError::TokenExchangeError(e.to_string()))?;

        let access_token = token_response.access_token().secret().clone();

        // Get user info
        let user_info: CoreUserInfoClaims = self
            .client
            .user_info(token_response.access_token().clone(), None)
            .map_err(|e| OidcError::UserInfoError(e.to_string()))?
            .request_async(async_http_client)
            .await
            .map_err(|e| OidcError::UserInfoError(e.to_string()))?;

        let user = OidcUser {
            subject: user_info.subject().to_string(),
            email: user_info.email().map(|e| e.to_string()),
            email_verified: user_info.email_verified(),
            name: user_info
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.to_string()),
            preferred_username: user_info.preferred_username().map(|u| u.to_string()),
            picture: user_info
                .picture()
                .and_then(|p| p.get(None))
                .map(|p| p.to_string()),
        };

        Ok((access_token, user))
    }
}

/// Convenience function to get login URL
pub async fn login_url() -> Result<String, OidcError> {
    let config = OidcConfig::from_env()?;
    let provider = OidcProvider::new(config).await?;
    let (url, _state) = provider.authorization_url();
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_config_fields() {
        let config = OidcConfig {
            client_id: "test-client".to_string(),
            client_secret: "test-secret".to_string(),
            issuer_url: "https://issuer.example.com".to_string(),
            redirect_url: "https://app.example.com/callback".to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
        };

        assert_eq!(config.client_id, "test-client");
        assert_eq!(config.scopes.len(), 2);
    }
}
