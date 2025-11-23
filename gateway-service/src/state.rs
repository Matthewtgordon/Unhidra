//! Shared application state for the WebSocket gateway.
//!
//! This module defines the centralized state management for the gateway-service,
//! including room-based broadcast channels for real-time messaging.

use dashmap::DashMap;
use jwt_common::TokenService;
use std::sync::Arc;
use tokio::sync::broadcast;

/// Type alias for room ID to broadcast channel sender mapping.
///
/// Uses DashMap for lock-free concurrent access across multiple connections.
/// Each room has its own broadcast channel for efficient fan-out messaging.
pub type RoomsMap = DashMap<String, broadcast::Sender<String>>;

/// Shared application state for the WebSocket gateway.
#[derive(Clone)]
pub struct AppState {
    /// Thread-safe map of room IDs to their broadcast channels.
    ///
    /// - Key: Room ID (derived from user/device token claims)
    /// - Value: Broadcast channel sender for that room
    pub rooms: Arc<RoomsMap>,

    /// JWT token service for validation (from jwt-common crate).
    pub token_service: TokenService,

    /// Allowed origins for WebSocket connections (CSRF protection).
    pub allowed_origins: Vec<String>,
}

impl AppState {
    /// Creates a new AppState with the given configuration.
    pub fn new(token_service: TokenService, allowed_origins: Vec<String>) -> Self {
        Self {
            rooms: Arc::new(DashMap::new()),
            token_service,
            allowed_origins,
        }
    }

    /// Creates AppState from environment variables.
    ///
    /// Reads JWT_SECRET for token validation.
    /// WARNING: In production, always set JWT_SECRET to a strong random value.
    pub fn from_env(allowed_origins: Vec<String>) -> Self {
        Self::new(TokenService::from_env(), allowed_origins)
    }

    /// Creates AppState with default development configuration.
    ///
    /// WARNING: Only use in development. Uses weak JWT secret.
    #[allow(dead_code)]
    pub fn new_dev() -> Self {
        Self::from_env(vec![
            "http://localhost:3000".to_string(),
            "http://127.0.0.1:3000".to_string(),
        ])
    }

    /// Checks if an origin is allowed for WebSocket connections.
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        // In development mode with default origins, allow all for testing
        if self.allowed_origins.is_empty() {
            return true;
        }
        self.allowed_origins.iter().any(|o| o == origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_check() {
        let state = AppState::new(
            TokenService::new("secret"),
            vec!["https://example.com".to_string()],
        );

        assert!(state.is_origin_allowed("https://example.com"));
        assert!(!state.is_origin_allowed("https://evil.com"));
    }

    #[test]
    fn test_empty_origins_allows_all() {
        let state = AppState::new(TokenService::new("secret"), vec![]);
        assert!(state.is_origin_allowed("https://any-origin.com"));
    }
}
