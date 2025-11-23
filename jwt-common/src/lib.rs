//! Shared JWT token handling for Unhidra services
//!
//! This crate provides unified JWT token generation and validation
//! for auth-api, gateway-service, and other Unhidra microservices.
//!
//! # Token Structure
//!
//! All tokens include these claims:
//! - `sub`: Subject (username or user ID)
//! - `exp`: Expiration timestamp
//! - `iat`: Issued-at timestamp
//! - `room`: Optional room assignment for WebSocket connections
//!
//! # Usage
//!
//! ```rust,ignore
//! use jwt_common::{TokenService, Claims};
//!
//! // Create service with secret
//! let service = TokenService::new("your-secret-key");
//!
//! // Generate token
//! let claims = Claims::new("username", 3600, None);
//! let token = service.generate(&claims)?;
//!
//! // Validate token
//! let validated = service.validate(&token)?;
//! ```

use chrono::Utc;
use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

/// Default token expiration time in seconds (1 hour)
pub const DEFAULT_EXPIRATION_SECS: i64 = 3600;

/// JWT claims structure used across all Unhidra services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject - typically the username or user ID
    pub sub: String,

    /// Expiration timestamp (Unix epoch seconds)
    pub exp: usize,

    /// Issued-at timestamp (Unix epoch seconds)
    pub iat: usize,

    /// Optional room/channel assignment for WebSocket connections
    /// If not set, gateway-service defaults to `user:{sub}`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,

    /// Optional display name for UI purposes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl Claims {
    /// Create new claims with the given subject and expiration
    ///
    /// # Arguments
    /// - `sub`: Subject identifier (username or user ID)
    /// - `expiration_secs`: Token lifetime in seconds from now
    /// - `room`: Optional room assignment
    pub fn new(sub: impl Into<String>, expiration_secs: i64, room: Option<String>) -> Self {
        let now = Utc::now().timestamp() as usize;
        Self {
            sub: sub.into(),
            exp: now + expiration_secs as usize,
            iat: now,
            room,
            display_name: None,
        }
    }

    /// Create claims with display name
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Create claims with a specific room
    pub fn with_room(mut self, room: impl Into<String>) -> Self {
        self.room = Some(room.into());
        self
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp() as usize;
        self.exp < now
    }

    /// Get the room ID for WebSocket connections
    /// Returns custom room if set, otherwise defaults to `user:{sub}`
    pub fn room_id(&self) -> String {
        self.room
            .clone()
            .unwrap_or_else(|| format!("user:{}", self.sub))
    }
}

/// Token service for JWT generation and validation
#[derive(Clone)]
pub struct TokenService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl TokenService {
    /// Create a new token service with the given secret
    ///
    /// # Arguments
    /// - `secret`: The secret key used for signing and verifying tokens.
    ///   MUST be the same across all services.
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        let secret_bytes = secret.as_ref();
        let mut validation = Validation::default();
        validation.leeway = 60; // 60 second clock skew tolerance
        validation.validate_exp = true;

        Self {
            encoding_key: EncodingKey::from_secret(secret_bytes),
            decoding_key: DecodingKey::from_secret(secret_bytes),
            validation,
        }
    }

    /// Create a token service from the JWT_SECRET environment variable
    ///
    /// Falls back to "supersecret" in development if not set.
    /// WARNING: Always set JWT_SECRET in production!
    pub fn from_env() -> Self {
        let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| {
            eprintln!("WARNING: JWT_SECRET not set, using default. DO NOT USE IN PRODUCTION!");
            "supersecret".to_string()
        });
        Self::new(secret)
    }

    /// Generate a JWT token from the given claims
    pub fn generate(&self, claims: &Claims) -> Result<String, JwtError> {
        encode(&Header::default(), claims, &self.encoding_key)
    }

    /// Validate a JWT token and extract claims
    ///
    /// Returns an error if:
    /// - Token signature is invalid
    /// - Token is expired
    /// - Token format is malformed
    pub fn validate(&self, token: &str) -> Result<Claims, JwtError> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)?;
        Ok(token_data.claims)
    }

    /// Validate a token and return the subject if valid
    ///
    /// Convenience method for simple authentication checks
    pub fn validate_subject(&self, token: &str) -> Result<String, JwtError> {
        let claims = self.validate(token)?;
        Ok(claims.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let service = TokenService::new("test-secret");
        let claims = Claims::new("testuser", 3600, None);

        let token = service.generate(&claims).expect("Token generation failed");
        let validated = service.validate(&token).expect("Token validation failed");

        assert_eq!(validated.sub, "testuser");
        assert!(!validated.is_expired());
    }

    #[test]
    fn test_token_with_room() {
        let service = TokenService::new("test-secret");
        let claims = Claims::new("user1", 3600, Some("chat:general".to_string()));

        let token = service.generate(&claims).expect("Token generation failed");
        let validated = service.validate(&token).expect("Token validation failed");

        assert_eq!(validated.room, Some("chat:general".to_string()));
        assert_eq!(validated.room_id(), "chat:general");
    }

    #[test]
    fn test_default_room_id() {
        let claims = Claims::new("alice", 3600, None);
        assert_eq!(claims.room_id(), "user:alice");
    }

    #[test]
    fn test_expired_token() {
        let service = TokenService::new("test-secret");
        // Create a token that expired 1 hour ago
        let mut claims = Claims::new("user", 3600, None);
        claims.exp = (Utc::now().timestamp() - 3600) as usize;

        let token = service.generate(&claims).expect("Token generation failed");
        let result = service.validate(&token);

        assert!(result.is_err(), "Expired token should fail validation");
    }

    #[test]
    fn test_invalid_signature() {
        let service1 = TokenService::new("secret-1");
        let service2 = TokenService::new("secret-2");

        let claims = Claims::new("user", 3600, None);
        let token = service1.generate(&claims).expect("Token generation failed");

        let result = service2.validate(&token);
        assert!(
            result.is_err(),
            "Token with wrong secret should fail validation"
        );
    }

    #[test]
    fn test_claims_with_display_name() {
        let claims = Claims::new("bob", 3600, None).with_display_name("Bob Smith");
        assert_eq!(claims.display_name, Some("Bob Smith".to_string()));
    }
}
