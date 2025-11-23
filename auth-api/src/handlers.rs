//! HTTP handlers for authentication endpoints
//!
//! This module provides the login handler with Argon2id password verification
//! and JWT token generation using the shared jwt-common crate.

use axum::{extract::State, Json};
use jwt_common::{Claims, TokenService, DEFAULT_EXPIRATION_SECS};
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::services::PasswordService;

/// Shared application state for auth-api handlers
pub struct AppState {
    /// Database connection (SQLite)
    pub db: Mutex<Connection>,
    /// Argon2id password hashing service
    pub password_service: PasswordService,
    /// JWT token generation service
    pub token_service: TokenService,
}

impl AppState {
    /// Create a new AppState with the given database connection
    pub fn new(db: Connection) -> Self {
        Self {
            db: Mutex::new(db),
            password_service: PasswordService::new(),
            token_service: TokenService::from_env(),
        }
    }

    /// Create AppState for development/testing with faster password hashing
    #[cfg(any(test, debug_assertions))]
    pub fn new_dev(db: Connection) -> Self {
        Self {
            db: Mutex::new(db),
            password_service: PasswordService::new_dev(),
            token_service: TokenService::from_env(),
        }
    }
}

/// Login request payload
#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Handle user login with Argon2id password verification and JWT generation
///
/// # Flow
/// 1. Query user from database
/// 2. Verify account is verified
/// 3. Verify password using Argon2id (constant-time)
/// 4. Generate JWT token with claims
///
/// # Returns
/// - Success: `{ "ok": true, "user": "...", "display_name": "...", "token": "..." }`
/// - Error: `{ "error": "..." }`
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Json<serde_json::Value> {
    info!(username = %payload.username, "Login request received");

    let username = payload.username.clone();
    let conn = state.db.lock().unwrap();

    // Query user with Argon2id password_hash (PHC format includes salt)
    let mut stmt = match conn.prepare(
        "SELECT password_hash, verified, display_name FROM users WHERE username = ?1",
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "Failed to prepare SQL statement");
            return Json(json!({ "error": "db_error" }));
        }
    };

    let row = stmt.query_row(params![username.clone()], |r| {
        Ok((
            r.get::<_, String>(0)?, // password_hash (PHC format with embedded salt)
            r.get::<_, i64>(1)?,    // verified
            r.get::<_, String>(2)?, // display_name
        ))
    });

    let (stored_hash, verified, display_name) = match row {
        Ok(t) => t,
        Err(_) => {
            warn!(username = %username, "User not found");
            return Json(json!({ "error": "User not found" }));
        }
    };

    if verified == 0 {
        warn!(username = %username, "User not verified");
        return Json(json!({ "error": "Not verified" }));
    }

    // Verify password using Argon2id (constant-time comparison)
    match state
        .password_service
        .verify_password(&payload.password, &stored_hash)
    {
        Ok(true) => {
            // Password matches - continue to token generation
        }
        Ok(false) => {
            warn!(username = %username, "Invalid password");
            return Json(json!({ "error": "Invalid password" }));
        }
        Err(e) => {
            warn!(username = %username, error = %e, "Password verification error");
            return Json(json!({ "error": "Invalid password" }));
        }
    }

    // Generate JWT token with claims
    let claims = Claims::new(&username, DEFAULT_EXPIRATION_SECS, None)
        .with_display_name(&display_name);

    let token = match state.token_service.generate(&claims) {
        Ok(t) => t,
        Err(e) => {
            warn!(username = %username, error = %e, "Token generation failed");
            return Json(json!({ "error": "token_error" }));
        }
    };

    info!(username = %username, display_name = %display_name, "Login successful");

    Json(json!({
        "ok": true,
        "user": username,
        "display_name": display_name,
        "token": token
    }))
}

/// Health check endpoint
pub async fn health_handler() -> &'static str {
    "OK"
}
