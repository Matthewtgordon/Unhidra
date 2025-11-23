//! Auth API - Authentication service with Argon2id and JWT
//!
//! This service provides HTTP endpoints for user authentication:
//! - POST /login - Authenticate user and receive JWT token
//! - GET /health - Health check endpoint
//!
//! # Security Features
//! - Argon2id password hashing (OWASP compliant)
//! - JWT token generation with configurable expiration
//! - Structured logging with tracing

mod handlers;
mod services;

use axum::{routing::{get, post}, Router};
use rusqlite::Connection;
use std::sync::Arc;
use tracing::info;

use handlers::{login_handler, health_handler, AppState};

#[tokio::main]
async fn main() {
    // Initialize tracing for structured logging
    tracing_subscriber_init();

    let bind_addr = std::env::var("AUTH_BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:9200".to_string());

    let db_path = std::env::var("AUTH_DB_PATH")
        .unwrap_or_else(|_| "/opt/unhidra/auth.db".to_string());

    // Open SQLite database connection
    let conn = Connection::open(&db_path)
        .expect(&format!("Failed to open database at {}", db_path));

    // Create application state with database, password service, and token service
    let state = Arc::new(AppState::new(conn));

    // Build router with authentication endpoints
    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    info!(bind_addr = %bind_addr, db_path = %db_path, "Auth API starting");

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind to address");

    info!("Auth API running on {}", bind_addr);

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}

/// Initialize tracing subscriber for structured logging
fn tracing_subscriber_init() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("auth_api=info"));

    fmt().with_env_filter(filter).init();
}
