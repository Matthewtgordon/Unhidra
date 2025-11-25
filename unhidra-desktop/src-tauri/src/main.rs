//! Unhidra Desktop Client
//!
//! Cross-platform desktop application with E2EE, OIDC login, and auto-updates.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth;
mod chat;
mod e2ee;

use tauri::Manager;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Application state shared across commands
pub struct AppState {
    /// WebSocket connection manager
    pub ws_manager: tokio::sync::RwLock<Option<chat::WsManager>>,
    /// E2EE ratchet sessions
    pub e2ee_sessions: tokio::sync::RwLock<std::collections::HashMap<String, e2ee::Ratchet>>,
    /// Current user info
    pub current_user: tokio::sync::RwLock<Option<auth::UserInfo>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            ws_manager: tokio::sync::RwLock::new(None),
            e2ee_sessions: tokio::sync::RwLock::new(std::collections::HashMap::new()),
            current_user: tokio::sync::RwLock::new(None),
        }
    }
}

/// Initialize logging
fn init_logging() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env().add_directive("unhidra_desktop=debug".parse().unwrap()))
        .init();
}

/// Tauri command: Get application version
#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Tauri command: Login with OIDC
#[tauri::command]
async fn login_oidc(
    state: tauri::State<'_, AppState>,
    issuer: String,
    client_id: String,
) -> Result<auth::LoginResult, String> {
    auth::login_oidc(&state, &issuer, &client_id)
        .await
        .map_err(|e| e.to_string())
}

/// Tauri command: Connect to chat server
#[tauri::command]
async fn connect_chat(
    state: tauri::State<'_, AppState>,
    server_url: String,
    token: String,
) -> Result<(), String> {
    chat::connect(&state, &server_url, &token)
        .await
        .map_err(|e| e.to_string())
}

/// Tauri command: Send encrypted message
#[tauri::command]
async fn send_message(
    state: tauri::State<'_, AppState>,
    channel_id: String,
    content: String,
) -> Result<String, String> {
    chat::send_message(&state, &channel_id, &content)
        .await
        .map_err(|e| e.to_string())
}

/// Tauri command: Get current user info
#[tauri::command]
async fn get_current_user(state: tauri::State<'_, AppState>) -> Result<Option<auth::UserInfo>, String> {
    let user = state.current_user.read().await;
    Ok(user.clone())
}

/// Tauri command: Logout
#[tauri::command]
async fn logout(state: tauri::State<'_, AppState>) -> Result<(), String> {
    auth::logout(&state).await.map_err(|e| e.to_string())
}

/// Tauri command: Initialize E2EE session with peer
#[tauri::command]
async fn init_e2ee_session(
    state: tauri::State<'_, AppState>,
    peer_id: String,
    peer_prekey_bundle: String,
) -> Result<String, String> {
    e2ee::init_session(&state, &peer_id, &peer_prekey_bundle)
        .await
        .map_err(|e| e.to_string())
}

fn main() {
    init_logging();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            get_version,
            login_oidc,
            connect_chat,
            send_message,
            get_current_user,
            logout,
            init_e2ee_session,
        ])
        .setup(|app| {
            // Set up system tray
            #[cfg(desktop)]
            {
                let _tray = app.tray_by_id("main");
            }

            tracing::info!("Unhidra Desktop v{} started", env!("CARGO_PKG_VERSION"));
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
