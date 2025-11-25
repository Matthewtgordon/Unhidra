//! Chat module for Unhidra Desktop
//!
//! Handles WebSocket connections and message handling.

use crate::AppState;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[derive(Error, Debug)]
pub enum ChatError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("Not connected")]
    NotConnected,

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Chat message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: String,
    pub channel_id: String,
    pub sender_id: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub encrypted: bool,
}

/// WebSocket connection manager
pub struct WsManager {
    tx: mpsc::Sender<String>,
}

impl WsManager {
    /// Send a message through the WebSocket
    pub async fn send(&self, message: &str) -> Result<(), ChatError> {
        self.tx
            .send(message.to_string())
            .await
            .map_err(|e| ChatError::SendFailed(e.to_string()))
    }
}

/// Connect to chat server
pub async fn connect(state: &AppState, server_url: &str, token: &str) -> Result<(), ChatError> {
    let url = format!("{}?token={}", server_url, token);
    tracing::info!(url = %server_url, "Connecting to chat server");

    let (ws_stream, _) = connect_async(&url).await?;
    let (mut write, mut read) = ws_stream.split();

    // Channel for outgoing messages
    let (tx, mut rx) = mpsc::channel::<String>(100);

    // Store manager in state
    *state.ws_manager.write().await = Some(WsManager { tx });

    // Spawn task to handle outgoing messages
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write.send(Message::Text(msg)).await {
                tracing::error!(error = %e, "Failed to send WebSocket message");
                break;
            }
        }
    });

    // Spawn task to handle incoming messages
    tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    tracing::debug!(message = %text, "Received message");
                    // In production, emit event to frontend
                }
                Ok(Message::Close(_)) => {
                    tracing::info!("WebSocket closed");
                    break;
                }
                Ok(Message::Ping(data)) => {
                    tracing::trace!("Received ping");
                    // Pong is handled automatically
                    let _ = data;
                }
                Err(e) => {
                    tracing::error!(error = %e, "WebSocket error");
                    break;
                }
                _ => {}
            }
        }
    });

    tracing::info!("Connected to chat server");
    Ok(())
}

/// Send an encrypted message
pub async fn send_message(
    state: &AppState,
    channel_id: &str,
    content: &str,
) -> Result<String, ChatError> {
    let ws = state.ws_manager.read().await;
    let ws = ws.as_ref().ok_or(ChatError::NotConnected)?;

    let message = ChatMessage {
        id: uuid::Uuid::new_v4().to_string(),
        channel_id: channel_id.to_string(),
        sender_id: "self".to_string(),
        content: content.to_string(),
        timestamp: chrono::Utc::now(),
        encrypted: true,
    };

    let json = serde_json::to_string(&message)?;
    ws.send(&json).await?;

    Ok(message.id)
}
