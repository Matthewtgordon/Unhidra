//! WebSocket handler for real-time bidirectional communication.
//!
//! This module implements Phase 3 WebSocket Fabric Hardening:
//! - Token authentication via Sec-WebSocket-Protocol header
//! - Room-based pub/sub with DashMap and tokio::broadcast
//! - Origin checking for CSRF protection
//! - Resource cleanup on disconnect

use axum::{
    extract::{ws::Message, ws::WebSocket, State, WebSocketUpgrade},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
// jwt-common crate is used via state.token_service
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::state::AppState;

/// Broadcast channel capacity per room.
/// If clients can't keep up, oldest messages are dropped.
const CHANNEL_CAPACITY: usize = 100;

/// WebSocket upgrade handler for GET /ws endpoint.
///
/// # Authentication Flow
/// 1. Extract token from Sec-WebSocket-Protocol header (browser WebSocket API limitation)
/// 2. Validate JWT signature and expiration using jwt-common
/// 3. Check Origin header against allowed origins (CSRF protection)
/// 4. If valid, upgrade to WebSocket and join the appropriate room
///
/// # Security
/// - Rejects connections without valid tokens (HTTP 403)
/// - Validates Origin header to prevent Cross-Site WebSocket Hijacking
/// - Token is passed securely in header (not URL query) to avoid logging
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    // Extract and validate Origin header for CSRF protection
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if !state.is_origin_allowed(origin) {
            warn!(origin = origin, "WebSocket rejected: disallowed origin");
            return (StatusCode::FORBIDDEN, "Origin not allowed").into_response();
        }
    }
    // Note: Missing Origin header is allowed for non-browser clients (IoT devices)

    // Extract token from Sec-WebSocket-Protocol header
    // This is the recommended approach since browsers can't set Authorization headers
    // for WebSocket connections via the JS WebSocket API
    let protocol_header = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // The client sends: new WebSocket(url, ["bearer", "<token>"])
    // Browser sends: Sec-WebSocket-Protocol: bearer, <token>
    // We extract the token part
    let token = extract_token_from_protocol(protocol_header);

    if token.is_empty() {
        warn!("WebSocket rejected: missing token in Sec-WebSocket-Protocol");
        return (StatusCode::FORBIDDEN, "Missing authentication token").into_response();
    }

    // Validate the JWT token using shared jwt-common TokenService
    let claims = match state.token_service.validate(&token) {
        Ok(claims) => claims,
        Err(e) => {
            warn!(error = %e, "WebSocket rejected: invalid token");
            return (StatusCode::FORBIDDEN, "Invalid or expired token").into_response();
        }
    };

    // Determine room ID from token claims using jwt-common's room_id() helper
    let room_id = claims.room_id();

    info!(
        user = claims.sub,
        room = room_id,
        "WebSocket connection authenticated"
    );

    // Get or create broadcast channel for the room
    let rooms = state.rooms.clone();
    let sender = rooms
        .entry(room_id.clone())
        .or_insert_with(|| {
            info!(room = room_id, "Creating new room broadcast channel");
            broadcast::channel::<String>(CHANNEL_CAPACITY).0
        })
        .clone();

    // Respond with the accepted subprotocol (required by WebSocket spec)
    let _response_protocol = HeaderValue::from_str("bearer").ok();

    // Complete the WebSocket upgrade
    ws.protocols(["bearer"]).on_upgrade(move |socket| {
        handle_socket(socket, room_id, sender, rooms, claims.sub)
    })
}

/// Extracts the token from Sec-WebSocket-Protocol header.
///
/// Supports two formats:
/// 1. "bearer, <token>" - Standard format from browser WebSocket API
/// 2. "<token>" - Direct token (for non-browser clients)
fn extract_token_from_protocol(header: &str) -> String {
    let parts: Vec<&str> = header.split(',').map(|s| s.trim()).collect();

    // Format: "bearer, <token>"
    if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("bearer") {
        return parts[1].to_string();
    }

    // Format: direct token (for testing/non-browser clients)
    if parts.len() == 1 && !parts[0].eq_ignore_ascii_case("bearer") {
        return parts[0].to_string();
    }

    String::new()
}

/// Handles an active WebSocket connection.
///
/// # Message Flow
/// 1. Subscribes to the room's broadcast channel
/// 2. Spawns a task to forward broadcast messages to this client
/// 3. Listens for incoming messages and broadcasts them to the room
/// 4. Cleans up resources on disconnect
async fn handle_socket(
    socket: WebSocket,
    room_id: String,
    sender: broadcast::Sender<String>,
    rooms: Arc<dashmap::DashMap<String, broadcast::Sender<String>>>,
    user_id: String,
) {
    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Subscribe to room broadcasts
    let mut rx = sender.subscribe();

    info!(user = user_id, room = room_id, "Client joined room");

    // Task: Forward broadcast messages to this WebSocket client
    let forward_room_id = room_id.clone();
    let forward_user_id = user_id.clone();
    let forward_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg)).await.is_err() {
                info!(
                    user = forward_user_id,
                    room = forward_room_id,
                    "Client disconnected (send failed)"
                );
                break;
            }
        }
    });

    // Main loop: Receive messages from client and broadcast to room
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                // Broadcast to all room subscribers (including sender)
                if let Err(e) = sender.send(text.to_string()) {
                    // This only fails if there are no receivers (shouldn't happen)
                    error!(error = %e, "Failed to broadcast message");
                }
            }
            Ok(Message::Binary(data)) => {
                // Convert binary to hex for broadcast
                let encoded = hex_encode(&data);
                let _ = sender.send(format!("{{\"type\":\"binary\",\"data\":\"{}\"}}", encoded));
            }
            Ok(Message::Ping(data)) => {
                // Axum handles pong automatically, but log for debugging
                tracing::trace!("Received ping from {}", user_id);
                let _ = data; // Suppress unused warning
            }
            Ok(Message::Pong(_)) => {
                // Pong received, connection is alive
                tracing::trace!("Received pong from {}", user_id);
            }
            Ok(Message::Close(_)) => {
                info!(user = user_id, room = room_id, "Client sent close frame");
                break;
            }
            Err(e) => {
                warn!(user = user_id, error = %e, "WebSocket receive error");
                break;
            }
        }
    }

    // Cleanup: Stop the forward task
    forward_task.abort();

    info!(
        user = user_id,
        room = room_id,
        receivers = sender.receiver_count(),
        "Client disconnected"
    );

    // Cleanup: Remove room if no subscribers remain
    // This prevents memory leaks from abandoned rooms
    if sender.receiver_count() == 0 {
        rooms.remove(&room_id);
        info!(room = room_id, "Room removed (no remaining subscribers)");
    }
}

/// Simple hex encoding for binary messages.
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_token_bearer_format() {
        let header = "bearer, eyJhbGciOiJIUzI1NiJ9.test";
        let token = extract_token_from_protocol(header);
        assert_eq!(token, "eyJhbGciOiJIUzI1NiJ9.test");
    }

    #[test]
    fn test_extract_token_direct() {
        let header = "eyJhbGciOiJIUzI1NiJ9.test";
        let token = extract_token_from_protocol(header);
        assert_eq!(token, "eyJhbGciOiJIUzI1NiJ9.test");
    }

    #[test]
    fn test_extract_token_empty() {
        let token = extract_token_from_protocol("");
        assert_eq!(token, "");
    }

    #[test]
    fn test_extract_token_bearer_only() {
        let token = extract_token_from_protocol("bearer");
        assert_eq!(token, "");
    }

    #[test]
    fn test_hex_encode() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(hex_encode(&data), "deadbeef");
    }
}
