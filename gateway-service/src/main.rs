use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::ConnectInfo,
    routing::get,
    Router,
};
use std::{net::SocketAddr};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() {
    // Broadcast channel to send messages between clients
    let (tx, _rx) = broadcast::channel::<String>(100);

    // Build Axum application
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(tx.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], 9000));
    println!("Gateway WebSocket running on ws://{}", addr);

    axum::serve(
        tokio::net::TcpListener::bind(addr).await.unwrap(),
        app,
    )
    .await
    .unwrap();
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    tx: axum::extract::State<broadcast::Sender<String>>,
) -> axum::response::Response {
    println!("Client connected: {}", addr);
    ws.on_upgrade(move |socket| handle_socket(socket, tx.0))
}

async fn handle_socket(
    mut socket: WebSocket,
    tx: broadcast::Sender<String>,
) {
    // each socket gets a receiver handle
    let mut rx = tx.subscribe();

    let mut send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if socket.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = socket.recv().await {
            if let Message::Text(text) = msg {
                let _ = tx.send(text);
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => send_task.abort(),
    }
}
