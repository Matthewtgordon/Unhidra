mod hub;

use axum::{
    extract::ws::{WebSocketUpgrade, WebSocket, Message},
    response::IntoResponse,
    routing::get,
    Router,
};

use tokio::net::TcpListener;
use axum::serve;
use tokio::task;

// Correct traits for split() and send()
use futures_util::{StreamExt, SinkExt};

use hub::RoomHub;

#[tokio::main]
async fn main() {
    let hub = RoomHub::new();

    let app = Router::new()
        .route("/", get(|| async { "Unhidra Chat Server Running" }))
        .route("/ws", get(move |ws| ws_handler(ws, hub.clone())));

    println!("WebSocket chat server on ws://0.0.0.0:8080/ws");

    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    serve(listener, app).await.unwrap();
}

async fn ws_handler(ws: WebSocketUpgrade, hub: RoomHub) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, hub))
}

async fn handle_socket(socket: WebSocket, hub: RoomHub) {
    println!("Client connected.");

    let tx = hub.get_room("general").await;
    let mut rx = tx.subscribe();

    // Split into send + receive halves
    let (mut sender, mut receiver) = socket.split();

    // Incoming messages: client → room
    let incoming = {
        let tx = tx.clone();
        task::spawn(async move {
            while let Some(msg) = receiver.next().await {
                if let Ok(Message::Text(utf8)) = msg {
                    let text = utf8.to_string();
                    let _ = tx.send(text);
                }
            }
        })
    };

    // Outgoing messages: room → client
    let outgoing = task::spawn(async move {
        while let Ok(text) = rx.recv().await {
            let _ = sender.send(Message::Text(text.into())).await;
        }
    });

    tokio::select! {
        _ = incoming => {},
        _ = outgoing => {},
    }

    println!("Client disconnected.");
}
