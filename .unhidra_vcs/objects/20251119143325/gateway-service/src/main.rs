use axum::{
    Router,
    routing::get,
    extract::ws::{WebSocketUpgrade, WebSocket, Message},
    response::IntoResponse,
};
use futures_util::{StreamExt, SinkExt};
use tokio::sync::broadcast;
use axum::serve;

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel::<String>(100);

    let app = Router::new()
        .route("/", get(|| async { "Gateway Service" }))
        .route("/ws", get(move |ws| ws_handler(ws, tx.clone())));

    println!("Gateway running on 0.0.0.0:9000");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9000")
        .await
        .unwrap();

    serve(listener, app).await.unwrap();
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    tx: broadcast::Sender<String>
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, tx))
}

async fn handle_socket(mut socket: WebSocket, tx: broadcast::Sender<String>) {
    let mut rx = tx.subscribe();

    let (mut outgoing, mut incoming) = socket.split();

    // incoming messages → broadcast
    tokio::spawn(async move {
        while let Some(Ok(msg)) = incoming.next().await {
            if let Message::Text(text_bytes) = msg {
                // Convert Utf8Bytes → String
                let text = text_bytes.to_string();
                let _ = tx.send(text);
            }
        }
    });

    // broadcast → outgoing WebSocket messages
    tokio::spawn(async move {
        while let Ok(text) = rx.recv().await {
            let _ = outgoing.send(Message::Text(text.into())).await;
        }
    });
}
