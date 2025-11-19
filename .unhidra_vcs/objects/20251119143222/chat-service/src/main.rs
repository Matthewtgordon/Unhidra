use axum::{
    routing::{post, get},
    extract::State,
    Json, Router,
};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

#[derive(Clone, Serialize, Deserialize)]
struct Message {
    user: String,
    text: String,
    timestamp: u64,
}

#[derive(Clone)]
struct AppState {
    messages: Arc<Mutex<Vec<Message>>>,
}

#[derive(Deserialize)]
struct SendInput {
    user: String,
    text: String,
}

async fn send_message(State(state): State<AppState>, Json(input): Json<SendInput>) -> &'static str {
    let mut list = state.messages.lock().unwrap();

    list.push(Message {
        user: input.user,
        text: input.text,
        timestamp: chrono::Utc::now().timestamp() as u64,
    });

    "OK"
}

async fn get_messages(State(state): State<AppState>) -> Json<Vec<Message>> {
    let list = state.messages.lock().unwrap();
    Json(list.clone())
}

#[tokio::main]
async fn main() {
    let state = AppState {
        messages: Arc::new(Mutex::new(Vec::new())),
    };

    let app = Router::new()
        .route("/send", post(send_message))
        .route("/messages", get(get_messages))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3001").await.unwrap();

    println!("chat-service running on port 3001");
    axum::serve(listener, app).await.unwrap();
}
