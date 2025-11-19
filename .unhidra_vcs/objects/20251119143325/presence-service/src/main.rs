use axum::{Router, routing::post, routing::get, Json};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::{Arc, Mutex}};
use chrono::Utc;

#[derive(Debug, Clone)]
struct AppState {
    online: Arc<Mutex<HashMap<String, u64>>>,
}

#[derive(Deserialize)]
struct PresenceUpdate {
    user: String,
}

#[derive(Serialize)]
struct OnlineResponse {
    users: Vec<String>,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        online: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/presence", post(update_presence))
        .route("/online", get(get_online))
        .with_state(state);

    println!("Presence service running on 0.0.0.0:3002");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3002").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn update_presence(
    axum::extract::State(state): axum::extract::State<AppState>,
    Json(body): Json<PresenceUpdate>,
) -> &'static str {
    let mut map = state.online.lock().unwrap();
    map.insert(body.user, Utc::now().timestamp() as u64);
    "ok"
}

async fn get_online(
    axum::extract::State(state): axum::extract::State<AppState>
) -> Json<OnlineResponse> {
    let map = state.online.lock().unwrap();
    let users = map.keys().cloned().collect::<Vec<_>>();
    Json(OnlineResponse { users })
}
