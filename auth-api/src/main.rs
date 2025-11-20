use axum::{Router, routing::{post, get}, Json};
use serde_json::json;
use std::net::SocketAddr;

async fn login_handler() -> &'static str {
    "login endpoint"
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

#[tokio::main]
async fn main() {
    println!("Auth API running on 0.0.0.0:9200");

    let app = Router::new()
        .route("/login", post(login_handler))
        .route("/health", get(health_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], 9200));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
