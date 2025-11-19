use axum::{Router, routing::post};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

mod handlers;
use handlers::{login_handler, AppState};

#[tokio::main]
async fn main() {
    println!("AUTH-API: Attempting to open DB at /opt/unhidra/auth.db");

    let conn = match Connection::open("/opt/unhidra/auth.db") {
        Ok(c) => {
            println!("AUTH-API: Successfully opened /opt/unhidra/auth.db");
            c
        }
        Err(e) => {
            println!("AUTH-API: FAILED to open /opt/unhidra/auth.db: {}", e);
            panic!("Cannot open DB");
        }
    };

    let shared = Arc::new(AppState {
        db: Mutex::new(conn),
    });

    let app = Router::new()
        .route("/login", post(login_handler))
        .layer(CorsLayer::permissive())
        .with_state(shared);

    println!("Auth API running on 0.0.0.0:9200");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9200")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}
