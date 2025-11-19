use axum::{Json, extract::State};
use serde::Deserialize;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};
use sha2::{Sha256, Digest};
use serde_json::json;

pub struct AppState {
    pub db: Mutex<Connection>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Json<serde_json::Value> {
    println!("AUTH-API: Received login request for {}", payload.username);

    let username = payload.username.clone();
    let conn = state.db.lock().unwrap();

    let mut stmt = match conn.prepare(
        "SELECT salt, password_hash, verified, display_name FROM users WHERE username = ?1"
    ) {
        Ok(s) => s,
        Err(e) => {
            println!("AUTH-API: Failed to prepare SQL: {}", e);
            return Json(json!({ "error": "db_error" }));
        }
    };

    let row = stmt.query_row(params![username.clone()], |r| {
        Ok((
            r.get::<_, String>(0)?,  // salt
            r.get::<_, String>(1)?,  // password_hash
            r.get::<_, i64>(2)?,     // verified
            r.get::<_, String>(3)?,  // display_name
        ))
    });

    let (salt, stored_hash, verified, display_name) = match row {
        Ok(t) => t,
        Err(_) => {
            println!("AUTH-API: User not found");
            return Json(json!({ "error": "User not found" }));
        }
    };

    if verified == 0 {
        println!("AUTH-API: User not verified");
        return Json(json!({ "error": "Not verified" }));
    }

    // Compute SHA256(salt + password)
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", salt, payload.password));
    let computed = format!("{:x}", hasher.finalize());

    if computed != stored_hash {
        println!("AUTH-API: Invalid password");
        return Json(json!({ "error": "Invalid password" }));
    }

    println!("AUTH-API: Login OK for {} ({})", username, display_name);

    Json(json!({
        "ok": true,
        "user": username,
        "display_name": display_name,
        "token": username
    }))
}
