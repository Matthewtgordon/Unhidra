use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use chrono::Utc;

use crate::AppState;

#[derive(Deserialize)]
pub struct IncomingMessage {
    pub email: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct OutgoingMessage {
    pub email: String,
    pub message: String,
    pub ts: String,
}

// POST /send
pub async fn send_message(
    State(state): State<AppState>,
    Json(body): Json<IncomingMessage>,
) -> Json<&'static str> {
    let ts = Utc::now().to_rfc3339();

    let db = state.db.lock().unwrap();

    db.execute(
        "INSERT INTO messages (email, message, ts) VALUES (?1, ?2, ?3)",
        (&body.email, &body.message, &ts),
    )
    .unwrap();

    Json("ok")
}

// GET /messages
pub async fn get_messages(
    State(state): State<AppState>,
) -> Json<Vec<OutgoingMessage>> {
    let db = state.db.lock().unwrap();

    let mut stmt = db.prepare("SELECT email, message, ts FROM messages ORDER BY id ASC").unwrap();

    let rows = stmt
        .query_map([], |row| {
            Ok(OutgoingMessage {
                email: row.get(0)?,
                message: row.get(1)?,
                ts: row.get(2)?,
            })
        })
        .unwrap();

    let mut out = vec![];
    for r in rows {
        out.push(r.unwrap());
    }

    Json(out)
}
