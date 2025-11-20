use reqwest::Client;
use serde::{Serialize, Deserialize};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use futures_util::{SinkExt, StreamExt};

#[derive(Serialize)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginResp {
    token: String,
}

#[tokio::main]
async fn main() {
    println!("--- UNHIDRA CLIENT ---");

    let http = Client::new();

    println!("Logging into Auth API...");
    let res = http.post("http://127.0.0.1:9200/login")
        .json(&LoginReq {
            username: "user".into(),
            password: "password".into(),
        })
        .send()
        .await
        .expect("Failed to send login request");

    let parsed = res.json::<LoginResp>()
        .await
        .expect("Failed to parse login response");

    println!("Login success. Token = {}", parsed.token);

    let ws_url = format!("ws://127.0.0.1:9000/ws?token={}", parsed.token);
    println!("Connecting to WebSocket: {}", ws_url);

    let (ws_stream, _) = connect_async(ws_url)
        .await
        .expect("Failed to connect to WebSocket");

    println!("Connected to Gateway WebSocket.");

    let (mut write, mut read) = ws_stream.split();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let _ = write.send(Message::Text("ping from client".into())).await;
        }
    });

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                println!("Received: {}", text);
            }
            Ok(_) => {}
            Err(e) => {
                println!("WebSocket error: {}", e);
                break;
            }
        }
    }

    println!("WebSocket closed.");
}
