use reqwest::Client;
use tokio;

#[tokio::main]
async fn main() {
    let api = "http://127.0.0.1:9200/health"; // Auth API
    let ws = "ws://127.0.0.1:9000/ws";        // Gateway

    println!("Testing Auth API...");
    let res = Client::new()
        .get(api)
        .send()
        .await
        .unwrap();
    println!("Auth API status: {}", res.status());

    println!("Connecting to gateway: {}", ws);
    // For now we just print, since gateway needs websocket handshake
    println!("(placeholder: WebSocket connect goes here)");
}
