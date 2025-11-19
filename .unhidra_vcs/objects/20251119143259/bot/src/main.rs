use reqwest::Client;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    let client = Client::new();
    loop {
        match client.get("http://localhost:8080/").send().await {
            Ok(res) => println!("Bot heartbeat: {}", res.text().await.unwrap()),
            Err(_) => println!("Bot: server unreachable"),
        }
        sleep(Duration::from_secs(5)).await;
    }
}
