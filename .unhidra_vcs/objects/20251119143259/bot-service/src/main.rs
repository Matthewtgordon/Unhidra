use proto::Envelope;
use tokio_tungstenite::connect_async;
use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {
    println!("Bot Service starting...");

    let mut ws = loop {
        match connect_async("ws://127.0.0.1:9000/ws").await {
            Ok((ws, _)) => {
                println!("Bot Service connected to Gateway");
                break ws;
            }
            Err(_) => {
                println!("Bot Service waiting for Gateway...");
                sleep(Duration::from_secs(1)).await;
            }
        }
    };

    println!("Bot Service running");
    loop { sleep(Duration::from_secs(5)).await; }
}
