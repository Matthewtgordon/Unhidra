use std::time::Duration;

pub async fn wait_for_gateway() {
    loop {
        match reqwest::get("http://localhost:9000/ping").await {
            Ok(_) => {
                println!("Gateway reachable");
                break;
            }
            Err(_) => {
                println!("Waiting for gateway...");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
