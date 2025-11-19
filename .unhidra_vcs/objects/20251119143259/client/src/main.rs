use reqwest::Client;

#[tokio::main]
async fn main() {
    let response = Client::new()
        .get("http://localhost:8080/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    println!("Server says: {}", response);
}
