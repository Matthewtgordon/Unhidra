use proto::{Envelope};
use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt}};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

type ClientMap = Arc<Mutex<HashMap<String, tokio::net::TcpStream>>>;

#[tokio::main]
async fn main() {
    println!("Event Hub running on 0.0.0.0:7000");

    let listener = TcpListener::bind("0.0.0.0:7000").await.unwrap();
    let clients: ClientMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (mut stream, _) = listener.accept().await.unwrap();
        let clients = clients.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 256];

            // First read: service ID registration
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }

            let id = String::from_utf8_lossy(&buf[..n]).trim().to_string();
            println!("Registered service: {}", id);

            clients
                .lock()
                .unwrap()
                .insert(id.clone(), stream.try_clone().unwrap());

            // Event loop
            loop {
                let mut buf = vec![0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };

                if let Ok(text) = String::from_utf8(buf[..n].to_vec()) {
                    if let Some(env) = Envelope::from_json(&text) {
                        let map = clients.lock().unwrap();

                        for (client_id, client_stream) in map.iter() {
                            if env.target.is_none()
                                || env.target.clone().unwrap() == *client_id
                            {
                                let _ = client_stream
                                    .write_all(env.to_json().as_bytes())
                                    .await;
                            }
                        }
                    }
                }
            }
        });
    }
}
