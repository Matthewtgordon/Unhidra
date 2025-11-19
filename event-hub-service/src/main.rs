use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use uuid::Uuid;
use anyhow::Result;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:9700").await?;
    let (tx, _) = broadcast::channel::<(Uuid, Vec<u8>)>(100);

    let connections = Arc::new(
        tokio::sync::Mutex::new(
            std::collections::HashMap::<Uuid, Arc<tokio::sync::Mutex<tokio::net::tcp::OwnedWriteHalf>>>::new()
        )
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let id = Uuid::new_v4();

        let (read_half, write_half) = stream.into_split();

        let tx_reader = tx.clone();
        let tx_writer = tx.clone();

        let write_half = Arc::new(tokio::sync::Mutex::new(write_half));
        let connections_reader = connections.clone();
        let connections_writer = connections.clone();

        connections
            .lock()
            .await
            .insert(id, write_half.clone());

        tokio::spawn(async move {
            let mut reader = read_half;
            let mut buf = [0u8; 1024];

            loop {
                let n = match reader.read(&mut buf).await {
                    Ok(n) if n == 0 => {
                        connections_reader.lock().await.remove(&id);
                        break;
                    }
                    Ok(n) => n,
                    Err(_) => {
                        connections_reader.lock().await.remove(&id);
                        break;
                    }
                };

                let _ = tx_reader.send((id, buf[..n].to_vec()));
            }
        });

        tokio::spawn(async move {
            let mut rx = tx_writer.subscribe();

            while let Ok((sender, msg)) = rx.recv().await {
                let conns = connections_writer.lock().await;

                for (other_id, writer_lock) in conns.iter() {
                    if *other_id == sender {
                        continue;
                    }

                    let mut writer = writer_lock.lock().await;
                    let _ = writer.write_all(&msg).await;
                }
            }
        });
    }
}
