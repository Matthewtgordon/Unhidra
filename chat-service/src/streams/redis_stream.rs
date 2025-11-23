//! Redis Streams backend for multi-node message distribution
//!
//! Enables horizontal scaling by using Redis Streams as the message bus.
//! All chat-service instances consume from the same stream using consumer groups.

use anyhow::Result;
use redis::{
    aio::ConnectionManager,
    streams::{StreamId, StreamReadOptions, StreamReadReply},
    AsyncCommands, Client, RedisResult,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Stream names for different event types
pub const MESSAGES_STREAM: &str = "unhidra:messages";
pub const PRESENCE_STREAM: &str = "unhidra:presence";
pub const TYPING_STREAM: &str = "unhidra:typing";

/// Consumer group name
pub const CONSUMER_GROUP: &str = "chat-workers";

#[derive(Error, Debug)]
pub enum StreamError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Stream not initialized")]
    NotInitialized,
}

/// Message payload for the stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMessage {
    pub id: Uuid,
    pub sender_id: Uuid,
    pub channel_id: Option<Uuid>,
    pub recipient_id: Option<Uuid>,
    /// Encrypted payload (E2EE ciphertext)
    pub payload: Vec<u8>,
    pub message_type: MessageType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Text,
    File,
    Reaction,
    Edit,
    Delete,
    System,
}

/// Presence update for the stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceUpdate {
    pub user_id: Uuid,
    pub status: PresenceStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Away,
    Busy,
    Offline,
}

/// Redis Streams publisher for sending messages
pub struct StreamPublisher {
    conn: ConnectionManager,
}

impl StreamPublisher {
    /// Create a new publisher connected to Redis
    pub async fn new(redis_url: &str) -> Result<Self, StreamError> {
        let client = Client::open(redis_url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }

    /// Publish a message to the messages stream
    pub async fn publish_message(&mut self, message: &StreamMessage) -> Result<String, StreamError> {
        let payload = serde_json::to_string(message)?;
        let id: String = self
            .conn
            .xadd(MESSAGES_STREAM, "*", &[("payload", payload)])
            .await?;
        Ok(id)
    }

    /// Publish a presence update
    pub async fn publish_presence(&mut self, update: &PresenceUpdate) -> Result<String, StreamError> {
        let payload = serde_json::to_string(update)?;
        let id: String = self
            .conn
            .xadd(PRESENCE_STREAM, "*", &[("payload", payload)])
            .await?;
        Ok(id)
    }

    /// Publish a typing indicator
    pub async fn publish_typing(
        &mut self,
        user_id: Uuid,
        channel_id: Uuid,
        is_typing: bool,
    ) -> Result<String, StreamError> {
        let payload = serde_json::json!({
            "user_id": user_id,
            "channel_id": channel_id,
            "is_typing": is_typing,
            "timestamp": chrono::Utc::now()
        });
        let id: String = self
            .conn
            .xadd(TYPING_STREAM, "*", &[("payload", payload.to_string())])
            .await?;
        Ok(id)
    }
}

/// Redis Streams consumer for receiving messages
pub struct StreamConsumer {
    conn: ConnectionManager,
    instance_id: String,
    /// Broadcast channel for local distribution
    tx: broadcast::Sender<StreamMessage>,
}

impl StreamConsumer {
    /// Create a new consumer with a unique instance ID
    pub async fn new(redis_url: &str) -> Result<(Self, broadcast::Receiver<StreamMessage>), StreamError> {
        let client = Client::open(redis_url)?;
        let mut conn = ConnectionManager::new(client).await?;
        let instance_id = format!("instance-{}", Uuid::new_v4());

        // Create consumer group if it doesn't exist
        let _: RedisResult<()> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(MESSAGES_STREAM)
            .arg(CONSUMER_GROUP)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;

        let (tx, rx) = broadcast::channel(1000);

        Ok((
            Self {
                conn,
                instance_id,
                tx,
            },
            rx,
        ))
    }

    /// Subscribe to receive messages
    pub fn subscribe(&self) -> broadcast::Receiver<StreamMessage> {
        self.tx.subscribe()
    }

    /// Start consuming messages from the stream
    ///
    /// This runs indefinitely and should be spawned as a task
    pub async fn run(&mut self) -> Result<(), StreamError> {
        info!(
            instance_id = %self.instance_id,
            "Starting Redis stream consumer"
        );

        loop {
            let opts = StreamReadOptions::default()
                .group(CONSUMER_GROUP, &self.instance_id)
                .count(100)
                .block(5000);

            let result: RedisResult<StreamReadReply> = self
                .conn
                .xread_options(&[MESSAGES_STREAM], &[">"], &opts)
                .await;

            match result {
                Ok(reply) => {
                    for stream_key in reply.keys {
                        for stream_id in stream_key.ids {
                            if let Err(e) = self.process_message(&stream_id).await {
                                error!(error = %e, "Failed to process stream message");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Redis stream read error, retrying...");
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn process_message(&mut self, stream_id: &StreamId) -> Result<(), StreamError> {
        if let Some(payload) = stream_id.get::<String>("payload") {
            let message: StreamMessage = serde_json::from_str(&payload)?;

            // Broadcast to local subscribers
            if self.tx.send(message.clone()).is_err() {
                warn!("No local subscribers for message");
            }

            // Acknowledge the message
            let _: () = self
                .conn
                .xack(MESSAGES_STREAM, CONSUMER_GROUP, &[&stream_id.id])
                .await?;
        }
        Ok(())
    }
}

/// Initialize Redis streams and consumer groups
pub async fn init_streams(redis_url: &str) -> Result<(), StreamError> {
    let client = Client::open(redis_url)?;
    let mut conn = ConnectionManager::new(client).await?;

    // Create streams with consumer groups
    for stream in [MESSAGES_STREAM, PRESENCE_STREAM, TYPING_STREAM] {
        let result: RedisResult<()> = redis::cmd("XGROUP")
            .arg("CREATE")
            .arg(stream)
            .arg(CONSUMER_GROUP)
            .arg("$")
            .arg("MKSTREAM")
            .query_async(&mut conn)
            .await;

        match result {
            Ok(_) => info!(stream = stream, "Created consumer group"),
            Err(e) if e.to_string().contains("BUSYGROUP") => {
                info!(stream = stream, "Consumer group already exists")
            }
            Err(e) => return Err(StreamError::Redis(e)),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_message_serialization() {
        let msg = StreamMessage {
            id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            channel_id: Some(Uuid::new_v4()),
            recipient_id: None,
            payload: vec![1, 2, 3, 4, 5],
            message_type: MessageType::Text,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: StreamMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg.id, decoded.id);
    }

    #[test]
    fn test_presence_serialization() {
        let update = PresenceUpdate {
            user_id: Uuid::new_v4(),
            status: PresenceStatus::Online,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("online"));
    }
}
