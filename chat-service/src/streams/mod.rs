//! Redis Streams module for scalable message distribution
//!
//! Provides pub/sub functionality using Redis Streams with consumer groups
//! for multi-node deployment support.

pub mod redis_stream;

pub use redis_stream::{
    init_streams, MessageType, PresenceStatus, PresenceUpdate, StreamConsumer, StreamError,
    StreamMessage, StreamPublisher, CONSUMER_GROUP, MESSAGES_STREAM, PRESENCE_STREAM,
    TYPING_STREAM,
};
