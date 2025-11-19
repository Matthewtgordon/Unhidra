use serde::{Serialize, de::DeserializeOwned};

pub struct EventClient;

impl EventClient {
    pub async fn connect(_addr: &str) -> Self {
        EventClient
    }

    pub async fn publish<T: Serialize>(&self, _topic: &str, _value: &T) {
        // Stub
    }

    pub async fn subscribe<T: DeserializeOwned + Send + 'static>(&self, _topic: &str) 
        -> tokio::sync::mpsc::Receiver<T> 
    {
        // Stub
        let (_tx, rx) = tokio::sync::mpsc::channel(32);
        rx
    }
}
