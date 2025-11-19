use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};

#[derive(Clone)]
pub struct RoomHub {
    pub rooms: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
}

impl RoomHub {
    pub fn new() -> Self {
        Self {
            rooms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_room(&self, name: &str) -> broadcast::Sender<String> {
        let mut rooms = self.rooms.write().await;
        rooms
            .entry(name.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(1000);
                tx
            })
            .clone()
    }
}
