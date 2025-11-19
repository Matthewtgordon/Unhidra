use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    UserChat {
        user: String,
        text: String,
    },

    PresenceUpdate {
        user: String,
        status: String,
    },

    BotMessage {
        text: String,
    },

    InternalForward {
        service: String,
        payload: String,
    },
}

/// Every message in the system travels wrapped inside this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub event: Event,
    pub source: String,
    pub target: Option<String>,
}

impl Envelope {
    pub fn new(event: Event, source: &str) -> Self {
        Self {
            event,
            source: source.to_string(),
            target: None,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}
