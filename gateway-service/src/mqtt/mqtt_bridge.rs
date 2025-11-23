//! MQTT-over-WebSocket Bridge for IoT/Automation devices
//!
//! Provides secure MQTT connectivity for devices that speak native MQTT protocol.
//! All messages are E2EE encrypted before forwarding to the chat system.

use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, MqttOptions, Outgoing, Packet, QoS, Transport,
};
use rustls::ClientConfig;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[derive(Error, Debug)]
pub enum MqttBridgeError {
    #[error("MQTT connection error: {0}")]
    Connection(#[from] rumqttc::ConnectionError),

    #[error("MQTT client error: {0}")]
    Client(#[from] rumqttc::ClientError),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Channel closed")]
    ChannelClosed,
}

/// MQTT bridge configuration
#[derive(Clone, Debug)]
pub struct MqttBridgeConfig {
    /// MQTT broker URL (mqtts://host:port)
    pub broker_url: String,
    /// Client ID for this bridge instance
    pub client_id: String,
    /// MQTT username (optional, for client cert auth)
    pub username: Option<String>,
    /// MQTT password (optional)
    pub password: Option<String>,
    /// Enable TLS
    pub tls_enabled: bool,
    /// Path to CA certificate
    pub ca_cert_path: Option<String>,
    /// Path to client certificate
    pub client_cert_path: Option<String>,
    /// Path to client key
    pub client_key_path: Option<String>,
    /// Keep-alive interval in seconds
    pub keep_alive_secs: u64,
    /// Topics to subscribe to
    pub subscribe_topics: Vec<String>,
}

impl Default for MqttBridgeConfig {
    fn default() -> Self {
        Self {
            broker_url: "mqtts://localhost:8883".to_string(),
            client_id: format!("unhidra-bridge-{}", uuid::Uuid::new_v4()),
            username: None,
            password: None,
            tls_enabled: true,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            keep_alive_secs: 60,
            subscribe_topics: vec![
                "unhidra/devices/+/telemetry".to_string(),
                "unhidra/devices/+/events".to_string(),
                "unhidra/devices/+/status".to_string(),
            ],
        }
    }
}

/// Message received from an MQTT device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMessage {
    /// Device ID extracted from topic
    pub device_id: String,
    /// Topic the message was received on
    pub topic: String,
    /// Raw payload (encrypted)
    pub payload: Vec<u8>,
    /// QoS level
    pub qos: u8,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Message to send to an MQTT device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCommand {
    /// Target device ID
    pub device_id: String,
    /// Topic to publish to
    pub topic: String,
    /// Encrypted payload
    pub payload: Vec<u8>,
    /// QoS level
    pub qos: u8,
}

/// MQTT Bridge for IoT device communication
pub struct MqttBridge {
    client: AsyncClient,
    eventloop: EventLoop,
    config: MqttBridgeConfig,
    /// Channel for received messages
    rx_sender: mpsc::Sender<DeviceMessage>,
    /// Channel for commands to send
    tx_receiver: mpsc::Receiver<DeviceCommand>,
}

impl MqttBridge {
    /// Create a new MQTT bridge
    pub async fn new(
        config: MqttBridgeConfig,
    ) -> Result<(Self, mpsc::Receiver<DeviceMessage>, mpsc::Sender<DeviceCommand>), MqttBridgeError>
    {
        // Parse broker URL
        let url = url::Url::parse(&config.broker_url)
            .map_err(|e| MqttBridgeError::Tls(e.to_string()))?;

        let host = url.host_str().unwrap_or("localhost");
        let port = url.port().unwrap_or(8883);

        let mut mqtt_options = MqttOptions::new(&config.client_id, host, port);
        mqtt_options.set_keep_alive(Duration::from_secs(config.keep_alive_secs));

        // Set credentials if provided
        if let (Some(user), Some(pass)) = (&config.username, &config.password) {
            mqtt_options.set_credentials(user, pass);
        }

        // Configure TLS
        if config.tls_enabled {
            let tls_config = Self::build_tls_config(&config)?;
            mqtt_options.set_transport(Transport::tls_with_config(tls_config.into()));
        }

        let (client, eventloop) = AsyncClient::new(mqtt_options, 100);

        // Create channels for message passing
        let (rx_sender, rx_receiver) = mpsc::channel(1000);
        let (tx_sender, tx_receiver) = mpsc::channel(1000);

        Ok((
            Self {
                client,
                eventloop,
                config,
                rx_sender,
                tx_receiver,
            },
            rx_receiver,
            tx_sender,
        ))
    }

    fn build_tls_config(config: &MqttBridgeConfig) -> Result<ClientConfig, MqttBridgeError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::BufReader;

        let mut root_store = rustls::RootCertStore::empty();

        // Add system root certificates
        let certs = rustls_native_certs::load_native_certs()
            .map_err(|e| MqttBridgeError::Tls(e.to_string()))?;
        for cert in certs {
            root_store.add(cert).ok();
        }

        // Add custom CA if provided
        if let Some(ca_path) = &config.ca_cert_path {
            let ca_file = std::fs::File::open(ca_path)
                .map_err(|e| MqttBridgeError::Tls(format!("Failed to open CA cert: {}", e)))?;
            let mut reader = BufReader::new(ca_file);
            let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut reader)
                .filter_map(|r| r.ok())
                .collect();
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| MqttBridgeError::Tls(e.to_string()))?;
            }
        }

        let builder = ClientConfig::builder().with_root_certificates(root_store);

        // Add client certificate if provided
        let tls_config = if let (Some(cert_path), Some(key_path)) =
            (&config.client_cert_path, &config.client_key_path)
        {
            let cert_file = std::fs::File::open(cert_path)
                .map_err(|e| MqttBridgeError::Tls(format!("Failed to open client cert: {}", e)))?;
            let mut cert_reader = BufReader::new(cert_file);
            let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
                .filter_map(|r| r.ok())
                .collect();

            let key_file = std::fs::File::open(key_path)
                .map_err(|e| MqttBridgeError::Tls(format!("Failed to open client key: {}", e)))?;
            let mut key_reader = BufReader::new(key_file);
            let key: PrivateKeyDer = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| MqttBridgeError::Tls(format!("Failed to read private key: {}", e)))?
                .ok_or_else(|| MqttBridgeError::Tls("No private key found".to_string()))?;

            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| MqttBridgeError::Tls(e.to_string()))?
        } else {
            builder.with_no_client_auth()
        };

        Ok(tls_config)
    }

    /// Start the MQTT bridge
    ///
    /// This runs indefinitely and should be spawned as a task
    pub async fn run(mut self) -> Result<(), MqttBridgeError> {
        info!(
            client_id = %self.config.client_id,
            broker = %self.config.broker_url,
            "Starting MQTT bridge"
        );

        // Subscribe to configured topics
        for topic in &self.config.subscribe_topics {
            self.client.subscribe(topic, QoS::AtLeastOnce).await?;
            info!(topic = %topic, "Subscribed to MQTT topic");
        }

        loop {
            tokio::select! {
                // Handle incoming MQTT events
                event = self.eventloop.poll() => {
                    match event {
                        Ok(Event::Incoming(incoming)) => {
                            self.handle_incoming(incoming).await;
                        }
                        Ok(Event::Outgoing(outgoing)) => {
                            debug!(?outgoing, "MQTT outgoing event");
                        }
                        Err(e) => {
                            error!(error = %e, "MQTT connection error");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                }

                // Handle outgoing commands
                Some(cmd) = self.tx_receiver.recv() => {
                    if let Err(e) = self.send_command(cmd).await {
                        error!(error = %e, "Failed to send MQTT command");
                    }
                }
            }
        }
    }

    async fn handle_incoming(&self, incoming: Incoming) {
        if let Incoming::Publish(publish) = incoming {
            // Extract device ID from topic
            let device_id = Self::extract_device_id(&publish.topic);

            let message = DeviceMessage {
                device_id: device_id.unwrap_or_else(|| "unknown".to_string()),
                topic: publish.topic.clone(),
                payload: publish.payload.to_vec(),
                qos: publish.qos as u8,
                timestamp: chrono::Utc::now(),
            };

            if self.rx_sender.send(message).await.is_err() {
                warn!("Failed to forward MQTT message - channel closed");
            }
        }
    }

    async fn send_command(&self, cmd: DeviceCommand) -> Result<(), MqttBridgeError> {
        let qos = match cmd.qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            _ => QoS::ExactlyOnce,
        };

        self.client
            .publish(&cmd.topic, qos, false, cmd.payload)
            .await?;

        debug!(
            device_id = %cmd.device_id,
            topic = %cmd.topic,
            "Sent MQTT command"
        );

        Ok(())
    }

    /// Extract device ID from topic pattern
    /// e.g., "unhidra/devices/device-123/telemetry" -> "device-123"
    fn extract_device_id(topic: &str) -> Option<String> {
        let parts: Vec<&str> = topic.split('/').collect();
        if parts.len() >= 3 && parts[0] == "unhidra" && parts[1] == "devices" {
            Some(parts[2].to_string())
        } else {
            None
        }
    }
}

/// Forward a message to an MQTT device with E2EE encryption
pub async fn forward_to_device(
    tx: &mpsc::Sender<DeviceCommand>,
    device_id: &str,
    payload: Vec<u8>,
) -> Result<(), MqttBridgeError> {
    let cmd = DeviceCommand {
        device_id: device_id.to_string(),
        topic: format!("unhidra/devices/{}/commands", device_id),
        payload,
        qos: 1,
    };

    tx.send(cmd)
        .await
        .map_err(|_| MqttBridgeError::ChannelClosed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_device_id() {
        assert_eq!(
            MqttBridge::extract_device_id("unhidra/devices/device-123/telemetry"),
            Some("device-123".to_string())
        );
        assert_eq!(
            MqttBridge::extract_device_id("unhidra/devices/abc/events"),
            Some("abc".to_string())
        );
        assert_eq!(MqttBridge::extract_device_id("other/topic"), None);
    }

    #[test]
    fn test_config_default() {
        let config = MqttBridgeConfig::default();
        assert!(config.tls_enabled);
        assert_eq!(config.keep_alive_secs, 60);
        assert!(!config.subscribe_topics.is_empty());
    }

    #[test]
    fn test_device_message_serialization() {
        let msg = DeviceMessage {
            device_id: "test-device".to_string(),
            topic: "unhidra/devices/test-device/telemetry".to_string(),
            payload: vec![1, 2, 3],
            qos: 1,
            timestamp: chrono::Utc::now(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let decoded: DeviceMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg.device_id, decoded.device_id);
    }
}
