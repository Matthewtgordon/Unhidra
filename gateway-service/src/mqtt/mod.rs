//! MQTT Bridge module for IoT/Automation device connectivity
//!
//! Provides secure MQTT-over-TLS connectivity for devices that speak
//! native MQTT protocol, with automatic E2EE encryption.

pub mod mqtt_bridge;

pub use mqtt_bridge::{
    forward_to_device, DeviceCommand, DeviceMessage, MqttBridge, MqttBridgeConfig,
    MqttBridgeError,
};
