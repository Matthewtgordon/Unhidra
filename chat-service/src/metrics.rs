//! Prometheus metrics for chat-service observability
//!
//! Exposes metrics at /metrics endpoint for scraping by Prometheus.

use metrics::{counter, gauge, histogram, describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;
use std::time::Duration;

/// Global Prometheus handle
static METRICS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

/// Metric names
pub const CHANNELS_CREATED: &str = "chat_service_channels_created_total";
pub const CHANNELS_ACTIVE: &str = "chat_service_channels_active";
pub const MESSAGES_SENT: &str = "chat_service_messages_sent_total";
pub const MESSAGES_RECEIVED: &str = "chat_service_messages_received_total";
pub const MESSAGE_LATENCY: &str = "chat_service_message_latency_seconds";
pub const THREADS_CREATED: &str = "chat_service_threads_created_total";
pub const THREADS_ACTIVE: &str = "chat_service_threads_active";
pub const THREAD_REPLIES: &str = "chat_service_thread_replies_total";
pub const FILES_UPLOADED: &str = "chat_service_files_uploaded_total";
pub const FILES_DOWNLOADED: &str = "chat_service_files_downloaded_total";
pub const FILES_DELETED: &str = "chat_service_files_deleted_total";
pub const FILE_UPLOAD_SIZE: &str = "chat_service_file_upload_bytes";
pub const CHANNEL_MEMBERS: &str = "chat_service_channel_members";
pub const READ_RECEIPTS: &str = "chat_service_read_receipts_total";

/// Initialize the metrics system
pub fn init_metrics() {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    METRICS_HANDLE.set(handle).expect("Metrics already initialized");

    // Describe metrics for Prometheus
    describe_counter!(CHANNELS_CREATED, "Total number of channels created");
    describe_gauge!(CHANNELS_ACTIVE, "Number of currently active channels");
    describe_counter!(MESSAGES_SENT, "Total messages sent");
    describe_counter!(MESSAGES_RECEIVED, "Total messages received");
    describe_histogram!(MESSAGE_LATENCY, "Message processing latency in seconds");
    describe_counter!(THREADS_CREATED, "Total threads created");
    describe_gauge!(THREADS_ACTIVE, "Number of currently active threads");
    describe_counter!(THREAD_REPLIES, "Total thread replies");
    describe_counter!(FILES_UPLOADED, "Total files uploaded");
    describe_counter!(FILES_DOWNLOADED, "Total files downloaded");
    describe_counter!(FILES_DELETED, "Total files deleted");
    describe_histogram!(FILE_UPLOAD_SIZE, "File upload size in bytes");
    describe_gauge!(CHANNEL_MEMBERS, "Number of members per channel");
    describe_counter!(READ_RECEIPTS, "Total read receipts processed");

    tracing::info!("Metrics system initialized");
}

/// Get the Prometheus metrics handle
fn get_handle() -> &'static PrometheusHandle {
    METRICS_HANDLE.get().expect("Metrics not initialized")
}

/// Handler for /metrics endpoint
pub async fn metrics_handler() -> String {
    get_handle().render()
}

// ============================================================================
// Channel Metrics
// ============================================================================

/// Record a channel creation
pub fn record_channel_created() {
    counter!(CHANNELS_CREATED).increment(1);
    gauge!(CHANNELS_ACTIVE).increment(1.0);
}

/// Record a channel deletion
pub fn record_channel_deleted() {
    gauge!(CHANNELS_ACTIVE).decrement(1.0);
}

/// Set the total number of active channels
pub fn set_active_channels(count: usize) {
    gauge!(CHANNELS_ACTIVE).set(count as f64);
}

/// Set the number of members in a channel
pub fn set_channel_members(channel_id: &str, count: usize) {
    gauge!(CHANNEL_MEMBERS, "channel_id" => channel_id.to_string()).set(count as f64);
}

// ============================================================================
// Message Metrics
// ============================================================================

/// Record a message sent
pub fn record_message_sent(channel_type: &str) {
    counter!(MESSAGES_SENT, "type" => channel_type.to_string()).increment(1);
}

/// Record a message received
pub fn record_message_received(channel_type: &str) {
    counter!(MESSAGES_RECEIVED, "type" => channel_type.to_string()).increment(1);
}

/// Record message processing latency
pub fn record_message_latency(duration: Duration) {
    histogram!(MESSAGE_LATENCY).record(duration.as_secs_f64());
}

// ============================================================================
// Thread Metrics
// ============================================================================

/// Record a thread creation
pub fn record_thread_created() {
    counter!(THREADS_CREATED).increment(1);
    gauge!(THREADS_ACTIVE).increment(1.0);
}

/// Record a thread reply
pub fn record_thread_reply() {
    counter!(THREAD_REPLIES).increment(1);
}

/// Set the total number of active threads
pub fn set_active_threads(count: usize) {
    gauge!(THREADS_ACTIVE).set(count as f64);
}

// ============================================================================
// File Metrics
// ============================================================================

/// Record a file upload
pub fn record_file_uploaded(size_bytes: u64) {
    counter!(FILES_UPLOADED).increment(1);
    histogram!(FILE_UPLOAD_SIZE).record(size_bytes as f64);
}

/// Record a file download
pub fn record_file_downloaded() {
    counter!(FILES_DOWNLOADED).increment(1);
}

/// Record a file deletion
pub fn record_file_deleted() {
    counter!(FILES_DELETED).increment(1);
}

// ============================================================================
// Read Receipt Metrics
// ============================================================================

/// Record a read receipt
pub fn record_read_receipt(receipt_type: &str) {
    counter!(READ_RECEIPTS, "type" => receipt_type.to_string()).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Metrics tests require careful handling due to global state
    // These tests verify the API compiles and basic operations work

    #[test]
    fn test_metric_constants_exist() {
        // Just verify the constants compile
        let _ = CHANNELS_CREATED;
        let _ = CHANNELS_ACTIVE;
        let _ = MESSAGES_SENT;
        let _ = THREADS_CREATED;
    }
}
