//! Prometheus metrics for auth-api observability
//!
//! Exposes metrics at /metrics endpoint for scraping by Prometheus.

use metrics::{counter, gauge, histogram, describe_counter, describe_gauge, describe_histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;
use std::time::Duration;

/// Global Prometheus handle
static METRICS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

/// Metric names
pub const LOGIN_ATTEMPTS: &str = "auth_api_login_attempts_total";
pub const LOGIN_SUCCESSES: &str = "auth_api_login_successes_total";
pub const LOGIN_FAILURES: &str = "auth_api_login_failures_total";
pub const LOGIN_DURATION: &str = "auth_api_login_duration_seconds";
pub const DEVICE_REGISTRATIONS: &str = "auth_api_device_registrations_total";
pub const DEVICE_REVOCATIONS: &str = "auth_api_device_revocations_total";
pub const ACTIVE_DEVICES: &str = "auth_api_active_devices";
pub const SSO_ATTEMPTS: &str = "auth_api_sso_attempts_total";
pub const SSO_SUCCESSES: &str = "auth_api_sso_successes_total";
pub const SSO_FAILURES: &str = "auth_api_sso_failures_total";
pub const PASSKEY_REGISTRATIONS: &str = "auth_api_passkey_registrations_total";
pub const PASSKEY_AUTHENTICATIONS: &str = "auth_api_passkey_authentications_total";
pub const PASSKEY_FAILURES: &str = "auth_api_passkey_failures_total";
pub const RATE_LIMIT_HITS: &str = "auth_api_rate_limit_hits_total";

/// Initialize the metrics system
pub fn init_metrics() {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    METRICS_HANDLE.set(handle).expect("Metrics already initialized");

    // Describe metrics for Prometheus
    describe_counter!(LOGIN_ATTEMPTS, "Total login attempts");
    describe_counter!(LOGIN_SUCCESSES, "Successful login attempts");
    describe_counter!(LOGIN_FAILURES, "Failed login attempts");
    describe_histogram!(LOGIN_DURATION, "Login request duration in seconds");
    describe_counter!(DEVICE_REGISTRATIONS, "Total device registrations");
    describe_counter!(DEVICE_REVOCATIONS, "Total device revocations");
    describe_gauge!(ACTIVE_DEVICES, "Number of currently active devices");
    describe_counter!(SSO_ATTEMPTS, "Total SSO authentication attempts");
    describe_counter!(SSO_SUCCESSES, "Successful SSO authentications");
    describe_counter!(SSO_FAILURES, "Failed SSO authentications");
    describe_counter!(PASSKEY_REGISTRATIONS, "Total passkey registrations");
    describe_counter!(PASSKEY_AUTHENTICATIONS, "Total passkey authentications");
    describe_counter!(PASSKEY_FAILURES, "Failed passkey authentications");
    describe_counter!(RATE_LIMIT_HITS, "Rate limit violations");

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
// Login Metrics
// ============================================================================

/// Record a login attempt
pub fn record_login_attempt() {
    counter!(LOGIN_ATTEMPTS).increment(1);
}

/// Record a successful login
pub fn record_login_success() {
    counter!(LOGIN_SUCCESSES).increment(1);
}

/// Record a failed login
pub fn record_login_failure(reason: &str) {
    counter!(LOGIN_FAILURES, "reason" => reason.to_string()).increment(1);
}

/// Record login duration
pub fn record_login_duration(duration: Duration) {
    histogram!(LOGIN_DURATION).record(duration.as_secs_f64());
}

// ============================================================================
// Device Metrics
// ============================================================================

/// Record a device registration
pub fn record_device_registration() {
    counter!(DEVICE_REGISTRATIONS).increment(1);
    gauge!(ACTIVE_DEVICES).increment(1.0);
}

/// Record a device revocation
pub fn record_device_revocation() {
    counter!(DEVICE_REVOCATIONS).increment(1);
    gauge!(ACTIVE_DEVICES).decrement(1.0);
}

/// Set the total number of active devices
pub fn set_active_devices(count: usize) {
    gauge!(ACTIVE_DEVICES).set(count as f64);
}

// ============================================================================
// SSO Metrics
// ============================================================================

/// Record an SSO authentication attempt
pub fn record_sso_attempt(provider: &str) {
    counter!(SSO_ATTEMPTS, "provider" => provider.to_string()).increment(1);
}

/// Record a successful SSO authentication
pub fn record_sso_success(provider: &str) {
    counter!(SSO_SUCCESSES, "provider" => provider.to_string()).increment(1);
}

/// Record a failed SSO authentication
pub fn record_sso_failure(provider: &str, reason: &str) {
    counter!(SSO_FAILURES,
        "provider" => provider.to_string(),
        "reason" => reason.to_string()
    ).increment(1);
}

// ============================================================================
// WebAuthn/Passkey Metrics
// ============================================================================

/// Record a passkey registration
pub fn record_passkey_registration() {
    counter!(PASSKEY_REGISTRATIONS).increment(1);
}

/// Record a passkey authentication attempt
pub fn record_passkey_authentication() {
    counter!(PASSKEY_AUTHENTICATIONS).increment(1);
}

/// Record a failed passkey authentication
pub fn record_passkey_failure(reason: &str) {
    counter!(PASSKEY_FAILURES, "reason" => reason.to_string()).increment(1);
}

// ============================================================================
// Rate Limiting Metrics
// ============================================================================

/// Record a rate limit hit
pub fn record_rate_limit_hit(endpoint: &str) {
    counter!(RATE_LIMIT_HITS, "endpoint" => endpoint.to_string()).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Metrics tests require careful handling due to global state
    // These tests verify the API compiles and basic operations work

    #[test]
    fn test_metric_constants_exist() {
        // Just verify the constants compile
        let _ = LOGIN_ATTEMPTS;
        let _ = LOGIN_SUCCESSES;
        let _ = LOGIN_FAILURES;
        let _ = DEVICE_REGISTRATIONS;
    }
}
