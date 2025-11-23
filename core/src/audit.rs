//! Immutable Audit Logging
//!
//! Provides tamper-evident logging for security-relevant events.
//! Requires the `postgres` feature to be enabled.
//!
//! # Usage
//!
//! ```ignore
//! use core::audit::{AuditLogger, AuditEvent, AuditAction};
//!
//! let logger = AuditLogger::new(pool).await?;
//! logger.log(AuditEvent {
//!     actor_id: user_id,
//!     action: AuditAction::AuthLogin,
//!     resource_type: Some("session"),
//!     ..Default::default()
//! }).await?;
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::net::IpAddr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Standard audit actions for categorization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication
    AuthLogin,
    AuthLogout,
    AuthFailed,
    AuthMfaEnabled,
    AuthMfaDisabled,
    AuthPasswordChanged,
    AuthPasswordReset,
    AuthOidcLogin,
    AuthWebAuthnRegister,
    AuthWebAuthnLogin,

    // Device management
    DeviceRegister,
    DeviceRemove,
    DeviceAuthFailed,

    // Messaging
    MessageSend,
    MessageEdit,
    MessageDelete,
    MessageReact,

    // Channel management
    ChannelCreate,
    ChannelUpdate,
    ChannelDelete,
    ChannelJoin,
    ChannelLeave,

    // File operations
    FileUpload,
    FileDownload,
    FileDelete,

    // User management
    UserCreate,
    UserUpdate,
    UserDelete,
    UserSuspend,
    UserReactivate,

    // Admin operations
    AdminConfigChange,
    AdminUserImpersonate,
    AdminAuditExport,

    // Security events
    SecuritySuspiciousActivity,
    SecurityRateLimitHit,
    SecurityKeyRotation,

    // Custom action
    Custom(String),
}

impl AuditAction {
    pub fn as_str(&self) -> String {
        match self {
            Self::Custom(s) => s.clone(),
            _ => {
                let json = serde_json::to_string(self).unwrap_or_default();
                json.trim_matches('"').to_string()
            }
        }
    }
}

/// Actor type for audit events
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    #[default]
    User,
    Device,
    Service,
    System,
}

impl ActorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::Service => "service",
            Self::System => "system",
        }
    }
}

/// Audit event to be logged
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ID of the actor performing the action
    pub actor_id: Uuid,
    /// Type of actor
    #[serde(default)]
    pub actor_type: ActorType,
    /// The action being performed
    pub action: AuditAction,
    /// Type of resource being acted upon
    pub resource_type: Option<String>,
    /// ID of the resource being acted upon
    pub resource_id: Option<Uuid>,
    /// Additional context as JSON
    pub details: Option<serde_json::Value>,
    /// Client IP address
    pub ip: Option<IpAddr>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Request correlation ID
    pub request_id: Option<Uuid>,
    /// Session ID
    pub session_id: Option<Uuid>,
}

impl Default for AuditEvent {
    fn default() -> Self {
        Self {
            actor_id: Uuid::nil(),
            actor_type: ActorType::default(),
            action: AuditAction::Custom("unknown".to_string()),
            resource_type: None,
            resource_id: None,
            details: None,
            ip: None,
            user_agent: None,
            request_id: None,
            session_id: None,
        }
    }
}

/// Stored audit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor_id: Uuid,
    pub actor_type: String,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
}

/// Audit logger for recording security events
pub struct AuditLogger {
    pool: PgPool,
}

impl AuditLogger {
    /// Create a new audit logger with a database connection pool
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log an audit event
    pub async fn log(&self, event: AuditEvent) -> Result<i64, AuditError> {
        let ip_str = event.ip.map(|ip| ip.to_string());

        let record = sqlx::query_scalar!(
            r#"
            INSERT INTO audit_log (
                actor_id, actor_type, action, resource_type, resource_id,
                details, ip_address, user_agent, request_id, session_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8, $9, $10)
            RETURNING id
            "#,
            event.actor_id,
            event.actor_type.as_str(),
            event.action.as_str(),
            event.resource_type,
            event.resource_id,
            event.details,
            ip_str,
            event.user_agent,
            event.request_id,
            event.session_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(record)
    }

    /// Query audit logs for a specific actor
    pub async fn query_by_actor(
        &self,
        actor_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let records = sqlx::query_as!(
            AuditRecord,
            r#"
            SELECT
                id, occurred_at, actor_id, actor_type, action,
                resource_type, resource_id, details,
                ip_address::text as ip_address, user_agent,
                request_id, session_id
            FROM audit_log
            WHERE actor_id = $1
            ORDER BY occurred_at DESC
            LIMIT $2
            "#,
            actor_id,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    /// Query audit logs by action type
    pub async fn query_by_action(
        &self,
        action: &str,
        limit: i64,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let records = sqlx::query_as!(
            AuditRecord,
            r#"
            SELECT
                id, occurred_at, actor_id, actor_type, action,
                resource_type, resource_id, details,
                ip_address::text as ip_address, user_agent,
                request_id, session_id
            FROM audit_log
            WHERE action = $1
            ORDER BY occurred_at DESC
            LIMIT $2
            "#,
            action,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    /// Query audit logs within a time range
    pub async fn query_by_time_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<AuditRecord>, AuditError> {
        let records = sqlx::query_as!(
            AuditRecord,
            r#"
            SELECT
                id, occurred_at, actor_id, actor_type, action,
                resource_type, resource_id, details,
                ip_address::text as ip_address, user_agent,
                request_id, session_id
            FROM audit_log
            WHERE occurred_at BETWEEN $1 AND $2
            ORDER BY occurred_at DESC
            LIMIT $3
            "#,
            start,
            end,
            limit
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }
}

/// Convenience function for logging audit events
pub async fn log(pool: &PgPool, event: AuditEvent) -> Result<i64, AuditError> {
    let logger = AuditLogger::new(pool.clone());
    logger.log(event).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_serialization() {
        assert_eq!(AuditAction::AuthLogin.as_str(), "auth_login");
        assert_eq!(AuditAction::MessageSend.as_str(), "message_send");
        assert_eq!(
            AuditAction::Custom("custom.action".to_string()).as_str(),
            "custom.action"
        );
    }

    #[test]
    fn test_audit_event_default() {
        let event = AuditEvent::default();
        assert_eq!(event.actor_id, Uuid::nil());
        assert!(matches!(event.actor_type, ActorType::User));
    }

    #[test]
    fn test_actor_type() {
        assert_eq!(ActorType::User.as_str(), "user");
        assert_eq!(ActorType::Device.as_str(), "device");
        assert_eq!(ActorType::Service.as_str(), "service");
        assert_eq!(ActorType::System.as_str(), "system");
    }
}
