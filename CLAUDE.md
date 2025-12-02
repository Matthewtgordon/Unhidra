# Claude Code Instructions for Unhidra

## Documentation Maintenance

**IMPORTANT**: Keep the `docs/status/` folder updated on each significant change:

1. **Progress Tracking** (`docs/status/PROGRESS.md`) - Update with completed tasks and milestones
2. **Todo/Tasks** (`docs/status/TODO.md`) - Maintain current and future development tasks
3. **Research Findings** (`docs/status/RESEARCH.md`) - Document research, findings, and technical decisions
4. **Deployment** (`docs/status/DEPLOYMENT.md`) - Deployment guides and configuration notes

## Project Structure

### Backend Services
- `auth-api/` - HTTP-based authentication API (Argon2id password hashing)
- `auth-service/` - WebSocket-based auth service
- `gateway-service/` - WebSocket gateway with JWT token validation (WSS)
- `chat-service/` - Chat functionality
- `presence-service/` - User presence tracking
- `history-service/` - Chat history
- `ml-bridge/` - ML IPC sidecar for Python inference isolation

### IoT/Embedded
- `firmware/` - ESP32 firmware with secure WSS client (Phase 4)
  - `src/main.rs` - Main application with Wi-Fi and WebSocket client
  - `Cargo.toml` - Dependencies (esp-idf-svc, esp-idf-sys)
  - `sdkconfig.defaults` - ESP-IDF SDK configuration
  - `.cargo/config.toml` - Target and build configuration

### Infrastructure
- `migrations/` - Database migration scripts
- `scripts/` - Utility scripts (inference_worker.py)

## Security Guidelines

- Use Argon2id for all password hashing (see `auth-api/src/services/auth_service.rs`)
- Never commit secrets or credentials (use .env files, excluded from git)
- Follow OWASP security best practices
- Use constant-time comparisons for sensitive data
- **WSS Required**: All WebSocket connections must use TLS (wss://)
- **Certificate Verification**: ESP32 firmware uses CA bundle for server verification
- **Device Authentication**: Devices authenticate via Sec-WebSocket-Protocol header
- **Audit Logging**: All security-relevant events must be logged via the audit system

### Audit Logging Implementation

Comprehensive audit logging is implemented across services using a fire-and-forget pattern to avoid handler trait issues:

```rust
// Fire-and-forget pattern for audit logging
tokio::spawn(async move {
    let audit_event = AuditEvent::new(user_id, AuditAction::Login)
        .with_service("auth-api")
        .with_ip(ip_str)
        .with_resource("user", "user");
    let _ = audit::log(audit_event).await;
});
```

**Auth-API Coverage:**
- Login events (success/failure with reasons: user_not_found, account_not_verified, invalid_password)
- Device management (registration, revocation with device metadata and IP)
- SSO/OIDC (successful/failed authentications with provider information)
- WebAuthn/Passkeys (registration, authentication, revocation with device names)

**Chat-Service Coverage:**
- Channel operations (creation, member additions with roles)
- Thread operations (message sends with content metadata, participant additions)
- File operations (uploads, deletions with file metadata)

## Development Notes

### Backend
- Run tests before committing: `cargo test -p <package-name>`
- Apply database migrations from `migrations/` folder
- Use `PasswordService::new_dev()` for faster testing (dev parameters only)

### ESP32 Firmware
- Requires ESP-IDF v5.2+ and Rust toolchain for Xtensa
- Configure device credentials in `firmware/.env` (copy from `.env.example`)
- Build: `cd firmware && cargo build --release`
- Flash: `cd firmware && cargo run --release`
- Target architectures: ESP32, ESP32-S2, ESP32-S3, ESP32-C3, ESP32-C6

## Security Phases Implemented

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Argon2id Password Hashing | ✅ Complete |
| 2 | ML IPC Sidecar Isolation | ✅ Complete |
| 3 | WSS Gateway Security | ✅ Complete |
| 4 | ESP32 Firmware & WSS Integration | ✅ Complete |
| 5 | Comprehensive Audit Logging | ✅ Complete |

## Build Status (v0.3.0)

### Working Services
- ✅ **auth-api**: Builds successfully (WebAuthn API updated to 0.5)
- ✅ **gateway-service**: Builds successfully
- ✅ **presence-service**: Builds successfully
- ✅ **history-service**: Builds successfully

### Known Issues
- ⚠️ **chat-service**: Requires SQLx query preparation (see `SQLX_NOTE.md`)
  - SQLx compile-time query verification needs a running PostgreSQL database
  - Run `cargo sqlx prepare --workspace` with DATABASE_URL set to generate query cache
  - Or build excluding chat-service: `cargo build --workspace --exclude chat-service`

### Recent Fixes (Step 3 - v0.3.0)
1. **auth-api**: Fixed WebAuthn 0.5 API compatibility
   - Updated Base64UrlSafeData usage (serialize challenge to JSON string)
   - Removed deprecated `start_discoverable_authentication()` method
   - Fixed response.id handling (already a String, not bytes)

2. **Axum 0.8 Compatibility**:
   - Removed `#[async_trait]` from `FromRequestParts` implementations (now uses native async fn in traits)
   - Added `IntoResponse` implementation for `UnhidraError` in `unhidra-core` (gated behind `axum-integration` feature)

3. **unhidra-core**: Added optional `axum-integration` feature for web framework compatibility

## Quick Reference

```bash
# Run all backend tests (excluding chat-service)
cargo test --workspace --exclude chat-service

# Build release binaries (excluding chat-service)
cargo build --release --workspace --exclude chat-service

# Start auth-api
./target/release/auth-api

# Build ESP32 firmware
cd firmware && cargo build --release

# Flash ESP32 (with monitor)
cd firmware && cargo run --release

# Prepare SQLx queries (requires running PostgreSQL)
DATABASE_URL="postgres://unhidra:password@localhost:5432/unhidra" \
  cargo sqlx prepare --workspace
```
