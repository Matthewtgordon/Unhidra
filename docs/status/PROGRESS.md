# Development Progress

## Project Evolution Timeline

| Date | Phase | Description | PR/Commit |
|------|-------|-------------|-----------|
| 2024-11 | Initial | Initial commit with base services | `fef3210` |
| 2024-11 | Phase 1 | Argon2id password hashing | `e358a05` |
| 2024-11 | Phase 2 | ML IPC sidecar isolation | `9d8d0df` |
| 2024-11 | Phase 3 | WSS Gateway Security | ✅ Complete |
| 2024-11 | Phase 4 | ESP32 Firmware & WSS Integration | ✅ Complete |
| 2024-11 | Phase 5 | Rate Limiting & Device Registration | ✅ Complete |
| 2025-11 | Phase 7 | E2EE Double Ratchet (Noise Protocol) | ✅ Complete |
| 2025-11 | Phase 8 | OIDC SSO + WebAuthn (Passkeys) | ✅ Complete |
| 2025-11 | Phase 9 | Redis Streams (Multi-Node Ready) | ✅ Complete |
| 2025-11 | Phase 10 | Immutable Audit Log | ✅ Complete |
| 2025-11 | Phase 11 | Helm Charts for Kubernetes | ✅ Complete |
| 2025-11 | Phase 12 | MQTT-over-WebSocket Bridge | ✅ Complete |
| 2025-11 | Phase 13 | Channels, Threads, E2EE File Sharing | ✅ Complete |
| 2025-11 | Phase 14 | Tauri Desktop Client | ✅ Complete |

---

## Phase 5: Rate Limiting & Device Registration

**Status**: ✅ Completed

### Overview

Implemented comprehensive rate limiting across all services and added device registration functionality to support IoT device management.

### Completed Tasks

- [x] **Gateway Service Rate Limiting**
  - Per-IP connection rate limiting (60/min default)
  - Per-user connection rate limiting (30/min default)
  - Per-connection message rate limiting (50/sec default)
  - Configurable via environment variables
  - File: `gateway-service/src/rate_limiter.rs`

- [x] **Auth API Rate Limiting**
  - Per-IP login attempt limiting (10/min default)
  - Per-IP registration limiting (5/hour default)
  - Per-IP device registration limiting (10/hour default)
  - File: `auth-api/src/rate_limiter.rs`

- [x] **Device Registration API**
  - POST `/devices/register` - Register new IoT device
  - POST `/devices/list` - List user's devices
  - POST `/devices/revoke` - Revoke device access
  - API key generation with Argon2id hashing
  - Device metadata storage in SQLite

- [x] **Connection Tracking**
  - Real-time connection metadata tracking
  - Messages sent/received counters
  - Connection duration tracking
  - IP address and user agent logging
  - File: `gateway-service/src/connection.rs`

- [x] **Prometheus Metrics**
  - `gateway_connections_total` - Total connections
  - `gateway_connections_active` - Active connections
  - `gateway_messages_total` - Messages processed
  - `gateway_message_latency_seconds` - Latency histogram
  - `gateway_rate_limit_hits_total` - Rate limit violations
  - File: `gateway-service/src/metrics.rs`

- [x] **Docker Compose Setup**
  - Multi-service orchestration
  - Prometheus metrics collection
  - Grafana dashboards
  - Volume persistence
  - Health checks

### Security Improvements (Phase 5)

| Improvement | Description |
|-------------|-------------|
| Rate limiting | Prevents brute force and DoS attacks |
| Device API keys | Secure device authentication |
| Connection tracking | Audit trail for connections |
| Metrics observability | Real-time security monitoring |

---

## Phase 4: ESP32 Firmware & WSS Integration (IoT Edge Hardening)

**Status**: ✅ Completed

### Overview

Implemented secure ESP32 firmware using the modern `esp-idf-svc` ecosystem for IoT edge devices. The firmware establishes encrypted WebSocket connections to the Unhidra backend with device authentication and automatic reconnection.

### Completed Tasks

- [x] **Created firmware directory structure**
- [x] **Implemented Wi-Fi management using EspWifi**
- [x] **Implemented secure WebSocket client**
- [x] **TLS certificate verification**
- [x] **Device authentication via Sec-WebSocket-Protocol**
- [x] **Automatic reconnection with exponential backoff**
- [x] **Application heartbeat mechanism**
- [x] **Keep-alive ping/pong**

### Security Improvements (Phase 4)

| Improvement | Description |
|-------------|-------------|
| End-to-end encryption | All device-cloud traffic over TLS |
| Certificate pinning ready | CA bundle with custom cert support |
| Authentication isolation | API keys in protocol header, not URL |
| Reconnect resilience | Automatic recovery with backoff |
| Memory safety | Rust ownership model, no raw pointers |
| Secure config | Credentials in .env (gitignored) |

---

## Phase 3: WSS Gateway Security

**Status**: ✅ Completed

### Completed Tasks

- [x] **Upgraded gateway to Axum framework**
- [x] **Sec-WebSocket-Protocol authentication**
  - Extract token from subprotocol header
  - Validate JWT during handshake
  - Return validated subprotocol in response

- [x] **Connection tracking with DashMap**
  - Store connected client info (user_id, device_id, connect_time)
  - Enable targeted message delivery
  - Support for presence tracking

- [x] **Graceful connection termination**
  - Send close frame with reason code
  - Clean up connection state
  - Log disconnection events

- [x] **Rate limiting for WebSocket connections**
  - Limit connections per IP
  - Limit connections per user/device
  - Prevent resource exhaustion

- [x] **Origin validation (CSRF protection)**
  - Configurable allowed origins
  - Reject unauthorized origins

---

## Phase 2: Architectural Decoupling (ML IPC Sidecar Isolation)

**Status**: ✅ Completed

### Completed Tasks

- [x] Created `ml-bridge` crate with PythonWorker implementation
- [x] Implemented length-prefixed JSON protocol
- [x] Created Python inference worker daemon
- [x] Added comprehensive error handling
- [x] Integrated into workspace

### Architecture Benefits

- **Event Loop Protection**: Python ML runs in separate process
- **GIL Bypass**: Separate process means no Python GIL contention
- **Fault Isolation**: Python crash doesn't bring down Rust server
- **Independent Scaling**: Can spawn multiple Python workers if needed
- **Security**: UDS is local-only, socket permissions set to 0600

---

## Phase 1: Cryptographic Hardening (Argon2id Password Hashing)

**Status**: ✅ Completed

### Completed Tasks

- [x] Created `PasswordService` with Argon2id implementation
- [x] Added argon2 crate dependency
- [x] Updated handlers to use Argon2id verification
- [x] Created database migration
- [x] Comprehensive test suite

### Security Improvements

- Memory-hard password hashing (resists GPU/ASIC attacks)
- 128-bit random salt per password (CSPRNG)
- Constant-time verification (timing attack protection)
- PHC-formatted strings (self-documenting hash format)

---

## Phase 14: Tauri Desktop Client

**Status**: ✅ Completed

### Overview

Cross-platform desktop application using Tauri 2.0 with E2EE, OIDC login, WebSocket chat, and auto-updates.

### Completed Tasks

- [x] Created `unhidra-desktop` crate with Tauri 2.0
- [x] Implemented OIDC authentication flow
- [x] WebSocket chat connection manager
- [x] Client-side E2EE using Noise Protocol
- [x] System tray integration
- [x] Cross-platform builds (Windows, macOS, Linux)
- [x] Auto-update support

### Files Added

- `unhidra-desktop/src-tauri/Cargo.toml`
- `unhidra-desktop/src-tauri/tauri.conf.json`
- `unhidra-desktop/src-tauri/src/main.rs`
- `unhidra-desktop/src-tauri/src/auth.rs`
- `unhidra-desktop/src-tauri/src/chat.rs`
- `unhidra-desktop/src-tauri/src/e2ee.rs`

---

## Phase 13: Channels, Threads, E2EE File Sharing

**Status**: ✅ Completed

### Overview

Group communication with channels, threaded conversations, and encrypted file attachments.

### Completed Tasks

- [x] Channels database schema (public, private, direct)
- [x] Channel membership with roles (owner, admin, member)
- [x] Messages with thread support (parent_id, thread_root_id)
- [x] Message reactions
- [x] E2EE file attachments with separate encryption keys
- [x] Read receipts
- [x] Pinned messages
- [x] Channel invites with codes

### Migration

- `migrations/004_channels_threads.sql`

---

## Phase 12: MQTT-over-WebSocket Bridge

**Status**: ✅ Completed

### Overview

Secure MQTT connectivity for IoT devices with TLS client certificates and E2EE message forwarding.

### Completed Tasks

- [x] MQTT bridge in gateway-service
- [x] TLS client certificate authentication
- [x] Topic-based device routing
- [x] E2EE encryption for device messages
- [x] Automatic ratchet provisioning
- [x] QoS support (0, 1, 2)

### Files Added

- `gateway-service/src/mqtt/mod.rs`
- `gateway-service/src/mqtt/mqtt_bridge.rs`

---

## Phase 11: Helm Charts for Kubernetes

**Status**: ✅ Completed

### Overview

Production-ready Kubernetes deployment with Helm charts, including PostgreSQL and Redis dependencies.

### Completed Tasks

- [x] Chart.yaml with Bitnami dependencies
- [x] values.yaml with comprehensive configuration
- [x] Gateway deployment with TLS
- [x] Service definitions
- [x] ConfigMaps for environment
- [x] HPA and PDB support
- [x] Network policies
- [x] ServiceMonitor for Prometheus

### Files Added

- `helm/unhidra/Chart.yaml`
- `helm/unhidra/values.yaml`
- `helm/unhidra/templates/_helpers.tpl`
- `helm/unhidra/templates/gateway-deployment.yaml`
- `helm/unhidra/templates/configmap.yaml`

---

## Phase 10: Immutable Audit Log

**Status**: ✅ Completed

### Overview

Tamper-evident logging for all security-relevant events with database triggers preventing modification.

### Completed Tasks

- [x] Audit log database schema
- [x] Immutability triggers (prevent UPDATE/DELETE)
- [x] Comprehensive audit actions enum
- [x] Actor types (user, device, service, system)
- [x] IP and user-agent tracking
- [x] Request correlation IDs
- [x] Query methods by actor, action, time range

### Files Added

- `migrations/003_audit_log.sql`
- `core/src/audit.rs`

---

## Phase 9: Redis Streams (Multi-Node Ready)

**Status**: ✅ Completed

### Overview

Redis Streams for scalable message distribution across multiple service instances using consumer groups.

### Completed Tasks

- [x] StreamPublisher for message broadcasting
- [x] StreamConsumer with consumer groups
- [x] Message types (text, file, reaction, system)
- [x] Presence updates via Redis Streams
- [x] Typing indicators
- [x] Automatic message acknowledgment

### Files Added

- `chat-service/src/streams/mod.rs`
- `chat-service/src/streams/redis_stream.rs`

---

## Phase 8: OIDC SSO + WebAuthn (Passkeys)

**Status**: ✅ Completed

### Overview

Enterprise SSO via OpenID Connect and passwordless authentication with WebAuthn/FIDO2.

### Completed Tasks

- [x] OIDC provider integration (any compliant IdP)
- [x] Authorization code flow with PKCE
- [x] User info retrieval
- [x] WebAuthn/Passkey registration
- [x] WebAuthn authentication
- [x] Secure state management

### Files Added

- `auth-api/src/oidc/mod.rs`
- `auth-api/src/webauthn/mod.rs`

---

## Phase 7: E2EE Double Ratchet (Noise Protocol)

**Status**: ✅ Completed

### Overview

End-to-end encryption using the Noise Protocol framework with forward secrecy. Server never sees plaintext.

### Completed Tasks

- [x] Noise XX pattern implementation
- [x] Pre-key bundle generation and exchange
- [x] Session handshake (initiator/responder)
- [x] Message encryption/decryption
- [x] Encrypted message envelope with sequence numbers
- [x] Base64 serialization for transport

### Files Added

- `core/src/crypto/mod.rs`
- `core/src/crypto/e2ee.rs`
- `core/src/lib.rs` (updated)

### Security Improvements (Phase 7)

| Improvement | Description |
|-------------|-------------|
| Forward secrecy | Compromise of keys doesn't reveal past messages |
| X25519 key exchange | Modern elliptic curve cryptography |
| ChaCha20-Poly1305 | High-performance AEAD encryption |
| BLAKE2s | Fast cryptographic hashing |

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Phases Completed | 13 (1-5, 7-14) |
| New Crates Added | 4 (ml-bridge, jwt-common enhanced, firmware, unhidra-desktop) |
| Security Improvements | 40+ |
| Test Coverage | Unit tests for auth, ML bridge, gateway, crypto |
| Supported Platforms | Linux (backend), ESP32 family (firmware), Windows/macOS/Linux (desktop) |
| Docker Support | Full compose with Prometheus/Grafana |
| Kubernetes Support | Helm charts with PostgreSQL/Redis |
| E2EE | Full end-to-end encryption with Noise Protocol |
