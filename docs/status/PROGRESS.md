# Development Progress

## Phase 1: Cryptographic Hardening (Argon2id Password Hashing)

**Status**: Completed

### Completed Tasks

- [x] Created `PasswordService` with Argon2id implementation
  - File: `auth-api/src/services/auth_service.rs`
  - Parameters: 48 MiB memory, 3 iterations, parallelism = 1
  - Exceeds OWASP 2024+ minimums

- [x] Added argon2 crate dependency
  - Replaced legacy sha2 crate with argon2 v0.5
  - Added rand_core for secure salt generation

- [x] Updated handlers to use Argon2id verification
  - File: `auth-api/src/handlers.rs`
  - Constant-time password verification
  - PHC-formatted hash storage

- [x] Created database migration
  - File: `migrations/001_argon2id_password_hash.sql`
  - Expands password_hash to VARCHAR(255)
  - Removes legacy salt column (embedded in PHC format)

- [x] Comprehensive test suite
  - 7 tests covering roundtrip, unique salts, unicode, edge cases
  - Development profile for faster testing

### Security Improvements

- Memory-hard password hashing (resists GPU/ASIC attacks)
- 128-bit random salt per password (CSPRNG)
- Constant-time verification (timing attack protection)
- PHC-formatted strings (self-documenting hash format)

---

## Phase 2: Token-Gated HTTP Route Foundation with JWT

**Status**: Completed (Integrated with Phase 3)

### Completed Tasks

- [x] JWT token generation on successful login
  - File: `auth-api/src/handlers.rs`
  - Uses shared `jwt-common` crate for token generation
  - Includes `sub`, `exp`, `iat`, `display_name` claims

- [x] Shared JWT crate (`jwt-common`)
  - File: `jwt-common/src/lib.rs`
  - Unified token generation and validation
  - Shared between auth-api and gateway-service
  - 6 unit tests for token handling

- [x] Token claims structure
  - `sub`: Subject (username)
  - `exp`: Expiration timestamp
  - `iat`: Issued-at timestamp
  - `room`: Optional room assignment
  - `display_name`: Optional display name

### Integration

The auth-api now generates proper JWT tokens that gateway-service can validate.
Both services use the same `JWT_SECRET` environment variable.

---

## Phase 3: Real-Time WebSocket Fabric Hardening

**Status**: Completed

### Completed Tasks

- [x] WebSocket endpoint implementation (`GET /ws`)
  - File: `gateway-service/src/ws_handler.rs`
  - Axum WebSocketUpgrade extractor for handshake
  - Health check endpoint at `/health`

- [x] Token authentication via Sec-WebSocket-Protocol header
  - Browsers cannot set Authorization headers in WebSocket JS API
  - Token passed as subprotocol: `new WebSocket(url, ["bearer", token])`
  - Server validates JWT using shared `jwt-common` crate
  - HTTP 403 returned for invalid/missing tokens

- [x] Room-based pub/sub with DashMap
  - File: `gateway-service/src/state.rs`
  - Lock-free concurrent room management
  - Room ID derived from JWT claims (user ID or custom room)
  - Automatic room creation on first client join

- [x] Tokio broadcast channels for fan-out messaging
  - Efficient message distribution to all room subscribers
  - Bounded capacity (100 messages) for backpressure
  - No explicit locking for message broadcast

- [x] Resource cleanup on disconnect
  - Forward task aborted when client disconnects
  - Empty rooms removed from DashMap
  - Memory freed when last subscriber leaves

- [x] CORS and Origin validation
  - Origin header checked against allowed origins list
  - Configurable via `ALLOWED_ORIGINS` environment variable
  - Prevents Cross-Site WebSocket Hijacking (CSWSH)

- [x] Structured logging with tracing
  - Connection/disconnection events logged
  - User and room context in log messages
  - Environment-configurable log levels

### Architecture

```
Client                    Gateway Service                    Room
  |                             |                              |
  |-- GET /ws (token in header) |                              |
  |                             |-- Validate JWT (jwt-common)  |
  |                             |-- Check Origin               |
  |                             |-- Join/Create Room --------->|
  |<-- WebSocket Upgrade -------|                              |
  |                             |                              |
  |-- Text Message ------------>|-- Broadcast ---------------->|
  |<-- Broadcast Messages ------|<-----------------------------|
  |                             |                              |
  |-- Close ------------------->|-- Cleanup (if last) -------->|
```

### Security Improvements

- Token in header (not URL query) - avoids logging sensitive data
- JWT signature and expiration validation (shared jwt-common)
- Origin checking prevents CSWSH attacks
- Room isolation - users only receive messages for their room
- TLS required in production (wss://)

### Files Added/Modified

| File | Change |
|------|--------|
| `jwt-common/` | New crate - shared JWT handling |
| `gateway-service/Cargo.toml` | Added dashmap, tracing, jwt-common |
| `gateway-service/src/main.rs` | Modular architecture, CORS, health check |
| `gateway-service/src/state.rs` | AppState with TokenService |
| `gateway-service/src/ws_handler.rs` | WebSocket handler with jwt-common |
| `auth-api/Cargo.toml` | Added jwt-common, tracing |
| `auth-api/src/handlers.rs` | JWT token generation on login |
| `auth-api/src/main.rs` | Updated to use handlers module |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET` | JWT signing secret (shared) | `supersecret` |
| `GATEWAY_BIND_ADDR` | Gateway bind address | `0.0.0.0:9000` |
| `ALLOWED_ORIGINS` | Comma-separated allowed origins | `http://localhost:3000,http://127.0.0.1:3000` |
| `AUTH_BIND_ADDR` | Auth API bind address | `0.0.0.0:9200` |
| `AUTH_DB_PATH` | SQLite database path | `/opt/unhidra/auth.db` |

---

## Optional Enhancements (Future Work)

### EF-CHAT-01: Room Message History Endpoint
- REST API: `GET /rooms/{id}/messages?limit=N`
- Store messages in database on broadcast
- Index on (room_id, timestamp)

### EF-CHAT-02: Typing Indicator Broadcast
- Ephemeral "typing" notifications via WebSocket
- Not persisted to database

### EF-OBS-02: Prometheus Metrics
- Active connection count gauge
- Message rate histogram
- Room count distribution
