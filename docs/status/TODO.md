# Todo / Development Tasks

## Current Sprint

### Optional Fast-Track Enhancements

- [ ] **EF-SEC-01**: Rate limiting on login endpoint
  - Add Tower rate limiter or governor crate
  - Limit login attempts per IP/account per minute
  - Prevents DoS via expensive hash computations

- [ ] **EF-DEVX-01**: Environment-based password cost selection
  - Implement config-based parameter selection
  - Use reduced params in development, full params in production
  - Environment variable or feature flag driven

- [ ] **EF-OBS-02**: Basic metrics for WebSockets
  - Active connection count gauge
  - Message rate histogram
  - Room count and subscriber distribution
  - Prometheus-compatible endpoint

## Backlog

### Security Enhancements

- [ ] Implement password change endpoint
- [ ] Add password reset flow with secure tokens
- [ ] Implement account lockout after failed attempts
- [ ] Add audit logging for authentication events

### Migration Tasks

- [ ] Create legacy hash migration flow
  - Detect old SHA256 hash format
  - Re-hash on successful login
  - Gradual migration without forced resets

### Infrastructure

- [x] Add health check endpoints (Done for gateway-service and auth-api)
- [ ] Implement proper error handling
- [x] Add structured logging (tracing crate) - Done for both services
- [ ] Set up CI/CD pipeline with security scanning

### Phase 3 Optional Enhancements (From Spec)

- [ ] **EF-CHAT-01**: Room message history endpoint
  - REST API: `GET /rooms/{id}/messages?limit=N`
  - Store messages in database on broadcast
  - Index on (room_id, timestamp)
  - Provides chat history / audit trail

- [ ] **EF-CHAT-02**: Typing indicator broadcast
  - Ephemeral "typing" notifications via WebSocket
  - JSON message type: `{type: "typing", user: X, state: "start|stop"}`
  - Not persisted to database
  - Nice-to-have for real-time collaboration UX

## Completed

### Phase 1 - Cryptographic Hardening

- [x] Argon2id password hashing implementation
- [x] Database migration for PHC-format hashes
- [x] Test suite for password service

### Phase 2 - Token-Gated HTTP Routes

- [x] **INT-01**: Unified JWT validation logic
  - Created `jwt-common` crate for shared token handling
  - Both auth-api and gateway-service use same TokenService
  - Consistent secret handling via `JWT_SECRET` env var

- [x] **INT-02**: Aligned token claims structure
  - auth-api generates tokens with `sub`, `exp`, `iat`, `display_name` claims
  - Optional `room` claim for custom room assignment
  - gateway-service uses `claims.room_id()` helper for room assignment

- [x] JWT token generation on successful login
- [x] JWT validation in gateway-service WebSocket handler

### Phase 3 - WebSocket Fabric Hardening

- [x] WebSocket endpoint (`GET /ws`) in gateway-service
- [x] Token authentication via Sec-WebSocket-Protocol header
- [x] Room-based pub/sub with DashMap
- [x] Tokio broadcast channels for message fan-out
- [x] CORS and Origin validation
- [x] Resource cleanup on disconnect
- [x] Structured logging with tracing
- [x] Health check endpoint (`GET /health`)

### Phase 2/3 Integration

- [x] **INT-03**: WebSocket reconnection guidance documented
  - Clients should obtain new token from auth-api before reconnecting
  - gateway-service validates token on each new connection

## Notes

### WebSocket Client Usage

To connect to the WebSocket endpoint:

```javascript
// 1. Login to get JWT token
const response = await fetch('http://auth-api:9200/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user', password: 'pass' })
});
const { token } = await response.json();

// 2. Connect WebSocket with token in subprotocol
const ws = new WebSocket("wss://gateway:9000/ws", ["bearer", token]);

ws.onopen = () => console.log("Connected");
ws.onmessage = (e) => console.log("Received:", e.data);
ws.send("Hello room!");
```

### Token Refresh

When the WebSocket connection is closed due to token expiry:
1. Client detects close event
2. Client fetches new token from auth-api `/login`
3. Client reconnects with new token in Sec-WebSocket-Protocol header

### Architecture Overview

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Client/IoT    │     │    auth-api     │     │ gateway-service │
└────────┬────────┘     └────────┬────────┘     └────────┬────────┘
         │                       │                       │
         │  POST /login          │                       │
         │──────────────────────>│                       │
         │                       │                       │
         │  { token: JWT }       │                       │
         │<──────────────────────│                       │
         │                       │                       │
         │  GET /ws (token in Sec-WebSocket-Protocol)    │
         │─────────────────────────────────────────────>│
         │                       │                       │
         │  WebSocket Upgrade    │   Validate JWT        │
         │<─────────────────────────────────────────────│
         │                       │                       │
         │  Messages <═══════════════════════════════>  │
         │                       │       (broadcast)     │
```
