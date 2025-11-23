# Claude Code Instructions for Unhidra

## Documentation Maintenance

**IMPORTANT**: Keep the `docs/status/` folder updated on each significant change:

1. **Progress Tracking** (`docs/status/PROGRESS.md`) - Update with completed tasks and milestones
2. **Todo/Tasks** (`docs/status/TODO.md`) - Maintain current and future development tasks
3. **Research Findings** (`docs/status/RESEARCH.md`) - Document research, findings, and technical decisions
4. **Deployment** (`docs/status/DEPLOYMENT.md`) - Deployment guides and configuration notes

## Project Structure

- `auth-api/` - HTTP-based authentication API (Argon2id password hashing, JWT generation)
- `gateway-service/` - WebSocket gateway with token validation and room-based pub/sub
- `jwt-common/` - Shared JWT token handling crate (used by auth-api and gateway-service)
- `auth-service/` - WebSocket-based auth service
- `chat-service/` - Chat functionality
- `presence-service/` - User presence tracking
- `history-service/` - Chat history
- `migrations/` - Database migration scripts

## Security Guidelines

- Use Argon2id for all password hashing (see `auth-api/src/services/auth_service.rs`)
- Use `jwt-common` crate for all JWT operations (unified token handling)
- Never commit secrets or credentials
- Follow OWASP security best practices
- Use constant-time comparisons for sensitive data
- WebSocket tokens must use Sec-WebSocket-Protocol header (not URL query params)
- Validate Origin header on WebSocket connections to prevent CSWSH attacks

## Development Notes

- Run tests before committing: `cargo test -p <package-name>`
- Apply database migrations from `migrations/` folder
- Use `PasswordService::new_dev()` for faster testing (dev parameters only)
- Set `JWT_SECRET` environment variable (same for all services)

## JWT Common Crate

The `jwt-common` crate provides unified JWT handling:

```rust
use jwt_common::{Claims, TokenService, DEFAULT_EXPIRATION_SECS};

// Create service (reads JWT_SECRET from env)
let service = TokenService::from_env();

// Generate token
let claims = Claims::new("username", DEFAULT_EXPIRATION_SECS, None);
let token = service.generate(&claims)?;

// Validate token
let validated = service.validate(&token)?;
println!("User: {}, Room: {}", validated.sub, validated.room_id());
```

### Token Claims Structure

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `sub` | String | Yes | Subject (username) |
| `exp` | usize | Yes | Expiration timestamp |
| `iat` | usize | Yes | Issued-at timestamp |
| `room` | String | No | Custom room assignment |
| `display_name` | String | No | User display name |

## Gateway Service (WebSocket)

### Architecture

The gateway-service provides real-time bidirectional WebSocket communication:

- **Token Auth**: JWT validated via `Sec-WebSocket-Protocol` header using `jwt-common`
- **Room-Based**: Clients join rooms based on token claims (user ID or custom room)
- **Pub/Sub**: DashMap + tokio::broadcast for efficient fan-out messaging
- **Cleanup**: Automatic resource cleanup when rooms become empty

### Key Files

| File | Purpose |
|------|---------|
| `gateway-service/src/main.rs` | Server setup, CORS, routing |
| `gateway-service/src/state.rs` | AppState with TokenService and RoomsMap |
| `gateway-service/src/ws_handler.rs` | WebSocket handler with jwt-common validation |

## Auth API

### Key Files

| File | Purpose |
|------|---------|
| `auth-api/src/main.rs` | Server setup, routing |
| `auth-api/src/handlers.rs` | Login handler with JWT generation |
| `auth-api/src/services/auth_service.rs` | Argon2id password hashing |

## Environment Variables

| Variable | Service | Description | Default |
|----------|---------|-------------|---------|
| `JWT_SECRET` | All | JWT signing secret (shared) | `supersecret` |
| `GATEWAY_BIND_ADDR` | gateway-service | Server bind address | `0.0.0.0:9000` |
| `ALLOWED_ORIGINS` | gateway-service | Comma-separated allowed origins | `http://localhost:3000,http://127.0.0.1:3000` |
| `AUTH_BIND_ADDR` | auth-api | Server bind address | `0.0.0.0:9200` |
| `AUTH_DB_PATH` | auth-api | SQLite database path | `/opt/unhidra/auth.db` |

## Client Integration Example

```javascript
// 1. Login to get JWT token
const response = await fetch('http://localhost:9200/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: 'user', password: 'pass' })
});
const { token } = await response.json();

// 2. Connect WebSocket with token
const ws = new WebSocket("ws://localhost:9000/ws", ["bearer", token]);

ws.onopen = () => console.log("Connected");
ws.onmessage = (e) => console.log("Received:", e.data);
ws.send("Hello room!");
```

## Phase Status

- **Phase 1**: Completed - Argon2id password hashing
- **Phase 2**: Completed - JWT token generation (integrated with Phase 3)
- **Phase 3**: Completed - WebSocket fabric hardening

All phases are now integrated via the shared `jwt-common` crate.

## Optional Enhancements (Future Work)

- **EF-CHAT-01**: Room message history endpoint
- **EF-CHAT-02**: Typing indicator broadcast
- **EF-OBS-02**: Prometheus metrics for WebSocket
- **EF-SEC-01**: Rate limiting on login endpoint
