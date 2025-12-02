# SQLx Offline Mode Setup Required

## Current Status

The `chat-service` crate uses SQLx's compile-time query verification which requires either:
1. A running PostgreSQL database during compilation, OR
2. Pre-prepared query metadata in a `.sqlx/` directory

## Error

When building without a database connection:
```
error: `SQLX_OFFLINE=true` but there is no cached data for this query
```

## Solution

To prepare the SQLx query cache:

```bash
# 1. Start a PostgreSQL database (e.g., via Docker)
docker run -d --name unhidra-postgres \
  -e POSTGRES_DB=unhidra \
  -e POSTGRES_USER=unhidra \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  postgres:16

# 2. Run migrations
DATABASE_URL="postgres://unhidra:password@localhost:5432/unhidra" \
  sqlx database create

# Apply migrations from migrations/ folder
# (Use your migration tool of choice)

# 3. Prepare SQLx query cache
DATABASE_URL="postgres://unhidra:password@localhost:5432/unhidra" \
  cargo sqlx prepare --workspace

# 4. Now you can build offline
SQLX_OFFLINE=true cargo build --workspace
```

## Alternative: Skip chat-service

To build other services without chat-service:

```bash
cargo build --workspace --exclude chat-service
```

## Services That Build Successfully

- ✅ auth-api
- ✅ gateway-service
- ✅ presence-service
- ✅ history-service
- ⚠️ chat-service (requires SQLx prepare)
