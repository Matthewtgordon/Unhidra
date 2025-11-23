-- Phase 10: Immutable Audit Log
-- Created: 2025-11-23
-- Purpose: Track all security-relevant events with tamper-evident logging

-- Audit log table with append-only design
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Actor information
    actor_id UUID NOT NULL,
    actor_type VARCHAR(50) NOT NULL DEFAULT 'user', -- user, device, service, system
    -- Event information
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    -- Context
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    -- Request correlation
    request_id UUID,
    session_id UUID,
    -- Integrity
    hash_chain VARCHAR(64), -- SHA-256 of previous record for tamper detection
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) WITH (fillfactor = 100); -- Optimize for append-only workload

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_log(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_request ON audit_log(request_id);

-- Prevent updates and deletes on audit_log (immutable)
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit log records cannot be modified or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_log_immutable_update ON audit_log;
CREATE TRIGGER audit_log_immutable_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

DROP TRIGGER IF EXISTS audit_log_immutable_delete ON audit_log;
CREATE TRIGGER audit_log_immutable_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_modification();

-- Common audit actions enum-like constraint
COMMENT ON TABLE audit_log IS 'Immutable append-only audit log for security events';
COMMENT ON COLUMN audit_log.action IS 'Event type: auth.login, auth.logout, auth.failed, message.send, device.register, etc.';
COMMENT ON COLUMN audit_log.actor_type IS 'Actor type: user, device, service, system';
COMMENT ON COLUMN audit_log.hash_chain IS 'SHA-256 hash of previous record for integrity verification';

-- Partitioning for large deployments (optional, enable as needed)
-- CREATE TABLE audit_log_y2025m01 PARTITION OF audit_log
--     FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');
