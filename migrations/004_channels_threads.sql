-- Phase 13: Channels, Threads, and E2EE File Sharing
-- Created: 2025-11-23
-- Purpose: Group communication with channels and threaded conversations

-- Channels table for group communication
CREATE TABLE IF NOT EXISTS channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    -- Channel type: public, private, direct (1:1)
    channel_type VARCHAR(20) NOT NULL DEFAULT 'public',
    -- Organization/workspace ID (for multi-tenant)
    org_id UUID,
    -- Creator
    created_by UUID NOT NULL,
    -- Settings
    is_archived BOOLEAN DEFAULT false,
    is_read_only BOOLEAN DEFAULT false,
    -- E2EE settings
    e2ee_required BOOLEAN DEFAULT true,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_channels_org ON channels(org_id);
CREATE INDEX IF NOT EXISTS idx_channels_type ON channels(channel_type);
CREATE INDEX IF NOT EXISTS idx_channels_created_by ON channels(created_by);

-- Channel membership
CREATE TABLE IF NOT EXISTS channel_members (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    -- Role in channel
    role VARCHAR(20) NOT NULL DEFAULT 'member', -- owner, admin, member
    -- Notification settings
    muted BOOLEAN DEFAULT false,
    muted_until TIMESTAMPTZ,
    -- Timestamps
    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_read_at TIMESTAMPTZ,
    PRIMARY KEY (channel_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_channel_members_user ON channel_members(user_id);

-- Messages table with channel and thread support
CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Channel (null for direct messages)
    channel_id UUID REFERENCES channels(id) ON DELETE CASCADE,
    -- For direct messages without channel
    sender_id UUID NOT NULL,
    recipient_id UUID,
    -- Thread support: parent message ID
    parent_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    thread_root_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    -- Content (E2EE encrypted)
    content_encrypted BYTEA NOT NULL,
    content_nonce BYTEA,
    -- Message type
    message_type VARCHAR(20) NOT NULL DEFAULT 'text', -- text, file, system, reaction
    -- Metadata (encrypted)
    metadata_encrypted BYTEA,
    -- Editing
    edited_at TIMESTAMPTZ,
    -- Deletion (soft delete)
    deleted_at TIMESTAMPTZ,
    deleted_by UUID,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_root_id);
CREATE INDEX IF NOT EXISTS idx_messages_parent ON messages(parent_id);

-- Reactions to messages
CREATE TABLE IF NOT EXISTS message_reactions (
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    -- Reaction emoji or custom reaction ID
    reaction VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (message_id, user_id, reaction)
);

-- Read receipts
CREATE TABLE IF NOT EXISTS read_receipts (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    last_read_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
    last_read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, user_id)
);

-- E2EE File attachments
CREATE TABLE IF NOT EXISTS file_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    -- File metadata (encrypted)
    filename_encrypted BYTEA NOT NULL,
    mime_type_encrypted BYTEA,
    size_bytes BIGINT NOT NULL,
    -- Storage location (encrypted URL)
    storage_url_encrypted BYTEA NOT NULL,
    -- E2EE key for file (encrypted with message key)
    file_key_encrypted BYTEA NOT NULL,
    -- Checksum of encrypted file
    checksum_sha256 VARCHAR(64) NOT NULL,
    -- Timestamps
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_file_attachments_message ON file_attachments(message_id);

-- Channel invites
CREATE TABLE IF NOT EXISTS channel_invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    created_by UUID NOT NULL,
    -- Invite code (for shareable links)
    invite_code VARCHAR(32) UNIQUE NOT NULL,
    -- Limits
    max_uses INT,
    uses INT DEFAULT 0,
    expires_at TIMESTAMPTZ,
    -- Status
    is_active BOOLEAN DEFAULT true,
    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_channel_invites_code ON channel_invites(invite_code) WHERE is_active = true;

-- Pinned messages
CREATE TABLE IF NOT EXISTS pinned_messages (
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    pinned_by UUID NOT NULL,
    pinned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (channel_id, message_id)
);

-- Update messages table to add channel_id if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'messages' AND column_name = 'channel_id'
    ) THEN
        ALTER TABLE messages ADD COLUMN channel_id UUID REFERENCES channels(id);
    END IF;
END $$;

-- Comments
COMMENT ON TABLE channels IS 'Group communication channels with E2EE support';
COMMENT ON TABLE channel_members IS 'Channel membership and roles';
COMMENT ON TABLE messages IS 'Encrypted messages with thread support';
COMMENT ON TABLE file_attachments IS 'E2EE encrypted file attachments';
COMMENT ON COLUMN messages.content_encrypted IS 'Message content encrypted with channel/recipient key';
COMMENT ON COLUMN file_attachments.file_key_encrypted IS 'Symmetric key for file, encrypted with message key';
