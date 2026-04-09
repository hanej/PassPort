-- Rebuild sessions table to allow 'reset' user_type for forgot-password flow.
-- Also ensures mfa_pending and mfa_state columns exist (from migration 002).
CREATE TABLE IF NOT EXISTS sessions_new (
    id                    TEXT PRIMARY KEY,
    user_type             TEXT NOT NULL CHECK (user_type IN ('local', 'provider', 'reset')),
    provider_id           TEXT,
    username              TEXT NOT NULL,
    is_admin              INTEGER NOT NULL DEFAULT 0,
    must_change_password  INTEGER NOT NULL DEFAULT 0,
    ip_address            TEXT NOT NULL,
    user_agent            TEXT NOT NULL DEFAULT '',
    flash_json            TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at            TEXT NOT NULL,
    last_activity_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    mfa_pending           INTEGER NOT NULL DEFAULT 0,
    mfa_state             TEXT NOT NULL DEFAULT ''
);

INSERT OR IGNORE INTO sessions_new
    (id, user_type, provider_id, username, is_admin, must_change_password,
     ip_address, user_agent, flash_json, created_at, expires_at, last_activity_at,
     mfa_pending, mfa_state)
SELECT
    id, user_type, provider_id, username, is_admin, must_change_password,
    ip_address, user_agent, flash_json, created_at, expires_at, last_activity_at,
    mfa_pending, mfa_state
FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
