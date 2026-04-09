CREATE TABLE IF NOT EXISTS mfa_providers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK (provider_type IN ('duo')),
    enabled       INTEGER NOT NULL DEFAULT 0,
    config_json   TEXT NOT NULL DEFAULT '{}',
    secret_blob   BLOB,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Recreate sessions table to add MFA columns and allow 'reset' user_type.
-- SQLite does not support ALTER COLUMN, so we rebuild the table.
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
    0, ''
FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;
