-- Add 'flash' as a valid session user_type.
-- SQLite does not support ALTER TABLE ... MODIFY CHECK, so we recreate the table.
PRAGMA foreign_keys = OFF;

CREATE TABLE sessions_new (
    id                   TEXT    PRIMARY KEY,
    user_type            TEXT    NOT NULL CHECK (user_type IN ('local', 'provider', 'reset', 'flash')),
    provider_id          TEXT,
    username             TEXT    NOT NULL,
    is_admin             INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    ip_address           TEXT    NOT NULL,
    user_agent           TEXT    NOT NULL DEFAULT '',
    flash_json           TEXT    NOT NULL DEFAULT '{}',
    mfa_pending          INTEGER NOT NULL DEFAULT 0,
    mfa_state            TEXT    NOT NULL DEFAULT '',
    mfa_attempts         INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at           TEXT    NOT NULL,
    last_activity_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO sessions_new SELECT * FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

PRAGMA foreign_keys = ON;
