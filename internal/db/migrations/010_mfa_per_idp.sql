-- Rebuild mfa_providers to add 'email' to the provider_type CHECK constraint.
-- SQLite does not support ALTER TABLE ... MODIFY COLUMN, so we rebuild the table.
CREATE TABLE IF NOT EXISTS mfa_providers_new (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK (provider_type IN ('duo', 'email')),
    enabled       INTEGER NOT NULL DEFAULT 0,
    config_json   TEXT NOT NULL DEFAULT '{}',
    secret_blob   BLOB,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO mfa_providers_new
    (id, name, provider_type, enabled, config_json, secret_blob, created_at, updated_at)
SELECT id, name, provider_type, enabled, config_json, secret_blob, created_at, updated_at
FROM mfa_providers;

DROP TABLE mfa_providers;
ALTER TABLE mfa_providers_new RENAME TO mfa_providers;

-- Add MFA provider assignment to identity providers.
ALTER TABLE identity_providers ADD COLUMN mfa_provider_id TEXT DEFAULT NULL;

-- Singleton table for global MFA settings (default provider).
CREATE TABLE IF NOT EXISTS mfa_settings (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    default_mfa_provider_id TEXT DEFAULT NULL,
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO mfa_settings (id) VALUES (1);
