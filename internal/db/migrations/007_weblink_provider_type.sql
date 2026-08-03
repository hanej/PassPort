-- Allow the 'weblink' provider type on identity_providers.
--
-- SQLite cannot alter a CHECK constraint in place, so the table is rebuilt.
-- The new table is created under a temporary name, populated, and only then does
-- the old table get dropped and the new one renamed into place. Child tables
-- keep referencing "identity_providers" throughout, so their foreign keys stay
-- correct. Migrate() runs with foreign key enforcement disabled so the DROP does
-- not cascade-delete child rows.
CREATE TABLE identity_providers_new (
    id                TEXT PRIMARY KEY,
    friendly_name     TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    provider_type     TEXT NOT NULL CHECK (provider_type IN ('ad', 'freeipa', 'weblink')),
    enabled           INTEGER NOT NULL DEFAULT 1,
    config_json       TEXT NOT NULL DEFAULT '{}',
    secret_blob       BLOB,
    logo_url          TEXT NOT NULL DEFAULT '',
    mfa_provider_id   TEXT DEFAULT NULL,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT INTO identity_providers_new (
    id, friendly_name, description, provider_type, enabled,
    config_json, secret_blob, logo_url, mfa_provider_id, created_at, updated_at
)
SELECT id, friendly_name, description, provider_type, enabled,
       config_json, secret_blob, logo_url, mfa_provider_id, created_at, updated_at
FROM identity_providers;

DROP TABLE identity_providers;

ALTER TABLE identity_providers_new RENAME TO identity_providers;
