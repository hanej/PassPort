-- Phase 1: All initial tables for PassPort

CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS local_admins (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT    NOT NULL UNIQUE,
    password_hash         TEXT    NOT NULL,
    must_change_password  INTEGER NOT NULL DEFAULT 1,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS identity_providers (
    id                TEXT PRIMARY KEY,
    friendly_name     TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    provider_type     TEXT NOT NULL CHECK (provider_type IN ('ad', 'freeipa')),
    enabled           INTEGER NOT NULL DEFAULT 1,
    config_json       TEXT NOT NULL DEFAULT '{}',
    secret_blob       BLOB,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS idp_attribute_mappings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id           TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    canonical_name   TEXT NOT NULL,
    directory_attr   TEXT NOT NULL,
    UNIQUE(idp_id, canonical_name)
);
CREATE INDEX IF NOT EXISTS idx_idp_attr_map_idp ON idp_attribute_mappings(idp_id);

CREATE TABLE IF NOT EXISTS idp_correlation_rules (
    idp_id                   TEXT PRIMARY KEY REFERENCES identity_providers(id) ON DELETE CASCADE,
    source_canonical_attr    TEXT NOT NULL,
    target_directory_attr    TEXT NOT NULL,
    match_mode               TEXT NOT NULL DEFAULT 'exact' CHECK (match_mode IN ('exact'))
);

CREATE TABLE IF NOT EXISTS admin_groups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id        TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    group_dn      TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(idp_id, group_dn)
);

CREATE TABLE IF NOT EXISTS smtp_config (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    config_json   TEXT NOT NULL DEFAULT '{}',
    secret_blob   BLOB,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id                    TEXT PRIMARY KEY,
    user_type             TEXT NOT NULL CHECK (user_type IN ('local', 'provider')),
    provider_id           TEXT,
    username              TEXT NOT NULL,
    is_admin              INTEGER NOT NULL DEFAULT 0,
    must_change_password  INTEGER NOT NULL DEFAULT 0,
    ip_address            TEXT NOT NULL,
    user_agent            TEXT NOT NULL DEFAULT '',
    flash_json            TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at            TEXT NOT NULL,
    last_activity_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS user_idp_mappings (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_provider_id         TEXT NOT NULL,
    auth_username            TEXT NOT NULL,
    target_idp_id            TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    target_account_dn        TEXT NOT NULL,
    link_type                TEXT NOT NULL CHECK (link_type IN ('auto', 'manual')),
    linked_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    verified_at              TEXT,
    UNIQUE(auth_provider_id, auth_username, target_idp_id)
);
CREATE INDEX IF NOT EXISTS idx_mappings_auth ON user_idp_mappings(auth_provider_id, auth_username);
CREATE INDEX IF NOT EXISTS idx_mappings_target ON user_idp_mappings(target_idp_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    username      TEXT NOT NULL DEFAULT '',
    source_ip     TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    provider_id   TEXT NOT NULL DEFAULT '',
    provider_name TEXT NOT NULL DEFAULT '',
    result        TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    details       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
