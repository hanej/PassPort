-- Baseline schema — represents the fully-consolidated state of the original
-- migrations 001 through 018.  Fresh installs apply this single file and then
-- any subsequent numbered migrations.  Existing installs that already have
-- version 1 recorded in schema_migrations will skip this file automatically.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── Local admin ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS local_admins (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT    NOT NULL UNIQUE,
    password_hash         TEXT    NOT NULL,
    must_change_password  INTEGER NOT NULL DEFAULT 1,
    created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── Identity providers ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS identity_providers (
    id                TEXT PRIMARY KEY,
    friendly_name     TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    provider_type     TEXT NOT NULL CHECK (provider_type IN ('ad', 'freeipa')),
    enabled           INTEGER NOT NULL DEFAULT 1,
    config_json       TEXT NOT NULL DEFAULT '{}',
    secret_blob       BLOB,
    logo_url          TEXT NOT NULL DEFAULT '',
    mfa_provider_id   TEXT DEFAULT NULL,
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
    idp_id                TEXT PRIMARY KEY REFERENCES identity_providers(id) ON DELETE CASCADE,
    source_canonical_attr TEXT NOT NULL,
    target_directory_attr TEXT NOT NULL,
    match_mode            TEXT NOT NULL DEFAULT 'exact' CHECK (match_mode IN ('exact'))
);

CREATE TABLE IF NOT EXISTS idp_expiration_config (
    idp_id                 TEXT PRIMARY KEY REFERENCES identity_providers(id) ON DELETE CASCADE,
    enabled                INTEGER NOT NULL DEFAULT 0,
    cron_schedule          TEXT    NOT NULL DEFAULT '0 6 * * *',
    days_before_expiration INTEGER NOT NULL DEFAULT 14,
    updated_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS idp_expiration_filters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id      TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    attribute   TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_expiration_filters_idp ON idp_expiration_filters(idp_id);

-- ── Admin groups ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS admin_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id      TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    group_dn    TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(idp_id, group_dn)
);

-- ── Sessions ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sessions (
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
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- ── User ↔ IDP mappings ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_idp_mappings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_provider_id  TEXT NOT NULL,
    auth_username     TEXT NOT NULL,
    target_idp_id     TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    target_account_dn TEXT NOT NULL,
    link_type         TEXT NOT NULL CHECK (link_type IN ('auto', 'manual')),
    linked_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    verified_at       TEXT,
    UNIQUE(auth_provider_id, auth_username, target_idp_id)
);
CREATE INDEX IF NOT EXISTS idx_mappings_auth     ON user_idp_mappings(auth_provider_id, auth_username);
CREATE INDEX IF NOT EXISTS idx_mappings_target   ON user_idp_mappings(target_idp_id);
CREATE INDEX IF NOT EXISTS idx_mappings_username ON user_idp_mappings(auth_username);

-- ── Correlation warnings ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS correlation_warnings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_username TEXT NOT NULL,
    target_idp_id TEXT NOT NULL,
    warning_type  TEXT NOT NULL,
    message       TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(auth_username, target_idp_id)
);

-- ── Audit log ─────────────────────────────────────────────────────────────────

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
CREATE INDEX IF NOT EXISTS idx_audit_username  ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log(action);

-- ── SMTP ──────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS smtp_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL DEFAULT '{}',
    secret_blob BLOB,
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- ── MFA ───────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS mfa_providers (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    provider_type TEXT NOT NULL CHECK (provider_type IN ('duo', 'email')),
    enabled       INTEGER NOT NULL DEFAULT 0,
    config_json   TEXT NOT NULL DEFAULT '{}',
    secret_blob   BLOB,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS mfa_settings (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    default_mfa_provider_id TEXT    DEFAULT NULL,
    require_mfa_on_login    INTEGER NOT NULL DEFAULT 0,
    updated_at              TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT OR IGNORE INTO mfa_settings (id) VALUES (1);

-- ── Branding ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS branding_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL DEFAULT '{}',
    updated_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
INSERT OR IGNORE INTO branding_config (id, config_json) VALUES (1, '{"app_title":"PassPort","app_abbreviation":"PassPort","app_subtitle":"Self-Service Password Management","logo_url":"","footer_text":""}');

-- ── Email templates ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS email_templates (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    template_type TEXT NOT NULL UNIQUE,
    subject       TEXT NOT NULL DEFAULT '',
    body_html     TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO email_templates (template_type, subject, body_html) VALUES
('password_changed',
 'Your password has been changed',
 '<h2>Password Changed</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> was successfully changed on {{.Timestamp}}.</p><p>If you did not make this change, please contact your administrator immediately.</p><p>— PassPort</p>'),
('password_reset',
 'Your password has been reset',
 '<h2>Password Reset</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> was reset on {{.Timestamp}}.</p><p>If you did not request this reset, please contact your administrator immediately.</p><p>— PassPort</p>'),
('password_expiration',
 'Your password is expiring soon',
 '<h2>Password Expiration Notice</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> will expire on <strong>{{.ExpirationDate}}</strong> ({{.DaysRemaining}} days remaining).</p><p>Please change your password before it expires to avoid service interruption.</p><p>— PassPort</p>'),
('account_locked',
 'Your account has been locked',
 '<h2>Account Locked</h2><p>Hello {{.Username}},</p><p>Your <strong>{{.ProviderName}}</strong> account was locked on {{.Timestamp}}.</p><p>Reason: {{.Reason}}</p><p>Please contact your administrator for assistance.</p><p>— PassPort</p>'),
('account_unlocked',
 'Your account has been unlocked',
 '<h2>Account Unlocked</h2><p>Hello {{.Username}},</p><p>Your <strong>{{.ProviderName}}</strong> account has been unlocked as of {{.Timestamp}}.</p><p>You may now log in normally.</p><p>— PassPort</p>'),
('smtp_test',
 'PassPort Test Email',
 '<h2>PassPort Test Email</h2><p>This is a test email from <strong>PassPort</strong>.</p><p>If you received this message, your SMTP configuration is working correctly.</p><p>Sent at: {{.Timestamp}}</p><p>— PassPort</p>'),
('forgot_password',
 'Password Reset Initiated',
 '<h2>Password Reset</h2><p>Hello {{.Username}},</p><p>A password reset has been initiated for your <strong>{{.ProviderName}}</strong> account on {{.Timestamp}}.</p><p>Your temporary password is: <strong>{{.TempPassword}}</strong></p><p>Please use this temporary password to complete your password reset. It will only be valid for a single use.</p><p>If you did not request this reset, please contact your administrator immediately.</p><p>— PassPort</p>'),
('expiration_report',
 'Soon-to-Expire Passwords Report - {{.ProviderName}}',
 '<h2>Soon-to-Expire Passwords Report</h2><p><strong>Provider:</strong> {{.ProviderName}}</p><p><strong>Generated:</strong> {{.GeneratedDate}}</p><p><strong>Accounts:</strong> {{.AccountCount}}</p>{{.ReportTable}}<p>This report was generated automatically by PassPort.</p>'),
('expired_accounts_report',
 'Expired Accounts - {{.ProviderName}}',
 '<h2>Expired Accounts</h2><p><strong>Provider:</strong> {{.ProviderName}}</p><p><strong>Generated:</strong> {{.GeneratedDate}}</p><p><strong>Accounts:</strong> {{.AccountCount}}</p>{{.ReportTable}}<p>This report was generated automatically by PassPort.</p>');

-- ── Reports ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS report_config (
    idp_id                 TEXT    NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    report_type            TEXT    NOT NULL CHECK (report_type IN ('expiration', 'expired')),
    enabled                INTEGER NOT NULL DEFAULT 0,
    cron_schedule          TEXT    NOT NULL DEFAULT '0 7 * * 1',
    days_before_expiration INTEGER NOT NULL DEFAULT 14,
    recipients             TEXT    NOT NULL DEFAULT '',
    exclude_disabled       INTEGER NOT NULL DEFAULT 1,
    updated_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (idp_id, report_type)
);

CREATE TABLE IF NOT EXISTS report_filters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id      TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL CHECK (report_type IN ('expiration', 'expired')),
    attribute   TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_report_filters_idp ON report_filters(idp_id, report_type);
