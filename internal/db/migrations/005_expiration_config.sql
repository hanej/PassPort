CREATE TABLE IF NOT EXISTS idp_expiration_config (
    idp_id                  TEXT PRIMARY KEY REFERENCES identity_providers(id) ON DELETE CASCADE,
    enabled                 INTEGER NOT NULL DEFAULT 0,
    cron_schedule           TEXT NOT NULL DEFAULT '0 6 * * *',
    days_before_expiration  INTEGER NOT NULL DEFAULT 14,
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS idp_expiration_filters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id      TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    attribute   TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_expiration_filters_idp ON idp_expiration_filters(idp_id);
