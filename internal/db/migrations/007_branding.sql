CREATE TABLE IF NOT EXISTS branding_config (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    config_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO branding_config (id, config_json) VALUES (1, '{"app_title":"PassPort","app_abbreviation":"PassPort","app_subtitle":"Self-Service Password Management","logo_url":"","footer_text":""}');
