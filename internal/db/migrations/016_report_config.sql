CREATE TABLE IF NOT EXISTS report_config (
    idp_id                  TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    report_type             TEXT NOT NULL CHECK(report_type IN ('expiration', 'expired')),
    enabled                 INTEGER NOT NULL DEFAULT 0,
    cron_schedule           TEXT NOT NULL DEFAULT '0 7 * * 1',
    days_before_expiration  INTEGER NOT NULL DEFAULT 14,
    recipients              TEXT NOT NULL DEFAULT '',
    updated_at              TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    PRIMARY KEY (idp_id, report_type)
);

CREATE TABLE IF NOT EXISTS report_filters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    idp_id      TEXT NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    report_type TEXT NOT NULL CHECK(report_type IN ('expiration', 'expired')),
    attribute   TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_report_filters_idp ON report_filters(idp_id, report_type);

INSERT OR IGNORE INTO email_templates (template_type, subject, body_html) VALUES
('expiration_report', 'Soon-to-Expire Passwords Report - {{.ProviderName}}', '<h2>Soon-to-Expire Passwords Report</h2><p><strong>Provider:</strong> {{.ProviderName}}</p><p><strong>Generated:</strong> {{.GeneratedDate}}</p><p><strong>Accounts:</strong> {{.AccountCount}}</p>{{.ReportTable}}<p>This report was generated automatically by PassPort.</p>'),
('expired_accounts_report', 'Expired Accounts - {{.ProviderName}}', '<h2>Expired Accounts</h2><p><strong>Provider:</strong> {{.ProviderName}}</p><p><strong>Generated:</strong> {{.GeneratedDate}}</p><p><strong>Accounts:</strong> {{.AccountCount}}</p>{{.ReportTable}}<p>This report was generated automatically by PassPort.</p>');
