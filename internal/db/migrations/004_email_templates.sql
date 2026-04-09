CREATE TABLE IF NOT EXISTS email_templates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    template_type  TEXT NOT NULL UNIQUE,
    subject        TEXT NOT NULL DEFAULT '',
    body_html      TEXT NOT NULL DEFAULT '',
    updated_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO email_templates (template_type, subject, body_html) VALUES
('password_changed', 'Your password has been changed', '<h2>Password Changed</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> was successfully changed on {{.Timestamp}}.</p><p>If you did not make this change, please contact your administrator immediately.</p><p>— PassPort</p>'),
('password_reset', 'Your password has been reset', '<h2>Password Reset</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> was reset on {{.Timestamp}}.</p><p>If you did not request this reset, please contact your administrator immediately.</p><p>— PassPort</p>'),
('password_expiration', 'Your password is expiring soon', '<h2>Password Expiration Notice</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> will expire on <strong>{{.ExpirationDate}}</strong> ({{.DaysRemaining}} days remaining).</p><p>Please change your password before it expires to avoid service interruption.</p><p>— PassPort</p>'),
('account_locked', 'Your account has been locked', '<h2>Account Locked</h2><p>Hello {{.Username}},</p><p>Your <strong>{{.ProviderName}}</strong> account was locked on {{.Timestamp}}.</p><p>Reason: {{.Reason}}</p><p>Please contact your administrator for assistance.</p><p>— PassPort</p>'),
('account_unlocked', 'Your account has been unlocked', '<h2>Account Unlocked</h2><p>Hello {{.Username}},</p><p>Your <strong>{{.ProviderName}}</strong> account has been unlocked as of {{.Timestamp}}.</p><p>You may now log in normally.</p><p>— PassPort</p>');
