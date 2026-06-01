-- Add days_after_expiration column to idp_expiration_config
ALTER TABLE idp_expiration_config ADD COLUMN days_after_expiration INTEGER NOT NULL DEFAULT 0;

-- Add default password_expired email template
INSERT OR IGNORE INTO email_templates (template_type, subject, body_html) VALUES
('password_expired',
 'Your password has expired',
 '<h2>Password Expired</h2><p>Hello {{.Username}},</p><p>Your password for <strong>{{.ProviderName}}</strong> expired on <strong>{{.ExpirationDate}}</strong> ({{.DaysExpired}} days ago).</p><p>Please change your password immediately to restore access to your account.</p><p>— PassPort</p>');
