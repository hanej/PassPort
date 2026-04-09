INSERT OR IGNORE INTO email_templates (template_type, subject, body_html) VALUES
('smtp_test', 'PassPort Test Email', '<h2>PassPort Test Email</h2><p>This is a test email from <strong>PassPort</strong> (Self-Service Password Reset).</p><p>If you received this message, your SMTP configuration is working correctly.</p><p>Sent at: {{.Timestamp}}</p><p>— PassPort</p>');
