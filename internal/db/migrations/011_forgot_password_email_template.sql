-- Fix the smtp_test template body which referenced "Self-Service Password Reset" (SSPR).
UPDATE email_templates
SET body_html = '<h2>PassPort Test Email</h2><p>This is a test email from <strong>PassPort</strong>.</p><p>If you received this message, your SMTP configuration is working correctly.</p><p>Sent at: {{.Timestamp}}</p><p>— PassPort</p>'
WHERE template_type = 'smtp_test';

-- Add the forgot-password notification template.
INSERT OR IGNORE INTO email_templates (template_type, subject, body_html) VALUES
('forgot_password', 'Password Reset Initiated', '<h2>Password Reset</h2><p>Hello {{.Username}},</p><p>A password reset has been initiated for your <strong>{{.ProviderName}}</strong> account on {{.Timestamp}}.</p><p>Your temporary password is: <strong>{{.TempPassword}}</strong></p><p>Please use this temporary password to complete your password reset. It will only be valid for a single use.</p><p>If you did not request this reset, please contact your administrator immediately.</p><p>— PassPort</p>');
