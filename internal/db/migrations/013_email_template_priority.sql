-- Message priority for each email template: 'normal', 'high', or 'low'.
-- Normal sends no priority headers.
ALTER TABLE email_templates ADD COLUMN priority TEXT NOT NULL DEFAULT 'normal';
