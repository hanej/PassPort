-- Add toggle for requiring MFA on login for IDP users.
ALTER TABLE mfa_settings ADD COLUMN require_mfa_on_login INTEGER NOT NULL DEFAULT 0;
