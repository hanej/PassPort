-- account_locked/account_unlocked notifications were never wired up to any
-- feature (no account lockout detection or admin unlock action exists) and
-- have been removed from the app. Delete any seeded/customized rows so they
-- no longer show up in the admin email templates list.
--
-- forgot_password was superseded by password_reset: the self-service reset
-- flow generates a temporary password internally to satisfy the directory
-- bind requirements, but never emails it or shows it to the user, so this
-- template was never sent by any code path either.
DELETE FROM email_templates WHERE template_type IN ('account_locked', 'account_unlocked', 'forgot_password');
