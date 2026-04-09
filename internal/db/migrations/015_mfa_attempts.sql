-- Add mfa_attempts column to sessions for tracking failed OTP verification
-- attempts. After reaching the configured limit (3), the OTP state is cleared
-- and the user must request a new code. The counter is reset to 0 whenever a
-- new OTP is initiated (UpdateSessionMFA with mfa_pending=true).
ALTER TABLE sessions ADD COLUMN mfa_attempts INTEGER NOT NULL DEFAULT 0;
