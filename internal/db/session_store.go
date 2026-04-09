package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const tsLayout = "2006-01-02T15:04:05Z"

// CreateSession inserts a new session row.
func (d *DB) CreateSession(ctx context.Context, s *Session) error {
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO sessions (id, user_type, provider_id, username, is_admin,
			must_change_password, ip_address, user_agent, flash_json,
			mfa_pending, mfa_state,
			created_at, expires_at, last_activity_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserType, s.ProviderID, s.Username, s.IsAdmin,
		s.MustChangePassword, s.IPAddress, s.UserAgent, s.FlashJSON,
		s.MFAPending, s.MFAState,
		s.CreatedAt.UTC().Format(tsLayout),
		s.ExpiresAt.UTC().Format(tsLayout),
		s.LastActivityAt.UTC().Format(tsLayout),
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by ID. Returns ErrNotFound if no row exists.
func (d *DB) GetSession(ctx context.Context, id string) (*Session, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, user_type, provider_id, username, is_admin, must_change_password,
			ip_address, user_agent, flash_json, mfa_pending, mfa_state, mfa_attempts,
			created_at, expires_at, last_activity_at
		FROM sessions WHERE id = ?`, id)

	var s Session
	var createdAt, expiresAt, lastActivity string
	err := row.Scan(&s.ID, &s.UserType, &s.ProviderID, &s.Username, &s.IsAdmin,
		&s.MustChangePassword, &s.IPAddress, &s.UserAgent, &s.FlashJSON,
		&s.MFAPending, &s.MFAState, &s.MFAAttempts,
		&createdAt, &expiresAt, &lastActivity)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan session: %w", err)
	}

	if s.CreatedAt, err = time.Parse(tsLayout, createdAt); err != nil {
		return nil, fmt.Errorf("parse created_at: %w", err)
	}
	if s.ExpiresAt, err = time.Parse(tsLayout, expiresAt); err != nil {
		return nil, fmt.Errorf("parse expires_at: %w", err)
	}
	if s.LastActivityAt, err = time.Parse(tsLayout, lastActivity); err != nil {
		return nil, fmt.Errorf("parse last_activity_at: %w", err)
	}

	return &s, nil
}

// TouchSession updates a session's last_activity_at to now and sets a new expires_at.
func (d *DB) TouchSession(ctx context.Context, id string, expiresAt time.Time) error {
	res, err := d.writer.ExecContext(ctx, `
		UPDATE sessions
		SET last_activity_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
			expires_at = ?
		WHERE id = ?`,
		expiresAt.UTC().Format(tsLayout), id)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateSessionFlash updates the flash_json column for a session.
func (d *DB) UpdateSessionFlash(ctx context.Context, id, flashJSON string) error {
	res, err := d.writer.ExecContext(ctx, `
		UPDATE sessions SET flash_json = ? WHERE id = ?`,
		flashJSON, id)
	if err != nil {
		return fmt.Errorf("update session flash: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateSessionMustChangePassword updates the must_change_password flag for a session.
func (d *DB) UpdateSessionMustChangePassword(ctx context.Context, id string, mustChange bool) error {
	res, err := d.writer.ExecContext(ctx, `
		UPDATE sessions SET must_change_password = ? WHERE id = ?`,
		mustChange, id)
	if err != nil {
		return fmt.Errorf("update session must_change_password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateSessionMFA updates the mfa_pending and mfa_state fields for a session
// and resets the mfa_attempts counter to zero (new OTP cycle starts fresh).
func (d *DB) UpdateSessionMFA(ctx context.Context, id string, mfaPending bool, mfaState string) error {
	res, err := d.writer.ExecContext(ctx, `
		UPDATE sessions SET mfa_pending = ?, mfa_state = ?, mfa_attempts = 0 WHERE id = ?`,
		mfaPending, mfaState, id)
	if err != nil {
		return fmt.Errorf("update session mfa: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateSessionMFAAttempts updates the mfa_attempts counter for a session
// without touching mfa_pending or mfa_state.
func (d *DB) UpdateSessionMFAAttempts(ctx context.Context, id string, attempts int) error {
	res, err := d.writer.ExecContext(ctx, `
		UPDATE sessions SET mfa_attempts = ? WHERE id = ?`,
		attempts, id)
	if err != nil {
		return fmt.Errorf("update session mfa_attempts: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSession removes a session by ID.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	_, err := d.writer.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// PurgeExpired deletes all sessions whose expires_at is in the past and returns the count deleted.
func (d *DB) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := d.writer.ExecContext(ctx, `
		DELETE FROM sessions WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now')`)
	if err != nil {
		return 0, fmt.Errorf("purge expired sessions: %w", err)
	}
	return res.RowsAffected()
}
