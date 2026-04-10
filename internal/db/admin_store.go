package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = fmt.Errorf("not found")

// GetLocalAdmin retrieves a local admin by username.
func (d *DB) GetLocalAdmin(ctx context.Context, username string) (*LocalAdmin, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, username, password_hash, must_change_password, created_at, updated_at
		FROM local_admins
		WHERE username = ?`, username)

	var a LocalAdmin
	var createdAt, updatedAt string
	var mustChange int64

	err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &mustChange, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying local admin: %w", err)
	}

	a.MustChangePassword = mustChange != 0

	a.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	a.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing updated_at: %w", err)
	}

	return &a, nil
}

// CreateLocalAdmin inserts a new local admin and returns the created record.
func (d *DB) CreateLocalAdmin(ctx context.Context, username, passwordHash string) (*LocalAdmin, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	result, err := d.writer.ExecContext(ctx, `
		INSERT INTO local_admins (username, password_hash, must_change_password, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?)`, username, passwordHash, now, now)
	if err != nil {
		return nil, fmt.Errorf("inserting local admin: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("getting last insert id: %w", err)
	}

	ts, _ := time.Parse(time.RFC3339, now)
	return &LocalAdmin{
		ID:                 id,
		Username:           username,
		PasswordHash:       passwordHash,
		MustChangePassword: true,
		CreatedAt:          ts,
		UpdatedAt:          ts,
	}, nil
}

// ListLocalAdmins returns all local admin accounts.
func (d *DB) ListLocalAdmins(ctx context.Context) ([]LocalAdmin, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, username, password_hash, must_change_password, created_at, updated_at
		FROM local_admins ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("listing local admins: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var admins []LocalAdmin
	for rows.Next() {
		var a LocalAdmin
		var createdAt, updatedAt string
		var mustChange int64
		if err := rows.Scan(&a.ID, &a.Username, &a.PasswordHash, &mustChange, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scanning local admin: %w", err)
		}
		a.MustChangePassword = mustChange != 0
		if a.CreatedAt, err = time.Parse(time.RFC3339, createdAt); err != nil {
			return nil, fmt.Errorf("parsing created_at: %w", err)
		}
		if a.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt); err != nil {
			return nil, fmt.Errorf("parsing updated_at: %w", err)
		}
		admins = append(admins, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating local admins: %w", err)
	}
	return admins, nil
}

// UpdateLocalAdminPassword updates the password hash and must_change_password flag for a local admin.
func (d *DB) UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var mustChangeInt int
	if mustChange {
		mustChangeInt = 1
	}

	result, err := d.writer.ExecContext(ctx, `
		UPDATE local_admins
		SET password_hash = ?, must_change_password = ?, updated_at = ?
		WHERE username = ?`, passwordHash, mustChangeInt, now, username)
	if err != nil {
		return fmt.Errorf("updating local admin password: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// AddPasswordHistory inserts a new password hash into the history for username,
// then deletes all but the most-recent keepN entries. keepN <= 0 skips trimming.
func (d *DB) AddPasswordHistory(ctx context.Context, username, passwordHash string, keepN int) error {
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO local_admin_password_history (username, password_hash)
		VALUES (?, ?)`, username, passwordHash)
	if err != nil {
		return fmt.Errorf("insert password history: %w", err)
	}

	if keepN > 0 {
		_, err = d.writer.ExecContext(ctx, `
			DELETE FROM local_admin_password_history
			WHERE username = ?
			  AND id NOT IN (
			    SELECT id FROM local_admin_password_history
			    WHERE username = ?
			    ORDER BY id DESC
			    LIMIT ?
			  )`, username, username, keepN)
		if err != nil {
			return fmt.Errorf("trim password history: %w", err)
		}
	}

	return nil
}

// GetPasswordHistory returns all stored password hashes for username, most-recent-first.
func (d *DB) GetPasswordHistory(ctx context.Context, username string) ([]string, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT password_hash
		FROM local_admin_password_history
		WHERE username = ?
		ORDER BY id DESC`, username)
	if err != nil {
		return nil, fmt.Errorf("query password history: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan password history: %w", err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate password history: %w", err)
	}
	return hashes, nil
}
