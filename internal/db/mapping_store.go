package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// GetMapping retrieves a single user-IDP mapping by its unique triple.
// Returns ErrNotFound if no matching row exists.
func (d *DB) GetMapping(ctx context.Context, authProviderID, authUsername, targetIDPID string) (*UserIDPMapping, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, auth_provider_id, auth_username, target_idp_id,
			target_account_dn, link_type, linked_at, verified_at
		FROM user_idp_mappings
		WHERE auth_provider_id = ? AND auth_username = ? AND target_idp_id = ?`,
		authProviderID, authUsername, targetIDPID)

	m, err := scanMapping(row)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mapping: %w", err)
	}
	return m, nil
}

// HasMappingToTarget returns true if any mapping exists for the given username
// and target IDP, regardless of which auth provider created it.
func (d *DB) HasMappingToTarget(ctx context.Context, authUsername, targetIDPID string) (bool, error) {
	var count int
	err := d.reader.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM user_idp_mappings
		WHERE auth_username = ? AND target_idp_id = ?`,
		authUsername, targetIDPID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking mapping existence: %w", err)
	}
	return count > 0, nil
}

// ListMappings returns mappings for a given auth provider and username.
// If authProviderID is empty, mappings from all auth providers are returned.
func (d *DB) ListMappings(ctx context.Context, authProviderID, authUsername string) ([]UserIDPMapping, error) {
	var query string
	var args []any

	if authProviderID != "" {
		query = `SELECT id, auth_provider_id, auth_username, target_idp_id,
			target_account_dn, link_type, linked_at, verified_at
			FROM user_idp_mappings
			WHERE auth_provider_id = ? AND auth_username = ?
			ORDER BY id`
		args = []any{authProviderID, authUsername}
	} else {
		query = `SELECT id, auth_provider_id, auth_username, target_idp_id,
			target_account_dn, link_type, linked_at, verified_at
			FROM user_idp_mappings
			WHERE auth_username = ?
			ORDER BY id`
		args = []any{authUsername}
	}

	rows, err := d.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var mappings []UserIDPMapping
	for rows.Next() {
		var m UserIDPMapping
		var linkedAt string
		var verifiedAt sql.NullString
		if err := rows.Scan(&m.ID, &m.AuthProviderID, &m.AuthUsername,
			&m.TargetIDPID, &m.TargetAccountDN, &m.LinkType,
			&linkedAt, &verifiedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		if m.LinkedAt, err = time.Parse(tsLayout, linkedAt); err != nil {
			return nil, fmt.Errorf("parse linked_at: %w", err)
		}
		if verifiedAt.Valid {
			t, err := time.Parse(tsLayout, verifiedAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse verified_at: %w", err)
			}
			m.VerifiedAt = &t
		}
		mappings = append(mappings, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mappings: %w", err)
	}
	return mappings, nil
}

// SearchMappings returns paginated mappings matching the filter.
// filter.Username supports '*' as a wildcard (converted to SQL LIKE '%').
// Returns the matched rows, the total count of matching rows, and any error.
func (d *DB) SearchMappings(ctx context.Context, filter MappingSearchFilter) ([]UserIDPMapping, int, error) {
	// Convert '*' wildcard to SQL LIKE '%'.
	usernamePattern := strings.ReplaceAll(filter.Username, "*", "%")

	var whereClause string
	var args []any
	if filter.ProviderID != "" {
		whereClause = `WHERE (auth_provider_id = ? OR target_idp_id = ?) AND auth_username LIKE ?`
		args = []any{filter.ProviderID, filter.ProviderID, usernamePattern}
	} else {
		whereClause = `WHERE auth_username LIKE ?`
		args = []any{usernamePattern}
	}

	// Total count for pagination.
	var total int
	if err := d.reader.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_idp_mappings `+whereClause,
		args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count mappings: %w", err)
	}

	// Paginated rows.
	pageArgs := append(args, filter.Limit, filter.Offset)
	rows, err := d.reader.QueryContext(ctx,
		`SELECT id, auth_provider_id, auth_username, target_idp_id,
			target_account_dn, link_type, linked_at, verified_at
		FROM user_idp_mappings `+whereClause+`
		ORDER BY id
		LIMIT ? OFFSET ?`,
		pageArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("search mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var mappings []UserIDPMapping
	for rows.Next() {
		var m UserIDPMapping
		var linkedAt string
		var verifiedAt sql.NullString
		if err := rows.Scan(&m.ID, &m.AuthProviderID, &m.AuthUsername,
			&m.TargetIDPID, &m.TargetAccountDN, &m.LinkType,
			&linkedAt, &verifiedAt); err != nil {
			return nil, 0, fmt.Errorf("scan mapping: %w", err)
		}
		if m.LinkedAt, err = time.Parse(tsLayout, linkedAt); err != nil {
			return nil, 0, fmt.Errorf("parse linked_at: %w", err)
		}
		if verifiedAt.Valid {
			t, err := time.Parse(tsLayout, verifiedAt.String)
			if err != nil {
				return nil, 0, fmt.Errorf("parse verified_at: %w", err)
			}
			m.VerifiedAt = &t
		}
		mappings = append(mappings, m)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate mappings: %w", err)
	}
	return mappings, total, nil
}

// UpsertMapping inserts or replaces a user-IDP mapping based on the unique constraint
// (auth_provider_id, auth_username, target_idp_id).
func (d *DB) UpsertMapping(ctx context.Context, m *UserIDPMapping) error {
	var verifiedAt *string
	if m.VerifiedAt != nil {
		s := m.VerifiedAt.UTC().Format(tsLayout)
		verifiedAt = &s
	}

	res, err := d.writer.ExecContext(ctx, `
		INSERT INTO user_idp_mappings
			(auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type, linked_at, verified_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(auth_provider_id, auth_username, target_idp_id)
		DO UPDATE SET
			target_account_dn = excluded.target_account_dn,
			link_type         = excluded.link_type,
			linked_at         = excluded.linked_at,
			verified_at       = excluded.verified_at`,
		m.AuthProviderID, m.AuthUsername, m.TargetIDPID,
		m.TargetAccountDN, m.LinkType,
		m.LinkedAt.UTC().Format(tsLayout), verifiedAt,
	)
	if err != nil {
		return fmt.Errorf("upsert mapping: %w", err)
	}
	id, err := res.LastInsertId()
	if err == nil && id > 0 {
		m.ID = id
	}
	return nil
}

// UpdateMappingVerified sets the verified_at timestamp for a mapping.
func (d *DB) UpdateMappingVerified(ctx context.Context, id int64, verifiedAt time.Time) error {
	res, err := d.writer.ExecContext(ctx, `
		UPDATE user_idp_mappings SET verified_at = ? WHERE id = ?`,
		verifiedAt.UTC().Format(tsLayout), id)
	if err != nil {
		return fmt.Errorf("update mapping verified: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteMapping removes a single mapping by ID.
func (d *DB) DeleteMapping(ctx context.Context, id int64) error {
	_, err := d.writer.ExecContext(ctx, `DELETE FROM user_idp_mappings WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete mapping: %w", err)
	}
	return nil
}

// DeleteAllMappings removes all mappings for a given auth provider and username,
// returning the number of rows deleted.
func (d *DB) DeleteAllMappings(ctx context.Context, authProviderID, authUsername string) (int64, error) {
	res, err := d.writer.ExecContext(ctx, `
		DELETE FROM user_idp_mappings
		WHERE auth_provider_id = ? AND auth_username = ?`,
		authProviderID, authUsername)
	if err != nil {
		return 0, fmt.Errorf("delete all mappings: %w", err)
	}
	return res.RowsAffected()
}

// DowngradeMapping removes a mapping row (downgrade = remove the link).
func (d *DB) DowngradeMapping(ctx context.Context, id int64) error {
	res, err := d.writer.ExecContext(ctx, `DELETE FROM user_idp_mappings WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("downgrade mapping: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListAllMappings returns all user-IDP mappings in the database.
func (d *DB) ListAllMappings(ctx context.Context) ([]UserIDPMapping, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, auth_provider_id, auth_username, target_idp_id,
			target_account_dn, link_type, linked_at, verified_at
		FROM user_idp_mappings
		ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list all mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var mappings []UserIDPMapping
	for rows.Next() {
		var m UserIDPMapping
		var linkedAt string
		var verifiedAt sql.NullString
		if err := rows.Scan(&m.ID, &m.AuthProviderID, &m.AuthUsername,
			&m.TargetIDPID, &m.TargetAccountDN, &m.LinkType,
			&linkedAt, &verifiedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		if m.LinkedAt, err = time.Parse(tsLayout, linkedAt); err != nil {
			return nil, fmt.Errorf("parse linked_at: %w", err)
		}
		if verifiedAt.Valid {
			t, err := time.Parse(tsLayout, verifiedAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse verified_at: %w", err)
			}
			m.VerifiedAt = &t
		}
		mappings = append(mappings, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mappings: %w", err)
	}
	return mappings, nil
}

// scanMapping scans a single mapping row from a *sql.Row.
func scanMapping(row *sql.Row) (*UserIDPMapping, error) {
	var m UserIDPMapping
	var linkedAt string
	var verifiedAt sql.NullString

	err := row.Scan(&m.ID, &m.AuthProviderID, &m.AuthUsername,
		&m.TargetIDPID, &m.TargetAccountDN, &m.LinkType,
		&linkedAt, &verifiedAt)
	if err != nil {
		return nil, err
	}

	var parseErr error
	if m.LinkedAt, parseErr = time.Parse(tsLayout, linkedAt); parseErr != nil {
		return nil, fmt.Errorf("parse linked_at: %w", parseErr)
	}
	if verifiedAt.Valid {
		t, parseErr := time.Parse(tsLayout, verifiedAt.String)
		if parseErr != nil {
			return nil, fmt.Errorf("parse verified_at: %w", parseErr)
		}
		m.VerifiedAt = &t
	}
	return &m, nil
}
