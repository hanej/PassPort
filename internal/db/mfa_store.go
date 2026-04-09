package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ListMFAProviders returns all MFA providers.
func (d *DB) ListMFAProviders(ctx context.Context) ([]MFAProviderRecord, error) {
	return d.queryMFAProviders(ctx, `
		SELECT id, name, provider_type, enabled,
		       config_json, secret_blob, created_at, updated_at
		FROM mfa_providers
		ORDER BY name`)
}

// GetMFAProvider retrieves an MFA provider by ID.
func (d *DB) GetMFAProvider(ctx context.Context, id string) (*MFAProviderRecord, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, name, provider_type, enabled,
		       config_json, secret_blob, created_at, updated_at
		FROM mfa_providers
		WHERE id = ?`, id)

	p, err := scanMFAProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// GetEnabledMFAProvider retrieves the first enabled MFA provider.
func (d *DB) GetEnabledMFAProvider(ctx context.Context) (*MFAProviderRecord, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, name, provider_type, enabled,
		       config_json, secret_blob, created_at, updated_at
		FROM mfa_providers
		WHERE enabled = 1
		LIMIT 1`)

	p, err := scanMFAProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// CreateMFAProvider inserts a new MFA provider.
func (d *DB) CreateMFAProvider(ctx context.Context, p *MFAProviderRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var enabled int
	if p.Enabled {
		enabled = 1
	}

	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO mfa_providers
			(id, name, provider_type, enabled, config_json, secret_blob, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, p.ProviderType,
		enabled, p.ConfigJSON, p.SecretBlob, now, now)
	if err != nil {
		return fmt.Errorf("inserting mfa provider: %w", err)
	}
	return nil
}

// UpdateMFAProvider updates all fields of an existing MFA provider.
func (d *DB) UpdateMFAProvider(ctx context.Context, p *MFAProviderRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var enabled int
	if p.Enabled {
		enabled = 1
	}

	result, err := d.writer.ExecContext(ctx, `
		UPDATE mfa_providers
		SET name = ?, provider_type = ?, enabled = ?,
		    config_json = ?, secret_blob = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.ProviderType, enabled,
		p.ConfigJSON, p.SecretBlob, now, p.ID)
	if err != nil {
		return fmt.Errorf("updating mfa provider: %w", err)
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

// DeleteMFAProvider deletes an MFA provider by ID.
func (d *DB) DeleteMFAProvider(ctx context.Context, id string) error {
	result, err := d.writer.ExecContext(ctx, `DELETE FROM mfa_providers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting mfa provider: %w", err)
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

// ToggleMFAProvider updates the enabled flag of an MFA provider.
func (d *DB) ToggleMFAProvider(ctx context.Context, id string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var enabledInt int
	if enabled {
		enabledInt = 1
	}

	result, err := d.writer.ExecContext(ctx, `
		UPDATE mfa_providers
		SET enabled = ?, updated_at = ?
		WHERE id = ?`, enabledInt, now, id)
	if err != nil {
		return fmt.Errorf("toggling mfa provider: %w", err)
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

// GetMFAProviderForIDP resolves the effective MFA provider for an IDP.
// Resolution order:
//  1. IDP's directly assigned mfa_provider_id (if enabled)
//  2. Default from mfa_settings (if enabled)
//  3. nil, nil (no MFA)
func (d *DB) GetMFAProviderForIDP(ctx context.Context, idpID string) (*MFAProviderRecord, error) {
	// Step 1: load IDP's directly assigned provider (enabled only).
	row := d.reader.QueryRowContext(ctx, `
		SELECT m.id, m.name, m.provider_type, m.enabled,
		       m.config_json, m.secret_blob, m.created_at, m.updated_at
		FROM identity_providers ip
		JOIN mfa_providers m ON m.id = ip.mfa_provider_id
		WHERE ip.id = ? AND m.enabled = 1`, idpID)

	p, err := scanMFAProvider(row)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("querying direct MFA provider for IDP %s: %w", idpID, err)
	}

	// Step 2: fall back to the global default provider (enabled only).
	row = d.reader.QueryRowContext(ctx, `
		SELECT m.id, m.name, m.provider_type, m.enabled,
		       m.config_json, m.secret_blob, m.created_at, m.updated_at
		FROM mfa_settings s
		JOIN mfa_providers m ON m.id = s.default_mfa_provider_id
		WHERE s.id = 1 AND m.enabled = 1`)

	p, err = scanMFAProvider(row)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("querying default MFA provider: %w", err)
	}

	// No MFA configured for this IDP.
	return nil, nil
}

// GetDefaultMFAProviderID returns the global default MFA provider ID from mfa_settings.
// Returns nil (with no error) when no default has been set.
func (d *DB) GetDefaultMFAProviderID(ctx context.Context) (*string, error) {
	var v sql.NullString
	err := d.reader.QueryRowContext(ctx, `
		SELECT default_mfa_provider_id FROM mfa_settings WHERE id = 1`).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("querying default MFA provider ID: %w", err)
	}
	if !v.Valid {
		return nil, nil
	}
	return &v.String, nil
}

// SetDefaultMFAProviderID sets or clears the global default MFA provider ID.
func (d *DB) SetDefaultMFAProviderID(ctx context.Context, id *string) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var v sql.NullString
	if id != nil {
		v = sql.NullString{String: *id, Valid: true}
	}

	_, err := d.writer.ExecContext(ctx, `
		UPDATE mfa_settings SET default_mfa_provider_id = ?, updated_at = ? WHERE id = 1`,
		v, now)
	if err != nil {
		return fmt.Errorf("setting default MFA provider: %w", err)
	}
	return nil
}

// GetMFALoginRequired returns whether MFA is required on login for IDP users.
func (d *DB) GetMFALoginRequired(ctx context.Context) (bool, error) {
	var v int64
	err := d.reader.QueryRowContext(ctx, `
		SELECT require_mfa_on_login FROM mfa_settings WHERE id = 1`).Scan(&v)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("querying MFA login required: %w", err)
	}
	return v != 0, nil
}

// SetMFALoginRequired enables or disables the MFA-on-login requirement.
func (d *DB) SetMFALoginRequired(ctx context.Context, required bool) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var v int
	if required {
		v = 1
	}

	_, err := d.writer.ExecContext(ctx, `
		UPDATE mfa_settings SET require_mfa_on_login = ?, updated_at = ? WHERE id = 1`,
		v, now)
	if err != nil {
		return fmt.Errorf("setting MFA login required: %w", err)
	}
	return nil
}

// queryMFAProviders is a helper that executes a query and scans rows into MFAProviderRecord slices.
func (d *DB) queryMFAProviders(ctx context.Context, query string, args ...any) ([]MFAProviderRecord, error) {
	rows, err := d.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying mfa providers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []MFAProviderRecord
	for rows.Next() {
		p, err := scanMFAProvider(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating mfa providers: %w", err)
	}
	return result, nil
}

// scanMFAProvider scans a single MFAProviderRecord from a row.
func scanMFAProvider(s scanner) (*MFAProviderRecord, error) {
	var p MFAProviderRecord
	var enabled int64
	var createdAt, updatedAt string

	err := s.Scan(
		&p.ID, &p.Name, &p.ProviderType,
		&enabled, &p.ConfigJSON, &p.SecretBlob, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning mfa provider: %w", err)
	}

	p.Enabled = enabled != 0

	p.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	p.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing updated_at: %w", err)
	}

	return &p, nil
}
