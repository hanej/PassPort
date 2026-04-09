package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ListIDPs returns all identity providers.
func (d *DB) ListIDPs(ctx context.Context) ([]IdentityProviderRecord, error) {
	return d.queryIDPs(ctx, `
		SELECT id, friendly_name, description, provider_type, enabled,
		       logo_url, mfa_provider_id, config_json, secret_blob, created_at, updated_at
		FROM identity_providers
		ORDER BY friendly_name`)
}

// ListEnabledIDPs returns all enabled identity providers.
func (d *DB) ListEnabledIDPs(ctx context.Context) ([]IdentityProviderRecord, error) {
	return d.queryIDPs(ctx, `
		SELECT id, friendly_name, description, provider_type, enabled,
		       logo_url, mfa_provider_id, config_json, secret_blob, created_at, updated_at
		FROM identity_providers
		WHERE enabled = 1
		ORDER BY friendly_name`)
}

// queryIDPs is a helper that executes a query and scans rows into IdentityProviderRecord slices.
func (d *DB) queryIDPs(ctx context.Context, query string, args ...any) ([]IdentityProviderRecord, error) {
	rows, err := d.reader.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying identity providers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []IdentityProviderRecord
	for rows.Next() {
		idp, err := scanIDP(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *idp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating identity providers: %w", err)
	}
	return result, nil
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// scanIDP scans a single IdentityProviderRecord from a row.
func scanIDP(s scanner) (*IdentityProviderRecord, error) {
	var idp IdentityProviderRecord
	var enabled int64
	var createdAt, updatedAt string
	var mfaProviderID sql.NullString

	err := s.Scan(
		&idp.ID, &idp.FriendlyName, &idp.Description, &idp.ProviderType,
		&enabled, &idp.LogoURL, &mfaProviderID, &idp.ConfigJSON, &idp.SecretBlob, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scanning identity provider: %w", err)
	}

	idp.Enabled = enabled != 0

	if mfaProviderID.Valid {
		idp.MFAProviderID = &mfaProviderID.String
	}

	idp.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	idp.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing updated_at: %w", err)
	}

	return &idp, nil
}

// GetIDP retrieves an identity provider by ID.
func (d *DB) GetIDP(ctx context.Context, id string) (*IdentityProviderRecord, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT id, friendly_name, description, provider_type, enabled,
		       logo_url, mfa_provider_id, config_json, secret_blob, created_at, updated_at
		FROM identity_providers
		WHERE id = ?`, id)

	idp, err := scanIDP(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return idp, nil
}

// CreateIDP inserts a new identity provider.
func (d *DB) CreateIDP(ctx context.Context, idp *IdentityProviderRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var enabled int
	if idp.Enabled {
		enabled = 1
	}

	var mfaProviderID sql.NullString
	if idp.MFAProviderID != nil {
		mfaProviderID = sql.NullString{String: *idp.MFAProviderID, Valid: true}
	}

	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO identity_providers
			(id, friendly_name, description, provider_type, enabled, logo_url, mfa_provider_id, config_json, secret_blob, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		idp.ID, idp.FriendlyName, idp.Description, idp.ProviderType,
		enabled, idp.LogoURL, mfaProviderID, idp.ConfigJSON, idp.SecretBlob, now, now)
	if err != nil {
		return fmt.Errorf("inserting identity provider: %w", err)
	}
	return nil
}

// UpdateIDP updates all fields of an existing identity provider.
func (d *DB) UpdateIDP(ctx context.Context, idp *IdentityProviderRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var enabled int
	if idp.Enabled {
		enabled = 1
	}

	var mfaProviderID sql.NullString
	if idp.MFAProviderID != nil {
		mfaProviderID = sql.NullString{String: *idp.MFAProviderID, Valid: true}
	}

	result, err := d.writer.ExecContext(ctx, `
		UPDATE identity_providers
		SET friendly_name = ?, description = ?, provider_type = ?, enabled = ?,
		    logo_url = ?, mfa_provider_id = ?, config_json = ?, secret_blob = ?, updated_at = ?
		WHERE id = ?`,
		idp.FriendlyName, idp.Description, idp.ProviderType, enabled,
		idp.LogoURL, mfaProviderID, idp.ConfigJSON, idp.SecretBlob, now, idp.ID)
	if err != nil {
		return fmt.Errorf("updating identity provider: %w", err)
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

// DeleteIDP deletes an identity provider by ID.
func (d *DB) DeleteIDP(ctx context.Context, id string) error {
	result, err := d.writer.ExecContext(ctx, `DELETE FROM identity_providers WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting identity provider: %w", err)
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

// ToggleIDP updates the enabled flag of an identity provider.
func (d *DB) ToggleIDP(ctx context.Context, id string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)

	var enabledInt int
	if enabled {
		enabledInt = 1
	}

	result, err := d.writer.ExecContext(ctx, `
		UPDATE identity_providers
		SET enabled = ?, updated_at = ?
		WHERE id = ?`, enabledInt, now, id)
	if err != nil {
		return fmt.Errorf("toggling identity provider: %w", err)
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

// ListAttributeMappings returns all attribute mappings for an identity provider.
func (d *DB) ListAttributeMappings(ctx context.Context, idpID string) ([]AttributeMapping, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, idp_id, canonical_name, directory_attr
		FROM idp_attribute_mappings
		WHERE idp_id = ?
		ORDER BY canonical_name`, idpID)
	if err != nil {
		return nil, fmt.Errorf("querying attribute mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []AttributeMapping
	for rows.Next() {
		var m AttributeMapping
		if err := rows.Scan(&m.ID, &m.IDPID, &m.CanonicalName, &m.DirectoryAttr); err != nil {
			return nil, fmt.Errorf("scanning attribute mapping: %w", err)
		}
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating attribute mappings: %w", err)
	}
	return result, nil
}

// SetAttributeMappings replaces all attribute mappings for an IDP within a transaction.
func (d *DB) SetAttributeMappings(ctx context.Context, idpID string, mappings []AttributeMapping) error {
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM idp_attribute_mappings WHERE idp_id = ?`, idpID); err != nil {
		return fmt.Errorf("deleting existing attribute mappings: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO idp_attribute_mappings (idp_id, canonical_name, directory_attr)
		VALUES (?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, m := range mappings {
		if _, err := stmt.ExecContext(ctx, idpID, m.CanonicalName, m.DirectoryAttr); err != nil {
			return fmt.Errorf("inserting attribute mapping %q: %w", m.CanonicalName, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// GetCorrelationRule retrieves the correlation rule for an identity provider.
func (d *DB) GetCorrelationRule(ctx context.Context, idpID string) (*CorrelationRule, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT idp_id, source_canonical_attr, target_directory_attr, match_mode
		FROM idp_correlation_rules
		WHERE idp_id = ?`, idpID)

	var rule CorrelationRule
	err := row.Scan(&rule.IDPID, &rule.SourceCanonicalAttr, &rule.TargetDirectoryAttr, &rule.MatchMode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("querying correlation rule: %w", err)
	}
	return &rule, nil
}

// SetCorrelationRule upserts a correlation rule for an identity provider.
func (d *DB) SetCorrelationRule(ctx context.Context, rule *CorrelationRule) error {
	_, err := d.writer.ExecContext(ctx, `
		INSERT OR REPLACE INTO idp_correlation_rules
			(idp_id, source_canonical_attr, target_directory_attr, match_mode)
		VALUES (?, ?, ?, ?)`,
		rule.IDPID, rule.SourceCanonicalAttr, rule.TargetDirectoryAttr, rule.MatchMode)
	if err != nil {
		return fmt.Errorf("upserting correlation rule: %w", err)
	}
	return nil
}

// DeleteCorrelationRule deletes the correlation rule for an identity provider.
func (d *DB) DeleteCorrelationRule(ctx context.Context, idpID string) error {
	result, err := d.writer.ExecContext(ctx, `DELETE FROM idp_correlation_rules WHERE idp_id = ?`, idpID)
	if err != nil {
		return fmt.Errorf("deleting correlation rule: %w", err)
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
