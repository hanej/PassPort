package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ---------- Admin Groups ----------

// ListAdminGroups returns all admin group entries.
func (d *DB) ListAdminGroups(ctx context.Context) ([]AdminGroup, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, idp_id, group_dn, description, created_at
		FROM admin_groups ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list admin groups: %w", err)
	}
	defer rows.Close()

	return scanAdminGroups(rows)
}

// CreateAdminGroup inserts a new admin group.
func (d *DB) CreateAdminGroup(ctx context.Context, g *AdminGroup) error {
	res, err := d.writer.ExecContext(ctx, `
		INSERT INTO admin_groups (idp_id, group_dn, description) VALUES (?, ?, ?)`,
		g.IDPID, g.GroupDN, g.Description)
	if err != nil {
		return fmt.Errorf("insert admin group: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("get admin group id: %w", err)
	}
	g.ID = id
	return nil
}

// DeleteAdminGroup removes an admin group by ID.
func (d *DB) DeleteAdminGroup(ctx context.Context, id int64) error {
	res, err := d.writer.ExecContext(ctx, `DELETE FROM admin_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete admin group: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetAdminGroupsByIDP returns all admin groups for a specific identity provider.
func (d *DB) GetAdminGroupsByIDP(ctx context.Context, idpID string) ([]AdminGroup, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, idp_id, group_dn, description, created_at
		FROM admin_groups WHERE idp_id = ? ORDER BY id`, idpID)
	if err != nil {
		return nil, fmt.Errorf("get admin groups by idp: %w", err)
	}
	defer rows.Close()

	return scanAdminGroups(rows)
}

// scanAdminGroups reads all rows into a slice of AdminGroup.
func scanAdminGroups(rows *sql.Rows) ([]AdminGroup, error) {
	var groups []AdminGroup
	for rows.Next() {
		var g AdminGroup
		var createdAt string
		if err := rows.Scan(&g.ID, &g.IDPID, &g.GroupDN, &g.Description, &createdAt); err != nil {
			return nil, fmt.Errorf("scan admin group: %w", err)
		}
		var err error
		if g.CreatedAt, err = time.Parse(tsLayout, createdAt); err != nil {
			return nil, fmt.Errorf("parse admin group created_at: %w", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin groups: %w", err)
	}
	return groups, nil
}

// ---------- SMTP Config ----------

// GetSMTPConfig retrieves the singleton SMTP configuration (id=1).
// Returns nil with no error if no configuration has been saved yet.
func (d *DB) GetSMTPConfig(ctx context.Context) (*SMTPConfig, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT config_json, secret_blob, updated_at FROM smtp_config WHERE id = 1`)

	var cfg SMTPConfig
	var updatedAt string
	err := row.Scan(&cfg.ConfigJSON, &cfg.SecretBlob, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get smtp config: %w", err)
	}
	if cfg.UpdatedAt, err = time.Parse(tsLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("parse smtp updated_at: %w", err)
	}
	return &cfg, nil
}

// SaveSMTPConfig inserts or replaces the singleton SMTP configuration row (id=1).
func (d *DB) SaveSMTPConfig(ctx context.Context, cfg *SMTPConfig) error {
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO smtp_config (id, config_json, secret_blob, updated_at)
		VALUES (1, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		ON CONFLICT(id) DO UPDATE SET
			config_json = excluded.config_json,
			secret_blob = excluded.secret_blob,
			updated_at  = excluded.updated_at`,
		cfg.ConfigJSON, cfg.SecretBlob)
	if err != nil {
		return fmt.Errorf("save smtp config: %w", err)
	}
	return nil
}

// ---------- Branding Config ----------

// GetBrandingConfig retrieves the singleton branding configuration (id=1).
// Returns a default config if no row exists yet.
func (d *DB) GetBrandingConfig(ctx context.Context) (*BrandingConfig, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT config_json FROM branding_config WHERE id = 1`)

	var configJSON string
	err := row.Scan(&configJSON)
	if err == sql.ErrNoRows {
		return &BrandingConfig{
			AppTitle:        "PassPort",
			AppAbbreviation: "PassPort",
			AppSubtitle:     "Self-Service Password Management",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get branding config: %w", err)
	}

	var cfg BrandingConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal branding config: %w", err)
	}
	return &cfg, nil
}

// SaveBrandingConfig inserts or replaces the singleton branding configuration row (id=1).
func (d *DB) SaveBrandingConfig(ctx context.Context, cfg *BrandingConfig) error {
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal branding config: %w", err)
	}
	_, err = d.writer.ExecContext(ctx, `
		INSERT INTO branding_config (id, config_json, updated_at)
		VALUES (1, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		ON CONFLICT(id) DO UPDATE SET
			config_json = excluded.config_json,
			updated_at  = excluded.updated_at`,
		string(configJSON))
	if err != nil {
		return fmt.Errorf("save branding config: %w", err)
	}
	return nil
}
