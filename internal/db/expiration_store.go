package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// GetExpirationConfig retrieves the expiration notification configuration for an IDP.
// Returns nil with no error if no configuration exists.
func (d *DB) GetExpirationConfig(ctx context.Context, idpID string) (*ExpirationConfig, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT idp_id, enabled, cron_schedule, days_before_expiration, updated_at
		FROM idp_expiration_config WHERE idp_id = ?`, idpID)

	var cfg ExpirationConfig
	var enabled int
	var updatedAt string
	err := row.Scan(&cfg.IDPID, &enabled, &cfg.CronSchedule, &cfg.DaysBeforeExpiration, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get expiration config: %w", err)
	}
	cfg.Enabled = enabled == 1
	if cfg.UpdatedAt, err = time.Parse(tsLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("parse expiration config updated_at: %w", err)
	}
	return &cfg, nil
}

// SaveExpirationConfig inserts or replaces the expiration configuration for an IDP.
func (d *DB) SaveExpirationConfig(ctx context.Context, cfg *ExpirationConfig) error {
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO idp_expiration_config (idp_id, enabled, cron_schedule, days_before_expiration, updated_at)
		VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		ON CONFLICT(idp_id) DO UPDATE SET
			enabled                = excluded.enabled,
			cron_schedule          = excluded.cron_schedule,
			days_before_expiration = excluded.days_before_expiration,
			updated_at             = excluded.updated_at`,
		cfg.IDPID, enabled, cfg.CronSchedule, cfg.DaysBeforeExpiration)
	if err != nil {
		return fmt.Errorf("save expiration config: %w", err)
	}
	return nil
}

// ListExpirationFilters returns all expiration filters for an IDP, ordered by ID.
func (d *DB) ListExpirationFilters(ctx context.Context, idpID string) ([]ExpirationFilter, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, idp_id, attribute, pattern, description
		FROM idp_expiration_filters
		WHERE idp_id = ?
		ORDER BY id`, idpID)
	if err != nil {
		return nil, fmt.Errorf("list expiration filters: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var filters []ExpirationFilter
	for rows.Next() {
		var f ExpirationFilter
		if err := rows.Scan(&f.ID, &f.IDPID, &f.Attribute, &f.Pattern, &f.Description); err != nil {
			return nil, fmt.Errorf("scan expiration filter: %w", err)
		}
		filters = append(filters, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expiration filters: %w", err)
	}
	return filters, nil
}

// SaveExpirationFilters replaces all expiration filters for an IDP within a transaction.
func (d *DB) SaveExpirationFilters(ctx context.Context, idpID string, filters []ExpirationFilter) error {
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM idp_expiration_filters WHERE idp_id = ?`, idpID); err != nil {
		return fmt.Errorf("deleting existing expiration filters: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO idp_expiration_filters (idp_id, attribute, pattern, description)
		VALUES (?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, f := range filters {
		if _, err := stmt.ExecContext(ctx, idpID, f.Attribute, f.Pattern, f.Description); err != nil {
			return fmt.Errorf("inserting expiration filter %q: %w", f.Attribute, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// ListEnabledExpirationConfigs returns all expiration configurations that are enabled.
func (d *DB) ListEnabledExpirationConfigs(ctx context.Context) ([]ExpirationConfig, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT idp_id, enabled, cron_schedule, days_before_expiration, updated_at
		FROM idp_expiration_config WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("list enabled expiration configs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var configs []ExpirationConfig
	for rows.Next() {
		var cfg ExpirationConfig
		var enabled int
		var updatedAt string
		if err := rows.Scan(&cfg.IDPID, &enabled, &cfg.CronSchedule, &cfg.DaysBeforeExpiration, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan expiration config: %w", err)
		}
		cfg.Enabled = enabled == 1
		if cfg.UpdatedAt, err = time.Parse(tsLayout, updatedAt); err != nil {
			return nil, fmt.Errorf("parse expiration config updated_at: %w", err)
		}
		configs = append(configs, cfg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate expiration configs: %w", err)
	}
	return configs, nil
}
