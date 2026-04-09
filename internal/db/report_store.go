package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// GetReportConfig retrieves the report configuration for a specific IDP and report type.
// Returns nil with no error if no configuration exists.
func (d *DB) GetReportConfig(ctx context.Context, idpID, reportType string) (*ReportConfig, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT idp_id, report_type, enabled, cron_schedule, days_before_expiration, recipients, exclude_disabled, updated_at
		FROM report_config WHERE idp_id = ? AND report_type = ?`, idpID, reportType)

	var cfg ReportConfig
	var enabled, excludeDisabled int
	var updatedAt string
	err := row.Scan(&cfg.IDPID, &cfg.ReportType, &enabled, &cfg.CronSchedule, &cfg.DaysBeforeExpiration, &cfg.Recipients, &excludeDisabled, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get report config: %w", err)
	}
	cfg.Enabled = enabled == 1
	cfg.ExcludeDisabled = excludeDisabled == 1
	if cfg.UpdatedAt, err = time.Parse(tsLayout, updatedAt); err != nil {
		return nil, fmt.Errorf("parse report config updated_at: %w", err)
	}
	return &cfg, nil
}

// SaveReportConfig inserts or replaces the report configuration for an IDP and report type.
func (d *DB) SaveReportConfig(ctx context.Context, cfg *ReportConfig) error {
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	excludeDisabled := 0
	if cfg.ExcludeDisabled {
		excludeDisabled = 1
	}
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO report_config (idp_id, report_type, enabled, cron_schedule, days_before_expiration, recipients, exclude_disabled, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		ON CONFLICT(idp_id, report_type) DO UPDATE SET
			enabled                = excluded.enabled,
			cron_schedule          = excluded.cron_schedule,
			days_before_expiration = excluded.days_before_expiration,
			recipients             = excluded.recipients,
			exclude_disabled       = excluded.exclude_disabled,
			updated_at             = excluded.updated_at`,
		cfg.IDPID, cfg.ReportType, enabled, cfg.CronSchedule, cfg.DaysBeforeExpiration, cfg.Recipients, excludeDisabled)
	if err != nil {
		return fmt.Errorf("save report config: %w", err)
	}
	return nil
}

// ListReportFilters returns all report filters for an IDP and report type, ordered by ID.
func (d *DB) ListReportFilters(ctx context.Context, idpID, reportType string) ([]ReportFilter, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, idp_id, report_type, attribute, pattern, description
		FROM report_filters
		WHERE idp_id = ? AND report_type = ?
		ORDER BY id`, idpID, reportType)
	if err != nil {
		return nil, fmt.Errorf("list report filters: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var filters []ReportFilter
	for rows.Next() {
		var f ReportFilter
		if err := rows.Scan(&f.ID, &f.IDPID, &f.ReportType, &f.Attribute, &f.Pattern, &f.Description); err != nil {
			return nil, fmt.Errorf("scan report filter: %w", err)
		}
		filters = append(filters, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate report filters: %w", err)
	}
	return filters, nil
}

// SaveReportFilters replaces all report filters for an IDP and report type within a transaction.
func (d *DB) SaveReportFilters(ctx context.Context, idpID, reportType string, filters []ReportFilter) error {
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM report_filters WHERE idp_id = ? AND report_type = ?`, idpID, reportType); err != nil {
		return fmt.Errorf("deleting existing report filters: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO report_filters (idp_id, report_type, attribute, pattern, description)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing insert statement: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, f := range filters {
		if _, err := stmt.ExecContext(ctx, idpID, reportType, f.Attribute, f.Pattern, f.Description); err != nil {
			return fmt.Errorf("inserting report filter %q: %w", f.Attribute, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing transaction: %w", err)
	}
	return nil
}

// ListEnabledReportConfigs returns all report configurations that are enabled.
func (d *DB) ListEnabledReportConfigs(ctx context.Context) ([]ReportConfig, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT idp_id, report_type, enabled, cron_schedule, days_before_expiration, recipients, exclude_disabled, updated_at
		FROM report_config WHERE enabled = 1`)
	if err != nil {
		return nil, fmt.Errorf("list enabled report configs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanReportConfigs(rows)
}

// ListReportConfigsForIDP returns all report configurations for a specific IDP.
func (d *DB) ListReportConfigsForIDP(ctx context.Context, idpID string) ([]ReportConfig, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT idp_id, report_type, enabled, cron_schedule, days_before_expiration, recipients, exclude_disabled, updated_at
		FROM report_config WHERE idp_id = ? ORDER BY report_type`, idpID)
	if err != nil {
		return nil, fmt.Errorf("list report configs for IDP: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return scanReportConfigs(rows)
}

func scanReportConfigs(rows *sql.Rows) ([]ReportConfig, error) {
	var configs []ReportConfig
	for rows.Next() {
		var cfg ReportConfig
		var enabled, excludeDisabled int
		var updatedAt string
		if err := rows.Scan(&cfg.IDPID, &cfg.ReportType, &enabled, &cfg.CronSchedule, &cfg.DaysBeforeExpiration, &cfg.Recipients, &excludeDisabled, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan report config: %w", err)
		}
		cfg.Enabled = enabled == 1
		cfg.ExcludeDisabled = excludeDisabled == 1
		var err error
		if cfg.UpdatedAt, err = time.Parse(tsLayout, updatedAt); err != nil {
			return nil, fmt.Errorf("parse report config updated_at: %w", err)
		}
		configs = append(configs, cfg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate report configs: %w", err)
	}
	return configs, nil
}
