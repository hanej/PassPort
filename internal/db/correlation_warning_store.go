package db

import (
	"context"
	"fmt"
	"time"
)

// SetCorrelationWarning inserts or replaces a correlation warning for the
// given user + target IDP pair.
func (d *DB) SetCorrelationWarning(ctx context.Context, w *CorrelationWarning) error {
	_, err := d.writer.ExecContext(ctx, `
		INSERT INTO correlation_warnings (auth_username, target_idp_id, warning_type, message)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(auth_username, target_idp_id)
		DO UPDATE SET
			warning_type = excluded.warning_type,
			message      = excluded.message,
			created_at   = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')`,
		w.AuthUsername, w.TargetIDPID, w.WarningType, w.Message,
	)
	if err != nil {
		return fmt.Errorf("set correlation warning: %w", err)
	}
	return nil
}

// DeleteCorrelationWarning removes any warning for the given user + target IDP.
func (d *DB) DeleteCorrelationWarning(ctx context.Context, authUsername, targetIDPID string) error {
	_, err := d.writer.ExecContext(ctx, `
		DELETE FROM correlation_warnings
		WHERE auth_username = ? AND target_idp_id = ?`,
		authUsername, targetIDPID,
	)
	if err != nil {
		return fmt.Errorf("delete correlation warning: %w", err)
	}
	return nil
}

// ListCorrelationWarnings returns all warnings for the given user.
func (d *DB) ListCorrelationWarnings(ctx context.Context, authUsername string) ([]CorrelationWarning, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT id, auth_username, target_idp_id, warning_type, message, created_at
		FROM correlation_warnings
		WHERE auth_username = ?
		ORDER BY id`, authUsername)
	if err != nil {
		return nil, fmt.Errorf("list correlation warnings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var warnings []CorrelationWarning
	for rows.Next() {
		var w CorrelationWarning
		var createdAt string
		if err := rows.Scan(&w.ID, &w.AuthUsername, &w.TargetIDPID,
			&w.WarningType, &w.Message, &createdAt); err != nil {
			return nil, fmt.Errorf("scan correlation warning: %w", err)
		}
		if w.CreatedAt, err = time.Parse(tsLayout, createdAt); err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		warnings = append(warnings, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate correlation warnings: %w", err)
	}
	return warnings, nil
}
