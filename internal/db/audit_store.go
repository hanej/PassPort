package db

import (
	"context"
	"fmt"
	"time"
)

const auditTSLayout = "2006-01-02T15:04:05.000Z"

// AppendAudit inserts a new audit log entry.
func (d *DB) AppendAudit(ctx context.Context, entry *AuditEntry) error {
	res, err := d.writer.ExecContext(ctx, `
		INSERT INTO audit_log (username, source_ip, action, provider_id, provider_name, result, details)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		entry.Username, entry.SourceIP, entry.Action,
		entry.ProviderID, entry.ProviderName, entry.Result, entry.Details,
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("get audit entry id: %w", err)
	}
	entry.ID = id
	return nil
}

// ListAudit queries the audit log with optional filters and pagination.
// It returns matching entries and the total count of rows matching the filter.
func (d *DB) ListAudit(ctx context.Context, filter AuditFilter) ([]AuditEntry, int, error) {
	where, args := buildAuditWhere(filter)

	// Apply defaults and limits.
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	// Count total matching rows.
	var total int
	countQuery := "SELECT COUNT(*) FROM audit_log a" + where
	if err := d.reader.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit entries: %w", err)
	}

	// Fetch the page. LEFT JOIN identity_providers so that provider_name is
	// populated from friendly_name when the stored column is empty (e.g. for
	// entries written before provider_name was set at log time).
	dataQuery := `SELECT a.id, a.timestamp, a.username, a.source_ip, a.action, a.provider_id,
		COALESCE(NULLIF(a.provider_name,''), idp.friendly_name, '') AS provider_name,
		a.result, a.details
		FROM audit_log a
		LEFT JOIN identity_providers idp ON a.provider_id = idp.id` + where + ` ORDER BY a.id DESC LIMIT ? OFFSET ?`
	dataArgs := append(args, limit, offset)

	rows, err := d.reader.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Username, &e.SourceIP, &e.Action,
			&e.ProviderID, &e.ProviderName, &e.Result, &e.Details); err != nil {
			return nil, 0, fmt.Errorf("scan audit entry: %w", err)
		}
		if e.Timestamp, err = time.Parse(auditTSLayout, ts); err != nil {
			return nil, 0, fmt.Errorf("parse audit timestamp: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit entries: %w", err)
	}

	return entries, total, nil
}

// PurgeAuditBefore deletes audit log entries with timestamps before the given time.
// Returns the number of rows deleted.
func (d *DB) PurgeAuditBefore(ctx context.Context, before time.Time) (int64, error) {
	res, err := d.writer.ExecContext(ctx,
		"DELETE FROM audit_log WHERE timestamp < ?",
		before.UTC().Format(auditTSLayout),
	)
	if err != nil {
		return 0, fmt.Errorf("purge audit entries: %w", err)
	}
	return res.RowsAffected()
}

// buildAuditWhere constructs a WHERE clause and argument list from the non-empty
// fields in the given AuditFilter. Column references use the "a" table alias
// expected by ListAudit's LEFT JOIN query.
func buildAuditWhere(f AuditFilter) (string, []any) {
	var conds []string
	var args []any

	if f.Username != "" {
		conds = append(conds, "a.username = ?")
		args = append(args, f.Username)
	}
	if f.Action != "" {
		conds = append(conds, "a.action = ?")
		args = append(args, f.Action)
	}
	if f.Result != "" {
		conds = append(conds, "a.result = ?")
		args = append(args, f.Result)
	}
	if f.ProviderID != "" {
		conds = append(conds, "a.provider_id = ?")
		args = append(args, f.ProviderID)
	}
	if f.StartDate != "" {
		conds = append(conds, "a.timestamp >= ?")
		args = append(args, f.StartDate)
	}
	if f.EndDate != "" {
		conds = append(conds, "a.timestamp <= ?")
		args = append(args, f.EndDate)
	}

	if len(conds) == 0 {
		return "", nil
	}
	where := " WHERE " + conds[0]
	for _, c := range conds[1:] {
		where += " AND " + c
	}
	return where, args
}
