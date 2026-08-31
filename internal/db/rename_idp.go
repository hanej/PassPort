package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// idpReference is a table column holding an identity provider slug.
type idpReference struct {
	table  string
	column string
	// enforced reports whether a FOREIGN KEY constraint covers this column.
	// Unenforced references are the easy ones to miss: PRAGMA foreign_key_check
	// will not flag them if they are left behind.
	enforced bool
}

// idpReferences lists every column that stores an identity provider slug,
// excluding audit_log, which is deliberately left as a historical record.
var idpReferences = []idpReference{
	{"idp_attribute_mappings", "idp_id", true},
	{"idp_correlation_rules", "idp_id", true},
	{"idp_expiration_config", "idp_id", true},
	{"idp_expiration_filters", "idp_id", true},
	{"admin_groups", "idp_id", true},
	{"report_config", "idp_id", true},
	{"report_filters", "idp_id", true},
	{"user_idp_mappings", "target_idp_id", true},
	{"user_idp_mappings", "auth_provider_id", false},
	{"correlation_warnings", "target_idp_id", false},
	{"sessions", "provider_id", false},
}

// RenameIDPResult reports how many rows were rewritten in each table.
type RenameIDPResult struct {
	// Rows maps "table.column" to the number of rows updated.
	Rows map[string]int64
	// Total is the sum of Rows plus the identity_providers row itself.
	Total int64
	// OldLogoURL is the logo_url value before the rename, if any.
	OldLogoURL string
	// NewLogoURL is the logo_url value written by the rename, if it changed.
	NewLogoURL string
}

// ErrIDPExists indicates the target slug is already in use.
var ErrIDPExists = errors.New("identity provider already exists")

// perIDPTemplatePrefixes lists the email template types that can carry a
// ":<idpID>" suffix for a per-IDP override (see admin_email_templates.go's
// IsPasswordExpirationTemplate/IsPasswordExpiredTemplate/IsReportTemplate).
// email_templates.template_type is a composite string, not a plain slug
// column, so it isn't covered by idpReferences and must be rewritten here.
var perIDPTemplatePrefixes = []string{
	"password_expiration",
	"password_expired",
	"expiration_report",
	"expired_accounts_report",
}

// RenameIDP changes an identity provider's slug and rewrites every reference to
// it, including the columns that carry no foreign key constraint. The logo_url
// column is updated when newLogoURL is non-empty; renaming the file on disk is
// the caller's responsibility.
//
// No foreign key declares ON UPDATE CASCADE, so the whole rename runs in one
// transaction with deferred foreign key enforcement: the parent row can be
// updated ahead of its children and the graph is validated once at COMMIT.
func (d *DB) RenameIDP(ctx context.Context, oldID, newID, newLogoURL string) (*RenameIDPResult, error) {
	if oldID == newID {
		return nil, fmt.Errorf("old and new IDs are identical")
	}

	var oldLogoURL string
	err := d.writer.QueryRowContext(ctx, `SELECT logo_url FROM identity_providers WHERE id = ?`, oldID).Scan(&oldLogoURL)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("identity provider %q: %w", oldID, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("loading identity provider %q: %w", oldID, err)
	}

	var exists int
	if err := d.writer.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_providers WHERE id = ?`, newID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("checking target ID: %w", err)
	}
	if exists > 0 {
		return nil, fmt.Errorf("identity provider %q: %w", newID, ErrIDPExists)
	}

	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `PRAGMA defer_foreign_keys = ON`); err != nil {
		return nil, fmt.Errorf("deferring foreign keys: %w", err)
	}

	result := &RenameIDPResult{Rows: make(map[string]int64, len(idpReferences)), OldLogoURL: oldLogoURL}

	res, err := tx.ExecContext(ctx, `UPDATE identity_providers SET id = ? WHERE id = ?`, newID, oldID)
	if err != nil {
		return nil, fmt.Errorf("renaming identity provider: %w", err)
	}
	n, _ := res.RowsAffected()
	result.Total += n

	for _, ref := range idpReferences {
		//nolint:gosec // table and column come from the fixed idpReferences list, never user input.
		stmt := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, ref.table, ref.column, ref.column)
		res, err := tx.ExecContext(ctx, stmt, newID, oldID)
		if err != nil {
			return nil, fmt.Errorf("updating %s.%s: %w", ref.table, ref.column, err)
		}
		n, _ := res.RowsAffected()
		result.Rows[ref.table+"."+ref.column] = n
		result.Total += n
	}

	if newLogoURL != "" && newLogoURL != oldLogoURL {
		if _, err := tx.ExecContext(ctx, `UPDATE identity_providers SET logo_url = ? WHERE id = ?`, newLogoURL, newID); err != nil {
			return nil, fmt.Errorf("updating logo_url: %w", err)
		}
		result.NewLogoURL = newLogoURL
	}

	for _, prefix := range perIDPTemplatePrefixes {
		res, err := tx.ExecContext(ctx,
			`UPDATE email_templates SET template_type = ? WHERE template_type = ?`,
			prefix+":"+newID, prefix+":"+oldID)
		if err != nil {
			return nil, fmt.Errorf("renaming %s email template: %w", prefix, err)
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			result.Rows["email_templates.template_type"] += n
			result.Total += n
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing rename: %w", err)
	}

	if err := d.checkForeignKeys(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

// checkForeignKeys runs PRAGMA foreign_key_check and reports any violation.
func (d *DB) checkForeignKeys(ctx context.Context) error {
	rows, err := d.writer.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("running foreign_key_check: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var violations []string
	for rows.Next() {
		var table, parent string
		var rowid sql.NullInt64
		var fkID int
		if err := rows.Scan(&table, &rowid, &parent, &fkID); err != nil {
			return fmt.Errorf("scanning foreign_key_check: %w", err)
		}
		violations = append(violations, fmt.Sprintf("%s -> %s (rowid %d)", table, parent, rowid.Int64))
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading foreign_key_check: %w", err)
	}
	if len(violations) > 0 {
		return fmt.Errorf("foreign key violations after rename: %v", violations)
	}
	return nil
}
