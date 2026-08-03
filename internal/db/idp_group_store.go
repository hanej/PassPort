package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const idpGroupColumns = `id, name, description, icon, collapsible, start_collapsed, display_order, created_at, updated_at`

// ListIDPGroups returns all provider groups in display order.
func (d *DB) ListIDPGroups(ctx context.Context) ([]IDPGroup, error) {
	rows, err := d.reader.QueryContext(ctx, `
		SELECT `+idpGroupColumns+`
		FROM idp_groups
		ORDER BY display_order, name`)
	if err != nil {
		return nil, fmt.Errorf("querying provider groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var result []IDPGroup
	for rows.Next() {
		g, err := scanIDPGroup(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating provider groups: %w", err)
	}
	return result, nil
}

// GetIDPGroup retrieves a provider group by ID.
func (d *DB) GetIDPGroup(ctx context.Context, id int64) (*IDPGroup, error) {
	row := d.reader.QueryRowContext(ctx, `
		SELECT `+idpGroupColumns+`
		FROM idp_groups
		WHERE id = ?`, id)

	g, err := scanIDPGroup(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return g, nil
}

func scanIDPGroup(s scanner) (*IDPGroup, error) {
	var g IDPGroup
	var collapsible, startCollapsed int64
	var createdAt, updatedAt string

	err := s.Scan(&g.ID, &g.Name, &g.Description, &g.Icon, &collapsible, &startCollapsed,
		&g.DisplayOrder, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scanning provider group: %w", err)
	}

	g.Collapsible = collapsible != 0
	g.StartCollapsed = g.Collapsible && startCollapsed != 0

	g.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("parsing created_at: %w", err)
	}
	g.UpdatedAt, err = time.Parse(time.RFC3339, updatedAt)
	if err != nil {
		return nil, fmt.Errorf("parsing updated_at: %w", err)
	}
	return &g, nil
}

// CreateIDPGroup inserts a new group and sets g.ID. New groups sort last.
func (d *DB) CreateIDPGroup(ctx context.Context, g *IDPGroup) error {
	now := time.Now().UTC().Format(time.RFC3339)

	res, err := d.writer.ExecContext(ctx, `
		INSERT INTO idp_groups (name, description, icon, collapsible, start_collapsed, display_order, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(display_order) + 1 FROM idp_groups), 0), ?, ?)`,
		g.Name, g.Description, g.Icon, boolToInt(g.Collapsible), boolToInt(g.Collapsible && g.StartCollapsed), now, now)
	if err != nil {
		return fmt.Errorf("inserting provider group: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("reading new provider group id: %w", err)
	}
	g.ID = id
	return nil
}

// UpdateIDPGroup updates a group's editable fields. Display order is owned by
// SetIDPArrangement and is deliberately left alone.
func (d *DB) UpdateIDPGroup(ctx context.Context, g *IDPGroup) error {
	now := time.Now().UTC().Format(time.RFC3339)

	res, err := d.writer.ExecContext(ctx, `
		UPDATE idp_groups
		SET name = ?, description = ?, icon = ?, collapsible = ?, start_collapsed = ?, updated_at = ?
		WHERE id = ?`,
		g.Name, g.Description, g.Icon, boolToInt(g.Collapsible), boolToInt(g.Collapsible && g.StartCollapsed), now, g.ID)
	if err != nil {
		return fmt.Errorf("updating provider group: %w", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteIDPGroup removes a group. Its providers are not deleted; they revert to
// ungrouped.
func (d *DB) DeleteIDPGroup(ctx context.Context, id int64) error {
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning delete group transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Done explicitly rather than relying on ON DELETE SET NULL, since foreign
	// key enforcement is not guaranteed to be on for every connection.
	if _, err := tx.ExecContext(ctx,
		`UPDATE identity_providers SET group_id = NULL WHERE group_id = ?`, id); err != nil {
		return fmt.Errorf("ungrouping providers: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE local_admin_placement SET group_id = NULL WHERE group_id = ?`, id); err != nil {
		return fmt.Errorf("ungrouping local admin: %w", err)
	}

	res, err := tx.ExecContext(ctx, `DELETE FROM idp_groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("deleting provider group: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("getting rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing delete group transaction: %w", err)
	}
	return nil
}

// SetIDPArrangement rewrites the whole layout in one transaction: the order of
// the groups, and the group and position of every provider listed. Providers
// absent from placements are left untouched.
func (d *DB) SetIDPArrangement(ctx context.Context, groupOrder []int64, placements []IDPPlacement) error {
	tx, err := d.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning arrangement transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for i, groupID := range groupOrder {
		if _, err := tx.ExecContext(ctx,
			`UPDATE idp_groups SET display_order = ? WHERE id = ?`, i, groupID); err != nil {
			return fmt.Errorf("ordering group %d: %w", groupID, err)
		}
	}

	for _, p := range placements {
		var groupID sql.NullInt64
		if p.GroupID != nil {
			groupID = sql.NullInt64{Int64: *p.GroupID, Valid: true}
		}
		// Local Admin has no identity_providers row to update.
		if p.IDPID == LocalAdminIDPID {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO local_admin_placement (id, group_id, display_order) VALUES (1, ?, ?)
				 ON CONFLICT(id) DO UPDATE SET group_id = excluded.group_id, display_order = excluded.display_order`,
				groupID, p.DisplayOrder); err != nil {
				return fmt.Errorf("placing local admin: %w", err)
			}
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE identity_providers SET group_id = ?, display_order = ? WHERE id = ?`,
			groupID, p.DisplayOrder, p.IDPID); err != nil {
			return fmt.Errorf("placing provider %q: %w", p.IDPID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing arrangement transaction: %w", err)
	}
	return nil
}

// GetLocalAdminPlacement returns where the built-in Local Admin card sits.
// A missing row means it has never been arranged, so it stays ungrouped.
func (d *DB) GetLocalAdminPlacement(ctx context.Context) (LocalAdminPlacement, error) {
	row := d.reader.QueryRowContext(ctx,
		`SELECT group_id, display_order FROM local_admin_placement WHERE id = 1`)

	var groupID sql.NullInt64
	var p LocalAdminPlacement
	switch err := row.Scan(&groupID, &p.DisplayOrder); {
	case err == sql.ErrNoRows:
		return LocalAdminPlacement{}, nil
	case err != nil:
		return LocalAdminPlacement{}, fmt.Errorf("get local admin placement: %w", err)
	}
	if groupID.Valid {
		p.GroupID = &groupID.Int64
	}
	return p, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
