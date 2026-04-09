package db

import (
	"context"
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies all pending SQL migrations in order.
func (d *DB) Migrate(ctx context.Context) error {
	// Ensure schema_migrations table exists
	_, err := d.writer.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		)
	`)
	if err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("reading migrations directory: %w", err)
	}

	type migration struct {
		version int
		name    string
	}

	var migrations []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(e.Name(), "_", 2)
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("parsing migration version from %s: %w", e.Name(), err)
		}
		migrations = append(migrations, migration{version: v, name: e.Name()})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	for _, m := range migrations {
		var applied int
		err := d.writer.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM schema_migrations WHERE version = ?", m.version,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("checking migration %d: %w", m.version, err)
		}
		if applied > 0 {
			continue
		}

		sql, err := migrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", m.name, err)
		}

		tx, err := d.writer.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("starting transaction for migration %d: %w", m.version, err)
		}

		if _, err := tx.ExecContext(ctx, string(sql)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("executing migration %s: %w", m.name, err)
		}

		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version) VALUES (?)", m.version,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recording migration %d: %w", m.version, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %d: %w", m.version, err)
		}
	}

	return nil
}

// MigrationsComplete returns true if all embedded migrations have been applied.
func (d *DB) MigrationsComplete(ctx context.Context) (bool, error) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return false, fmt.Errorf("reading migrations: %w", err)
	}

	var expected int
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			expected++
		}
	}

	var applied int
	err = d.reader.QueryRowContext(ctx, "SELECT COUNT(*) FROM schema_migrations").Scan(&applied)
	if err != nil {
		return false, fmt.Errorf("counting applied migrations: %w", err)
	}

	return applied >= expected, nil
}
