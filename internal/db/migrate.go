package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ensureChecksumColumn adds the checksum column to ledgers created before it
// existed. Rows written then keep an empty checksum and are not verifiable.
func (d *DB) ensureChecksumColumn(ctx context.Context) error {
	var present int
	if err := d.writer.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM pragma_table_info('schema_migrations') WHERE name = 'checksum'`,
	).Scan(&present); err != nil {
		return fmt.Errorf("inspecting schema_migrations: %w", err)
	}
	if present > 0 {
		return nil
	}
	if _, err := d.writer.ExecContext(ctx,
		"ALTER TABLE schema_migrations ADD COLUMN checksum TEXT NOT NULL DEFAULT ''",
	); err != nil {
		return fmt.Errorf("adding checksum column to schema_migrations: %w", err)
	}
	return nil
}

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

	if err := d.ensureChecksumColumn(ctx); err != nil {
		return err
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

	// Some migrations rebuild a table (create/copy/drop/rename). With foreign
	// keys enforced, the DROP would cascade-delete child rows, so enforcement is
	// suspended for the duration of the migration run. SQLite ignores this
	// pragma inside a transaction, hence it is set on the connection here.
	// MaxOpenConns(1) on the writer guarantees this is the same connection the
	// migrations run on.
	if _, err := d.writer.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("disabling foreign keys for migration: %w", err)
	}
	defer func() {
		_, _ = d.writer.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	}()

	for _, m := range migrations {
		body, err := migrationsFS.ReadFile("migrations/" + m.name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", m.name, err)
		}
		digest := sha256.Sum256(body)
		checksum := hex.EncodeToString(digest[:])

		var recorded string
		err = d.writer.QueryRowContext(ctx,
			"SELECT checksum FROM schema_migrations WHERE version = ?", m.version,
		).Scan(&recorded)
		switch {
		case err == nil:
			// A version whose content has changed means a migration was replaced
			// after it shipped, which would otherwise be skipped in silence.
			if recorded != "" && recorded != checksum {
				return fmt.Errorf("migration %s differs from the version %d already applied to this database; "+
					"migration files must never be renumbered or edited once released", m.name, m.version)
			}
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return fmt.Errorf("checking migration %d: %w", m.version, err)
		}

		tx, err := d.writer.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("starting transaction for migration %d: %w", m.version, err)
		}

		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("executing migration %s: %w", m.name, err)
		}

		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version, checksum) VALUES (?, ?)", m.version, checksum,
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
