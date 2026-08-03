package db

import (
	"context"
	"strings"
	"testing"
)

// Version 008 was recorded by a migration that was later replaced, so the
// replacement was skipped in silence. A checksum mismatch must now be loud.
func TestMigrate_ReplacedMigrationIsRejected(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if _, err := d.writer.ExecContext(ctx,
		"UPDATE schema_migrations SET checksum = 'stale' WHERE version = 1"); err != nil {
		t.Fatalf("seeding stale checksum: %v", err)
	}

	err := d.Migrate(ctx)
	if err == nil {
		t.Fatal("expected migrate to reject the replaced migration")
	}
	if !strings.Contains(err.Error(), "001_baseline.sql") {
		t.Errorf("expected the offending file to be named, got: %v", err)
	}
}

// Ledgers written before checksums existed cannot be verified, and must not be
// mistaken for replaced migrations.
func TestMigrate_UnverifiableLedgerIsAccepted(t *testing.T) {
	d := newTestDB(t)
	ctx := context.Background()

	if _, err := d.writer.ExecContext(ctx,
		"UPDATE schema_migrations SET checksum = ''"); err != nil {
		t.Fatalf("clearing checksums: %v", err)
	}

	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("expected migrate to accept an unverifiable ledger, got: %v", err)
	}
}
