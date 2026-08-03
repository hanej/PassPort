package db

import (
	"context"
	"testing"
)

// TestMigrate007WeblinkRebuild simulates an existing v1.1.9 install (baseline
// schema with the old provider_type CHECK constraint) and verifies that the
// identity_providers table rebuild in migration 007 preserves parent rows,
// child rows, foreign key wiring, and cascade behaviour.
func TestMigrate007WeblinkRebuild(t *testing.T) {
	ctx := context.Background()
	d, err := OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	defer func() { _ = d.Close() }()

	// Build the pre-007 schema: run every migration, then rewind
	// identity_providers to the original two-value CHECK constraint.
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("initial migrate: %v", err)
	}
	rewind := `
		PRAGMA foreign_keys = OFF;
		CREATE TABLE identity_providers_old (
		    id                TEXT PRIMARY KEY,
		    friendly_name     TEXT NOT NULL,
		    description       TEXT NOT NULL DEFAULT '',
		    provider_type     TEXT NOT NULL CHECK (provider_type IN ('ad', 'freeipa')),
		    enabled           INTEGER NOT NULL DEFAULT 1,
		    config_json       TEXT NOT NULL DEFAULT '{}',
		    secret_blob       BLOB,
		    logo_url          TEXT NOT NULL DEFAULT '',
		    mfa_provider_id   TEXT DEFAULT NULL,
		    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
		    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		);
		DROP TABLE identity_providers;
		ALTER TABLE identity_providers_old RENAME TO identity_providers;
		DELETE FROM schema_migrations WHERE version = 7;
		PRAGMA foreign_keys = ON;`
	if _, err := d.writer.ExecContext(ctx, rewind); err != nil {
		t.Fatalf("rewinding schema: %v", err)
	}

	// Populate the parent and every table that references it.
	seed := `
		INSERT INTO identity_providers
		    (id, friendly_name, description, provider_type, enabled, config_json,
		     secret_blob, logo_url, mfa_provider_id, created_at, updated_at)
		VALUES
		    ('corp-ad', 'Corp AD', 'desc', 'ad', 1, '{"endpoint":"a:389"}',
		     X'DEADBEEF', '/uploads/l.png', 'mfa-1', '2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z'),
		    ('corp-ipa', 'Corp IPA', '', 'freeipa', 0, '{}', NULL, '', NULL,
		     '2020-01-03T00:00:00Z', '2020-01-04T00:00:00Z');

		INSERT INTO idp_attribute_mappings (idp_id, canonical_name, directory_attr)
		     VALUES ('corp-ad', 'email', 'mail');
		INSERT INTO idp_correlation_rules (idp_id, source_canonical_attr, target_directory_attr)
		     VALUES ('corp-ad', 'email', 'mail');
		INSERT INTO idp_expiration_config (idp_id, enabled) VALUES ('corp-ad', 1);
		INSERT INTO idp_expiration_filters (idp_id, attribute, pattern)
		     VALUES ('corp-ad', 'userAccountControl', '2');
		INSERT INTO admin_groups (idp_id, group_dn) VALUES ('corp-ad', 'cn=admins');
		INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type)
		     VALUES ('corp-ad', 'alice', 'corp-ad', 'cn=alice', 'auto');
		INSERT INTO report_config (idp_id, report_type, enabled) VALUES ('corp-ad', 'expiration', 1);
		INSERT INTO report_filters (idp_id, report_type, attribute, pattern)
		     VALUES ('corp-ad', 'expiration', 'attr', 'val');`
	if _, err := d.writer.ExecContext(ctx, seed); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	// Apply migration 007.
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("applying migration 007: %v", err)
	}

	// Parent rows survive byte-for-byte.
	var (
		name, desc, ptype, cfg, logo, mfa, created, updated string
		enabled                                             int
		blob                                                []byte
	)
	err = d.writer.QueryRowContext(ctx, `
		SELECT friendly_name, description, provider_type, enabled, config_json,
		       secret_blob, logo_url, mfa_provider_id, created_at, updated_at
		FROM identity_providers WHERE id = 'corp-ad'`).
		Scan(&name, &desc, &ptype, &enabled, &cfg, &blob, &logo, &mfa, &created, &updated)
	if err != nil {
		t.Fatalf("reading migrated row: %v", err)
	}
	if name != "Corp AD" || desc != "desc" || ptype != "ad" || enabled != 1 ||
		cfg != `{"endpoint":"a:389"}` || logo != "/uploads/l.png" || mfa != "mfa-1" ||
		created != "2020-01-01T00:00:00Z" || updated != "2020-01-02T00:00:00Z" {
		t.Errorf("parent row altered by migration: %s %s %s %d %s %s %s %s %s",
			name, desc, ptype, enabled, cfg, logo, mfa, created, updated)
	}
	if len(blob) != 4 || blob[0] != 0xDE || blob[3] != 0xEF {
		t.Errorf("secret_blob corrupted: %x", blob)
	}

	var parentCount int
	if err := d.writer.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity_providers`).Scan(&parentCount); err != nil {
		t.Fatalf("counting providers: %v", err)
	}
	if parentCount != 2 {
		t.Errorf("expected 2 providers after migration, got %d", parentCount)
	}

	// No child rows were cascade-deleted by the DROP.
	children := []string{
		"idp_attribute_mappings", "idp_correlation_rules", "idp_expiration_config",
		"idp_expiration_filters", "admin_groups", "user_idp_mappings",
		"report_config", "report_filters",
	}
	for _, table := range children {
		var n int
		if err := d.writer.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if n != 1 {
			t.Errorf("%s: expected 1 row after migration, got %d", table, n)
		}
	}

	// Foreign keys still resolve to identity_providers and are enforced again.
	rows, err := d.writer.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check: %v", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		t.Error("foreign_key_check reported violations after migration")
	}

	var fk int
	if err := d.writer.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("reading foreign_keys pragma: %v", err)
	}
	if fk != 1 {
		t.Error("foreign key enforcement was left disabled after Migrate")
	}

	// The widened CHECK accepts weblink and still rejects unknown types.
	if _, err := d.writer.ExecContext(ctx, `
		INSERT INTO identity_providers (id, friendly_name, provider_type)
		VALUES ('portal', 'Portal', 'weblink')`); err != nil {
		t.Errorf("inserting weblink provider: %v", err)
	}
	if _, err := d.writer.ExecContext(ctx, `
		INSERT INTO identity_providers (id, friendly_name, provider_type)
		VALUES ('bogus', 'Bogus', 'nope')`); err == nil {
		t.Error("expected CHECK constraint to reject unknown provider_type")
	}

	// ON DELETE CASCADE survived the rebuild.
	if _, err := d.writer.ExecContext(ctx, `DELETE FROM identity_providers WHERE id = 'corp-ad'`); err != nil {
		t.Fatalf("deleting provider: %v", err)
	}
	var orphans int
	if err := d.writer.QueryRowContext(ctx, `SELECT COUNT(*) FROM idp_attribute_mappings`).Scan(&orphans); err != nil {
		t.Fatalf("counting mappings: %v", err)
	}
	if orphans != 0 {
		t.Errorf("expected cascade delete to remove child rows, got %d", orphans)
	}
}
