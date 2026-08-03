package db

import (
	"context"
	"errors"
	"testing"
)

// seedRenameFixture creates two providers and one row in every table that
// stores a provider slug, including the columns with no foreign key.
func seedRenameFixture(t *testing.T, d *DB) {
	t.Helper()
	seed := `
		INSERT INTO identity_providers
		    (id, friendly_name, description, provider_type, enabled, config_json,
		     secret_blob, logo_url, mfa_provider_id, created_at, updated_at)
		VALUES
		    ('corp-ad', 'Corp AD', 'desc', 'ad', 1, '{"endpoint":"a:389"}',
		     X'DEADBEEF', '/uploads/idp-logo-corp-ad.png', 'mfa-1',
		     '2020-01-01T00:00:00Z', '2020-01-02T00:00:00Z'),
		    ('other', 'Other', '', 'freeipa', 1, '{}', NULL, '', NULL,
		     '2020-01-03T00:00:00Z', '2020-01-04T00:00:00Z');

		INSERT INTO idp_attribute_mappings (idp_id, canonical_name, directory_attr)
		     VALUES ('corp-ad', 'email', 'mail'), ('other', 'email', 'mail');
		INSERT INTO idp_correlation_rules (idp_id, source_canonical_attr, target_directory_attr)
		     VALUES ('corp-ad', 'email', 'mail');
		INSERT INTO idp_expiration_config (idp_id, enabled) VALUES ('corp-ad', 1);
		INSERT INTO idp_expiration_filters (idp_id, attribute, pattern)
		     VALUES ('corp-ad', 'userAccountControl', '2');
		INSERT INTO admin_groups (idp_id, group_dn) VALUES ('corp-ad', 'cn=admins');
		INSERT INTO report_config (idp_id, report_type, enabled) VALUES ('corp-ad', 'expiration', 1);
		INSERT INTO report_filters (idp_id, report_type, attribute, pattern)
		     VALUES ('corp-ad', 'expiration', 'attr', 'val');

		-- target_idp_id is FK-enforced; auth_provider_id is not.
		INSERT INTO user_idp_mappings (auth_provider_id, auth_username, target_idp_id, target_account_dn, link_type)
		     VALUES ('corp-ad', 'alice', 'corp-ad', 'cn=alice', 'auto'),
		            ('corp-ad', 'bob',   'other',   'cn=bob',   'manual');

		INSERT INTO correlation_warnings (auth_username, target_idp_id, warning_type)
		     VALUES ('alice', 'corp-ad', 'ambiguous');
		INSERT INTO sessions (id, user_type, provider_id, username, ip_address, expires_at)
		     VALUES ('sess-1', 'provider', 'corp-ad', 'alice', '127.0.0.1', '2099-01-01T00:00:00Z');
		INSERT INTO audit_log (username, action, provider_id, provider_name, result)
		     VALUES ('alice', 'login', 'corp-ad', 'Corp AD', 'success');`
	if _, err := d.writer.ExecContext(context.Background(), seed); err != nil {
		t.Fatalf("seeding: %v", err)
	}
}

func countWhere(t *testing.T, d *DB, table, column, value string) int {
	t.Helper()
	var n int
	q := "SELECT COUNT(*) FROM " + table + " WHERE " + column + " = ?"
	if err := d.writer.QueryRow(q, value).Scan(&n); err != nil {
		t.Fatalf("counting %s.%s: %v", table, column, err)
	}
	return n
}

func TestRenameIDP_RewritesEveryReference(t *testing.T) {
	ctx := context.Background()
	d, err := OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	seedRenameFixture(t, d)

	// Without enforcement active this test would prove nothing about the
	// deferred-FK strategy, since the parent row is updated before its children.
	var fkOn int
	if err := d.writer.QueryRow(`PRAGMA foreign_keys`).Scan(&fkOn); err != nil {
		t.Fatalf("reading foreign_keys pragma: %v", err)
	}
	if fkOn != 1 {
		t.Fatal("foreign key enforcement is off; the rename test would be vacuous")
	}

	result, err := d.RenameIDP(ctx, "corp-ad", "corp-ad-2", "/uploads/idp-logo-corp-ad-2.png")
	if err != nil {
		t.Fatalf("renaming: %v", err)
	}

	// Every column that stores a slug must have moved.
	moved := []struct{ table, column string }{
		{"idp_attribute_mappings", "idp_id"},
		{"idp_correlation_rules", "idp_id"},
		{"idp_expiration_config", "idp_id"},
		{"idp_expiration_filters", "idp_id"},
		{"admin_groups", "idp_id"},
		{"report_config", "idp_id"},
		{"report_filters", "idp_id"},
		{"user_idp_mappings", "target_idp_id"},
		{"user_idp_mappings", "auth_provider_id"},
		{"correlation_warnings", "target_idp_id"},
		{"sessions", "provider_id"},
	}
	for _, m := range moved {
		if n := countWhere(t, d, m.table, m.column, "corp-ad"); n != 0 {
			t.Errorf("%s.%s still has %d row(s) referencing the old slug", m.table, m.column, n)
		}
		if n := countWhere(t, d, m.table, m.column, "corp-ad-2"); n == 0 {
			t.Errorf("%s.%s has no row referencing the new slug", m.table, m.column)
		}
	}

	// Nothing may be cascade-deleted, and the unrelated provider is untouched.
	for _, tc := range []struct {
		table string
		want  int
	}{
		{"identity_providers", 2},
		{"idp_attribute_mappings", 2},
		{"user_idp_mappings", 2},
		{"admin_groups", 1},
		{"report_filters", 1},
	} {
		var n int
		if err := d.writer.QueryRow("SELECT COUNT(*) FROM " + tc.table).Scan(&n); err != nil {
			t.Fatalf("counting %s: %v", tc.table, err)
		}
		if n != tc.want {
			t.Errorf("%s: expected %d rows after rename, got %d", tc.table, tc.want, n)
		}
	}
	if n := countWhere(t, d, "idp_attribute_mappings", "idp_id", "other"); n != 1 {
		t.Errorf("unrelated provider's mapping was modified")
	}

	// The provider row keeps its data, including the encrypted secret blob.
	var friendly, logo string
	var blob []byte
	err = d.writer.QueryRow(
		`SELECT friendly_name, logo_url, secret_blob FROM identity_providers WHERE id = ?`,
		"corp-ad-2").Scan(&friendly, &logo, &blob)
	if err != nil {
		t.Fatalf("loading renamed provider: %v", err)
	}
	if friendly != "Corp AD" {
		t.Errorf("friendly_name changed: %q", friendly)
	}
	if logo != "/uploads/idp-logo-corp-ad-2.png" {
		t.Errorf("logo_url not rewritten: %q", logo)
	}
	if len(blob) != 4 || blob[0] != 0xDE {
		t.Errorf("secret_blob altered: %x", blob)
	}

	// Audit history is deliberately left pointing at the old slug.
	if n := countWhere(t, d, "audit_log", "provider_id", "corp-ad"); n != 1 {
		t.Errorf("audit_log should retain the old provider_id, got %d matching rows", n)
	}

	if result.NewLogoURL != "/uploads/idp-logo-corp-ad-2.png" {
		t.Errorf("unexpected NewLogoURL %q", result.NewLogoURL)
	}
	if result.Rows["sessions.provider_id"] != 1 {
		t.Errorf("expected 1 session row updated, got %d", result.Rows["sessions.provider_id"])
	}
	// 1 provider + 12 seeded references.
	if result.Total != 13 {
		t.Errorf("expected 13 rows updated in total, got %d", result.Total)
	}
}

func TestRenameIDP_Errors(t *testing.T) {
	ctx := context.Background()
	d, err := OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	seedRenameFixture(t, d)

	if _, err := d.RenameIDP(ctx, "nope", "whatever", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for a missing provider, got %v", err)
	}
	if _, err := d.RenameIDP(ctx, "corp-ad", "other", ""); !errors.Is(err, ErrIDPExists) {
		t.Errorf("expected ErrIDPExists when the target slug is taken, got %v", err)
	}
	if _, err := d.RenameIDP(ctx, "corp-ad", "corp-ad", ""); err == nil {
		t.Error("expected an error when old and new slugs are identical")
	}

	// A failed rename must leave everything exactly as it was.
	if n := countWhere(t, d, "identity_providers", "id", "corp-ad"); n != 1 {
		t.Error("original provider disappeared after a failed rename")
	}
	if n := countWhere(t, d, "admin_groups", "idp_id", "corp-ad"); n != 1 {
		t.Error("child rows were modified by a failed rename")
	}
}

// TestRenameIDP_KeepsLogoWhenNotRenamed verifies logo_url is left alone when the
// caller has no replacement for it.
func TestRenameIDP_KeepsLogoWhenNotRenamed(t *testing.T) {
	ctx := context.Background()
	d, err := OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	defer func() { _ = d.Close() }()
	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	seedRenameFixture(t, d)

	result, err := d.RenameIDP(ctx, "corp-ad", "renamed", "")
	if err != nil {
		t.Fatalf("renaming: %v", err)
	}
	if result.NewLogoURL != "" {
		t.Errorf("expected no logo change, got %q", result.NewLogoURL)
	}
	var logo string
	if err := d.writer.QueryRow(`SELECT logo_url FROM identity_providers WHERE id = 'renamed'`).Scan(&logo); err != nil {
		t.Fatalf("loading provider: %v", err)
	}
	if logo != "/uploads/idp-logo-corp-ad.png" {
		t.Errorf("logo_url should be untouched, got %q", logo)
	}
}
