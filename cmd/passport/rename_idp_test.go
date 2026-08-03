package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanej/passport/internal/db"
)

func seedRenameIDP(t *testing.T, database *db.DB, id, logoURL string) {
	t.Helper()
	err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           id,
		FriendlyName: "Help Desk",
		ProviderType: "weblink",
		Enabled:      true,
		ConfigJSON:   `{"url":"https://example.com"}`,
		LogoURL:      logoURL,
	})
	if err != nil {
		t.Fatalf("seeding IDP %q: %v", id, err)
	}
}

func TestParseRenameSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantOld string
		wantNew string
		wantErr bool
	}{
		{"valid", "old-slug=new-slug", "old-slug", "new-slug", false},
		{"trims whitespace", " old = new ", "old", "new", false},
		{"missing separator", "oldslug", "", "", true},
		{"empty old", "=new", "", "", true},
		{"empty new", "old=", "", "", true},
		{"identical", "same=same", "", "", true},
		{"uppercase", "old=NewSlug", "", "", true},
		{"path traversal", "old=../../etc/passwd", "", "", true},
		{"underscore", "old=new_slug", "", "", true},
		{"space in slug", "old=new slug", "", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOld, gotNew, err := parseRenameSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tc.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotOld != tc.wantOld || gotNew != tc.wantNew {
				t.Errorf("got (%q, %q), want (%q, %q)", gotOld, gotNew, tc.wantOld, tc.wantNew)
			}
		})
	}
}

func TestRunRenameIDP_MovesLogoFile(t *testing.T) {
	ctx := context.Background()
	database := testDB(t)
	uploads := t.TempDir()
	seedRenameIDP(t, database, "helpdesk", "/uploads/idp-logo-helpdesk.png")

	oldLogo := filepath.Join(uploads, "idp-logo-helpdesk.png")
	if err := os.WriteFile(oldLogo, []byte("png"), 0600); err != nil {
		t.Fatalf("writing logo: %v", err)
	}

	var out bytes.Buffer
	if err := runRenameIDP(ctx, database, ":memory:", uploads, "helpdesk=support", &out); err != nil {
		t.Fatalf("renaming: %v", err)
	}

	if _, err := os.Stat(oldLogo); !os.IsNotExist(err) {
		t.Error("old logo file should have been moved")
	}
	if _, err := os.Stat(filepath.Join(uploads, "idp-logo-support.png")); err != nil {
		t.Errorf("new logo file missing: %v", err)
	}

	record, err := database.GetIDP(ctx, "support")
	if err != nil {
		t.Fatalf("loading renamed provider: %v", err)
	}
	if record.LogoURL != "/uploads/idp-logo-support.png" {
		t.Errorf("logo_url = %q, want /uploads/idp-logo-support.png", record.LogoURL)
	}
	if !strings.Contains(out.String(), `Renamed identity provider "helpdesk" to "support"`) {
		t.Errorf("unexpected output: %s", out.String())
	}
}

// TestRunRenameIDP_LeavesForeignLogoAlone verifies that a logo_url PassPort did
// not generate is not touched, since its filename carries no slug to rewrite.
func TestRunRenameIDP_LeavesForeignLogoAlone(t *testing.T) {
	ctx := context.Background()
	database := testDB(t)
	uploads := t.TempDir()
	seedRenameIDP(t, database, "helpdesk", "https://cdn.example.com/logo.png")

	var out bytes.Buffer
	if err := runRenameIDP(ctx, database, ":memory:", uploads, "helpdesk=support", &out); err != nil {
		t.Fatalf("renaming: %v", err)
	}

	record, err := database.GetIDP(ctx, "support")
	if err != nil {
		t.Fatalf("loading renamed provider: %v", err)
	}
	if record.LogoURL != "https://cdn.example.com/logo.png" {
		t.Errorf("external logo_url was rewritten: %q", record.LogoURL)
	}
}

// TestRunRenameIDP_MissingLogoFile covers a logo_url that points at a file that
// is no longer on disk: the column is still rewritten and no error is returned.
func TestRunRenameIDP_MissingLogoFile(t *testing.T) {
	ctx := context.Background()
	database := testDB(t)
	uploads := t.TempDir()
	seedRenameIDP(t, database, "helpdesk", "/uploads/idp-logo-helpdesk.svg")

	var out bytes.Buffer
	if err := runRenameIDP(ctx, database, ":memory:", uploads, "helpdesk=support", &out); err != nil {
		t.Fatalf("renaming: %v", err)
	}

	record, err := database.GetIDP(ctx, "support")
	if err != nil {
		t.Fatalf("loading renamed provider: %v", err)
	}
	if record.LogoURL != "/uploads/idp-logo-support.svg" {
		t.Errorf("logo_url = %q, want /uploads/idp-logo-support.svg", record.LogoURL)
	}
}

func TestRunRenameIDP_Errors(t *testing.T) {
	ctx := context.Background()
	database := testDB(t)
	uploads := t.TempDir()
	seedRenameIDP(t, database, "helpdesk", "")
	seedRenameIDP(t, database, "taken", "")

	tests := []struct {
		name string
		spec string
	}{
		{"unknown provider", "missing=whatever"},
		{"target exists", "helpdesk=taken"},
		{"malformed spec", "helpdesk"},
		{"invalid target slug", "helpdesk=Bad Slug"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := runRenameIDP(ctx, database, ":memory:", uploads, tc.spec, &out); err == nil {
				t.Fatalf("expected an error for %q", tc.spec)
			}
		})
	}

	if _, err := database.GetIDP(ctx, "helpdesk"); err != nil {
		t.Errorf("provider should be untouched after failed renames: %v", err)
	}
}

// TestRunRenameIDP_UnknownProviderNamesTheDatabase covers the most likely
// operator mistake: running without -config so an unrelated (often empty)
// database is opened. The error must point at the file and list what is in it.
func TestRunRenameIDP_UnknownProviderNamesTheDatabase(t *testing.T) {
	ctx := context.Background()
	database := testDB(t)
	seedRenameIDP(t, database, "helpdesk", "")
	seedRenameIDP(t, database, "corp-ad", "")

	var out bytes.Buffer
	err := runRenameIDP(ctx, database, "/srv/passport/passport.db", t.TempDir(), "redhat-idm=cc-redhat-idm", &out)
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	msg := err.Error()
	for _, want := range []string{"redhat-idm", "/srv/passport/passport.db", "corp-ad", "helpdesk"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message should mention %q, got:\n%s", want, msg)
		}
	}
}

func TestRunRenameIDP_EmptyDatabaseHint(t *testing.T) {
	ctx := context.Background()
	database := testDB(t)

	var out bytes.Buffer
	err := runRenameIDP(ctx, database, "passport.db", t.TempDir(), "redhat-idm=cc-redhat-idm", &out)
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	if !strings.Contains(err.Error(), "no identity providers") {
		t.Errorf("expected a hint that the database is empty, got:\n%s", err.Error())
	}
	if !strings.Contains(err.Error(), "-config") {
		t.Errorf("expected the hint to mention -config, got:\n%s", err.Error())
	}
}
