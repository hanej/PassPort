package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/migrate"
)

// adminCommandStore is the minimal DB subset required by admin CLI commands.
type adminCommandStore interface {
	GetLocalAdmin(ctx context.Context, username string) (*db.LocalAdmin, error)
	UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error
	AddPasswordHistory(ctx context.Context, username, passwordHash string, keepN int) error
}

// runResetAdminPassword generates a new random password for username, stores it
// with mustChangePassword=true, records it in history, and writes status to out.
// Returns the generated plaintext password.
func runResetAdminPassword(ctx context.Context, store adminCommandStore, username string, historyLen int, out io.Writer, logger *slog.Logger) (string, error) {
	if _, err := store.GetLocalAdmin(ctx, username); err != nil {
		return "", fmt.Errorf("local admin %q not found: %w", username, err)
	}
	newPw, err := auth.GenerateRandomPassword(24)
	if err != nil {
		return "", fmt.Errorf("failed to generate password: %w", err)
	}
	newHash, err := auth.HashPassword(newPw)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	if err := store.UpdateLocalAdminPassword(ctx, username, newHash, true); err != nil {
		return "", fmt.Errorf("failed to update password: %w", err)
	}
	if err := store.AddPasswordHistory(ctx, username, newHash, historyLen); err != nil {
		if logger != nil {
			logger.Warn("failed to record password history after reset", "error", err)
		}
	}
	_, _ = fmt.Fprintf(out, "Password for %q has been reset.\n", username)
	_, _ = fmt.Fprintf(out, "New password: %s\n", newPw)
	_, _ = fmt.Fprintln(out, "The account has been flagged to require a password change at next login.")
	return newPw, nil
}

// runForcePasswordChange sets must_change_password=true for username without changing
// the password. Writes a confirmation message to out.
func runForcePasswordChange(ctx context.Context, store adminCommandStore, username string, out io.Writer) error {
	admin, err := store.GetLocalAdmin(ctx, username)
	if err != nil {
		return fmt.Errorf("local admin %q not found: %w", username, err)
	}
	if err := store.UpdateLocalAdminPassword(ctx, admin.Username, admin.PasswordHash, true); err != nil {
		return fmt.Errorf("failed to set must_change_password: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Account %q will be required to change their password at next login.\n", username)
	return nil
}

// runExport writes a decrypted JSON export of the full configuration to outPath.
func runExport(ctx context.Context, database *db.DB, cryptoSvc *crypto.Service, outPath string) error {
	data, err := migrate.BuildExport(ctx, database, cryptoSvc)
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling export: %w", err)
	}
	if err := os.WriteFile(outPath, jsonBytes, 0600); err != nil {
		return fmt.Errorf("writing export file: %w", err)
	}
	return nil
}

// runBackup writes an encrypted JSON backup of the full configuration to outPath.
func runBackup(ctx context.Context, database *db.DB, outPath string) error {
	data, err := migrate.BuildBackup(ctx, database)
	if err != nil {
		return fmt.Errorf("backup failed: %w", err)
	}
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling backup: %w", err)
	}
	if err := os.WriteFile(outPath, jsonBytes, 0600); err != nil {
		return fmt.Errorf("writing backup file: %w", err)
	}
	return nil
}

// runImport reads a JSON export/backup from inPath and imports it into the database.
// Returns the import result summary.
func runImport(ctx context.Context, database *db.DB, cryptoSvc *crypto.Service, inPath string) (*migrate.ImportResult, error) {
	fileBytes, err := os.ReadFile(inPath)
	if err != nil {
		return nil, fmt.Errorf("reading import file: %w", err)
	}
	var data migrate.ExportData
	if err := json.Unmarshal(fileBytes, &data); err != nil {
		return nil, fmt.Errorf("parsing import file: %w", err)
	}
	result, err := migrate.RunImport(ctx, database, cryptoSvc, &data, migrate.AllSections())
	if err != nil {
		return nil, fmt.Errorf("import failed: %w", err)
	}
	return result, nil
}

// parseRenameSpec splits an "old=new" slug rename argument and validates both halves.
func parseRenameSpec(spec string) (oldID, newID string, err error) {
	parts := strings.SplitN(spec, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("expected <old-slug>=<new-slug>, got %q", spec)
	}
	oldID, newID = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if !idp.ValidID(oldID) {
		return "", "", fmt.Errorf("invalid old slug %q: use lowercase letters, numbers, and hyphens", oldID)
	}
	if !idp.ValidID(newID) {
		return "", "", fmt.Errorf("invalid new slug %q: use lowercase letters, numbers, and hyphens", newID)
	}
	if oldID == newID {
		return "", "", fmt.Errorf("old and new slugs are identical")
	}
	return oldID, newID, nil
}

// runRenameIDP renames an identity provider slug and every reference to it,
// then moves the uploaded logo, whose filename embeds the slug.
func runRenameIDP(ctx context.Context, database *db.DB, dbPath, uploadsDir, spec string, out io.Writer) error {
	oldID, newID, err := parseRenameSpec(spec)
	if err != nil {
		return err
	}

	// Resolve the logo move before touching the database so a bad path fails early.
	oldLogoPath, newLogoPath, newLogoURL, err := plannedLogoRename(ctx, database, uploadsDir, oldID, newID)
	if err != nil {
		return fmt.Errorf("%w\n%s", err, describeDatabase(ctx, database, dbPath))
	}

	result, err := database.RenameIDP(ctx, oldID, newID, newLogoURL)
	if err != nil {
		return fmt.Errorf("renaming %q to %q: %w", oldID, newID, err)
	}

	if oldLogoPath != "" {
		if err := os.Rename(oldLogoPath, newLogoPath); err != nil {
			// The database rename already committed; report rather than unwind.
			_, _ = fmt.Fprintf(out, "WARNING: could not move logo %s -> %s: %v\n", oldLogoPath, newLogoPath, err)
			_, _ = fmt.Fprintln(out, "Re-upload the logo from the admin UI.")
		}
	}

	_, _ = fmt.Fprintf(out, "Renamed identity provider %q to %q.\n", oldID, newID)
	for _, ref := range sortedKeys(result.Rows) {
		if result.Rows[ref] > 0 {
			_, _ = fmt.Fprintf(out, "  %-38s %d\n", ref, result.Rows[ref])
		}
	}
	_, _ = fmt.Fprintf(out, "  %-38s %d\n", "total rows updated", result.Total)
	if result.NewLogoURL != "" {
		_, _ = fmt.Fprintf(out, "  %-38s %s\n", "logo", result.NewLogoURL)
	}
	_, _ = fmt.Fprintln(out, "Audit log entries still reference the old ID, which preserves the historical record.")
	return nil
}

// plannedLogoRename works out where the uploaded logo should move to. It returns
// empty strings when the provider has no logo or the logo is not a managed upload.
func plannedLogoRename(ctx context.Context, database *db.DB, uploadsDir, oldID, newID string) (oldPath, newPath, newURL string, err error) {
	var logoURL string
	row := database.Reader().QueryRowContext(ctx, `SELECT logo_url FROM identity_providers WHERE id = ?`, oldID)
	if err := row.Scan(&logoURL); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", fmt.Errorf("identity provider %q not found", oldID)
		}
		return "", "", "", fmt.Errorf("loading identity provider %q: %w", oldID, err)
	}

	// Only logos this application named are safe to move; anything else is left alone.
	expected := "/uploads/idp-logo-" + oldID
	if logoURL == "" || !strings.HasPrefix(logoURL, expected+".") {
		return "", "", "", nil
	}
	ext := strings.TrimPrefix(logoURL, expected)

	oldPath = filepath.Join(uploadsDir, "idp-logo-"+oldID+ext)
	newPath = filepath.Join(uploadsDir, "idp-logo-"+newID+ext)
	if _, statErr := os.Stat(oldPath); statErr != nil {
		// Column points at a file that is not there; rewrite the URL anyway.
		return "", "", "/uploads/idp-logo-" + newID + ext, nil
	}
	return oldPath, newPath, "/uploads/idp-logo-" + newID + ext, nil
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// describeDatabase reports which database file was opened and which provider
// slugs it holds. Running a maintenance command from the wrong directory opens
// (and creates) an unrelated database, which is otherwise hard to spot.
func describeDatabase(ctx context.Context, database *db.DB, dbPath string) string {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		abs = dbPath
	}
	var b strings.Builder
	fmt.Fprintf(&b, "database: %s\n", abs)

	rows, err := database.Reader().QueryContext(ctx, `SELECT id FROM identity_providers ORDER BY id`)
	if err != nil {
		fmt.Fprintf(&b, "could not list identity providers: %v", err)
		return b.String()
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		b.WriteString("this database contains no identity providers — check that -config points at the right config.yaml")
		return b.String()
	}
	fmt.Fprintf(&b, "available slugs: %s", strings.Join(ids, ", "))
	return b.String()
}
