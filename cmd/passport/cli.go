package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
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
