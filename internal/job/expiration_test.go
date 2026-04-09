package job

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/email"
	"github.com/hanej/passport/internal/idp"
)

// openTestDB creates an in-memory SQLite DB with all migrations applied.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	database, err := db.OpenMemory()
	if err != nil {
		t.Fatalf("opening memory db: %v", err)
	}
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("running migrations: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newCryptoService(t *testing.T) *crypto.Service {
	t.Helper()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	svc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}
	return svc
}

func newAuditLogger(t *testing.T, database *db.DB) *audit.Logger {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating audit log file: %v", err)
	}
	f.Close()
	al, err := audit.NewLogger(database, f.Name(), testLogger())
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { al.Close() })
	return al
}

// --- executeTemplate ---

func TestExecuteTemplate_Success(t *testing.T) {
	got, err := executeTemplate("Hello, {{.Username}}!", map[string]string{"Username": "jdoe"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "Hello, jdoe!" {
		t.Errorf("expected 'Hello, jdoe!', got %q", got)
	}
}

func TestExecuteTemplate_MultipleFields(t *testing.T) {
	tmpl := "{{.Username}} expires on {{.ExpirationDate}} ({{.DaysRemaining}} days, {{.ProviderName}})"
	data := map[string]string{
		"Username":       "alice",
		"ExpirationDate": "Jan 1, 2026",
		"DaysRemaining":  "7",
		"ProviderName":   "Corp AD",
	}
	got, err := executeTemplate(tmpl, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "alice") || !strings.Contains(got, "Corp AD") {
		t.Errorf("unexpected output: %q", got)
	}
}

func TestExecuteTemplate_InvalidTemplate(t *testing.T) {
	_, err := executeTemplate("{{.Unclosed", nil)
	if err == nil {
		t.Error("expected error for invalid template syntax")
	}
}

func TestExecuteTemplate_ExecutionError(t *testing.T) {
	// Template that calls a non-existent function will fail at execution.
	_, err := executeTemplate("{{call .Func}}", map[string]string{})
	if err == nil {
		t.Error("expected error for template execution failure")
	}
}

// --- New constructor ---

func TestNew_Constructor(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	logger := testLogger()

	notifier := New(database, registry, cryptoSvc, al, logger)
	if notifier == nil {
		t.Fatal("expected non-nil notifier")
	}
}

// --- buildEmailConfig ---

func TestBuildEmailConfig_Success(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := map[string]any{
		"host":            "smtp.example.com",
		"port":            "587",
		"from_address":    "no-reply@example.com",
		"from_name":       "Test",
		"use_tls":         false,
		"use_starttls":    true,
		"tls_skip_verify": false,
		"enabled":         true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	rec := &db.SMTPConfig{ConfigJSON: string(cfgJSON)}

	emailCfg, err := n.buildEmailConfig(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if emailCfg.Host != "smtp.example.com" {
		t.Errorf("expected smtp.example.com, got %s", emailCfg.Host)
	}
	if !emailCfg.UseStartTLS {
		t.Error("expected UseStartTLS=true")
	}
}

func TestBuildEmailConfig_Disabled(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "25",
		"enabled": false,
	}
	cfgJSON, _ := json.Marshal(cfg)
	rec := &db.SMTPConfig{ConfigJSON: string(cfgJSON)}

	_, err := n.buildEmailConfig(rec)
	if err == nil {
		t.Error("expected error for disabled SMTP config")
	}
}

func TestBuildEmailConfig_InvalidJSON(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	rec := &db.SMTPConfig{ConfigJSON: "not-json}"}
	_, err := n.buildEmailConfig(rec)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuildEmailConfig_WithSecrets(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "587",
		"enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)

	secrets := map[string]string{
		"username": "smtpuser",
		"password": "smtppass",
	}
	secretsJSON, _ := json.Marshal(secrets)
	encrypted, err := cryptoSvc.Encrypt(secretsJSON)
	if err != nil {
		t.Fatalf("encrypting secrets: %v", err)
	}

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: encrypted,
	}

	emailCfg, err := n.buildEmailConfig(rec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if emailCfg.Username != "smtpuser" {
		t.Errorf("expected smtpuser, got %s", emailCfg.Username)
	}
}

func TestBuildEmailConfig_DecryptError(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	cfg := map[string]any{
		"host":    "smtp.example.com",
		"port":    "587",
		"enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)

	rec := &db.SMTPConfig{
		ConfigJSON: string(cfgJSON),
		SecretBlob: []byte("this-is-not-valid-ciphertext"),
	}

	_, err := n.buildEmailConfig(rec)
	if err == nil {
		t.Error("expected error for bad ciphertext")
	}
}

// --- RunForIDP error paths ---

func testCreateIDP(t *testing.T, database *db.DB, idpID string) {
	t.Helper()
	idpCfg, _ := json.Marshal(idp.Config{Endpoint: "ldap://localhost:389", Protocol: "ldap"})
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   string(idpCfg),
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}
}

func TestRunForIDP_NoConfig(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	_, err := n.RunForIDP(context.Background(), "nonexistent-idp")
	if err == nil {
		t.Error("expected error when config not found")
	}
}

func TestRunForIDP_DisabledConfig(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	// FK requires IDP to exist before saving expiration config.
	testCreateIDP(t, database, "corp-ad")

	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              false,
		CronSchedule:         "0 * * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error for disabled config")
	}
}

func TestRunForIDP_NoSMTP(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	// Set up IDP and enabled expiration config, but no SMTP.
	testCreateIDP(t, database, "corp-ad")

	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              true,
		CronSchedule:         "0 * * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}

	_, err := n.RunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error when SMTP not configured")
	}
}

// --- loadSchedules / Start / ReloadSchedules ---

func TestLoadSchedules_EmptyDB(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	n.Start(ctx)
	// Wait for context to cancel — just verifying no panic.
	<-ctx.Done()
}

func TestReloadSchedules(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	// Set up a scheduler before calling ReloadSchedules.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.Start(ctx)

	// Add a config then reload (IDP must exist first due to FK).
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap://localhost","protocol":"ldap"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              true,
		CronSchedule:         "0 0 * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("saving expiration config: %v", err)
	}

	n.ReloadSchedules(context.Background())

	// Remove the config and reload again (exercises removal path).
	if err := database.SaveExpirationConfig(context.Background(), &db.ExpirationConfig{
		IDPID:                "corp-ad",
		Enabled:              false,
		CronSchedule:         "0 0 * * *",
		DaysBeforeExpiration: 14,
	}); err != nil {
		t.Fatalf("updating expiration config: %v", err)
	}

	n.ReloadSchedules(context.Background())
}

// --- email.Config (used in RunForIDP) ---

func TestEmailConfig_Fields(t *testing.T) {
	cfg := email.Config{
		Host: "smtp.example.com",
	}
	// Just verify struct construction.
	if cfg.Host != "smtp.example.com" {
		t.Errorf("unexpected host: %s", cfg.Host)
	}
}

// --- DryRunForIDP error paths ---

func TestDryRunForIDP_NoIDP(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	_, err := n.DryRunForIDP(context.Background(), "nonexistent-idp")
	if err == nil {
		t.Error("expected error when IDP not found")
	}
}

func TestDryRunForIDP_InvalidConfig(t *testing.T) {
	database := openTestDB(t)
	registry := idp.NewRegistry(testLogger())
	cryptoSvc := newCryptoService(t)
	al := newAuditLogger(t, database)
	n := New(database, registry, cryptoSvc, al, testLogger())

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   "invalid-json}",
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	_, err := n.DryRunForIDP(context.Background(), "corp-ad")
	if err == nil {
		t.Error("expected error for invalid IDP config")
	}
}
