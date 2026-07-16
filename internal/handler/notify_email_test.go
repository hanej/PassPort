package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
)

func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, &buf
}

func testCryptoService(t *testing.T) *crypto.Service {
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

// TestSendPasswordEventEmail_Success verifies that a templated notification
// email is actually sent (via SMTP) and logged when SMTP is configured,
// a template exists, and a user email is available. This exercises the
// exact bug reported: password change events must actually send email.
func TestSendPasswordEventEmail_Success(t *testing.T) {
	database := setupTestDB(t)
	cryptoSvc := testCryptoService(t)
	logger, logs := bufferLogger()

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()
	host, port, _ := strings.Cut(addr, ":")

	cfg := map[string]any{
		"host":         host,
		"port":         port,
		"from_address": "noreply@example.com",
		"enabled":      true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(cfgJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	sendPasswordEventEmail(context.Background(), database, cryptoSvc, logger,
		"password_changed", "corp-ad", "Corp AD", "jdoe", "jdoe@example.com", "10.0.0.1")

	if !strings.Contains(logs.String(), "notification email sent") {
		t.Errorf("expected success log, got: %s", logs.String())
	}
}

// TestSendPasswordEventEmail_NoUserEmail verifies we skip sending (and log a
// warning) rather than erroring when no email address is on file.
func TestSendPasswordEventEmail_NoUserEmail(t *testing.T) {
	database := setupTestDB(t)
	cryptoSvc := testCryptoService(t)
	logger, logs := bufferLogger()

	sendPasswordEventEmail(context.Background(), database, cryptoSvc, logger,
		"password_changed", "corp-ad", "Corp AD", "jdoe", "", "10.0.0.1")

	if !strings.Contains(logs.String(), "no email address on file") {
		t.Errorf("expected skip-log, got: %s", logs.String())
	}
}

// TestSendPasswordEventEmail_SMTPNotConfigured verifies we log and skip
// instead of failing the calling request when SMTP has never been configured.
func TestSendPasswordEventEmail_SMTPNotConfigured(t *testing.T) {
	database := setupTestDB(t)
	cryptoSvc := testCryptoService(t)
	logger, logs := bufferLogger()

	sendPasswordEventEmail(context.Background(), database, cryptoSvc, logger,
		"password_changed", "corp-ad", "Corp AD", "jdoe", "jdoe@example.com", "10.0.0.1")

	if !strings.Contains(logs.String(), "SMTP not configured") {
		t.Errorf("expected SMTP-not-configured log, got: %s", logs.String())
	}
}

// mockProviderWithEmail returns a fixed value from GetUserAttribute, simulating
// a directory user with a notification email address set.
type mockProviderWithEmail struct {
	mockProvider
	email string
}

func (m *mockProviderWithEmail) GetUserAttribute(_ context.Context, _, _ string) (string, error) {
	return m.email, nil
}

func TestResolveNotificationEmailByDN(t *testing.T) {
	database := setupTestDB(t)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	provider := &mockProviderWithEmail{mockProvider: mockProvider{id: "corp-ad"}, email: "jdoe@example.com"}

	got, err := resolveNotificationEmailByDN(context.Background(), database, provider, "corp-ad", "CN=jdoe,DC=example,DC=com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "jdoe@example.com" {
		t.Errorf("expected jdoe@example.com, got %q", got)
	}
}

func TestResolveNotificationEmailByUsername(t *testing.T) {
	database := setupTestDB(t)
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	registry := idp.NewRegistry(testLogger())
	registry.Register("corp-ad", &mockProviderWithEmail{mockProvider: mockProvider{id: "corp-ad"}, email: "jdoe@example.com"})

	got, err := resolveNotificationEmailByUsername(context.Background(), database, registry, "corp-ad", "jdoe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "jdoe@example.com" {
		t.Errorf("expected jdoe@example.com, got %q", got)
	}
}

func TestResolveNotificationEmailByUsername_UnknownIDP(t *testing.T) {
	database := setupTestDB(t)
	registry := idp.NewRegistry(testLogger())

	if _, err := resolveNotificationEmailByUsername(context.Background(), database, registry, "missing", "jdoe"); err == nil {
		t.Error("expected error for unregistered IDP")
	}
}
