package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// failingAttrProvider fails both directory lookups used by the notification
// email resolvers.
type failingAttrProvider struct {
	mockProvider
	searchErr error
	attrErr   error
}

func (m *failingAttrProvider) SearchUser(_ context.Context, _, _ string) (string, error) {
	return "", m.searchErr
}

func (m *failingAttrProvider) GetUserAttribute(_ context.Context, _, _ string) (string, error) {
	return "", m.attrErr
}

func TestResolveNotificationEmailByDN_Failures(t *testing.T) {
	t.Run("IDP record missing", func(t *testing.T) {
		database := setupTestDB(t)
		provider := &mockProviderWithEmail{mockProvider: mockProvider{id: "corp-ad"}, email: "x@example.com"}

		if _, err := resolveNotificationEmailByDN(context.Background(), database, provider, "corp-ad", "CN=jdoe"); err == nil {
			t.Error("expected an error when the IDP record does not exist")
		}
	})

	t.Run("config JSON is malformed", func(t *testing.T) {
		database := setupTestDB(t)
		if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
			ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true, ConfigJSON: `{`,
		}); err != nil {
			t.Fatalf("creating IDP: %v", err)
		}
		provider := &mockProviderWithEmail{mockProvider: mockProvider{id: "corp-ad"}, email: "x@example.com"}

		_, err := resolveNotificationEmailByDN(context.Background(), database, provider, "corp-ad", "CN=jdoe")
		if err == nil || !strings.Contains(err.Error(), "parsing IDP config") {
			t.Errorf("expected a config parse error, got %v", err)
		}
	})

	t.Run("directory attribute lookup fails", func(t *testing.T) {
		database := setupTestDB(t)
		if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
			ID: "corp-ad", FriendlyName: "Corp AD", ProviderType: "ad", Enabled: true,
			ConfigJSON: `{"notification_email_attr":"userPrincipalName"}`,
		}); err != nil {
			t.Fatalf("creating IDP: %v", err)
		}
		provider := &failingAttrProvider{
			mockProvider: mockProvider{id: "corp-ad"},
			attrErr:      errors.New("ldap: no such attribute"),
		}

		_, err := resolveNotificationEmailByDN(context.Background(), database, provider, "corp-ad", "CN=jdoe")
		if err == nil || !strings.Contains(err.Error(), "userPrincipalName") {
			t.Errorf("expected the configured attribute name in the error, got %v", err)
		}
	})
}

// TestResolveNotificationEmailByUsername_NotFound covers the fallback from uid
// to sAMAccountName: when both lookups fail the user is genuinely unknown.
func TestResolveNotificationEmailByUsername_NotFound(t *testing.T) {
	database := setupTestDB(t)
	registry := idp.NewRegistry(testLogger())
	registry.Register("corp-ad", &failingAttrProvider{
		mockProvider: mockProvider{id: "corp-ad"},
		searchErr:    errors.New("no entries"),
	})

	_, err := resolveNotificationEmailByUsername(context.Background(), database, registry, "corp-ad", "ghost")
	if err == nil || !strings.Contains(err.Error(), "not found in directory") {
		t.Errorf("expected a not-found error, got %v", err)
	}
}

// saveSMTP stores an SMTP config pointing at host:port.
func saveSMTP(t *testing.T, database *db.DB, host, port string) {
	t.Helper()
	cfg := map[string]any{
		"host": host, "port": port, "from_address": "noreply@example.com", "enabled": true,
	}
	cfgJSON, _ := json.Marshal(cfg)
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(cfgJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}
}

// TestSendPasswordEventEmail_FailuresAreSwallowed pins the contract that a
// notification problem is only ever logged: the password change has already
// been committed to the directory, so failing the request here would tell the
// user their change did not work when it did.
func TestSendPasswordEventEmail_FailuresAreSwallowed(t *testing.T) {
	addr, stop := fakeSMTPServerHandler(t)
	defer stop()
	liveHost, livePort, _ := strings.Cut(addr, ":")

	tests := []struct {
		name    string
		setup   func(t *testing.T, database *db.DB)
		wantLog string
	}{
		{
			name: "SMTP config is disabled",
			setup: func(t *testing.T, database *db.DB) {
				if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
					ConfigJSON: `{"host":"localhost","port":"25","enabled":false}`,
				}); err != nil {
					t.Fatalf("saving SMTP config: %v", err)
				}
			},
			wantLog: "SMTP not usable",
		},
		{
			name: "template subject is malformed",
			setup: func(t *testing.T, database *db.DB) {
				saveSMTP(t, database, liveHost, livePort)
				if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
					TemplateType: "password_changed",
					Subject:      "{{.Username",
					BodyHTML:     "<p>ok</p>",
				}); err != nil {
					t.Fatalf("saving template: %v", err)
				}
			},
			wantLog: "failed to render notification email subject",
		},
		{
			name: "template body is malformed",
			setup: func(t *testing.T, database *db.DB) {
				saveSMTP(t, database, liveHost, livePort)
				if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
					TemplateType: "password_changed",
					Subject:      "Password changed",
					BodyHTML:     "<p>{{.Username</p>",
				}); err != nil {
					t.Fatalf("saving template: %v", err)
				}
			},
			wantLog: "failed to render notification email body",
		},
		{
			name: "SMTP host is unreachable",
			setup: func(t *testing.T, database *db.DB) {
				saveSMTP(t, database, "127.0.0.1", "1")
			},
			wantLog: "failed to send notification email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			database := setupTestDB(t)
			logger, logs := bufferLogger()
			tt.setup(t, database)

			sendPasswordEventEmail(context.Background(), database, testCryptoService(t), logger,
				"password_changed", "corp-ad", "Corp AD", "jdoe", "jdoe@example.com", "10.0.0.1")

			if !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("expected a log containing %q, got: %s", tt.wantLog, logs.String())
			}
		})
	}
}

// TestSendPasswordEventEmail_IDPSpecificTemplate verifies the per-IDP template
// ("<type>:<idpID>") takes precedence over the global one.
func TestSendPasswordEventEmail_IDPSpecificTemplate(t *testing.T) {
	database := setupTestDB(t)
	logger, logs := bufferLogger()

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()
	host, port, _ := strings.Cut(addr, ":")
	saveSMTP(t, database, host, port)

	if err := database.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "password_changed:corp-ad",
		Subject:      "Corp AD password changed for {{.Username}}",
		BodyHTML:     "<p>{{.Timestamp}} from {{.IPAddress}}</p>",
	}); err != nil {
		t.Fatalf("saving template: %v", err)
	}

	sendPasswordEventEmail(context.Background(), database, testCryptoService(t), logger,
		"password_changed", "corp-ad", "Corp AD", "jdoe", "jdoe@example.com", "10.0.0.1")

	if !strings.Contains(logs.String(), "notification email sent") {
		t.Errorf("expected the email to be sent, got: %s", logs.String())
	}
}

// mockNoTemplateStore reports that no email template exists, which migrations
// otherwise always seed.
type mockNoTemplateStore struct {
	*db.DB
}

func (m *mockNoTemplateStore) GetEmailTemplate(context.Context, string) (*db.EmailTemplate, error) {
	return nil, nil
}

func TestSendPasswordEventEmail_NoTemplate(t *testing.T) {
	database := setupTestDB(t)
	logger, logs := bufferLogger()
	saveSMTP(t, database, "127.0.0.1", "25")

	sendPasswordEventEmail(context.Background(), &mockNoTemplateStore{DB: database}, testCryptoService(t), logger,
		"password_changed", "corp-ad", "Corp AD", "jdoe", "jdoe@example.com", "10.0.0.1")

	if !strings.Contains(logs.String(), "template not found") {
		t.Errorf("expected a template-not-found log, got: %s", logs.String())
	}
}
