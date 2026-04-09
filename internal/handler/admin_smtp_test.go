package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
)

type smtpTestEnv struct {
	db      *db.DB
	crypto  *crypto.Service
	handler *AdminSMTPHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubSMTPRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_smtp.html"] = template.Must(template.New("admin_smtp.html").Funcs(funcMap).Parse(`{{define "base"}}smtp config page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupSMTPTest(t *testing.T) *smtpTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubSMTPRenderer(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	_ = tmpFile.Close()

	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	h := NewAdminSMTPHandler(database, cryptoSvc, renderer, auditLog, logger)

	return &smtpTestEnv{
		db:      database,
		crypto:  cryptoSvc,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *smtpTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
	t.Helper()

	hash, err := auth.HashPassword("admin-pass")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := env.db.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		if !strings.Contains(err.Error(), "UNIQUE") {
			t.Fatalf("creating admin: %v", err)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = env.sm.CreateSession(rec, req, "local", "", "admin", true, false)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	return rec.Result().Cookies()
}

func (env *smtpTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
	t.Helper()

	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	wrapped := env.sm.Middleware(handler)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

func TestSMTPShow(t *testing.T) {
	env := setupSMTPTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "smtp config page") {
		t.Errorf("expected smtp config content, got: %s", rec.Body.String())
	}
}

func TestSMTPSave(t *testing.T) {
	env := setupSMTPTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("host", "smtp.example.com")
	form.Set("port", "587")
	form.Set("username", "smtp-user")
	form.Set("password", "smtp-pass")
	form.Set("from_address", "noreply@example.com")
	form.Set("from_name", "PassPort")
	form.Set("use_tls", "on")
	form.Set("enabled", "on")

	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/smtp", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify SMTP config was saved.
	cfg, err := env.db.GetSMTPConfig(context.Background())
	if err != nil {
		t.Fatalf("getting SMTP config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected SMTP config to exist")
	}

	var configFields SMTPConfigFields
	if err := json.Unmarshal([]byte(cfg.ConfigJSON), &configFields); err != nil {
		t.Fatalf("unmarshaling config JSON: %v", err)
	}
	if configFields.Host != "smtp.example.com" {
		t.Errorf("expected host smtp.example.com, got %s", configFields.Host)
	}
	if !configFields.Enabled {
		t.Error("expected SMTP to be enabled")
	}

	// Verify secrets were encrypted.
	plaintext, err := env.crypto.Decrypt(cfg.SecretBlob)
	if err != nil {
		t.Fatalf("decrypting SMTP secrets: %v", err)
	}
	var secrets SMTPSecrets
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		t.Fatalf("unmarshaling SMTP secrets: %v", err)
	}
	if secrets.Username != "smtp-user" {
		t.Errorf("expected username smtp-user, got %s", secrets.Username)
	}
}

func TestSMTPTestEmail(t *testing.T) {
	env := setupSMTPTest(t)
	cookies := env.createAdminSession(t)

	// First, save a valid SMTP config.
	configFields := SMTPConfigFields{
		Host:    "smtp.example.com",
		Port:    "587",
		Enabled: true,
	}
	configJSON, _ := json.Marshal(configFields)
	secrets := SMTPSecrets{Username: "user", Password: "pass"}
	secretsJSON, _ := json.Marshal(secrets)
	secretBlob, _ := env.crypto.Encrypt(secretsJSON)

	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: secretBlob,
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	// The test email endpoint now requires a 'to' address but actually sends mail,
	// so we test the validation path: a missing 'to' returns 400.
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, "")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 (missing to), got %d", rec.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status error, got %s: %s", result["status"], result["message"])
	}
}

func TestSMTPTestEmailNoConfig(t *testing.T) {
	env := setupSMTPTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, "")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status error, got %s", result["status"])
	}
}

// --- Additional tests appended below ---

// TestRenderSimpleTemplate verifies that renderSimpleTemplate parses and
// executes a Go html/template string with the given data.
func TestRenderSimpleTemplate(t *testing.T) {
	tmplStr := `<p>Hello {{.Name}}, sent at {{.Timestamp}}.</p>`
	data := map[string]string{
		"Name":      "World",
		"Timestamp": "Jan 1, 2026",
	}

	result, err := renderSimpleTemplate(tmplStr, data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result, "Hello World") {
		t.Errorf("expected 'Hello World' in output, got: %s", result)
	}
	if !strings.Contains(result, "Jan 1, 2026") {
		t.Errorf("expected 'Jan 1, 2026' in output, got: %s", result)
	}
}

func TestRenderSimpleTemplate_EmptyTemplate(t *testing.T) {
	result, err := renderSimpleTemplate("", nil)
	if err != nil {
		t.Fatalf("unexpected error on empty template: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result, got: %s", result)
	}
}

func TestRenderSimpleTemplate_InvalidSyntax(t *testing.T) {
	_, err := renderSimpleTemplate(`{{.Unclosed`, nil)
	if err == nil {
		t.Error("expected error for invalid template syntax")
	}
}

func TestRenderSimpleTemplate_NoVariables(t *testing.T) {
	result, err := renderSimpleTemplate("<p>Static content</p>", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "<p>Static content</p>" {
		t.Errorf("expected '<p>Static content</p>', got: %s", result)
	}
}

// TestSendEmail_PlainError verifies that sendEmail returns an error when the
// SMTP host is unreachable (no server listening on the given port).
func TestSendEmail_PlainError(t *testing.T) {
	cfg := SMTPConfigFields{
		Host:        "127.0.0.1",
		Port:        "60999", // nothing listening here
		UseTLS:      false,
		FromAddress: "test@example.com",
	}
	err := sendEmail(cfg, SMTPSecrets{}, "to@example.com", "Test Subject", "<p>Test body</p>")
	if err == nil {
		t.Error("expected error from sendEmail to unreachable host")
	}
}

// TestSendEmail_TLSError verifies that sendEmail returns an error when the
// TLS SMTP host is unreachable.
func TestSendEmail_TLSError(t *testing.T) {
	cfg := SMTPConfigFields{
		Host:        "127.0.0.1",
		Port:        "60998", // nothing listening here
		UseTLS:      true,
		FromAddress: "test@example.com",
	}
	err := sendEmail(cfg, SMTPSecrets{}, "to@example.com", "Test Subject", "<p>Test body</p>")
	if err == nil {
		t.Error("expected error from sendEmail with TLS to unreachable host")
	}
}

// TestSmtpSend requires an established smtp.Client from a real SMTP server
// and cannot be tested in a unit test environment without a live SMTP server.
func TestSmtpSend_Skip(t *testing.T) {
	t.Skip("smtpSend requires an established smtp.Client; covered indirectly by TestSendEmail_PlainError")
}

// TestSMTPShowWithConfig tests the Show handler when SMTP config is pre-saved.
func TestSMTPShowWithConfig(t *testing.T) {
	env := setupSMTPTest(t)

	// Pre-save a config with secrets.
	configFields := SMTPConfigFields{
		Host:        "smtp.example.com",
		Port:        "587",
		FromAddress: "no-reply@example.com",
		Enabled:     true,
	}
	configJSON, _ := json.Marshal(configFields)
	secrets := SMTPSecrets{Username: "user", Password: "pass"}
	secretsJSON, _ := json.Marshal(secrets)
	secretBlob, _ := env.crypto.Encrypt(secretsJSON)

	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: secretBlob,
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// mockSMTPErrStore wraps *db.DB and overrides SaveSMTPConfig to inject errors.
type mockSMTPErrStore struct {
	*db.DB
	saveSMTPConfigErr   error
	getSMTPConfigErr    error
	getEmailTemplateErr error
}

func (m *mockSMTPErrStore) SaveSMTPConfig(ctx context.Context, cfg *db.SMTPConfig) error {
	if m.saveSMTPConfigErr != nil {
		return m.saveSMTPConfigErr
	}
	return m.DB.SaveSMTPConfig(ctx, cfg)
}

func (m *mockSMTPErrStore) GetSMTPConfig(ctx context.Context) (*db.SMTPConfig, error) {
	if m.getSMTPConfigErr != nil {
		return nil, m.getSMTPConfigErr
	}
	return m.DB.GetSMTPConfig(ctx)
}

func (m *mockSMTPErrStore) GetEmailTemplate(ctx context.Context, templateType string) (*db.EmailTemplate, error) {
	if m.getEmailTemplateErr != nil {
		return nil, m.getEmailTemplateErr
	}
	return m.DB.GetEmailTemplate(ctx, templateType)
}

// TestSMTPSave_SaveConfigError covers admin_smtp.go:171-184 where SaveSMTPConfig
// fails and the handler re-renders the SMTP page with a flash error (200 response).
func TestSMTPSave_SaveConfigError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockSMTPErrStore{
		DB:                database,
		saveSMTPConfigErr: fmt.Errorf("disk full"),
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	_ = tmpFile.Close()

	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	renderer := stubSMTPRenderer(t)
	h := NewAdminSMTPHandler(mockStore, cryptoSvc, renderer, auditLog, logger)

	form := url.Values{}
	form.Set("host", "smtp.example.com")
	form.Set("port", "587")
	req := httptest.NewRequest(http.MethodPost, "/admin/smtp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	// SaveSMTPConfig failure re-renders the page with a flash error (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when SaveSMTPConfig fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "smtp config page") {
		t.Errorf("expected smtp page re-render, got: %s", rec.Body.String())
	}
}

// TestSMTPTestEmail_NotEnabled verifies that TestEmail returns an error when SMTP is disabled.
func TestSMTPTestEmail_NotEnabled(t *testing.T) {
	env := setupSMTPTest(t)

	configFields := SMTPConfigFields{
		Host:    "smtp.example.com",
		Port:    "587",
		Enabled: false,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(configJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestSMTPTestEmail_EmptyHostPort verifies that TestEmail returns an error when host/port are empty.
func TestSMTPTestEmail_EmptyHostPort(t *testing.T) {
	env := setupSMTPTest(t)

	configFields := SMTPConfigFields{
		Host:    "",
		Port:    "",
		Enabled: true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(configJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestSMTPTestEmail_Success uses a fake SMTP server to exercise the successful send path.
func TestSMTPTestEmail_Success(t *testing.T) {
	env := setupSMTPTest(t)

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := strings.Cut(addr, ":")
	configFields := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		Enabled:     true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(configJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "recipient@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("expected success, got %s: %s", result["status"], result["message"])
	}
}

// TestSMTPTestEmail_SuccessWithTemplate exercises the email template found branch.
func TestSMTPTestEmail_SuccessWithTemplate(t *testing.T) {
	env := setupSMTPTest(t)

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	// Seed an smtp_test email template so the handler uses it rather than the fallback.
	if err := env.db.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "smtp_test",
		Subject:      "Test Subject {{.Timestamp}}",
		BodyHTML:     "<p>Test at {{.Timestamp}}</p>",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}

	host, port, _ := strings.Cut(addr, ":")
	configFields := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		Enabled:     true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(configJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "recipient@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("expected success, got %s: %s", result["status"], result["message"])
	}
}

// TestRenderSimpleTemplate_ExecuteError verifies that renderSimpleTemplate returns an
// error when template execution fails (e.g. calling a non-function value).
func TestRenderSimpleTemplate_ExecuteError(t *testing.T) {
	// {{call .}} on a string (non-function) causes Execute to return an error.
	_, err := renderSimpleTemplate("{{call .}}", "not-a-function")
	if err == nil {
		t.Error("expected error for calling a non-function value in template")
	}
}

// TestSMTPTestEmail_InvalidConfigJSON verifies that TestEmail returns 500 when
// the stored ConfigJSON cannot be unmarshaled.
func TestSMTPTestEmail_InvalidConfigJSON(t *testing.T) {
	env := setupSMTPTest(t)

	// Save a config with invalid JSON in ConfigJSON.
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: "not-valid-json{",
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid config JSON, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestSMTPTestEmail_DecryptError verifies that TestEmail returns 500 when the
// stored SecretBlob cannot be decrypted.
func TestSMTPTestEmail_DecryptError(t *testing.T) {
	env := setupSMTPTest(t)

	// Save a config with valid enabled fields but a corrupt SecretBlob.
	configFields := SMTPConfigFields{
		Host:    "127.0.0.1",
		Port:    "25",
		Enabled: true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: []byte("not-valid-ciphertext"),
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for decrypt error, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestSMTPTestEmail_InvalidSecretsJSON verifies that TestEmail returns 500 when
// the SecretBlob decrypts successfully but the plaintext is not valid JSON.
func TestSMTPTestEmail_InvalidSecretsJSON(t *testing.T) {
	env := setupSMTPTest(t)

	// Encrypt bytes that are not valid JSON.
	blob, err := env.crypto.Encrypt([]byte("not-json-bytes"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	configFields := SMTPConfigFields{
		Host:    "127.0.0.1",
		Port:    "25",
		Enabled: true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: blob,
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid secrets JSON, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestSMTPTestEmail_BodyTemplateError exercises the else branch where BodyHTML fails
// to render (htmlBody = tmpl.BodyHTML). Email is still sent using the raw template string.
func TestSMTPTestEmail_BodyTemplateError(t *testing.T) {
	env := setupSMTPTest(t)

	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	// Seed an smtp_test template with a syntactically invalid BodyHTML.
	if err := env.db.SaveEmailTemplate(context.Background(), &db.EmailTemplate{
		TemplateType: "smtp_test",
		Subject:      "Test Subject",
		BodyHTML:     "{{.Unclosed",
	}); err != nil {
		t.Fatalf("saving email template: %v", err)
	}

	host, port, _ := strings.Cut(addr, ":")
	configFields := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		Enabled:     true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(configJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	form := url.Values{}
	form.Set("to", "recipient@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	// Email is sent with the raw template string as body (renderSimpleTemplate parse error → else branch).
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 even with body template error, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("expected success, got %s: %s", result["status"], result["message"])
	}
}

// TestSMTPTestEmail_ValidToWithBadSMTP verifies the path where 'to' is valid
// but the SMTP send fails (connection refused confirms the plumbing works).
func TestSMTPTestEmail_ValidToWithBadSMTP(t *testing.T) {
	env := setupSMTPTest(t)

	// Save a config that will fail to connect.
	configFields := SMTPConfigFields{
		Host:        "127.0.0.1",
		Port:        "60997",
		FromAddress: "no-reply@example.com",
		Enabled:     true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	// Expect an error response (SMTP connection refused).
	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest && rec.Code != http.StatusInternalServerError {
		t.Errorf("unexpected status %d", rec.Code)
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestSMTPTestEmail_NoConfigWithValidTo covers the cfg == nil path in TestEmail
// (valid to address, but no SMTP config has been saved → 400).
func TestSMTPTestEmail_NoConfigWithValidTo(t *testing.T) {
	env := setupSMTPTest(t)
	cookies := env.createAdminSession(t)

	// No SMTP config saved — GetSMTPConfig returns nil, nil.
	form := url.Values{}
	form.Set("to", "test@example.com")
	rec := env.serveWithAdminSession(t, env.handler.TestEmail, http.MethodPost, "/admin/smtp/test", cookies, form.Encode())

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when no config exists, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestSMTPShow_InvalidConfigJSON covers Show when ConfigJSON is invalid JSON (soft error — logs and continues).
func TestSMTPShow_InvalidConfigJSON(t *testing.T) {
	env := setupSMTPTest(t)

	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: "not-valid-json{",
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	// Soft error — page still renders 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSMTPShow_DecryptError covers Show when SecretBlob cannot be decrypted (soft error).
func TestSMTPShow_DecryptError(t *testing.T) {
	env := setupSMTPTest(t)

	configJSON, _ := json.Marshal(SMTPConfigFields{Host: "smtp.example.com", Port: "587", Enabled: true})
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: []byte("not-valid-ciphertext"),
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	// Soft error — page still renders 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSMTPShow_InvalidSecretsJSON covers Show when decrypted SecretBlob is not valid JSON (soft error).
func TestSMTPShow_InvalidSecretsJSON(t *testing.T) {
	env := setupSMTPTest(t)

	blob, err := env.crypto.Encrypt([]byte("not-json-bytes"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	configJSON, _ := json.Marshal(SMTPConfigFields{Host: "smtp.example.com", Port: "587", Enabled: true})
	if err := env.db.SaveSMTPConfig(context.Background(), &db.SMTPConfig{
		ConfigJSON: string(configJSON),
		SecretBlob: blob,
	}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/smtp", cookies, "")

	// Soft error — page still renders 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// newSMTPMockHandler creates an AdminSMTPHandler backed by the given mock store.
func newSMTPMockHandler(t *testing.T, database *db.DB, mock *mockSMTPErrStore) *AdminSMTPHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}
	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	return NewAdminSMTPHandler(mock, cryptoSvc, stubSMTPRenderer(t), auditLog, logger)
}

// TestSMTPShow_GetConfigError covers Show when GetSMTPConfig returns an error
// (admin_smtp.go line 79 — soft error, logs and continues to render 200).
func TestSMTPShow_GetConfigError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockSMTPErrStore{DB: database, getSMTPConfigErr: fmt.Errorf("DB read failed")}
	h := newSMTPMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/smtp", nil)
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	// Soft error — page still renders 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when GetSMTPConfig fails (soft error), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSMTPSave_ParseFormError covers Save when ParseForm fails
// (admin_smtp.go lines 123-125).
func TestSMTPSave_ParseFormError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockSMTPErrStore{DB: database}
	h := newSMTPMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/smtp", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for Save ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSMTPTestEmail_GetEmailTemplateError covers admin_smtp.go:284-288 where
// GetEmailTemplate returns an error, causing the handler to use the fallback subject/body.
func TestSMTPTestEmail_GetEmailTemplateError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	mockStore := &mockSMTPErrStore{
		DB:                  database,
		getEmailTemplateErr: fmt.Errorf("template not found"),
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	renderer := stubSMTPRenderer(t)
	h := NewAdminSMTPHandler(mockStore, cryptoSvc, renderer, auditLog, logger)
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)

	// Start a fake SMTP server to accept the outbound email.
	addr, stop := fakeSMTPServerHandler(t)
	defer stop()

	host, port, _ := strings.Cut(addr, ":")
	configFields := SMTPConfigFields{
		Host:        host,
		Port:        port,
		FromAddress: "from@example.com",
		Enabled:     true,
	}
	configJSON, _ := json.Marshal(configFields)
	if err := database.SaveSMTPConfig(context.Background(), &db.SMTPConfig{ConfigJSON: string(configJSON)}); err != nil {
		t.Fatalf("saving SMTP config: %v", err)
	}

	// Create admin session.
	hash, err := auth.HashPassword("admin-pass")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := database.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(wCookie, rCookie, "local", "", "admin", true, false); err != nil {
		t.Fatalf("creating admin session: %v", err)
	}
	cookies := wCookie.Result().Cookies()

	form := url.Values{}
	form.Set("to", "recipient@example.com")
	req := httptest.NewRequest(http.MethodPost, "/admin/smtp/test", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	sm.Middleware(http.HandlerFunc(h.TestEmail)).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "success" {
		t.Errorf("expected success, got %s: %s", result["status"], result["message"])
	}
}
