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

type mfaTestEnv struct {
	db      *db.DB
	crypto  *crypto.Service
	handler *AdminMFAHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubMFARenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_mfa_list.html"] = template.Must(template.New("admin_mfa_list.html").Funcs(funcMap).Parse(`{{define "base"}}mfa list page{{end}}`))
	pages["admin_mfa_form.html"] = template.Must(template.New("admin_mfa_form.html").Funcs(funcMap).Parse(`{{define "base"}}mfa form page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupMFATest(t *testing.T) *mfaTestEnv {
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
	renderer := stubMFARenderer(t)

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

	h := NewAdminMFAHandler(database, cryptoSvc, renderer, auditLog, logger)

	return &mfaTestEnv{
		db:      database,
		crypto:  cryptoSvc,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *mfaTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *mfaTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

// createTestDuoProvider inserts a Duo MFA provider record directly in the DB
// and returns its ID.
func (env *mfaTestEnv) createTestDuoProvider(t *testing.T) string {
	t.Helper()

	record := &db.MFAProviderRecord{
		ID:           "test-duo-id",
		Name:         "Test Duo",
		ProviderType: "duo",
		Enabled:      false,
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"DICLIENTID","redirect_uri":"https://example.com/callback"}`,
		SecretBlob:   nil,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating test Duo provider: %v", err)
	}
	return record.ID
}

// --- Unit tests for pure/private functions ---

func TestParseInt(t *testing.T) {
	tests := []struct {
		input   string
		want    int
		wantErr bool
	}{
		{"5", 5, false},
		{"0", 0, false},
		{"100", 100, false},
		{" 42 ", 42, false}, // TrimSpace applied
		{"abc", 0, true},
		{"", 0, true},
		{"3.14", 0, true},
		{"-1", -1, false},
	}
	for _, tc := range tests {
		got, err := parseInt(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseInt(%q): error=%v, wantErr=%v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseInt(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestMarshalProviderConfig_Duo(t *testing.T) {
	env := setupMFATest(t)

	form := url.Values{
		"api_hostname":  {"api.duo.example.com"},
		"client_id":     {"DICLIENTID123"},
		"redirect_uri":  {"https://example.com/mfa/callback"},
		"client_secret": {"super-secret-value"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	configJSON, secretBlob, err := env.handler.marshalProviderConfig(req, "duo", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// configJSON should be valid JSON with the Duo fields.
	var cfg map[string]any
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("configJSON not valid JSON: %v", err)
	}
	if cfg["api_hostname"] != "api.duo.example.com" {
		t.Errorf("expected api_hostname 'api.duo.example.com', got %v", cfg["api_hostname"])
	}
	if cfg["client_id"] != "DICLIENTID123" {
		t.Errorf("expected client_id 'DICLIENTID123', got %v", cfg["client_id"])
	}

	// secretBlob should be an encrypted blob that decrypts to the client_secret.
	if len(secretBlob) == 0 {
		t.Fatal("expected non-empty secretBlob")
	}
	plaintext, err := env.crypto.Decrypt(secretBlob)
	if err != nil {
		t.Fatalf("decrypting secretBlob: %v", err)
	}
	var secrets map[string]any
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		t.Fatalf("secrets JSON invalid: %v", err)
	}
	if secrets["client_secret"] != "super-secret-value" {
		t.Errorf("expected client_secret 'super-secret-value', got %v", secrets["client_secret"])
	}
}

func TestMarshalProviderConfig_DuoPreservesExistingSecret(t *testing.T) {
	// When updating and client_secret is blank, the existing encrypted secret
	// should be preserved.
	env := setupMFATest(t)

	// Create an existing record with an encrypted secret.
	origSecrets := `{"client_secret":"original-secret"}`
	encrypted, err := env.crypto.Encrypt([]byte(origSecrets))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	existing := &db.MFAProviderRecord{
		ID:           "existing-id",
		ProviderType: "duo",
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"DIC","redirect_uri":""}`,
		SecretBlob:   encrypted,
	}

	// POST with blank client_secret (update scenario).
	form := url.Values{
		"api_hostname":  {"api.duo.example.com"},
		"client_id":     {"DIC"},
		"redirect_uri":  {""},
		"client_secret": {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, secretBlob, err := env.handler.marshalProviderConfig(req, "duo", existing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The new secretBlob should still contain the original secret.
	plaintext, err := env.crypto.Decrypt(secretBlob)
	if err != nil {
		t.Fatalf("decrypting secretBlob: %v", err)
	}
	var secrets map[string]any
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		t.Fatalf("secrets JSON invalid: %v", err)
	}
	if secrets["client_secret"] != "original-secret" {
		t.Errorf("expected preserved 'original-secret', got %v", secrets["client_secret"])
	}
}

func TestMarshalProviderConfig_UnknownType(t *testing.T) {
	env := setupMFATest(t)

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	_, _, err := env.handler.marshalProviderConfig(req, "unknown_type", nil)
	if err == nil {
		t.Error("expected error for unknown provider type")
	}
}

// --- Handler tests ---

func TestAdminMFAList(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/mfa", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mfa list page") {
		t.Errorf("expected mfa list page content, got: %s", rec.Body.String())
	}
}

func TestAdminMFAShowCreate(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.ShowCreate, http.MethodGet, "/admin/mfa/new", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mfa form page") {
		t.Errorf("expected mfa form page content, got: %s", rec.Body.String())
	}
}

func TestAdminMFACreate(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{
		"name":          {"My Duo Provider"},
		"provider_type": {"duo"},
		"api_hostname":  {"api.duo.example.com"},
		"client_id":     {"DICLIENTID"},
		"redirect_uri":  {"https://example.com/callback"},
		"client_secret": {"my-secret"},
	}

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/mfa", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302 (redirect), got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/mfa" {
		t.Errorf("expected redirect to /admin/mfa, got %s", loc)
	}

	// Verify provider was created.
	providers, err := env.db.ListMFAProviders(context.Background())
	if err != nil {
		t.Fatalf("listing MFA providers: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 MFA provider, got %d", len(providers))
	}
	if providers[0].Name != "My Duo Provider" {
		t.Errorf("expected name 'My Duo Provider', got %q", providers[0].Name)
	}
	if providers[0].ProviderType != "duo" {
		t.Errorf("expected type 'duo', got %q", providers[0].ProviderType)
	}
}

// TestRenderFormError verifies that Create with an empty name re-renders the
// form with an error flash (via renderFormError).
func TestRenderFormError_EmptyName(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{
		"name":          {""}, // empty name triggers renderFormError
		"provider_type": {"duo"},
	}

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/mfa", cookies, form.Encode())

	// renderFormError renders the mfa form (200), not a redirect.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (form re-render with error), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "mfa form page") {
		t.Errorf("expected mfa form page content, got: %s", rec.Body.String())
	}
}

func TestAdminMFACreate_InvalidProviderType(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{
		"name":          {"Bad Provider"},
		"provider_type": {"invalid_type"},
	}

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/mfa", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (error re-render), got %d", rec.Code)
	}
}

func TestAdminMFAShowEdit(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)
	providerID := env.createTestDuoProvider(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", providerID)
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/mfa/"+providerID+"/edit", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mfa form page") {
		t.Errorf("expected mfa form page content, got: %s", rec.Body.String())
	}
}

func TestAdminMFAShowEdit_NotFound(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-id")
		env.handler.ShowEdit(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/mfa/nonexistent-id/edit", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}

func TestAdminMFAUpdate(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)
	providerID := env.createTestDuoProvider(t)

	form := url.Values{
		"name":          {"Updated Duo"},
		"api_hostname":  {"updated.duo.example.com"},
		"client_id":     {"UPDATEDCLIENTID"},
		"redirect_uri":  {"https://example.com/updated"},
		"client_secret": {"updated-secret"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", providerID)
		env.handler.Update(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/mfa/"+providerID, cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/mfa" {
		t.Errorf("expected redirect to /admin/mfa, got %s", loc)
	}

	// Verify the name was updated.
	provider, err := env.db.GetMFAProvider(context.Background(), providerID)
	if err != nil {
		t.Fatalf("getting MFA provider: %v", err)
	}
	if provider.Name != "Updated Duo" {
		t.Errorf("expected name 'Updated Duo', got %q", provider.Name)
	}
}

func TestAdminMFADelete(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)
	providerID := env.createTestDuoProvider(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", providerID)
		env.handler.Delete(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/mfa/"+providerID+"/delete", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/mfa" {
		t.Errorf("expected redirect to /admin/mfa, got %s", loc)
	}

	// Verify the provider was deleted.
	providers, err := env.db.ListMFAProviders(context.Background())
	if err != nil {
		t.Fatalf("listing MFA providers: %v", err)
	}
	if len(providers) != 0 {
		t.Errorf("expected 0 providers after delete, got %d", len(providers))
	}
}

func TestAdminMFAToggle(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)
	providerID := env.createTestDuoProvider(t)

	// Provider starts disabled; toggling should enable it.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", providerID)
		env.handler.Toggle(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/mfa/"+providerID+"/toggle", cookies, "")

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify enabled state was flipped.
	provider, err := env.db.GetMFAProvider(context.Background(), providerID)
	if err != nil {
		t.Fatalf("getting MFA provider: %v", err)
	}
	if !provider.Enabled {
		t.Error("expected provider to be enabled after toggle from disabled")
	}
}

func TestAdminMFAToggle_SecondTime(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)
	providerID := env.createTestDuoProvider(t)

	doToggle := func() {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = withChiURLParam(r, "id", providerID)
			env.handler.Toggle(w, r)
		})
		env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/mfa/"+providerID+"/toggle", cookies, "")
	}

	// Toggle once → enabled.
	doToggle()
	// Toggle again → disabled.
	doToggle()

	provider, err := env.db.GetMFAProvider(context.Background(), providerID)
	if err != nil {
		t.Fatalf("getting MFA provider: %v", err)
	}
	if provider.Enabled {
		t.Error("expected provider to be disabled after second toggle")
	}
}

func TestAdminMFASetDefault(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)
	providerID := env.createTestDuoProvider(t)

	form := url.Values{}
	form.Set("default_mfa_provider_id", providerID)

	rec := env.serveWithAdminSession(t, env.handler.SetDefault, http.MethodPost, "/admin/mfa/default", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/mfa" {
		t.Errorf("expected redirect to /admin/mfa, got %s", loc)
	}

	// Verify the default was set.
	defaultID, err := env.db.GetDefaultMFAProviderID(context.Background())
	if err != nil {
		t.Fatalf("getting default MFA provider ID: %v", err)
	}
	if defaultID == nil || *defaultID != providerID {
		t.Errorf("expected default MFA provider ID %q, got %v", providerID, defaultID)
	}
}

func TestAdminMFASetDefault_Clear(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	// Setting with an empty string clears the default.
	form := url.Values{}
	form.Set("default_mfa_provider_id", "")

	rec := env.serveWithAdminSession(t, env.handler.SetDefault, http.MethodPost, "/admin/mfa/default", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminMFACreate_EmailType(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{
		"name":            {"Email OTP"},
		"provider_type":   {"email"},
		"otp_length":      {"6"},
		"otp_ttl_minutes": {"10"},
		"email_subject":   {"Your code"},
	}

	rec := env.serveWithAdminSession(t, env.handler.Create, http.MethodPost, "/admin/mfa", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d; body: %s", rec.Code, rec.Body.String())
	}

	providers, err := env.db.ListMFAProviders(context.Background())
	if err != nil {
		t.Fatalf("listing MFA providers: %v", err)
	}
	if len(providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(providers))
	}
	if providers[0].ProviderType != "email" {
		t.Errorf("expected provider type 'email', got %q", providers[0].ProviderType)
	}
}

func TestAdminMFAList_WithProviders(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	// Create a provider so the list is non-empty.
	env.createTestDuoProvider(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/mfa", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// TestAdminMFA_TestConnection_NotFound verifies that TestConnection returns 404
// when the MFA provider is not found.
func TestAdminMFA_TestConnection_NotFound(t *testing.T) {
	env := setupMFATest(t)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/nonexistent/test", nil),
		"id", "nonexistent",
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_TestConnection_EmailOTP verifies that TestConnection for email OTP
// returns 200 (email OTP has no external dependency).
func TestAdminMFA_TestConnection_EmailOTP(t *testing.T) {
	env := setupMFATest(t)

	// Create an email OTP provider.
	cfgBytes, _ := json.Marshal(map[string]any{
		"otp_length":      6,
		"otp_ttl_minutes": 5,
		"email_subject":   "OTP",
	})
	providerID := "test-email-otp-id"
	record := &db.MFAProviderRecord{
		ID:           providerID,
		Name:         "email-otp",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+providerID+"/test", nil),
		"id", providerID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	// Email OTP HealthCheck always returns nil → status online.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// mockMFAErrStore wraps *db.DB and overrides specific methods to inject errors.
type mockMFAErrStore struct {
	*db.DB
	listProvidersErr           error
	createProviderErr          error
	getMFALoginRequiredErr     error
	setMFALoginRequiredErr     error
	getDefaultMFAProviderIDErr error
}

func (m *mockMFAErrStore) ListMFAProviders(ctx context.Context) ([]db.MFAProviderRecord, error) {
	if m.listProvidersErr != nil {
		return nil, m.listProvidersErr
	}
	return m.DB.ListMFAProviders(ctx)
}

func (m *mockMFAErrStore) CreateMFAProvider(ctx context.Context, record *db.MFAProviderRecord) error {
	if m.createProviderErr != nil {
		return m.createProviderErr
	}
	return m.DB.CreateMFAProvider(ctx, record)
}

func (m *mockMFAErrStore) GetMFALoginRequired(ctx context.Context) (bool, error) {
	if m.getMFALoginRequiredErr != nil {
		return false, m.getMFALoginRequiredErr
	}
	return m.DB.GetMFALoginRequired(ctx)
}

func (m *mockMFAErrStore) SetMFALoginRequired(ctx context.Context, required bool) error {
	if m.setMFALoginRequiredErr != nil {
		return m.setMFALoginRequiredErr
	}
	return m.DB.SetMFALoginRequired(ctx, required)
}

func (m *mockMFAErrStore) GetDefaultMFAProviderID(ctx context.Context) (*string, error) {
	if m.getDefaultMFAProviderIDErr != nil {
		return nil, m.getDefaultMFAProviderIDErr
	}
	return m.DB.GetDefaultMFAProviderID(ctx)
}

func newMFAMockHandler(t *testing.T, database *db.DB, mock *mockMFAErrStore) *AdminMFAHandler {
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
	renderer := stubMFARenderer(t)
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
	return NewAdminMFAHandler(mock, cryptoSvc, renderer, auditLog, logger)
}

// TestAdminMFAList_DBError covers List when ListMFAProviders fails (lines 56-60).
func TestAdminMFAList_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAErrStore{DB: database, listProvidersErr: fmt.Errorf("DB read failed")}
	h := newMFAMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/mfa", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListMFAProviders fails, got %d", rec.Code)
	}
}

// TestAdminMFACreate_DBError covers Create when CreateMFAProvider fails (lines 138-142).
func TestAdminMFACreate_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAErrStore{DB: database, createProviderErr: fmt.Errorf("DB write failed")}
	h := newMFAMockHandler(t, database, mock)

	form := url.Values{
		"name":          {"My Duo"},
		"provider_type": {"duo"},
		"api_hostname":  {"api.duo.example.com"},
		"client_id":     {"DICLIENTID"},
		"redirect_uri":  {"https://example.com/callback"},
		"client_secret": {"my-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/mfa", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	// CreateMFAProvider failure calls renderFormError → re-renders form (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (form re-render) when CreateMFAProvider fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mfa form page") {
		t.Errorf("expected mfa form page content, got: %s", rec.Body.String())
	}
}

// mockMFAFullStore adds additional DB method overrides for Update/Delete/Toggle/SetDefault error tests.
type mockMFAFullStore struct {
	*db.DB
	getMFAProviderErr        error
	getMFAProviderRecord     *db.MFAProviderRecord
	updateMFAProviderErr     error
	deleteMFAProviderErr     error
	toggleMFAProviderErr     error
	setDefaultMFAProviderErr error
}

func (m *mockMFAFullStore) GetMFAProvider(ctx context.Context, id string) (*db.MFAProviderRecord, error) {
	if m.getMFAProviderErr != nil {
		return nil, m.getMFAProviderErr
	}
	if m.getMFAProviderRecord != nil {
		return m.getMFAProviderRecord, nil
	}
	return m.DB.GetMFAProvider(ctx, id)
}

func (m *mockMFAFullStore) UpdateMFAProvider(ctx context.Context, record *db.MFAProviderRecord) error {
	if m.updateMFAProviderErr != nil {
		return m.updateMFAProviderErr
	}
	return m.DB.UpdateMFAProvider(ctx, record)
}

func (m *mockMFAFullStore) DeleteMFAProvider(ctx context.Context, id string) error {
	if m.deleteMFAProviderErr != nil {
		return m.deleteMFAProviderErr
	}
	return m.DB.DeleteMFAProvider(ctx, id)
}

func (m *mockMFAFullStore) ToggleMFAProvider(ctx context.Context, id string, enabled bool) error {
	if m.toggleMFAProviderErr != nil {
		return m.toggleMFAProviderErr
	}
	return m.DB.ToggleMFAProvider(ctx, id, enabled)
}

func (m *mockMFAFullStore) SetDefaultMFAProviderID(ctx context.Context, id *string) error {
	if m.setDefaultMFAProviderErr != nil {
		return m.setDefaultMFAProviderErr
	}
	return m.DB.SetDefaultMFAProviderID(ctx, id)
}

func newMFAFullMockHandler(t *testing.T, database *db.DB, mock *mockMFAFullStore) *AdminMFAHandler {
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
	renderer := stubMFARenderer(t)
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
	return NewAdminMFAHandler(mock, cryptoSvc, renderer, auditLog, logger)
}

// TestAdminMFAUpdate_GetProviderError covers Update when GetMFAProvider fails → 404.
func TestAdminMFAUpdate_GetProviderError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAFullStore{DB: database, getMFAProviderErr: fmt.Errorf("not found")}
	h := newMFAFullMockHandler(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/nonexistent", nil),
		"id", "nonexistent",
	)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when GetMFAProvider fails, got %d", rec.Code)
	}
}

// TestAdminMFAUpdate_UpdateProviderError covers Update when UpdateMFAProvider fails → 500.
func TestAdminMFAUpdate_UpdateProviderError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAFullStore{DB: database, updateMFAProviderErr: fmt.Errorf("db write failed")}
	h := newMFAFullMockHandler(t, database, mock)

	// Create a real provider so GetMFAProvider succeeds.
	record := &db.MFAProviderRecord{
		ID:           "test-duo-update",
		Name:         "Test Duo",
		ProviderType: "duo",
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"DIC","redirect_uri":""}`,
	}
	if err := database.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating provider: %v", err)
	}

	form := url.Values{
		"name":          {"Updated Name"},
		"api_hostname":  {"api.duo.example.com"},
		"client_id":     {"DIC"},
		"redirect_uri":  {""},
		"client_secret": {"secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "id", record.ID)
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when UpdateMFAProvider fails, got %d", rec.Code)
	}
}

// TestAdminMFADelete_DBError covers Delete when DeleteMFAProvider fails → 500.
func TestAdminMFADelete_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAFullStore{DB: database, deleteMFAProviderErr: fmt.Errorf("db write failed")}
	h := newMFAFullMockHandler(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/someid/delete", nil),
		"id", "someid",
	)
	rec := httptest.NewRecorder()
	h.Delete(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when DeleteMFAProvider fails, got %d", rec.Code)
	}
}

// TestAdminMFAToggle_GetProviderError covers Toggle when GetMFAProvider fails → 404.
func TestAdminMFAToggle_GetProviderError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAFullStore{DB: database, getMFAProviderErr: fmt.Errorf("not found")}
	h := newMFAFullMockHandler(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/nonexistent/toggle", nil),
		"id", "nonexistent",
	)
	rec := httptest.NewRecorder()
	h.Toggle(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when GetMFAProvider fails in Toggle, got %d", rec.Code)
	}
}

// TestAdminMFAToggle_ToggleError covers Toggle when ToggleMFAProvider fails → 500.
func TestAdminMFAToggle_ToggleError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAFullStore{DB: database, toggleMFAProviderErr: fmt.Errorf("db write failed")}
	h := newMFAFullMockHandler(t, database, mock)

	// Create a real provider so GetMFAProvider succeeds.
	record := &db.MFAProviderRecord{
		ID:           "test-duo-toggle",
		Name:         "Test Duo",
		ProviderType: "duo",
		ConfigJSON:   `{}`,
	}
	if err := database.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/toggle", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	h.Toggle(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ToggleMFAProvider fails, got %d", rec.Code)
	}
}

// TestAdminMFASetDefault_DBError covers SetDefault when SetDefaultMFAProviderID fails → 500.
func TestAdminMFASetDefault_DBError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAFullStore{DB: database, setDefaultMFAProviderErr: fmt.Errorf("db write failed")}
	h := newMFAFullMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("default_mfa_provider_id", "some-id")
	req := httptest.NewRequest(http.MethodPost, "/admin/mfa/default", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.SetDefault(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when SetDefaultMFAProviderID fails, got %d", rec.Code)
	}
}

// TestAdminMFA_TestConnection_DuoInvalidConfig covers the path where DUO ConfigJSON
// cannot be unmarshaled (admin_mfa.go:329-335).
func TestAdminMFA_TestConnection_DuoInvalidConfig(t *testing.T) {
	env := setupMFATest(t)

	record := &db.MFAProviderRecord{
		ID:           "test-duo-badcfg",
		Name:         "Bad Config Duo",
		ProviderType: "duo",
		ConfigJSON:   "not-valid-json{",
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid DUO config JSON, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_TestConnection_DuoDecryptError covers the path where DUO SecretBlob
// cannot be decrypted (admin_mfa.go:338-345).
func TestAdminMFA_TestConnection_DuoDecryptError(t *testing.T) {
	env := setupMFATest(t)

	record := &db.MFAProviderRecord{
		ID:           "test-duo-badsecret",
		Name:         "Bad Secret Duo",
		ProviderType: "duo",
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"DIC","redirect_uri":""}`,
		SecretBlob:   []byte("not-a-valid-ciphertext"),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for DUO decrypt error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_TestConnection_DuoInvalidSecrets covers the path where the decrypted
// DUO secrets blob isn't valid JSON (admin_mfa.go:346-352).
func TestAdminMFA_TestConnection_DuoInvalidSecrets(t *testing.T) {
	env := setupMFATest(t)

	// Encrypt content that decrypts to invalid JSON.
	blob, err := env.crypto.Encrypt([]byte("not-json{"))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.MFAProviderRecord{
		ID:           "test-duo-badsecrets",
		Name:         "Bad Secrets Duo",
		ProviderType: "duo",
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"DIC","redirect_uri":""}`,
		SecretBlob:   blob,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for invalid DUO secrets JSON, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestToggleMFALogin_Success verifies that ToggleMFALogin toggles the setting and redirects.
func TestToggleMFALogin_Success(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.ToggleMFALogin, http.MethodPost, "/admin/mfa/login-toggle", cookies, "")

	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/admin/mfa" {
		t.Errorf("expected redirect to /admin/mfa, got %q", loc)
	}
}

// TestToggleMFALogin_GetError covers the GetMFALoginRequired error path.
func TestToggleMFALogin_GetError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAErrStore{
		DB:                     database,
		getMFALoginRequiredErr: fmt.Errorf("db read failed"),
	}
	h := newMFAMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/mfa/login-toggle", nil)
	rec := httptest.NewRecorder()
	h.ToggleMFALogin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for GetMFALoginRequired error, got %d", rec.Code)
	}
}

// TestToggleMFALogin_SetError covers the SetMFALoginRequired error path.
func TestToggleMFALogin_SetError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAErrStore{
		DB:                     database,
		setMFALoginRequiredErr: fmt.Errorf("db write failed"),
	}
	h := newMFAMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/mfa/login-toggle", nil)
	rec := httptest.NewRecorder()
	h.ToggleMFALogin(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for SetMFALoginRequired error, got %d", rec.Code)
	}
}

// --- Additional coverage tests ---

// TestRenderFormError_EditMode exercises the mode == "edit" branch in renderFormError
// which sets the title to "Edit MFA Provider".
func TestRenderFormError_EditMode(t *testing.T) {
	env := setupMFATest(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/mfa/test-id/edit", nil)
	rec := httptest.NewRecorder()
	env.handler.renderFormError(rec, req, "edit", nil, "some error", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mfa form page") {
		t.Errorf("expected mfa form page content, got: %s", rec.Body.String())
	}
}

// TestRenderFormError_WithProvider exercises the provider != nil branch in renderFormError
// which adds Provider and ProviderType to the template data.
func TestRenderFormError_WithProvider(t *testing.T) {
	env := setupMFATest(t)

	provider := &db.MFAProviderRecord{
		ID:           "test-provider-id",
		Name:         "Test Provider",
		ProviderType: "duo",
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/mfa/test-provider-id/edit", nil)
	rec := httptest.NewRecorder()
	env.handler.renderFormError(rec, req, "create", provider, "some error", nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_TestConnection_UnknownType verifies that TestConnection returns 400
// for a provider with an unknown type (default case in the provider-type switch).
func TestAdminMFA_TestConnection_UnknownType(t *testing.T) {
	database := setupTestDB(t)
	record := &db.MFAProviderRecord{
		ID:           "test-unknown-type",
		Name:         "Unknown Provider",
		ProviderType: "unknown_mfa_type",
		Enabled:      true,
		ConfigJSON:   `{}`,
	}
	mock := &mockMFAFullStore{DB: database, getMFAProviderRecord: record}
	h := newMFAFullMockHandler(t, database, mock)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	h.TestConnection(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown provider type, got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected error status, got %s", result["status"])
	}
}

// TestAdminMFAShowEdit_EmailProvider exercises the ProviderTypeEmail case in the
// ShowEdit switch (separate from the Duo branch tested elsewhere).
func TestAdminMFAShowEdit_EmailProvider(t *testing.T) {
	env := setupMFATest(t)
	cookies := env.createAdminSession(t)

	cfgBytes, _ := json.Marshal(map[string]any{
		"otp_length":      6,
		"otp_ttl_minutes": 5,
		"email_subject":   "OTP Code",
	})
	providerID := "test-email-show-id"
	record := &db.MFAProviderRecord{
		ID:           providerID,
		Name:         "Email OTP",
		ProviderType: "email",
		Enabled:      false,
		ConfigJSON:   string(cfgBytes),
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", providerID)
		env.handler.ShowEdit(w, r)
	})
	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/mfa/"+providerID+"/edit", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "mfa form page") {
		t.Errorf("expected mfa form page content, got: %s", rec.Body.String())
	}
}

// TestAdminMFAUpdate_UnknownProviderType exercises the marshalProviderConfig error
// path in Update when the stored provider has an unrecognized provider type.
func TestAdminMFAUpdate_UnknownProviderType(t *testing.T) {
	database := setupTestDB(t)
	record := &db.MFAProviderRecord{
		ID:           "test-unknown-update",
		Name:         "Unknown Provider",
		ProviderType: "unknown_type",
		ConfigJSON:   `{}`,
	}
	mock := &mockMFAFullStore{DB: database, getMFAProviderRecord: record}
	h := newMFAFullMockHandler(t, database, mock)

	form := url.Values{"name": {"Updated Name"}}
	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID, strings.NewReader(form.Encode())),
		"id", record.ID,
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Update(rec, req)

	// marshalProviderConfig returns error for unknown type → 500.
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for unknown provider type in Update, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestMarshalProviderConfig_EmailDefaultSubject exercises the empty email_subject
// branch in marshalProviderConfig (defaults to "Your verification code").
func TestMarshalProviderConfig_EmailDefaultSubject(t *testing.T) {
	env := setupMFATest(t)

	form := url.Values{
		"otp_length":      {"6"},
		"otp_ttl_minutes": {"5"},
		// email_subject deliberately omitted — should default.
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	configJSON, _, err := env.handler.marshalProviderConfig(req, "email", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		t.Fatalf("configJSON not valid JSON: %v", err)
	}
	if cfg["email_subject"] != "Your verification code" {
		t.Errorf("expected default email_subject 'Your verification code', got %v", cfg["email_subject"])
	}
}

// TestAdminMFAList_DefaultIDError covers List when GetDefaultMFAProviderID returns an
// error. This is a soft error: the handler logs it and continues to render 200.
func TestAdminMFAList_DefaultIDError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAErrStore{DB: database, getDefaultMFAProviderIDErr: fmt.Errorf("DB read failed")}
	h := newMFAMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/mfa", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	// Soft error: handler logs and continues → 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (soft error), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFAList_LoginRequiredError covers List when GetMFALoginRequired returns an
// error. This is a soft error: the handler logs it and continues to render 200.
func TestAdminMFAList_LoginRequiredError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMFAErrStore{DB: database, getMFALoginRequiredErr: fmt.Errorf("DB read failed")}
	h := newMFAMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/mfa", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	// Soft error: handler logs and continues → 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (soft error), got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFAList_DefaultProviderSet covers List when there IS a default MFA provider
// (defaultIDPtr != nil → defaultID = *defaultIDPtr branch, admin_mfa.go line 68).
func TestAdminMFAList_DefaultProviderSet(t *testing.T) {
	env := setupMFATest(t)

	// Create a provider and set it as the default.
	record := &db.MFAProviderRecord{
		ID:           "default-provider",
		Name:         "My Email OTP",
		ProviderType: "email",
		Enabled:      true,
		ConfigJSON:   `{"email_subject":"Code","ttl_minutes":10}`,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}
	defID := record.ID
	if err := env.db.SetDefaultMFAProviderID(context.Background(), &defID); err != nil {
		t.Fatalf("setting default: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/mfa", nil)
	rec := httptest.NewRecorder()
	env.handler.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_Create_ParseFormError covers Create when ParseForm fails
// (admin_mfa.go lines 110-112).
func TestAdminMFA_Create_ParseFormError(t *testing.T) {
	env := setupMFATest(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/mfa", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for Create ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_Update_ParseFormError covers Update when ParseForm fails
// (admin_mfa.go lines 218-220).
func TestAdminMFA_Update_ParseFormError(t *testing.T) {
	env := setupMFATest(t)

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/some-id", errReader{}),
		"id", "some-id",
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.Update(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for Update ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_SetDefault_ParseFormError covers SetDefault when ParseForm fails
// (admin_mfa.go lines 400-402).
func TestAdminMFA_SetDefault_ParseFormError(t *testing.T) {
	env := setupMFATest(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/mfa/default", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	env.handler.SetDefault(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for SetDefault ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFAShowEdit_DuoWithSecretBlob covers ShowEdit when the DUO provider has
// a non-empty SecretBlob that decrypts successfully (admin_mfa.go lines 188-191).
func TestAdminMFAShowEdit_DuoWithSecretBlob(t *testing.T) {
	env := setupMFATest(t)

	// Encrypt a valid DUO secrets payload.
	type duoSecrets struct {
		ClientSecret string `json:"client_secret"`
	}
	secretsBytes, _ := json.Marshal(duoSecrets{ClientSecret: "testsecret"})
	blob, err := env.crypto.Encrypt(secretsBytes)
	if err != nil {
		t.Fatalf("encrypting secrets: %v", err)
	}

	record := &db.MFAProviderRecord{
		ID:           "duo-with-blob",
		Name:         "Duo With Secret",
		ProviderType: "duo",
		Enabled:      true,
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"DICLIENTID12345678","redirect_uri":"https://example.com/cb"}`,
		SecretBlob:   blob,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodGet, "/admin/mfa/"+record.ID+"/edit", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.ShowEdit(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_TestConnection_DuoNewError covers TestConnection when duo.New fails
// because client_id is not 20 chars (admin_mfa.go lines 361-366).
func TestAdminMFA_TestConnection_DuoNewError(t *testing.T) {
	env := setupMFATest(t)

	// Valid JSON config but client_id is only 8 chars (not 20) → duo.New fails.
	record := &db.MFAProviderRecord{
		ID:           "duo-bad-clientid",
		Name:         "Bad ClientID DUO",
		ProviderType: "duo",
		ConfigJSON:   `{"api_hostname":"api.duo.example.com","client_id":"tooshort","redirect_uri":"https://example.com/cb"}`,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for duo.New error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminMFA_TestConnection_DuoHealthCheckFails covers TestConnection when duo.New
// succeeds but HealthCheck fails (offline server) (admin_mfa.go lines 368-373).
func TestAdminMFA_TestConnection_DuoHealthCheckFails(t *testing.T) {
	env := setupMFATest(t)

	// Valid 20-char client_id and 40-char client_secret but pointing to a non-existent server.
	type duoCfg struct {
		APIHostname string `json:"api_hostname"`
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
	}
	type duoSec struct {
		ClientSecret string `json:"client_secret"`
	}
	cfgBytes, _ := json.Marshal(duoCfg{
		APIHostname: "api-offline-never-exists.duo.invalid",
		ClientID:    "12345678901234567890", // exactly 20 chars
		RedirectURI: "https://example.com/cb",
	})
	secretsBytes, _ := json.Marshal(duoSec{
		ClientSecret: "1234567890123456789012345678901234567890", // exactly 40 chars
	})
	blob, err := env.crypto.Encrypt(secretsBytes)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	record := &db.MFAProviderRecord{
		ID:           "duo-healthcheck-fail",
		Name:         "Offline DUO",
		ProviderType: "duo",
		ConfigJSON:   string(cfgBytes),
		SecretBlob:   blob,
	}
	if err := env.db.CreateMFAProvider(context.Background(), record); err != nil {
		t.Fatalf("creating MFA provider: %v", err)
	}

	req := withChiURLParam(
		httptest.NewRequest(http.MethodPost, "/admin/mfa/"+record.ID+"/test", nil),
		"id", record.ID,
	)
	rec := httptest.NewRecorder()
	env.handler.TestConnection(rec, req)

	// HealthCheck fails → 200 with status "error".
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (health check error is a soft error), got %d; body: %s", rec.Code, rec.Body.String())
	}
	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status=error, got %s", result["status"])
	}
}
