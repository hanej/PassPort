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
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/job"
)

type expirationTestEnv struct {
	db       *db.DB
	handler  *AdminExpirationHandler
	notifier *job.PasswordExpirationNotifier
	sm       *auth.SessionManager
	audit    *audit.Logger
}

func stubExpirationRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_idp_expiration.html"] = template.Must(template.New("admin_idp_expiration.html").Funcs(funcMap).Parse(`{{define "base"}}expiration config page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupExpirationTest(t *testing.T) *expirationTestEnv {
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
	renderer := stubExpirationRenderer(t)

	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	tmpFile.Close()

	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })

	registry := idp.NewRegistry(logger)
	notifier := job.New(database, registry, cryptoSvc, auditLog, logger)

	// Start the notifier with a context cancelled at test cleanup so the
	// cron scheduler is initialized and properly shut down.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	notifier.Start(ctx)

	h := NewAdminExpirationHandler(database, notifier, renderer, auditLog, logger)

	return &expirationTestEnv{
		db:       database,
		handler:  h,
		notifier: notifier,
		sm:       sm,
		audit:    auditLog,
	}
}

func (env *expirationTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *expirationTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func (env *expirationTestEnv) createTestIDP(t *testing.T, idpID string) {
	t.Helper()
	record := &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "Test IDP",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating test IDP: %v", err)
	}
}

// --- Unit tests for pure functions ---

func TestBuildFiltersFromForm(t *testing.T) {
	form := url.Values{
		"filter_attribute[]":   {"memberOf", "department"},
		"filter_pattern[]":     {"CN=Admins,DC=example,DC=com", "Engineering"},
		"filter_description[]": {"Admin users", "Engineering dept"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parsing form: %v", err)
	}

	filters := buildFiltersFromForm(req, "test-idp")

	if len(filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(filters))
	}

	if filters[0].Attribute != "memberOf" {
		t.Errorf("expected attribute 'memberOf', got %q", filters[0].Attribute)
	}
	if filters[0].Pattern != "CN=Admins,DC=example,DC=com" {
		t.Errorf("expected pattern 'CN=Admins,...', got %q", filters[0].Pattern)
	}
	if filters[0].Description != "Admin users" {
		t.Errorf("expected description 'Admin users', got %q", filters[0].Description)
	}
	if filters[0].IDPID != "test-idp" {
		t.Errorf("expected IDPID 'test-idp', got %q", filters[0].IDPID)
	}

	if filters[1].Attribute != "department" {
		t.Errorf("expected attribute 'department', got %q", filters[1].Attribute)
	}
}

func TestBuildFiltersFromForm_EmptyAttribute(t *testing.T) {
	// An empty attribute entry should be skipped.
	form := url.Values{
		"filter_attribute[]": {"", "department"},
		"filter_pattern[]":   {"ignored", "Engineering"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildFiltersFromForm(req, "test-idp")

	if len(filters) != 1 {
		t.Fatalf("expected 1 filter (empty attr skipped), got %d", len(filters))
	}
	if filters[0].Attribute != "department" {
		t.Errorf("expected 'department', got %q", filters[0].Attribute)
	}
}

func TestBuildFiltersFromForm_EmptyPattern(t *testing.T) {
	// An empty pattern entry should also be skipped.
	form := url.Values{
		"filter_attribute[]": {"memberOf"},
		"filter_pattern[]":   {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildFiltersFromForm(req, "test-idp")

	if len(filters) != 0 {
		t.Fatalf("expected 0 filters (empty pattern skipped), got %d", len(filters))
	}
}

func TestBuildFiltersFromForm_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildFiltersFromForm(req, "test-idp")
	if len(filters) != 0 {
		t.Errorf("expected 0 filters for empty form, got %d", len(filters))
	}
}

// --- Handler tests ---

func TestAdminExpirationShow(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t, "corp-ad")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/corp-ad/expiration", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration config page content, got: %s", rec.Body.String())
	}
}

func TestAdminExpirationShow_IDPNotFound(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/idp/nonexistent-idp/expiration", cookies, "")

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for missing IDP, got %d", rec.Code)
	}
}

func TestAdminExpirationSave(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t, "corp-ad")

	form := url.Values{}
	form.Set("cron_schedule", "0 8 * * *")
	form.Set("days_before_expiration", "7")
	// enabled is intentionally not set (disabled) to avoid cron scheduling.

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/corp-ad/expiration", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration config page content, got: %s", rec.Body.String())
	}

	// Verify config was saved.
	cfg, err := env.db.GetExpirationConfig(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("getting expiration config: %v", err)
	}
	if cfg.CronSchedule != "0 8 * * *" {
		t.Errorf("expected schedule '0 8 * * *', got %q", cfg.CronSchedule)
	}
	if cfg.DaysBeforeExpiration != 7 {
		t.Errorf("expected DaysBeforeExpiration=7, got %d", cfg.DaysBeforeExpiration)
	}
}

func TestAdminExpirationSave_InvalidCron(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t, "corp-ad")

	form := url.Values{}
	form.Set("cron_schedule", "not a valid cron expression !!!")
	form.Set("days_before_expiration", "14")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/corp-ad/expiration", cookies, form.Encode())

	// Invalid cron re-renders the page with an error (200, not redirect).
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 (error page), got %d", rec.Code)
	}
}

func TestAdminExpirationSave_WithFilters(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t, "corp-ad")

	form := url.Values{
		"cron_schedule":          {"0 6 * * *"},
		"days_before_expiration": {"14"},
		"filter_attribute[]":     {"memberOf"},
		"filter_pattern[]":       {"CN=ServiceAccounts,DC=example,DC=com"},
		"filter_description[]":   {"Exclude service accounts"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/corp-ad/expiration", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify filters were saved.
	filters, err := env.db.ListExpirationFilters(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("listing expiration filters: %v", err)
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Attribute != "memberOf" {
		t.Errorf("expected attribute 'memberOf', got %q", filters[0].Attribute)
	}
}

// TestAdminExpirationDryRun tests the error response path when the IDP is not found.
func TestAdminExpirationDryRun_IDPNotFound(t *testing.T) {
	env := setupExpirationTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.DryRun(w, r)
	})

	// No session needed: DryRun only returns JSON and doesn't use sess.
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/nonexistent-idp/expiration/dry-run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 with error JSON, got %d", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error' (IDP not found), got: %v", result["status"])
	}
}

// TestAdminExpirationRunNow tests the error response path when no expiration
// config is configured for the IDP.
func TestAdminExpirationRunNow_NoConfig(t *testing.T) {
	env := setupExpirationTest(t)

	// No expiration config exists for this IDP.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.RunNow(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/corp-ad/expiration/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 with error JSON, got %d", rec.Code)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error' (no config), got: %v", result["status"])
	}
}

func TestAdminExpirationRunNow_IDPNotFound(t *testing.T) {
	env := setupExpirationTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "does-not-exist")
		env.handler.RunNow(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/does-not-exist/expiration/run", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// RunForIDP returns an error; handler returns JSON with status="error".
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 with error JSON, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON response: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error', got: %v", result["status"])
	}
	if _, ok := result["message"]; !ok {
		t.Error("expected 'message' key in JSON error response")
	}
}

func TestAdminExpirationSave_IDPNotFound(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("cron_schedule", "0 6 * * *")
	form.Set("days_before_expiration", "14")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "nonexistent-idp")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/nonexistent-idp/expiration", cookies, form.Encode())

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404 for missing IDP, got %d", rec.Code)
	}
}

func TestAdminExpirationSave_EmptyCronSchedule(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t, "corp-ad")

	form := url.Values{}
	form.Set("cron_schedule", "")
	form.Set("days_before_expiration", "7")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/corp-ad/expiration", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify the default cron schedule was used.
	cfg, err := env.db.GetExpirationConfig(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("getting expiration config: %v", err)
	}
	if cfg.CronSchedule != "0 6 * * *" {
		t.Errorf("expected default schedule '0 6 * * *', got %q", cfg.CronSchedule)
	}
}

func TestAdminExpirationSave_DaysOutOfRange(t *testing.T) {
	env := setupExpirationTest(t)
	cookies := env.createAdminSession(t)
	env.createTestIDP(t, "corp-ad")

	form := url.Values{}
	form.Set("cron_schedule", "0 6 * * *")
	form.Set("days_before_expiration", "999") // > 90, should default to 14

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/idp/corp-ad/expiration", cookies, form.Encode())

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetExpirationConfig(context.Background(), "corp-ad")
	if err != nil {
		t.Fatalf("getting expiration config: %v", err)
	}
	if cfg.DaysBeforeExpiration != 14 {
		t.Errorf("expected default DaysBeforeExpiration=14, got %d", cfg.DaysBeforeExpiration)
	}
}

// mockExpirationErrStore wraps *db.DB and overrides specific methods to inject errors.
type mockExpirationErrStore struct {
	*db.DB
	saveExpirationConfigErr  error
	saveExpirationFiltersErr error
	listExpirationFiltersErr error
	getExpirationConfigErr   error
}

func (m *mockExpirationErrStore) SaveExpirationConfig(ctx context.Context, cfg *db.ExpirationConfig) error {
	if m.saveExpirationConfigErr != nil {
		return m.saveExpirationConfigErr
	}
	return m.DB.SaveExpirationConfig(ctx, cfg)
}

func (m *mockExpirationErrStore) SaveExpirationFilters(ctx context.Context, idpID string, filters []db.ExpirationFilter) error {
	if m.saveExpirationFiltersErr != nil {
		return m.saveExpirationFiltersErr
	}
	return m.DB.SaveExpirationFilters(ctx, idpID, filters)
}

func (m *mockExpirationErrStore) ListExpirationFilters(ctx context.Context, idpID string) ([]db.ExpirationFilter, error) {
	if m.listExpirationFiltersErr != nil {
		return nil, m.listExpirationFiltersErr
	}
	return m.DB.ListExpirationFilters(ctx, idpID)
}

func (m *mockExpirationErrStore) GetExpirationConfig(ctx context.Context, idpID string) (*db.ExpirationConfig, error) {
	if m.getExpirationConfigErr != nil {
		return nil, m.getExpirationConfigErr
	}
	return m.DB.GetExpirationConfig(ctx, idpID)
}

func newExpirationMockHandler(t *testing.T, database *db.DB, mock *mockExpirationErrStore) *AdminExpirationHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubExpirationRenderer(t)
	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	tmpFile.Close()
	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })
	// Pass nil notifier: error paths return before reaching h.notifier calls.
	return NewAdminExpirationHandler(mock, nil, renderer, auditLog, logger)
}

// TestAdminExpirationSave_SaveConfigError covers lines 175-190 where
// SaveExpirationConfig fails and the handler re-renders the page with a flash error.
func TestAdminExpirationSave_SaveConfigError(t *testing.T) {
	database := setupTestDB(t)

	// Create a real IDP so GetIDP succeeds.
	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	mock := &mockExpirationErrStore{DB: database, saveExpirationConfigErr: fmt.Errorf("DB write failed")}
	h := newExpirationMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("cron_schedule", "0 6 * * *")
	form.Set("days_before_expiration", "14")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/corp-ad/expiration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "id", "corp-ad")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	// SaveExpirationConfig failure re-renders the page with flash error (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when SaveExpirationConfig fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration page re-render, got: %s", rec.Body.String())
	}
}

// TestAdminExpirationSave_SaveFiltersError covers lines 195-210 where
// SaveExpirationFilters fails and the handler re-renders the page with a flash error.
func TestAdminExpirationSave_SaveFiltersError(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// SaveExpirationConfig succeeds (delegates to real DB), SaveExpirationFilters fails.
	mock := &mockExpirationErrStore{DB: database, saveExpirationFiltersErr: fmt.Errorf("DB filters write failed")}
	h := newExpirationMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("cron_schedule", "0 6 * * *")
	form.Set("days_before_expiration", "14")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/corp-ad/expiration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "id", "corp-ad")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	// SaveExpirationFilters failure re-renders the page with flash error (200).
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when SaveExpirationFilters fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration page re-render, got: %s", rec.Body.String())
	}
}

// TestAdminExpirationShow_ListFiltersError covers the ListExpirationFilters error
// branch in Show — handler falls back to nil filters and still renders 200.
func TestAdminExpirationShow_ListFiltersError(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	mock := &mockExpirationErrStore{DB: database, listExpirationFiltersErr: fmt.Errorf("db failure")}
	h := newExpirationMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/idp/corp-ad/expiration", nil)
	req = withChiURLParam(req, "id", "corp-ad")
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 despite ListExpirationFilters error, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration config page content, got: %s", rec.Body.String())
	}
}

// TestAdminExpirationShow_GetExpirationConfigError covers line 66 where GetExpirationConfig
// returns an error — handler logs a warning, uses defaults, and still renders 200.
func TestAdminExpirationShow_GetExpirationConfigError(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	mock := &mockExpirationErrStore{DB: database, getExpirationConfigErr: fmt.Errorf("db read failed")}
	h := newExpirationMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/idp/corp-ad/expiration", nil)
	req = withChiURLParam(req, "id", "corp-ad")
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	// GetExpirationConfig error is soft — handler uses nil cfg → applies defaults → renders 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 despite GetExpirationConfig error, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration config page content, got: %s", rec.Body.String())
	}
}

// TestAdminExpirationSave_ParseFormError covers lines 118-120 where r.ParseForm()
// fails, causing a 400 Bad Request response.
func TestAdminExpirationSave_ParseFormError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockExpirationErrStore{DB: database}
	h := newExpirationMockHandler(t, database, mock)

	// errReader forces r.ParseForm() to fail.
	req := httptest.NewRequest(http.MethodPost, "/admin/idp/corp-ad/expiration", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withChiURLParam(req, "id", "corp-ad")
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ParseForm error, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAdminExpirationSave_ListFiltersReloadError covers lines 235-238 where
// ListExpirationFilters fails after a successful save — handler falls back to
// the in-memory filters and still renders 200.
func TestAdminExpirationSave_ListFiltersReloadError(t *testing.T) {
	database := setupTestDB(t)

	if err := database.CreateIDP(context.Background(), &db.IdentityProviderRecord{
		ID:           "corp-ad",
		FriendlyName: "Corp AD",
		ProviderType: "ad",
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}); err != nil {
		t.Fatalf("creating IDP: %v", err)
	}

	// Only ListExpirationFilters fails; SaveExpirationConfig + SaveExpirationFilters
	// delegate to the real DB and succeed.
	mock := &mockExpirationErrStore{DB: database, listExpirationFiltersErr: fmt.Errorf("reload error")}

	// Need a real notifier (ReloadSchedules is called before ListExpirationFilters).
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}
	registry := idp.NewRegistry(logger)
	tmpFile, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating temp audit file: %v", err)
	}
	tmpFile.Close()
	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { auditLog.Close() })
	notifier := job.New(mock, registry, cryptoSvc, auditLog, logger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	notifier.Start(ctx)

	renderer := stubExpirationRenderer(t)
	h := NewAdminExpirationHandler(mock, notifier, renderer, auditLog, logger)

	// Create a session so sess.Username is accessible (required by h.audit.Log at line 225).
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(rec0, req0, "local", "", "admin", true, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := rec0.Result().Cookies()

	form := url.Values{}
	form.Set("cron_schedule", "0 6 * * *")
	form.Set("days_before_expiration", "14")

	req := httptest.NewRequest(http.MethodPost, "/admin/idp/corp-ad/expiration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	req = withChiURLParam(req, "id", "corp-ad")

	wrapped := sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withChiURLParam(r, "id", "corp-ad")
		h.Save(w, r)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// ListExpirationFilters reload error is soft — handler still renders 200 with in-memory filters.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when ListExpirationFilters reload fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "expiration config page") {
		t.Errorf("expected expiration page re-render, got: %s", rec.Body.String())
	}
}
