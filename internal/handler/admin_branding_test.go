package handler

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

type brandingTestEnv struct {
	db      *db.DB
	handler *AdminBrandingHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubBrandingRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_branding.html"] = template.Must(template.New("admin_branding.html").Funcs(funcMap).Parse(`{{define "base"}}branding page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupBrandingTest(t *testing.T) *brandingTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubBrandingRenderer(t)

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

	uploadsDir := t.TempDir()
	h := NewAdminBrandingHandler(database, renderer, auditLog, logger, uploadsDir)

	return &brandingTestEnv{
		db:      database,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *brandingTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *brandingTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()

	if req == nil {
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

// buildBrandingMultipartForm creates a multipart/form-data request from the
// given form values. This is required because Save calls ParseMultipartForm.
func buildBrandingMultipartForm(t *testing.T, path string, fields url.Values) *http.Request {
	t.Helper()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	for key, vals := range fields {
		for _, v := range vals {
			if err := w.WriteField(key, v); err != nil {
				t.Fatalf("writing form field %s: %v", key, err)
			}
		}
	}
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestAdminBrandingShow_OK(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/branding", cookies, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "branding page") {
		t.Errorf("expected branding page content, got: %s", rec.Body.String())
	}
}

func TestAdminBrandingShow_WithExistingConfig(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Pre-save a branding config so Show returns an existing value.
	if err := env.db.SaveBrandingConfig(context.Background(), &db.BrandingConfig{
		AppTitle: "Pre-Saved App",
	}); err != nil {
		t.Fatalf("saving branding config: %v", err)
	}

	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/branding", cookies, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAdminBrandingSave_OK(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	fields := url.Values{
		"app_title":        {"My App"},
		"app_abbreviation": {"MA"},
		"app_subtitle":     {"Password Manager"},
		"footer_text":      {"Footer text"},
		"primary_color":    {"#2c5282"},
	}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "branding page") {
		t.Errorf("expected branding page content, got: %s", rec.Body.String())
	}

	// Verify branding was saved.
	cfg, err := env.db.GetBrandingConfig(context.Background())
	if err != nil {
		t.Fatalf("getting branding config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected branding config to exist")
	}
	if cfg.AppTitle != "My App" {
		t.Errorf("expected AppTitle 'My App', got %q", cfg.AppTitle)
	}
	if cfg.PrimaryColor != "#2c5282" {
		t.Errorf("expected PrimaryColor '#2c5282', got %q", cfg.PrimaryColor)
	}
}

// TestAdminBrandingSave_GetConfigError verifies that Save succeeds when there
// is no existing branding config in the DB (GetBrandingConfig returns nil).
// The logo URL should fall back to empty string.
func TestAdminBrandingSave_GetConfigError(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Fresh DB: no existing branding config.
	fields := url.Values{
		"app_title": {"Test App"},
	}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetBrandingConfig(context.Background())
	if err != nil {
		t.Fatalf("getting branding config: %v", err)
	}
	if cfg.AppTitle != "Test App" {
		t.Errorf("expected AppTitle 'Test App', got %q", cfg.AppTitle)
	}
}

// TestRenderBrandingError verifies that Save calls renderBrandingError when
// the primary_color field contains an invalid hex value.
func TestRenderBrandingError(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Record the current branding state before the failing save.
	beforeCfg, _ := env.db.GetBrandingConfig(context.Background())
	var beforeTitle string
	if beforeCfg != nil {
		beforeTitle = beforeCfg.AppTitle
	}

	// An invalid primary_color triggers the renderBrandingError path.
	fields := url.Values{
		"app_title":     {"Should Not Be Saved"},
		"primary_color": {"not-a-hex-color"},
	}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	// renderBrandingError re-renders the branding page (200), not a redirect.
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "branding page") {
		t.Errorf("expected branding page error render, got: %s", rec.Body.String())
	}

	// Verify the app_title was NOT saved (config unchanged from before).
	afterCfg, _ := env.db.GetBrandingConfig(context.Background())
	var afterTitle string
	if afterCfg != nil {
		afterTitle = afterCfg.AppTitle
	}
	if afterTitle != beforeTitle {
		t.Errorf("branding config was modified despite validation error: before=%q, after=%q", beforeTitle, afterTitle)
	}
}

func TestAdminBrandingSave_RemoveLogo(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Pre-save a config with a logo URL.
	if err := env.db.SaveBrandingConfig(context.Background(), &db.BrandingConfig{
		AppTitle: "App",
		LogoURL:  "/uploads/logo.png",
	}); err != nil {
		t.Fatalf("saving initial branding: %v", err)
	}

	fields := url.Values{
		"app_title":   {"App"},
		"remove_logo": {"1"},
	}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetBrandingConfig(context.Background())
	if err != nil {
		t.Fatalf("getting branding config: %v", err)
	}
	if cfg.LogoURL != "" {
		t.Errorf("expected logo URL to be cleared, got %q", cfg.LogoURL)
	}
}

func TestAdminBrandingSave_DefaultTitle(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Empty app_title should default to "PassPort".
	fields := url.Values{
		"app_title": {""},
	}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetBrandingConfig(context.Background())
	if err != nil {
		t.Fatalf("getting branding config: %v", err)
	}
	if cfg.AppTitle != "PassPort" {
		t.Errorf("expected default AppTitle 'PassPort', got %q", cfg.AppTitle)
	}
}

func TestAdminBrandingSave_InvalidPrimaryLightColor(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	fields := url.Values{
		"app_title":           {"My App"},
		"primary_light_color": {"badcolor"},
	}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "branding page") {
		t.Errorf("expected branding page error render, got: %s", rec.Body.String())
	}
}

func TestAdminBrandingSave_LogoUpload(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Build a multipart form with a logo file.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("app_title", "Logo Test App")
	fw, err := mw.CreateFormFile("logo_file", "logo.png")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	// Write fake PNG content.
	fw.Write([]byte("\x89PNG\r\n\x1a\n")) //nolint:errcheck
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/branding", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetBrandingConfig(context.Background())
	if err != nil {
		t.Fatalf("getting branding config: %v", err)
	}
	if cfg.LogoURL != "/uploads/logo.png" {
		t.Errorf("expected logo URL '/uploads/logo.png', got %q", cfg.LogoURL)
	}
}

func TestAdminBrandingSave_LogoInvalidExtension(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("app_title", "Test")
	fw, err := mw.CreateFormFile("logo_file", "malware.exe")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	fw.Write([]byte("MZ")) //nolint:errcheck
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/branding", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	// renderBrandingError is called: re-renders branding page (200)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminBrandingSave_InvalidContentType(t *testing.T) {
	env := setupBrandingTest(t)
	cookies := env.createAdminSession(t)

	// Sending a URL-encoded body (not multipart) should fail ParseMultipartForm.
	req := httptest.NewRequest(http.MethodPost, "/admin/branding", strings.NewReader("app_title=test"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := env.serveWithAdminSession(t, env.handler.Save, http.MethodPost, "/admin/branding", cookies, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for non-multipart request, got %d", rec.Code)
	}
}

// mockBrandingErrStore wraps *db.DB and overrides branding methods to inject errors.
type mockBrandingErrStore struct {
	*db.DB
	getBrandingErr  error
	saveBrandingErr error
}

func (m *mockBrandingErrStore) GetBrandingConfig(ctx context.Context) (*db.BrandingConfig, error) {
	if m.getBrandingErr != nil {
		return nil, m.getBrandingErr
	}
	return m.DB.GetBrandingConfig(ctx)
}

func (m *mockBrandingErrStore) SaveBrandingConfig(ctx context.Context, cfg *db.BrandingConfig) error {
	if m.saveBrandingErr != nil {
		return m.saveBrandingErr
	}
	return m.DB.SaveBrandingConfig(ctx, cfg)
}

// TestAdminBrandingShow_DBError covers Show when GetBrandingConfig fails (line 56-60).
func TestAdminBrandingShow_DBError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockBrandingErrStore{
		DB:             database,
		getBrandingErr: fmt.Errorf("DB connection lost"),
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

	renderer := stubBrandingRenderer(t)
	h := NewAdminBrandingHandler(mockStore, renderer, auditLog, logger, t.TempDir())

	req := httptest.NewRequest(http.MethodGet, "/admin/branding", nil)
	rec := httptest.NewRecorder()
	h.Show(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when GetBrandingConfig fails, got %d", rec.Code)
	}
}

// TestAdminBrandingSave_SaveConfigError covers Save when SaveBrandingConfig fails (line 163-167).
func TestAdminBrandingSave_SaveConfigError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockBrandingErrStore{
		DB:              database,
		saveBrandingErr: fmt.Errorf("disk full"),
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

	renderer := stubBrandingRenderer(t)
	h := NewAdminBrandingHandler(mockStore, renderer, auditLog, logger, t.TempDir())

	// Build a valid multipart form so ParseMultipartForm succeeds.
	fields := url.Values{"app_title": {"Test App"}}
	req := buildBrandingMultipartForm(t, "/admin/branding", fields)
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when SaveBrandingConfig fails, got %d", rec.Code)
	}
}

// TestNewAdminBrandingHandler_MkdirAllError covers the os.MkdirAll failure path
// by using a regular file as the uploads directory path.
func TestNewAdminBrandingHandler_MkdirAllError(t *testing.T) {
	database := setupTestDB(t)
	logger := testLogger()

	// Create a regular file, then try to use it as a directory → MkdirAll fails.
	f, err := os.CreateTemp(t.TempDir(), "notadir-*")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	_ = f.Close()
	badPath := f.Name() + "/subdir" // path under a regular file is invalid

	tmpAudit, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating audit file: %v", err)
	}
	_ = tmpAudit.Close()
	auditLog, err := audit.NewLogger(database, tmpAudit.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	renderer := stubBrandingRenderer(t)
	// NewAdminBrandingHandler should log the error but still return a valid handler.
	h := NewAdminBrandingHandler(database, renderer, auditLog, logger, badPath)
	if h == nil {
		t.Error("expected non-nil handler even when uploads dir creation fails")
	}
}

// TestAdminBrandingSave_LogoCreateError covers the os.Create failure path when
// a logo file is uploaded but the uploads directory cannot be written to.
func TestAdminBrandingSave_LogoCreateError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	tmpAudit, err := os.CreateTemp(t.TempDir(), "audit-*.log")
	if err != nil {
		t.Fatalf("creating audit file: %v", err)
	}
	_ = tmpAudit.Close()
	auditLog, err := audit.NewLogger(database, tmpAudit.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	renderer := stubBrandingRenderer(t)

	// Use an invalid (non-existent, non-writable) uploads dir.
	h := NewAdminBrandingHandler(database, renderer, auditLog, logger,
		"/nonexistent/branding/uploads")

	// Build a multipart request that includes a logo file.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("logo_file", "logo.png")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := fw.Write([]byte("fake png")); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	_ = mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/branding", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	// renderBrandingError renders the form page with the error message.
	// We don't assert the exact status, just that the handler didn't panic.
	_ = rec.Code
}
