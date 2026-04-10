package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/migrate"
)

type migrateTestEnv struct {
	db      *db.DB
	crypto  *crypto.Service
	handler *AdminMigrateHandler
	sm      *auth.SessionManager
	audit   *audit.Logger
}

func stubMigrateRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
		"branding": func() *db.BrandingConfig { return &db.BrandingConfig{AppTitle: "PassPort"} },
	}
	pages := make(map[string]*template.Template)
	pages["admin_migrate.html"] = template.Must(template.New("admin_migrate.html").Funcs(funcMap).Parse(`{{define "base"}}migrate page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupMigrateTest(t *testing.T) *migrateTestEnv {
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
	renderer := stubMigrateRenderer(t)

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

	h := NewAdminMigrateHandler(database, cryptoSvc, renderer, auditLog, logger, t.TempDir())

	return &migrateTestEnv{
		db:      database,
		crypto:  cryptoSvc,
		handler: h,
		sm:      sm,
		audit:   auditLog,
	}
}

func (env *migrateTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *migrateTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, req *http.Request) *httptest.ResponseRecorder {
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

func TestMigrateShow(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.Show, http.MethodGet, "/admin/migrate", cookies, nil)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected migrate page content, got: %s", rec.Body.String())
	}
}

func TestMigrateExport(t *testing.T) {
	env := setupMigrateTest(t)
	ctx := context.Background()

	// Seed some data
	if _, err := env.db.CreateLocalAdmin(ctx, "alice", "hash"); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	if err := env.db.SaveBrandingConfig(ctx, &db.BrandingConfig{AppTitle: "TestApp"}); err != nil {
		t.Fatalf("saving branding: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Export, http.MethodGet, "/admin/migrate/export", cookies, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify content type
	ct := rec.Header().Get("Content-Type")
	if ct != "application/zip" {
		t.Errorf("expected Content-Type application/zip, got %s", ct)
	}

	// Verify Content-Disposition
	cd := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, "attachment; filename=") {
		t.Errorf("expected attachment Content-Disposition, got %s", cd)
	}
	if !strings.Contains(cd, ".zip") {
		t.Errorf("expected .zip filename in Content-Disposition, got %s", cd)
	}

	// Verify ZIP contains passport-export.json with correct content
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("opening export as zip: %v", err)
	}
	var jsonFile *zip.File
	for _, f := range zr.File {
		if f.Name == "passport-export.json" {
			jsonFile = f
			break
		}
	}
	if jsonFile == nil {
		t.Fatal("passport-export.json not found in export zip")
	}
	rc, err := jsonFile.Open()
	if err != nil {
		t.Fatalf("opening passport-export.json from zip: %v", err)
	}
	defer func() { _ = rc.Close() }()
	var data migrate.ExportData
	if err := json.NewDecoder(rc).Decode(&data); err != nil {
		t.Fatalf("decoding passport-export.json: %v", err)
	}
	if data.Version != 1 {
		t.Errorf("expected version 1, got %d", data.Version)
	}
	if data.SecretsEncrypted {
		t.Error("export should not have encrypted secrets")
	}
	if data.Branding == nil || data.Branding.AppTitle != "TestApp" {
		t.Errorf("expected branding with TestApp, got %+v", data.Branding)
	}
	// admin "admin" (session) + "alice" should be 2 local admins
	if len(data.LocalAdmins) != 2 {
		t.Errorf("expected 2 local admins, got %d", len(data.LocalAdmins))
	}
}

func TestMigrateImport_ValidFile(t *testing.T) {
	env := setupMigrateTest(t)
	ctx := context.Background()

	// Build export data to import
	exportData := migrate.ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		Branding: &db.BrandingConfig{
			AppTitle: "ImportedApp", AppAbbreviation: "IA",
		},
		EmailTemplates: []migrate.ExportEmailTemplate{
			{TemplateType: "password_reset", Subject: "Imported Reset", BodyHTML: "<p>Reset</p>"},
		},
	}

	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("marshaling export data: %v", err)
	}

	req := buildImportRequest(t, jsonBytes, map[string]string{
		"import_branding":  "1",
		"import_templates": "1",
	})
	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected migrate page response, got: %s", rec.Body.String())
	}

	// Verify branding was imported
	branding, err := env.db.GetBrandingConfig(ctx)
	if err != nil {
		t.Fatalf("getting branding: %v", err)
	}
	if branding.AppTitle != "ImportedApp" {
		t.Errorf("expected ImportedApp, got %s", branding.AppTitle)
	}

	// Verify email template was imported
	tpl, err := env.db.GetEmailTemplate(ctx, "password_reset")
	if err != nil {
		t.Fatalf("getting email template: %v", err)
	}
	if tpl.Subject != "Imported Reset" {
		t.Errorf("expected Imported Reset, got %s", tpl.Subject)
	}
}

func TestMigrateImport_NoFile(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	req := httptest.NewRequest(http.MethodPost, "/admin/migrate/import", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected error rendered in migrate page, got: %s", rec.Body.String())
	}
}

func TestMigrateImport_InvalidJSON(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	req := buildImportRequest(t, []byte(`{invalid json`), nil)
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected error in migrate page, got: %s", rec.Body.String())
	}
}

func TestMigrateImport_UnknownField(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	// JSON with an unknown field — DisallowUnknownFields should reject this
	req := buildImportRequest(t, []byte(`{"version":1,"unknown_field":"bad"}`), nil)
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected error in migrate page, got: %s", rec.Body.String())
	}
}

func TestMigrateImport_SectionsRespected(t *testing.T) {
	env := setupMigrateTest(t)
	ctx := context.Background()

	exportData := migrate.ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: false,
		Branding:         &db.BrandingConfig{AppTitle: "ShouldNotImport"},
		EmailTemplates: []migrate.ExportEmailTemplate{
			{TemplateType: "password_reset", Subject: "Should Import", BodyHTML: "<p>Reset</p>"},
		},
	}

	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("marshaling export data: %v", err)
	}

	// Only import templates, not branding
	req := buildImportRequest(t, jsonBytes, map[string]string{
		"import_templates": "1",
		// import_branding intentionally omitted
	})
	cookies := env.createAdminSession(t)
	env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	// Branding should NOT have been updated to "ShouldNotImport"
	branding, err := env.db.GetBrandingConfig(ctx)
	if err != nil {
		t.Fatalf("getting branding: %v", err)
	}
	if branding.AppTitle == "ShouldNotImport" {
		t.Error("branding should not have been imported (section not selected)")
	}

	// Template should have been imported
	tpl, err := env.db.GetEmailTemplate(ctx, "password_reset")
	if err != nil {
		t.Fatalf("getting template: %v", err)
	}
	if tpl.Subject != "Should Import" {
		t.Errorf("expected 'Should Import', got %s", tpl.Subject)
	}
}

// buildImportRequest creates a multipart form request with a ZIP import file containing
// passport-export.json with the given bytes, plus optional form fields.
func buildImportRequest(t *testing.T, jsonBytes []byte, fields map[string]string) *http.Request {
	t.Helper()

	// Wrap jsonBytes in a ZIP archive as passport-export.json
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	je, err := zw.Create("passport-export.json")
	if err != nil {
		t.Fatalf("creating zip entry: %v", err)
	}
	if _, err := je.Write(jsonBytes); err != nil {
		t.Fatalf("writing json to zip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Add extra form fields
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatalf("writing field %s: %v", k, err)
		}
	}

	// Add the ZIP file
	fw, err := w.CreateFormFile("import_file", "export.zip")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := fw.Write(zipBuf.Bytes()); err != nil {
		t.Fatalf("writing file contents: %v", err)
	}
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/migrate/import", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

// errMigrateStub is a minimal error type used to avoid importing "fmt" in this file.
type errMigrateStub struct{ msg string }

func (e *errMigrateStub) Error() string { return e.msg }

// mockMigrateErrStore wraps *db.DB and forces ListLocalAdmins to fail,
// causing migrate.BuildExport → buildCommon to return an error.
type mockMigrateErrStore struct {
	*db.DB
	listLocalAdminsErr error
}

func (m *mockMigrateErrStore) ListLocalAdmins(ctx context.Context) ([]db.LocalAdmin, error) {
	if m.listLocalAdminsErr != nil {
		return nil, m.listLocalAdminsErr
	}
	return m.DB.ListLocalAdmins(ctx)
}

// TestMigrateExport_BuildExportError covers the error path in Export when
// migrate.BuildExport returns an error (triggered by a DB failure in buildCommon).
func TestMigrateExport_BuildExportError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMigrateErrStore{
		DB:                 database,
		listLocalAdminsErr: &errMigrateStub{"db failure"},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}

	renderer := stubMigrateRenderer(t)

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

	h := NewAdminMigrateHandler(mock, cryptoSvc, renderer, auditLog, logger, "")

	req := httptest.NewRequest(http.MethodGet, "/admin/migrate/export", nil)
	rec := httptest.NewRecorder()
	h.Export(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when BuildExport fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "error page") {
		t.Errorf("expected error page content, got: %s", rec.Body.String())
	}
}

// TestMigrateImport_NoImportFileInMultipart covers line 109 where FormFile("import_file")
// fails because the multipart form has no file field.
func TestMigrateImport_NoImportFileInMultipart(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	// Build a valid multipart form but without an "import_file" field.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("import_branding", "1"); err != nil { // some non-file field
		t.Fatalf("WriteField: %v", err)
	}
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/migrate/import", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())

	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected error rendered in migrate page, got: %s", rec.Body.String())
	}
}

// TestMigrateImport_RunImportVersionError covers lines 136-138 where RunImport
// returns an error because the export data version is unsupported.
func TestMigrateImport_RunImportVersionError(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	// Version 99 is not supported — RunImport returns an error.
	exportData := migrate.ExportData{
		Version:    99,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("marshaling export data: %v", err)
	}

	req := buildImportRequest(t, jsonBytes, nil)
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected error in migrate page, got: %s", rec.Body.String())
	}
}

// TestMigrateImport_WithWarnings covers line 148 where `category = "warning"` is set
// because RunImport succeeds but result.Errors is non-empty.
// We trigger this by importing an IDP with SecretsEncrypted=true and an invalid base64 secret.
func TestMigrateImport_WithWarnings(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	exportData := migrate.ExportData{
		Version:          1,
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		SecretsEncrypted: true,
		IdentityProviders: []migrate.ExportIDP{
			{
				ID:           "bad-secret-idp",
				FriendlyName: "Bad Secret IDP",
				ProviderType: "ad",
				Enabled:      true,
				Config:       json.RawMessage(`{}`),
				// Invalid base64 — resolveSecretBlob will fail, adding to result.Errors.
				Secrets: json.RawMessage(`"!!!not-valid-base64-data!!!"`),
			},
		},
	}
	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("marshaling export data: %v", err)
	}

	req := buildImportRequest(t, jsonBytes, map[string]string{"import_idps": "1"})
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	// RunImport succeeds but has errors → category="warning" → handler renders migrate page.
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected migrate page response, got: %s", rec.Body.String())
	}
}

// mockMigrateCreateIDPErrStore wraps *db.DB and forces CreateIDP to fail,
// causing RunImport to add an error entry when importing IDPs.
type mockMigrateCreateIDPErrStore struct {
	*db.DB
	createIDPErr error
}

func (m *mockMigrateCreateIDPErrStore) CreateIDP(ctx context.Context, record *db.IdentityProviderRecord) error {
	if m.createIDPErr != nil {
		return m.createIDPErr
	}
	return m.DB.CreateIDP(ctx, record)
}

// TestMigrateImport_CreateIDPError covers migrate/export.go:516-518 where CreateIDP
// fails for a new IDP during import → error is added to result.Errors (warning category).
func TestMigrateImport_CreateIDPError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockMigrateCreateIDPErrStore{
		DB:           database,
		createIDPErr: &errMigrateStub{"db failure"},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generating crypto key: %v", err)
	}
	cryptoSvc, err := crypto.NewService(key, 1)
	if err != nil {
		t.Fatalf("creating crypto service: %v", err)
	}
	renderer := stubMigrateRenderer(t)

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

	h := NewAdminMigrateHandler(mock, cryptoSvc, renderer, auditLog, logger, "")

	// Need a session so the handler can access sess.Username for audit logging.
	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	hash, _ := auth.HashPassword("admin-pass")
	database.CreateLocalAdmin(context.Background(), "admin", hash) //nolint:errcheck
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest(http.MethodGet, "/", nil)
	sm.CreateSession(wCookie, rCookie, "local", "", "admin", true, false) //nolint:errcheck
	cookies := wCookie.Result().Cookies()

	// IDP "new-idp" does not exist in DB → GetIDP returns nil → CreateIDP is called → fails.
	exportData := migrate.ExportData{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
		IdentityProviders: []migrate.ExportIDP{
			{
				ID:           "new-idp",
				FriendlyName: "New IDP",
				ProviderType: "ad",
				Enabled:      true,
				Config:       json.RawMessage(`{}`),
			},
		},
	}
	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("marshaling export data: %v", err)
	}

	req := buildImportRequest(t, jsonBytes, map[string]string{"import_idps": "1"})
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := sm.Middleware(http.HandlerFunc(h.Import))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// RunImport succeeds but result.Errors is non-empty → category="warning" → 200.
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (warning category), got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected migrate page, got: %s", rec.Body.String())
	}
}

// TestMigrateImport_InvalidZip sends raw bytes that are not a valid ZIP archive,
// covering the zip.NewReader error path (lines 179-182).
func TestMigrateImport_InvalidZip(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("import_file", "bad.zip")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := fw.Write([]byte("this is not a zip file at all")); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/migrate/import", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected error rendered in migrate page, got: %s", rec.Body.String())
	}
}

// TestMigrateImport_NoJsonInArchive sends a valid ZIP that does not contain
// passport-export.json, covering the continue-in-loop path (line 189) and the
// "archive does not contain" error path (lines 208-211).
func TestMigrateImport_NoJsonInArchive(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	// Build a ZIP with an unrelated file.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	e, err := zw.Create("readme.txt")
	if err != nil {
		t.Fatalf("creating zip entry: %v", err)
	}
	if _, err := e.Write([]byte("hello")); err != nil {
		t.Fatalf("writing zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("import_file", "no-json.zip")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := fw.Write(zipBuf.Bytes()); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/migrate/import", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200 (error page), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "migrate page") {
		t.Errorf("expected migrate page with error, got: %s", rec.Body.String())
	}
}

// TestMigrateImport_WithUploadFiles sends a ZIP containing both passport-export.json
// and an uploads/ file, covering the upload restore code path (lines 238-262).
func TestMigrateImport_WithUploadFiles(t *testing.T) {
	env := setupMigrateTest(t)
	cookies := env.createAdminSession(t)

	exportData := migrate.ExportData{
		Version:    1,
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}
	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("marshaling export data: %v", err)
	}

	// Build a ZIP with passport-export.json + an uploads/ file.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	je, err := zw.Create("passport-export.json")
	if err != nil {
		t.Fatalf("creating json zip entry: %v", err)
	}
	if _, err := je.Write(jsonBytes); err != nil {
		t.Fatalf("writing json: %v", err)
	}
	ue, err := zw.Create("uploads/logo.png")
	if err != nil {
		t.Fatalf("creating uploads zip entry: %v", err)
	}
	if _, err := ue.Write([]byte("fake png data")); err != nil {
		t.Fatalf("writing upload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("import_uploads", "1"); err != nil {
		t.Fatalf("writing import_uploads field: %v", err)
	}
	fw, err := w.CreateFormFile("import_file", "export.zip")
	if err != nil {
		t.Fatalf("creating form file: %v", err)
	}
	if _, err := fw.Write(zipBuf.Bytes()); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/migrate/import", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := env.serveWithAdminSession(t, env.handler.Import, http.MethodPost, "/admin/migrate/import", cookies, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify the upload file was restored.
	uploadsDir := env.handler.uploadsDir
	restoredPath := uploadsDir + "/logo.png"
	if _, statErr := os.Stat(restoredPath); os.IsNotExist(statErr) {
		t.Error("expected uploads/logo.png to be restored after import")
	}
}

// TestMigrateExport_WithUploads exercises the uploads walk in Export
// (lines 111-125) by placing a file in the uploads directory.
func TestMigrateExport_WithUploads(t *testing.T) {
	env := setupMigrateTest(t)

	// Place a file in the uploads directory used by the handler.
	uploadsDir := env.handler.uploadsDir
	if err := os.MkdirAll(uploadsDir, 0750); err != nil {
		t.Fatalf("creating uploads dir: %v", err)
	}
	testFile := uploadsDir + "/test-logo.png"
	if err := os.WriteFile(testFile, []byte("fake png"), 0640); err != nil {
		t.Fatalf("writing test file: %v", err)
	}

	cookies := env.createAdminSession(t)
	rec := env.serveWithAdminSession(t, env.handler.Export, http.MethodGet, "/admin/migrate/export", cookies, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	// Verify the ZIP contains the upload file.
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("opening export as zip: %v", err)
	}
	var found bool
	for _, f := range zr.File {
		if f.Name == "uploads/test-logo.png" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected uploads/test-logo.png in export archive")
	}
}
