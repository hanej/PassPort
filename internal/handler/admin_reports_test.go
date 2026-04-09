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

	"github.com/go-chi/chi/v5"
	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/crypto"
	"github.com/hanej/passport/internal/db"
	"github.com/hanej/passport/internal/idp"
	"github.com/hanej/passport/internal/job"
)

// withReportChiURLParams sets both "id" and "type" chi URL params in a single
// route context, avoiding the issue where sequential withChiURLParam calls each
// create a new context (overwriting the previous params).
func withReportChiURLParams(r *http.Request, idpID, reportType string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", idpID)
	rctx.URLParams.Add("type", reportType)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

type reportsTestEnv struct {
	db       *db.DB
	handler  *AdminReportsHandler
	reporter *job.ReportScheduler
	sm       *auth.SessionManager
	audit    *audit.Logger
}

func stubReportsRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_reports.html"] = template.Must(template.New("admin_reports.html").Funcs(funcMap).Parse(`{{define "base"}}reports list page{{end}}`))
	pages["admin_report_config.html"] = template.Must(template.New("admin_report_config.html").Funcs(funcMap).Parse(`{{define "base"}}report config page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupReportsTest(t *testing.T) *reportsTestEnv {
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
	renderer := stubReportsRenderer(t)

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

	registry := idp.NewRegistry(logger)
	reporter := job.NewReportScheduler(database, registry, cryptoSvc, auditLog, logger)

	// Start with a context cancelled at test cleanup so the cron scheduler
	// is initialised (required before ReloadSchedules can be called) and
	// properly shut down afterwards.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reporter.Start(ctx)

	h := NewAdminReportsHandler(database, reporter, renderer, auditLog, logger)

	return &reportsTestEnv{
		db:       database,
		handler:  h,
		reporter: reporter,
		sm:       sm,
		audit:    auditLog,
	}
}

func (env *reportsTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *reportsTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func (env *reportsTestEnv) createReportsTestIDP(t *testing.T, idpID, providerType string) {
	t.Helper()
	record := &db.IdentityProviderRecord{
		ID:           idpID,
		FriendlyName: "Test IDP",
		ProviderType: providerType,
		Enabled:      true,
		ConfigJSON:   `{"endpoint":"ldap.example.com:636","protocol":"ldaps","base_dn":"dc=example,dc=com"}`,
	}
	if err := env.db.CreateIDP(context.Background(), record); err != nil {
		t.Fatalf("creating test IDP: %v", err)
	}
}

// --- Pure function tests ---

func TestBuildReportFiltersFromForm(t *testing.T) {
	form := url.Values{
		"filter_attribute[]":   {"dn", "department"},
		"filter_pattern[]":     {"^ou=Service", "IT"},
		"filter_description[]": {"Exclude service accounts", "IT dept"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("parsing form: %v", err)
	}

	filters := buildReportFiltersFromForm(req, "corp-ad", db.ReportTypeExpiration)

	if len(filters) != 2 {
		t.Fatalf("expected 2 filters, got %d", len(filters))
	}
	if filters[0].Attribute != "dn" {
		t.Errorf("expected attribute 'dn', got %q", filters[0].Attribute)
	}
	if filters[0].Pattern != "^ou=Service" {
		t.Errorf("expected pattern '^ou=Service', got %q", filters[0].Pattern)
	}
	if filters[0].Description != "Exclude service accounts" {
		t.Errorf("expected description 'Exclude service accounts', got %q", filters[0].Description)
	}
	if filters[0].IDPID != "corp-ad" {
		t.Errorf("expected IDPID 'corp-ad', got %q", filters[0].IDPID)
	}
	if filters[0].ReportType != db.ReportTypeExpiration {
		t.Errorf("expected ReportType %q, got %q", db.ReportTypeExpiration, filters[0].ReportType)
	}
	if filters[1].Attribute != "department" {
		t.Errorf("expected attribute 'department', got %q", filters[1].Attribute)
	}
}

func TestBuildReportFiltersFromForm_EmptyAttribute(t *testing.T) {
	form := url.Values{
		"filter_attribute[]": {"", "department"},
		"filter_pattern[]":   {"ignored", "Engineering"},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildReportFiltersFromForm(req, "corp-ad", db.ReportTypeExpiration)

	if len(filters) != 1 {
		t.Fatalf("expected 1 filter (empty attr skipped), got %d", len(filters))
	}
	if filters[0].Attribute != "department" {
		t.Errorf("expected 'department', got %q", filters[0].Attribute)
	}
}

func TestBuildReportFiltersFromForm_EmptyPattern(t *testing.T) {
	form := url.Values{
		"filter_attribute[]": {"memberOf"},
		"filter_pattern[]":   {""},
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildReportFiltersFromForm(req, "corp-ad", db.ReportTypeExpiration)

	if len(filters) != 0 {
		t.Errorf("expected 0 filters (empty pattern skipped), got %d", len(filters))
	}
}

func TestBuildReportFiltersFromForm_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildReportFiltersFromForm(req, "corp-ad", db.ReportTypeExpiration)
	if len(filters) != 0 {
		t.Errorf("expected 0 filters for empty form, got %d", len(filters))
	}
}

func TestBuildReportFiltersFromForm_MissingDescriptions(t *testing.T) {
	// Descriptions slice shorter than attributes/patterns → empty description used.
	form := url.Values{
		"filter_attribute[]": {"memberOf"},
		"filter_pattern[]":   {"CN=Admins"},
		// no filter_description[]
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}

	filters := buildReportFiltersFromForm(req, "corp-ad", db.ReportTypeExpiration)
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Description != "" {
		t.Errorf("expected empty description, got %q", filters[0].Description)
	}
}

// --- List handler tests ---

func TestAdminReportsList(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.handler.List(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "reports list page") {
		t.Errorf("expected reports list page content, got: %s", rec.Body.String())
	}
}

func TestAdminReportsList_Empty(t *testing.T) {
	// No IDPs → items is nil → still renders 200.
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.handler.List(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for empty list, got %d", rec.Code)
	}
}

func TestAdminReportsList_ListIDPsError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockReportsErrStore{DB: database, listIDPsErr: fmt.Errorf("db error")}
	h := newReportsMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodGet, "/admin/reports", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListIDPs fails, got %d", rec.Code)
	}
}

// --- Show handler tests ---

func TestAdminReportsShow_UnknownType(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", "unknown_type")
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports/corp-ad/unknown_type", cookies, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown report type, got %d", rec.Code)
	}
}

func TestAdminReportsShow_IDPNotFound(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "nonexistent", db.ReportTypeExpiration)
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports/nonexistent/expiration", cookies, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing IDP, got %d", rec.Code)
	}
}

func TestAdminReportsShow_Success(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports/corp-ad/expiration", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page content, got: %s", rec.Body.String())
	}
}

func TestAdminReportsShow_ExpiredType(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpired)
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports/corp-ad/expired", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for expired type, got %d", rec.Code)
	}
}

func TestAdminReportsShow_FreeIPADefaultFilters(t *testing.T) {
	// FreeIPA with no saved filters should pre-populate the nsAccountLock default.
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "freeipa-test", "freeipa")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "freeipa-test", db.ReportTypeExpiration)
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports/freeipa-test/expiration", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for FreeIPA show with default filters, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page content, got: %s", rec.Body.String())
	}
}

func TestAdminReportsShow_WithExistingConfig(t *testing.T) {
	// When a config already exists, Show loads it rather than using defaults.
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	if err := env.db.SaveReportConfig(context.Background(), &db.ReportConfig{
		IDPID:                "corp-ad",
		ReportType:           db.ReportTypeExpiration,
		Enabled:              true,
		CronSchedule:         "0 6 * * 1",
		DaysBeforeExpiration: 21,
	}); err != nil {
		t.Fatalf("saving report config: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Show(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodGet, "/admin/reports/corp-ad/expiration", cookies, "")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// --- Save handler tests ---

func TestAdminReportsSave_UnknownType(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", "bad_type")
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/corp-ad/bad_type", cookies, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown report type in Save, got %d", rec.Code)
	}
}

func TestAdminReportsSave_ParseFormError(t *testing.T) {
	database := setupTestDB(t)
	mock := &mockReportsErrStore{DB: database}
	h := newReportsMockHandler(t, database, mock)

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/expiration", errReader{})
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withReportChiURLParams(req, "corp-ad", db.ReportTypeExpiration)
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for ParseForm error, got %d", rec.Code)
	}
}

func TestAdminReportsSave_IDPNotFound(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)

	form := url.Values{}
	form.Set("cron_schedule", "0 7 * * 1")
	form.Set("days_before_expiration", "14")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "nonexistent", db.ReportTypeExpiration)
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/nonexistent/expiration", cookies, form.Encode())
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing IDP in Save, got %d", rec.Code)
	}
}

func TestAdminReportsSave_BadCron(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	form := url.Values{}
	form.Set("cron_schedule", "not a valid cron !!!")
	form.Set("days_before_expiration", "14")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/corp-ad/expiration", cookies, form.Encode())
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (re-render with cron error), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page re-render on bad cron, got: %s", rec.Body.String())
	}
}

func TestAdminReportsSave_EmptyCronDefaulted(t *testing.T) {
	// Empty cron_schedule is replaced with the default "0 7 * * 1".
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	form := url.Values{}
	form.Set("cron_schedule", "")
	form.Set("days_before_expiration", "14")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/corp-ad/expiration", cookies, form.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetReportConfig(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil || cfg == nil {
		t.Fatalf("expected non-nil config, err=%v", err)
	}
	if cfg.CronSchedule != "0 7 * * 1" {
		t.Errorf("expected default schedule '0 7 * * 1', got %q", cfg.CronSchedule)
	}
}

func TestAdminReportsSave_DaysOutOfRange(t *testing.T) {
	// days_before_expiration > 90 falls back to 14.
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	form := url.Values{}
	form.Set("cron_schedule", "0 7 * * 1")
	form.Set("days_before_expiration", "999")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/corp-ad/expiration", cookies, form.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	cfg, err := env.db.GetReportConfig(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil || cfg == nil {
		t.Fatalf("expected non-nil config, err=%v", err)
	}
	if cfg.DaysBeforeExpiration != 14 {
		t.Errorf("expected default DaysBeforeExpiration=14, got %d", cfg.DaysBeforeExpiration)
	}
}

func TestAdminReportsSave_Success(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	form := url.Values{}
	form.Set("cron_schedule", "0 7 * * 1")
	form.Set("days_before_expiration", "14")
	form.Set("recipients", "admin@example.com")
	// enabled not set (disabled) to avoid needing LDAP connectivity.

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/corp-ad/expiration", cookies, form.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on successful Save, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page content, got: %s", rec.Body.String())
	}

	cfg, err := env.db.GetReportConfig(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("getting report config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config after save")
	}
	if cfg.CronSchedule != "0 7 * * 1" {
		t.Errorf("expected schedule '0 7 * * 1', got %q", cfg.CronSchedule)
	}
	if cfg.Recipients != "admin@example.com" {
		t.Errorf("expected recipients 'admin@example.com', got %q", cfg.Recipients)
	}
}

func TestAdminReportsSave_WithFilters(t *testing.T) {
	env := setupReportsTest(t)
	cookies := env.createAdminSession(t)
	env.createReportsTestIDP(t, "corp-ad", "ad")

	form := url.Values{
		"cron_schedule":          {"0 7 * * 1"},
		"days_before_expiration": {"14"},
		"filter_attribute[]":     {"dn"},
		"filter_pattern[]":       {"^ou=Service"},
		"filter_description[]":   {"Exclude service accounts"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.Save(w, r)
	})

	rec := env.serveWithAdminSession(t, handler, http.MethodPost, "/admin/reports/corp-ad/expiration", cookies, form.Encode())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	filters, err := env.db.ListReportFilters(context.Background(), "corp-ad", db.ReportTypeExpiration)
	if err != nil {
		t.Fatalf("listing filters: %v", err)
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Attribute != "dn" {
		t.Errorf("expected attribute 'dn', got %q", filters[0].Attribute)
	}
}

// mockReportsErrStore wraps *db.DB and overrides specific methods to inject errors.
type mockReportsErrStore struct {
	*db.DB
	listIDPsErr          error
	saveReportConfigErr  error
	saveReportFiltersErr error
}

func (m *mockReportsErrStore) ListIDPs(ctx context.Context) ([]db.IdentityProviderRecord, error) {
	if m.listIDPsErr != nil {
		return nil, m.listIDPsErr
	}
	return m.DB.ListIDPs(ctx)
}

func (m *mockReportsErrStore) SaveReportConfig(ctx context.Context, cfg *db.ReportConfig) error {
	if m.saveReportConfigErr != nil {
		return m.saveReportConfigErr
	}
	return m.DB.SaveReportConfig(ctx, cfg)
}

func (m *mockReportsErrStore) SaveReportFilters(ctx context.Context, idpID, reportType string, filters []db.ReportFilter) error {
	if m.saveReportFiltersErr != nil {
		return m.saveReportFiltersErr
	}
	return m.DB.SaveReportFilters(ctx, idpID, reportType, filters)
}

func newReportsMockHandler(t *testing.T, database *db.DB, mock *mockReportsErrStore) *AdminReportsHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	renderer := stubReportsRenderer(t)
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
	// Pass nil reporter: error paths return before reaching reporter calls.
	return NewAdminReportsHandler(mock, nil, renderer, auditLog, logger)
}

func TestAdminReportsSave_SaveConfigError(t *testing.T) {
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

	mock := &mockReportsErrStore{DB: database, saveReportConfigErr: fmt.Errorf("db write failed")}
	h := newReportsMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("cron_schedule", "0 7 * * 1")
	form.Set("days_before_expiration", "14")

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/expiration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withReportChiURLParams(req, "corp-ad", db.ReportTypeExpiration)
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when SaveReportConfig fails (re-render), got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page re-render, got: %s", rec.Body.String())
	}
}

func TestAdminReportsSave_SaveFiltersError(t *testing.T) {
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

	mock := &mockReportsErrStore{DB: database, saveReportFiltersErr: fmt.Errorf("filters write failed")}
	h := newReportsMockHandler(t, database, mock)

	form := url.Values{}
	form.Set("cron_schedule", "0 7 * * 1")
	form.Set("days_before_expiration", "14")

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/expiration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withReportChiURLParams(req, "corp-ad", db.ReportTypeExpiration)
	rec := httptest.NewRecorder()
	h.Save(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when SaveReportFilters fails (re-render), got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page re-render, got: %s", rec.Body.String())
	}
}

// TestAdminReportsSave_ListFiltersReloadError covers the branch where
// ListReportFilters fails after a successful save — falls back to in-memory filters.
func TestAdminReportsSave_ListFiltersReloadError(t *testing.T) {
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

	// We need a reporter that calls ReloadSchedules successfully, so build
	// a real one backed by a store that fails ListReportFilters.
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
	_ = tmpFile.Close()
	auditLog, err := audit.NewLogger(database, tmpFile.Name(), logger)
	if err != nil {
		t.Fatalf("creating audit logger: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })

	mock := &mockReportsListFiltersErrStore{DB: database}
	reporter := job.NewReportScheduler(mock, registry, cryptoSvc, auditLog, logger)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reporter.Start(ctx)

	renderer := stubReportsRenderer(t)
	h := NewAdminReportsHandler(mock, reporter, renderer, auditLog, logger)

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	hash, err := auth.HashPassword("admin-pass")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := database.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}
	rec0 := httptest.NewRecorder()
	req0 := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := sm.CreateSession(rec0, req0, "local", "", "admin", true, false); err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := rec0.Result().Cookies()

	form := url.Values{}
	form.Set("cron_schedule", "0 7 * * 1")
	form.Set("days_before_expiration", "14")

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/expiration", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	wrapped := sm.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		h.Save(w, r)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 when ListReportFilters reload fails, got %d; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "report config page") {
		t.Errorf("expected report config page content, got: %s", rec.Body.String())
	}
}

// mockReportsListFiltersErrStore fails only ListReportFilters.
type mockReportsListFiltersErrStore struct {
	*db.DB
}

func (m *mockReportsListFiltersErrStore) ListReportFilters(ctx context.Context, idpID, reportType string) ([]db.ReportFilter, error) {
	return nil, fmt.Errorf("reload list error")
}

// --- SendNow handler tests ---

func TestAdminReportsSendNow_UnknownType(t *testing.T) {
	env := setupReportsTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", "bad_type")
		env.handler.SendNow(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/bad_type/send", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown type in SendNow, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error', got: %v", result["status"])
	}
}

func TestAdminReportsSendNow_ReporterError(t *testing.T) {
	// No report config configured → RunReportForIDP returns an error.
	env := setupReportsTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", db.ReportTypeExpiration)
		env.handler.SendNow(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/expiration/send", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with error JSON, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error' (no config), got: %v", result["status"])
	}
	if _, ok := result["message"]; !ok {
		t.Error("expected 'message' key in JSON error response")
	}
}

// --- Preview handler tests ---

func TestAdminReportsPreview_UnknownType(t *testing.T) {
	env := setupReportsTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "corp-ad", "bad_type")
		env.handler.Preview(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/corp-ad/bad_type/preview", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown type in Preview, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error', got: %v", result["status"])
	}
}

func TestAdminReportsPreview_ReporterError(t *testing.T) {
	// No IDP configured → PreviewForIDP returns an error.
	env := setupReportsTest(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = withReportChiURLParams(r, "nonexistent", db.ReportTypeExpiration)
		env.handler.Preview(w, r)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/reports/nonexistent/expiration/preview", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with error JSON, got %d", rec.Code)
	}
	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if result["status"] != "error" {
		t.Errorf("expected status 'error' (no IDP), got: %v", result["status"])
	}
	if _, ok := result["message"]; !ok {
		t.Error("expected 'message' key in JSON error response")
	}
}
