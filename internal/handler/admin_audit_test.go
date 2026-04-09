package handler

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hanej/passport/internal/audit"
	"github.com/hanej/passport/internal/auth"
	"github.com/hanej/passport/internal/db"
)

type auditTestEnv struct {
	db       *db.DB
	handler  *AdminAuditHandler
	sm       *auth.SessionManager
	auditLog *audit.Logger
}

func stubAuditRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["admin_audit.html"] = template.Must(template.New("admin_audit.html").Funcs(funcMap).Parse(`{{define "base"}}audit log page{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))
	return &Renderer{pages: pages, logger: logger}
}

func setupAuditTest(t *testing.T) *auditTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubAuditRenderer(t)

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

	h := NewAdminAuditHandler(database, renderer, logger)

	return &auditTestEnv{
		db:       database,
		handler:  h,
		sm:       sm,
		auditLog: auditLog,
	}
}

func (env *auditTestEnv) createAdminSession(t *testing.T) []*http.Cookie {
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

func (env *auditTestEnv) serveWithAdminSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	wrapped := env.sm.Middleware(handler)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)
	return rec
}

func TestAuditList(t *testing.T) {
	env := setupAuditTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit", cookies)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "audit log page") {
		t.Errorf("expected audit log content, got: %s", rec.Body.String())
	}
}

func TestAuditListWithEntries(t *testing.T) {
	env := setupAuditTest(t)
	cookies := env.createAdminSession(t)

	// Add some audit entries.
	for i := 0; i < 5; i++ {
		env.auditLog.Log(context.Background(), &db.AuditEntry{
			Timestamp: time.Now().UTC(),
			Username:  "testuser",
			SourceIP:  "127.0.0.1",
			Action:    audit.ActionLogin,
			Result:    audit.ResultSuccess,
			Details:   "test entry",
		})
	}

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit", cookies)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAuditListWithFilters(t *testing.T) {
	env := setupAuditTest(t)
	cookies := env.createAdminSession(t)

	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit?username=testuser&action=login&result=success&page=1", cookies)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAuditListPagination(t *testing.T) {
	env := setupAuditTest(t)
	cookies := env.createAdminSession(t)

	// Add enough entries to create multiple pages.
	for i := 0; i < 55; i++ {
		env.auditLog.Log(context.Background(), &db.AuditEntry{
			Timestamp: time.Now().UTC(),
			Username:  "testuser",
			SourceIP:  "127.0.0.1",
			Action:    audit.ActionLogin,
			Result:    audit.ResultSuccess,
			Details:   "test entry",
		})
	}

	// First page
	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit?page=1", cookies)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	// Second page
	rec = env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit?page=2", cookies)
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 for page 2, got %d", rec.Code)
	}
}

func TestAuditListInvalidPage(t *testing.T) {
	env := setupAuditTest(t)
	cookies := env.createAdminSession(t)

	// Negative page should default to 1.
	rec := env.serveWithAdminSession(t, env.handler.List, http.MethodGet, "/admin/audit?page=-1", cookies)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

// mockAuditErrDB wraps *db.DB and overrides ListAudit to return an error.
type mockAuditErrDB struct {
	*db.DB
	listAuditErr error
}

func (m *mockAuditErrDB) ListAudit(ctx context.Context, filter db.AuditFilter) ([]db.AuditEntry, int, error) {
	if m.listAuditErr != nil {
		return nil, 0, m.listAuditErr
	}
	return m.DB.ListAudit(ctx, filter)
}

// TestAuditList_DBError covers the ListAudit error path (admin_audit.go:64-68).
func TestAuditList_DBError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockAuditErrDB{
		DB:           database,
		listAuditErr: fmt.Errorf("database unavailable"),
	}

	renderer := stubAuditRenderer(t)
	h := NewAdminAuditHandler(mockStore, renderer, logger)

	req := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when ListAudit fails, got %d", rec.Code)
	}
}
