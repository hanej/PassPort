package handler

import (
	"context"
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
	"github.com/hanej/passport/internal/db"
)

// stubRenderer creates a minimal Renderer with stub templates for testing.
func stubRenderer(t *testing.T) *Renderer {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	funcMap := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"subtract": func(a, b int) int { return a - b },
		"pages":    func(n int) []int { return nil },
	}
	pages := make(map[string]*template.Template)
	pages["force_password_change.html"] = template.Must(template.New("force_password_change.html").Funcs(funcMap).Parse(`{{define "base"}}change password form{{end}}`))
	pages["error.html"] = template.Must(template.New("error.html").Funcs(funcMap).Parse(`{{define "base"}}error page{{end}}`))

	return &Renderer{pages: pages, logger: logger}
}

type bootstrapTestEnv struct {
	db       *db.DB
	sm       *auth.SessionManager
	handler  *BootstrapHandler
	auditLog *audit.Logger
}

func setupBootstrapTest(t *testing.T) *bootstrapTestEnv {
	t.Helper()

	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubRenderer(t)

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

	h := NewBootstrapHandler(database, sm, renderer, auditLog, logger)

	return &bootstrapTestEnv{
		db:       database,
		sm:       sm,
		handler:  h,
		auditLog: auditLog,
	}
}

// createAdminAndSession creates a local admin and a session, returning the
// session cookies and session ID.
func (env *bootstrapTestEnv) createAdminAndSession(t *testing.T, mustChangePassword bool) ([]*http.Cookie, string) {
	t.Helper()

	hash, err := auth.HashPassword("old-password")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := env.db.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	sessionID, err := env.sm.CreateSession(rec, req, "local", "", "admin", true, mustChangePassword)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}

	return rec.Result().Cookies(), sessionID
}

// wrapWithSession wraps a handler in the session middleware and attaches cookies.
func (env *bootstrapTestEnv) serveWithSession(t *testing.T, handler http.HandlerFunc, method, path string, cookies []*http.Cookie, body string) *httptest.ResponseRecorder {
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

func TestShowChangePassword(t *testing.T) {
	env := setupBootstrapTest(t)
	cookies, _ := env.createAdminAndSession(t, true)

	// ShowChangePassword calls csrf.TemplateField(r), which panics without
	// CSRF middleware context. We wrap with a handler that skips CSRF by
	// catching the panic and still verifying the handler path was reached.
	//
	// A simpler approach: test that the session middleware does not redirect
	// and the handler attempts to render the form template.
	handlerReached := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.SessionFromContext(r.Context())
		if sess == nil {
			t.Error("expected session in context")
			return
		}
		handlerReached = true
		// Render the template directly without CSRF field (avoids panic).
		env.handler.renderer.Render(w, r, "force_password_change.html", PageData{
			Title:   "Change Password",
			Session: sess,
		})
	})

	rec := env.serveWithSession(t, testHandler, http.MethodGet, "/change-password", cookies, "")

	if !handlerReached {
		t.Fatal("handler was not reached")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "change password form") {
		t.Errorf("expected form content, got: %s", rec.Body.String())
	}
}

func TestChangePasswordSuccess(t *testing.T) {
	env := setupBootstrapTest(t)
	cookies, sessionID := env.createAdminAndSession(t, true)

	form := url.Values{}
	form.Set("new_password", "new-secure-password-123!")
	form.Set("confirm_password", "new-secure-password-123!")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/change-password", cookies, form.Encode())

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusFound, rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc != "/dashboard" {
		t.Errorf("expected redirect to /dashboard, got %s", loc)
	}

	// Verify password was updated in the DB.
	admin, err := env.db.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if err := auth.CheckPassword(admin.PasswordHash, "new-secure-password-123!"); err != nil {
		t.Error("new password should match stored hash")
	}
	if admin.MustChangePassword {
		t.Error("must_change_password should be false after password change")
	}

	// Verify session must_change_password flag was cleared.
	sess, err := env.db.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("getting session: %v", err)
	}
	if sess.MustChangePassword {
		t.Error("session must_change_password should be false after password change")
	}
}

func TestChangePasswordMismatch(t *testing.T) {
	env := setupBootstrapTest(t)
	cookies, _ := env.createAdminAndSession(t, true)

	form := url.Values{}
	form.Set("new_password", "password-one")
	form.Set("confirm_password", "password-two")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/change-password", cookies, form.Encode())

	// Should NOT redirect to /dashboard.
	if rec.Code == http.StatusFound {
		loc := rec.Header().Get("Location")
		if loc == "/dashboard" {
			t.Fatal("should not redirect to /dashboard on password mismatch")
		}
	}

	// Verify password was NOT changed.
	admin, err := env.db.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if err := auth.CheckPassword(admin.PasswordHash, "old-password"); err != nil {
		t.Error("password should not have changed on mismatch")
	}
}

func TestChangePasswordEmpty(t *testing.T) {
	env := setupBootstrapTest(t)
	cookies, _ := env.createAdminAndSession(t, true)

	form := url.Values{}
	form.Set("new_password", "")
	form.Set("confirm_password", "")

	rec := env.serveWithSession(t, env.handler.ChangePassword, http.MethodPost, "/change-password", cookies, form.Encode())

	// Should NOT redirect to /dashboard.
	if rec.Code == http.StatusFound {
		loc := rec.Header().Get("Location")
		if loc == "/dashboard" {
			t.Fatal("should not redirect to /dashboard on empty password")
		}
	}

	// Verify password was NOT changed.
	admin, err := env.db.GetLocalAdmin(context.Background(), "admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if err := auth.CheckPassword(admin.PasswordHash, "old-password"); err != nil {
		t.Error("password should not have changed on empty input")
	}
}

// TestShowChangePassword_Direct calls ShowChangePassword directly without CSRF middleware.
// csrf.TemplateField(r) returns "" when no middleware is present — no panic.
func TestShowChangePassword_Direct(t *testing.T) {
	env := setupBootstrapTest(t)
	cookies, _ := env.createAdminAndSession(t, true)

	// Serve directly through session middleware so sess is in context.
	rec := env.serveWithSession(t, env.handler.ShowChangePassword, http.MethodGet, "/change-password", cookies, "")

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// mockBootstrapAdminStore wraps *db.DB and overrides UpdateLocalAdminPassword to inject errors.
type mockBootstrapAdminStore struct {
	*db.DB
	updatePasswordErr error
}

func (m *mockBootstrapAdminStore) UpdateLocalAdminPassword(ctx context.Context, username, passwordHash string, mustChange bool) error {
	if m.updatePasswordErr != nil {
		return m.updatePasswordErr
	}
	return m.DB.UpdateLocalAdminPassword(ctx, username, passwordHash, mustChange)
}

// TestChangePassword_DBError covers admin_bootstrap.go:93-97 where
// UpdateLocalAdminPassword fails and the handler renders a 500.
func TestChangePassword_DBError(t *testing.T) {
	database := setupTestDB(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mockStore := &mockBootstrapAdminStore{
		DB:                database,
		updatePasswordErr: fmt.Errorf("DB write failed"),
	}

	sm := auth.NewSessionManager(database, 30*time.Minute, false, logger)
	renderer := stubRenderer(t)

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

	h := NewBootstrapHandler(mockStore, sm, renderer, auditLog, logger)

	// Create admin and session in real DB so session middleware can authenticate the request.
	hash, err := auth.HashPassword("temp-pass")
	if err != nil {
		t.Fatalf("hashing password: %v", err)
	}
	if _, err := database.CreateLocalAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatalf("creating admin: %v", err)
	}

	sessionRec := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "/", nil)
	_, err = sm.CreateSession(sessionRec, sessionReq, "local", "", "admin", true, true)
	if err != nil {
		t.Fatalf("creating session: %v", err)
	}
	cookies := sessionRec.Result().Cookies()

	// Submit a valid change-password form (matching non-empty passwords).
	form := url.Values{}
	form.Set("new_password", "new-secure-pass-123!")
	form.Set("confirm_password", "new-secure-pass-123!")

	req := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	wrapped := sm.Middleware(http.HandlerFunc(h.ChangePassword))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when UpdateLocalAdminPassword fails, got %d", rec.Code)
	}
}
